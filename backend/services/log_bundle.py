"""Diagnostic log bundle service.

Builds a ZIP archive containing the most relevant UCM logs and a small system
diagnostic file, with sensitive-looking tokens redacted. The bundle is meant
for support / troubleshooting: the user downloads it from Settings and
attaches it to a support request or GitHub issue.

Contents:
  - ucm.log      (last ~2 MB of application log)
  - error.log    (last ~2 MB of gunicorn/error log)
  - journal.log  (last 2000 lines of `journalctl -u ucm`, systemd hosts only)
  - access.log   (last 1 MB of access log, when present)
  - system.txt    (version, migration count, DB backend, services status)

Sanitisation (defence in depth — logs should never contain secrets, but a
redaction pass guards against accidental leakage):
  - RFC 6750 Bearer tokens:  `Authorization: Bearer xxx` → `Authorization: Bearer [redacted]`
  - `password=...`, `pass=...`, `pwd=...` query-param style assignments
  - `token=...` query-param style assignments
  - PEM private key blocks (BEGIN ... PRIVATE KEY ... END ... PRIVATE KEY)
  - Long JWT-like strings (three base64 segments separated by dots)

Size policy: each included log file is truncated to its last ``MAX_BYTES_PER_FILE``
bytes before being added; the resulting ZIP stays well under the ~5 MB target.
"""
from __future__ import annotations

import io
import logging
import os
import re
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config.settings import is_docker

logger = logging.getLogger(__name__)

# --- size policy -----------------------------------------------------------
MAX_BYTES_PER_FILE = 2 * 1024 * 1024      # 2 MB per log file (last N bytes retained)
MAX_BYTES_ACCESS = 1 * 1024 * 1024       # 1 MB for the access log
MAX_JOURNAL_LINES = 2000                  # last N lines of journalctl

# Where UCM stores its file logs (matches the gunicorn/logging config).
LOG_DIR = Path(os.environ.get('UCM_LOG_DIR', '/var/log/ucm'))

# --- sanitisation patterns -------------------------------------------------
# Each entry is (compiled_regex, replacement_template).
_PATTERNS: list[tuple[re.Pattern, str]] = []


def _add(pattern: str, repl: str, flags: int = 0) -> None:
    _PATTERNS.append((re.compile(pattern, flags), repl))


# Authorization header, any casing.  `Bearer xyz`, `Basic xyz`, etc.
_add(r'(?i)(authorization\s*[:=]\s*)([A-Za-z]+)\s+([^\s,;]+)', r'\1\2 [redacted]')
# Bare `Bearer <token>` (in JSON payloads / logs).
_add(r'(?i)\b(bearer)\s+([A-Za-z0-9_\-=\.]+)', r'\1 [redacted]')
# `password=secret`, `pass=`, `pwd=`, `passwd=`  (query string / config style)
_add(r'(?i)\b(pass(word|wd)?|secret)\s*[:=]\s*([^\s,;&]+)', r'\1=[redacted]')
# `token=...` (API tokens in URLs / config)
_add(r'(?i)\b(token|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*([^\s,;&]+)',
     r'\1=[redacted]')
# JWT-ish: three base64url segments separated by dots, middle one reasonably long.
_add(r'\beyJ[A-Za-z0-9_\-=]{6,}\.[A-Za-z0-9_\-=]{6,}\.[A-Za-z0-9_\-=]{6,}\b', '[redacted-jwt]')
# Whole PEM private-key blocks (RSA, EC, OPENSSH, ENCRYPTED, ...).
_add(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
     '[redacted-private-key]', flags=re.DOTALL)


def redact(text: str) -> str:
    """Apply every sanitisation pattern to ``text`` and return the redacted copy."""
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text


# --- file collection -------------------------------------------------------
def _tail_bytes(path: Path, max_bytes: int) -> Optional[bytes]:
    """Return the last ``max_bytes`` bytes of ``path`` (raw), or None if unreadable."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    try:
        with path.open('rb') as fh:
            if size > max_bytes:
                fh.seek(-max_bytes, os.SEEK_END)
                # drop partial first line so we start at a line boundary
                fh.readline()
            return fh.read()
    except OSError as exc:
        logger.warning('log_bundle: could not read %s: %s', path, exc)
        return None


def collect_journal() -> Optional[bytes]:
    """Return the last ``MAX_JOURNAL_LINES`` lines of the ucm unit journal.

    Skipped on Docker (no systemd journal) and when journalctl is missing.
    Returns raw bytes (may be empty); None when journalctl is unavailable.
    """
    if is_docker():
        return None
    exe = shutil.which('journalctl')
    if not exe:
        return None
    try:
        proc = subprocess.run(
            [exe, '-u', 'ucm', '--no-pager', '-n', str(MAX_JOURNAL_LINES),
             '--output=short-iso'],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode != 0:
            logger.info('log_bundle: journalctl rc=%d: %s', proc.returncode,
                        (proc.stderr or '').strip()[:200])
        return (proc.stdout or '').encode('utf-8', errors='replace') or None
    except Exception as exc:  # noqa: BLE001
        logger.info('log_bundle: journalctl skipped: %s', exc)
        return None


# --- system diagnostic -----------------------------------------------------
def _system_diagnostic() -> str:
    """Build a short, secret-free diagnostic string."""
    lines: list[str] = []
    lines.append(f'Generated: {datetime.now(timezone.utc).isoformat()}')
    lines.append(f'Deployment: {"docker" if is_docker() else "systemd"}')
    lines.append(f'Hostname: {os.uname().nodename}')
    try:
        from services.updates import get_current_version
        lines.append(f'Version: {get_current_version()}')
    except Exception:  # noqa: BLE001
        pass
    try:
        url = os.getenv('DATABASE_URL', '')
        backend = 'postgresql' if url.startswith('postgresql') else 'sqlite'
        lines.append(f'DB backend: {backend}')
    except Exception:  # noqa: BLE001
        pass
    try:
        from app import db
        from sqlalchemy import text
        mig = db.session.execute(text("SELECT value FROM system_config WHERE key='migration_version'")).scalar()
        lines.append(f'Migration version: {mig}')
    except Exception:  # noqa: BLE001
        pass
    # Service statuses (reuses the dashboard helper, no secrets).
    try:
        from api.v2.dashboard import get_system_status
        st = get_system_status() or {}
        lines.append('Services:')
        for k, v in st.items():
            lines.append(f'  {k}: {v}')
    except Exception:  # noqa: BLE001
        pass
    return '\n'.join(lines) + '\n'


# --- bundle assembly -------------------------------------------------------
def build_bundle() -> bytes:
    """Assemble the diagnostic bundle and return it as ZIP bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        # primary logs. The application log is taken from the path the logging
        # setup actually chose, so the bundle is not empty on Docker (which
        # writes nothing under LOG_DIR) or wherever that path was unwritable.
        from utils.app_log import resolved_path
        app_log = resolved_path() or (LOG_DIR / 'ucm.log')
        for path, arcname, cap in ((app_log, 'ucm.log', MAX_BYTES_PER_FILE),
                                   (LOG_DIR / 'error.log', 'error.log', MAX_BYTES_PER_FILE),
                                   (LOG_DIR / 'access.log', 'access.log', MAX_BYTES_ACCESS)):
            raw = _tail_bytes(path, cap)
            if raw is None:
                continue
            text = raw.decode('utf-8', errors='replace')
            zf.writestr(arcname, redact(text))
        # journal (systemd only)
        jraw = collect_journal()
        if jraw:
            zf.writestr('journal.log', redact(jraw.decode('utf-8', errors='replace')))
        # diagnostic
        try:
            zf.writestr('system.txt', redact(_system_diagnostic()))
        except Exception as exc:  # noqa: BLE001 — never break the download over the diagnostic
            logger.warning('log_bundle: diagnostic failed: %s', exc)
    data = buf.getvalue()
    logger.info('log_bundle: built %.1f KB', len(data) / 1024.0)
    return data


def bundle_filename() -> str:
    """Suggested download filename, e.g. ``ucm-logs-netsuit-20260627T1123.zip``."""
    host = os.uname().nodename
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    return f'ucm-logs-{host}-{ts}.zip'
