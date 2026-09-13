"""The rollback artefact a migration is not allowed to start without.

``_backup_current_db()`` reports every failure the same way it reports "there
was nothing to snapshot": by returning ``None``. ``migrate_data()`` stored
that in its statistics and carried on, so a migration could copy an entire
installation onto another backend, rewrite ``ucm.env`` and restart the
service with no way back — and the only trace was a line in the log.

This module turns that into a refusal, and then goes one step further: a file
that exists is not yet a snapshot. A truncated SQLite copy or a ``pg_dump``
that wrote a header and died looks exactly like a good one from the outside,
which is worse than no snapshot at all because an operator would trust it. So
the artefact is re-opened and read back before the migration is allowed to
touch the target, and what was checked is returned as a proof the operator
can see.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import quote
import hashlib
import logging
import os
import shutil
import subprocess

from sqlalchemy import inspect

from .helpers import (
    _backup_current_db,
    _discard,
    _live_database_url,
    _short_err,
)

logger = logging.getLogger(__name__)

# Reading a snapshot back is a sequential read of a file this host just
# wrote; anything slower than this means the storage is in trouble and the
# migration should not be relying on it.
_VALIDATION_TIMEOUT = 120

# Hashing happens on a file the size of the database, so it is read in
# chunks rather than loaded whole.
_HASH_CHUNK = 1024 * 1024


class SnapshotError(Exception):
    """No usable snapshot of the source, so the migration must not start.

    The message is meant for the operator and is safe to return from the API:
    it names what failed, never a credential and never an absolute path.
    """


@dataclass(frozen=True)
class SourceSnapshot:
    """A verified rollback point, and what proves it is one."""

    path: Path
    backend: str
    size_bytes: int
    sha256: str
    created_at: str
    verified: str
    method: str

    def as_proof(self) -> Dict[str, Any]:
        """What the API returns and the audit log records.

        The directory is deliberately absent: the snapshot lives under the
        instance's data directory, which is not the operator's business and
        has no place in an audit entry forwarded to syslog.
        """
        return {
            'name': self.path.name,
            'backend': self.backend,
            'method': self.method,
            'size_bytes': self.size_bytes,
            'sha256': self.sha256,
            'created_at': self.created_at,
            'verified': self.verified,
        }


def read_only_uri(path: Path) -> str:
    """A SQLite URI that can only be read, whatever the path looks like.

    The data directory is the operator's to choose, so a space or a question
    mark in it would otherwise end the URI early and silently open a
    different file — or none.
    """
    return f"file:{quote(str(path))}?mode=ro"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _source_backend() -> str:
    """Which backend is actually connected, not which one is configured.

    Everything below branches on this — how the snapshot is taken, how it is
    read back — so it has to describe the database the migration will read.
    """
    try:
        return _live_database_url().get_backend_name()
    except Exception as exc:
        raise SnapshotError(
            f"The database in use could not be identified: {_short_err(str(exc))}"
        ) from exc


def _verify_sqlite(path: Path, expected_tables: set) -> str:
    """Open the copy and read it, the way a rollback would have to.

    ``quick_check`` is the cheap half of ``integrity_check``: it reads every
    page and validates the b-trees without the cross-index checks, which is
    what catches the failure mode that matters here — a copy truncated by a
    full disk or interrupted mid-page.
    """
    import sqlite3

    try:
        conn = sqlite3.connect(read_only_uri(path), uri=True)
    except sqlite3.Error as exc:
        raise SnapshotError(
            f"The snapshot cannot be opened: {_short_err(str(exc))}") from exc

    try:
        row = conn.execute("PRAGMA quick_check").fetchone()
        if not row or str(row[0]).lower() != 'ok':
            raise SnapshotError(
                "The snapshot did not pass SQLite's integrity check; "
                "the migration was not started.")
        names = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    except sqlite3.Error as exc:
        raise SnapshotError(
            f"The snapshot could not be read back: {_short_err(str(exc))}"
        ) from exc
    finally:
        conn.close()

    missing = sorted(expected_tables - names)
    if missing:
        raise SnapshotError(
            f"The snapshot is missing {len(missing)} table(s) the source has, "
            f"starting with '{missing[0]}'; the migration was not started.")

    return f"quick_check ok, {len(names)} tables"


def _verify_pg_dump(path: Path) -> str:
    """List the dump's table of contents, which is what a restore reads first.

    ``pg_restore --list`` parses the custom-format header and the whole entry
    catalogue, so a dump cut short by a failed ``pg_dump`` fails here rather
    than on the day someone needs it.
    """
    binary = shutil.which('pg_restore')
    if not binary:
        raise SnapshotError(
            "pg_restore is not installed, so the snapshot cannot be verified; "
            "install the PostgreSQL client tools before migrating.")

    try:
        result = subprocess.run(
            [binary, '--list', str(path)],
            capture_output=True, timeout=_VALIDATION_TIMEOUT, check=False)
    except subprocess.TimeoutExpired as exc:
        raise SnapshotError(
            "Verifying the snapshot timed out; the migration was not started."
        ) from exc
    except OSError as exc:
        raise SnapshotError(
            f"The snapshot could not be verified: {_short_err(str(exc))}"
        ) from exc

    if result.returncode != 0:
        stderr = (result.stderr or b'').decode(errors='replace')
        raise SnapshotError(
            f"The snapshot is not a readable dump: {_short_err(stderr)}")

    entries = [
        line for line in (result.stdout or b'').decode(errors='replace').splitlines()
        if line.strip() and not line.startswith(';')
    ]
    if not entries:
        raise SnapshotError(
            "The snapshot contains no restorable object; "
            "the migration was not started.")

    return f"pg_restore listed {len(entries)} objects"


def _live_table_names() -> set:
    """The tables the running instance has, to compare the copy against."""
    from models import db as _db

    try:
        return set(inspect(_db.engine).get_table_names())
    except Exception as exc:
        raise SnapshotError(
            f"The source database could not be inspected: {_short_err(str(exc))}"
        ) from exc


def create_source_snapshot() -> SourceSnapshot:
    """Snapshot the current database and read it back, or refuse to migrate.

    Called before anything touches the target: a migration whose rollback
    artefact is missing or unreadable is a migration nobody can undo, and the
    right moment to find that out is the only moment when nothing has
    happened yet.
    """
    backend = _source_backend()
    expected_tables = _live_table_names() if backend == 'sqlite' else set()

    reasons: list = []
    # How the artefact was produced travels with it: on SQLite the copy reads
    # from this file, so which mechanism wrote it is part of what the
    # operator is being asked to trust.
    details: dict = {}
    try:
        path: Optional[Path] = _backup_current_db(reasons, details)
    except Exception as exc:
        logger.exception("Source snapshot failed")
        raise SnapshotError(
            f"The source database could not be snapshotted: "
            f"{_short_err(str(exc))}") from exc

    if path is None:
        # The reason travels with the refusal. An operator told only that the
        # snapshot "could not be taken" has to go and find a log line to
        # learn that their pg_dump is older than the server it is dumping.
        detail = reasons[-1] if reasons else (
            "no reason was recorded; check the service log")
        raise SnapshotError(
            f"No snapshot of the {backend} source could be taken, so the "
            f"migration was not started: {detail}.")

    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise SnapshotError(
            f"The snapshot disappeared right after it was written: "
            f"{_short_err(str(exc))}") from exc

    if size == 0:
        _discard(path)
        raise SnapshotError(
            "The snapshot is empty; the migration was not started.")

    try:
        if backend == 'sqlite':
            verified = _verify_sqlite(path, expected_tables)
        else:
            verified = _verify_pg_dump(path)
        digest = _sha256(path)
    except SnapshotError:
        # An artefact that failed verification is worse than none: it would
        # be trusted. It is removed, and it stops the migration either way.
        _discard(path)
        raise
    except OSError as exc:
        _discard(path)
        raise SnapshotError(
            f"The snapshot could not be read back: {_short_err(str(exc))}"
        ) from exc

    logger.info("Source snapshot verified (%s, %d bytes, %s): %s",
                path.name, size, details.get('method', 'unknown'), verified)

    return SourceSnapshot(
        path=path,
        backend=backend,
        size_bytes=size,
        sha256=digest,
        created_at=datetime.now(timezone.utc).isoformat(timespec='seconds'),
        verified=verified,
        method=details.get('method', 'unknown'),
    )
