"""Application log file: where it is written, and where to read it back.

UCM used to write its application log to ``/var/log/ucm/ucm.log`` on native
installs and to stdout in Docker, with a silent fall back to stderr when that
file could not be opened. Nothing could read the log back: Docker wrote no file
at all, and on a native install the fallback left the lines reachable only
through the journal, which the service user is not a member of ``systemd-journal``
to read. The diagnostic bundle therefore shipped without the log it advertised.

This module resolves one file that is always written and always readable by UCM
itself, and records which one it chose so the bundle and the log viewer read the
same file the logging setup writes.
"""
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from config.settings import Config, is_docker

NATIVE_LOG_PATH = Path('/var/log/ucm/ucm.log')
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_BACKUPS = 5

_resolved_path: Optional[Path] = None


def _positive_int_env(name: str, default: int) -> int:
    """Read a positive integer from the environment, ignoring anything else.

    A misconfigured rotation limit must not stop the service logging, and a
    zero or negative one would either disable rotation or raise.
    """
    try:
        value = int(os.environ[name])
    except (KeyError, ValueError):
        return default
    return value if value > 0 else default


def candidate_paths() -> list[Path]:
    """Log file paths in preference order.

    Docker has no ``/var/log/ucm`` — the image logs to stdout — so the data
    directory is the only candidate there. It is the one writable, persistent
    location on every deployment: ``/opt/ucm/data`` under the DEB, the RPM and
    the container volume, or wherever ``DATA_DIR`` points.

    Native installs keep their existing path first, so logrotate and operator
    tooling are unaffected, and fall back to the data directory rather than to
    stderr when it cannot be opened.
    """
    data_path = Path(Config.LOG_FILE)
    if is_docker():
        return [data_path]
    override = os.getenv('UCM_LOG_FILE')
    native = Path(override) if override else NATIVE_LOG_PATH
    return [native] if native == data_path else [native, data_path]


def install_file_handler(logger, formatter) -> Optional[Path]:
    """Attach a rotating file handler at the first usable candidate path.

    Returns the path in use, or None when no candidate could be opened — the
    caller is expected to fall back to a stream handler so the lines are not
    lost entirely.
    """
    global _resolved_path
    max_bytes = _positive_int_env('UCM_LOG_MAX_BYTES', DEFAULT_MAX_BYTES)
    backups = _positive_int_env('UCM_LOG_BACKUPS', DEFAULT_BACKUPS)

    for path in candidate_paths():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                str(path), maxBytes=max_bytes, backupCount=backups
            )
        except OSError:
            continue
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        _resolved_path = path
        return path
    return None


def resolved_path() -> Optional[Path]:
    """The log file this process writes, or None when it writes to no file."""
    return _resolved_path
