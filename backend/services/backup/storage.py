"""Writing a backup archive to disk, and proving what was written.

Structure cannot prove that an archive is restorable: the header of a
truncated or half-overwritten container still parses, and nothing short of the
backup password can check the payload. What can be proven is that the bytes on
disk are the bytes the service produced, so every archive written here is read
back and recorded with its size and SHA-256. Retention protects the most
recent file that still matches its record.
"""
import hashlib
import json
import logging
import os
import tempfile
from pathlib import Path

from utils.datetime_utils import utc_isoformat, utc_now

from .errors import BackupValidationError

logger = logging.getLogger(__name__)

CATALOG_NAME = '.ucm_backup_catalog.json'
_CATALOG_VERSION = 1
_READ_CHUNK = 1024 * 1024


def write_archive_atomically(backup_dir: Path, filename: str, data: bytes) -> Path:
    """Write an archive whole, or not at all.

    The temporary file is fsynced before it is published, and publication uses
    a link, which fails rather than overwrite an existing archive.
    """
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)

    temp_path = None
    destination = backup_dir / filename
    try:
        fd, temp_path = tempfile.mkstemp(
            dir=str(backup_dir), prefix='.ucm_backup_', suffix='.tmp')
        with os.fdopen(fd, 'wb') as temp_file:
            temp_file.write(data)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.chmod(temp_path, 0o600)

        os.link(temp_path, destination)
        os.unlink(temp_path)
        temp_path = None
        return destination
    except Exception:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        raise


def digest_of(path) -> tuple:
    """Return (size, sha256) read back from disk."""
    digest = hashlib.sha256()
    size = 0
    with open(path, 'rb') as fh:
        while True:
            chunk = fh.read(_READ_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def catalog_path(backup_dir) -> Path:
    return Path(backup_dir) / CATALOG_NAME


def read_catalog(backup_dir) -> dict:
    """Return the recorded archives, keyed by filename."""
    try:
        with open(catalog_path(backup_dir), 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    archives = data.get('archives') if isinstance(data, dict) else None
    return archives if isinstance(archives, dict) else {}


def _write_catalog(backup_dir, archives: dict) -> None:
    backup_dir = Path(backup_dir)
    payload = json.dumps(
        {'version': _CATALOG_VERSION, 'archives': archives},
        indent=2, sort_keys=True).encode()

    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(
            dir=str(backup_dir), prefix='.ucm_catalog_', suffix='.tmp')
        with os.fdopen(fd, 'wb') as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, catalog_path(backup_dir))
        temp_path = None
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def validate_and_record(path, expected: bytes) -> dict:
    """Read the archive back and record it, or refuse it.

    Called once the file is published: a short write, a full disk or a
    truncating collision shows up here rather than on the day of a restore.
    """
    path = Path(path)
    try:
        size, sha256 = digest_of(path)
    except OSError as exc:
        raise BackupValidationError(
            f"The backup {path.name} could not be read back after writing"
        ) from exc

    if size != len(expected) or sha256 != hashlib.sha256(expected).hexdigest():
        raise BackupValidationError(
            f"The backup {path.name} did not read back as it was written "
            f"({size} bytes on disk for {len(expected)} written)"
        )

    entry = {
        'size': size,
        'sha256': sha256,
        'recorded_at': utc_isoformat(utc_now()),
    }
    backup_dir = path.parent
    archives = read_catalog(backup_dir)
    archives[path.name] = entry
    # Drop records of archives that are gone, so the catalogue cannot grow
    # without bound and cannot vouch for a name a new file might reuse.
    for name in list(archives):
        if not (Path(backup_dir) / name).is_file():
            del archives[name]
    try:
        _write_catalog(backup_dir, archives)
    except OSError as exc:
        raise BackupValidationError(
            f"The backup {path.name} was written but could not be recorded "
            "as validated"
        ) from exc
    return entry


def matches_record(path, entry: dict) -> bool:
    """Whether the file on disk still is the archive that was recorded."""
    if not isinstance(entry, dict):
        return False
    try:
        if os.path.getsize(path) != entry.get('size'):
            return False
        _size, sha256 = digest_of(path)
    except OSError:
        return False
    return sha256 == entry.get('sha256')


def newest_validated(paths) -> object:
    """Return the most recent archive that still matches its record.

    Files are checked newest first and hashing stops at the first match, so a
    directory of archives is not read end to end on every retention run.
    """
    if not paths:
        return None
    archives = read_catalog(Path(list(paths)[0]).parent)
    if not archives:
        return None
    for path in _newest_first(paths):
        entry = archives.get(Path(path).name)
        if entry and matches_record(path, entry):
            return path
    return None


def unrecorded(paths) -> list:
    """Archives with no validation record, newest first.

    Written before validation records existed, or by a path that does not
    write one. Nothing can be proven about them either way.
    """
    if not paths:
        return []
    archives = read_catalog(Path(list(paths)[0]).parent)
    return [p for p in _newest_first(paths) if Path(p).name not in archives]


def _newest_first(paths) -> list:
    def mtime(path):
        try:
            return os.stat(path).st_mtime
        except OSError:
            return 0.0
    return sorted(paths, key=mtime, reverse=True)
