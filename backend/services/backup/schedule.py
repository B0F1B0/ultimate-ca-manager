"""Scheduled backup support.

Runs unattended encrypted backups when due, applies retention, and lists
backup history from disk.

The source of truth is the General-settings keys the UI actually writes:
``auto_backup_enabled``, ``backup_frequency`` (daily/weekly/monthly),
``backup_retention_days`` and ``backup_password``. There is no time-of-day in
the UI, so cadence is driven by a stored ``backup.last_run`` timestamp.
"""
import base64
import glob
import json
import logging
import os
from datetime import datetime, timezone

from models import db, SystemConfig
from config.settings import Config
from utils.datetime_utils import utc_now, utc_isoformat

from .backup_service import BackupService
from .errors import ScheduledBackupError

logger = logging.getLogger(__name__)

_BACKUP_GLOB = 'ucm_backup_*.ucmbkp'
_LAST_RUN_KEY = 'backup.last_run'
_VALID_FREQUENCIES = ('daily', 'weekly', 'monthly')
_PERIOD_SECONDS = {'daily': 86400, 'weekly': 604800, 'monthly': 2592000}

# Container shapes, from the format the service writes: v2 starts with the
# magic, a known format byte and a metadata block, v1 is a bare salt + nonce
# + GCM ciphertext with nothing to recognise it by.
_CONTAINER_MAGIC = BackupService.MAGIC
_KNOWN_FORMAT_VERSIONS = frozenset({BackupService.FORMAT_VERSION_V2})
_KNOWN_FLAGS = frozenset({0, BackupService.FLAG_GZIP})
_KNOWN_KDF_IDS = frozenset({BackupService.KDF_PBKDF2, BackupService.KDF_ARGON2ID})
_REQUIRED_METADATA_KEYS = frozenset({
    'format_version', 'kdf', 'salt_b64', 'nonce_b64',
})
_MIN_CIPHERTEXT_SIZE = 16  # GCM tag
_MIN_V1_CONTAINER_SIZE = (
    BackupService.SALT_SIZE + BackupService.NONCE_SIZE + _MIN_CIPHERTEXT_SIZE
)


def _get(key, default=None):
    cfg = SystemConfig.query.filter_by(key=key).first()
    return cfg.value if cfg and cfg.value is not None else default


def get_schedule() -> dict:
    """Return the effective backup schedule (from General settings)."""
    freq = _get('backup_frequency', 'daily')
    if freq not in _VALID_FREQUENCIES:
        freq = 'daily'
    try:
        retention = int(_get('backup_retention_days', '30'))
    except (ValueError, TypeError):
        retention = 30
    return {
        'enabled': _get('auto_backup_enabled', 'false') == 'true',
        'frequency': freq,
        'retention_days': retention,
        'last_run': _get(_LAST_RUN_KEY),
        'password_set': bool(_get('backup_password')),
    }


def _get_backup_password() -> str:
    """Return the decrypted configured backup password, or '' if unset.

    A stored value that looks encrypted but does not decrypt is an error, not
    a password: returning the ciphertext produced archives encrypted with a
    string the administrator has never seen, reported as successful backups.
    """
    val = _get('backup_password')
    if not val:
        return ''

    from utils.encryption import decrypt_value, is_encrypted
    if not is_encrypted(val):
        return val  # stored before at-rest encryption was enabled

    password = decrypt_value(val)  # raises when the key is missing/unusable
    if not password:
        raise ScheduledBackupError(
            'The configured backup password could not be decrypted '
            '(the DB encryption key changed?). Set it again under '
            'Settings > Backup.'
        )
    return password


def list_backups() -> list[dict]:
    """List backup files on disk, newest first."""
    backups = []
    try:
        for path in glob.glob(os.path.join(str(Config.BACKUP_DIR), _BACKUP_GLOB)):
            try:
                st = os.stat(path)
            except OSError:
                continue
            backups.append({
                'filename': os.path.basename(path),
                'size': st.st_size,
                'created_at': utc_isoformat(datetime.fromtimestamp(st.st_mtime, timezone.utc)),
            })
    except Exception as e:
        logger.error(f"Failed to list backups: {e}")
    backups.sort(key=lambda b: b['created_at'] or '', reverse=True)
    return backups


def _container_shape(path: str) -> int:
    """Rank a file by how much of a backup container it still is.

    2 = a complete v2 header: magic, known format and KDF bytes, and a
        metadata block that parses and carries the fields a restore reads.
    1 = no magic but large enough to be a legacy v1 container (bare salt +
        nonce + GCM ciphertext, which has nothing to check).
    0 = not a backup any more.

    Only the header is read: the payload cannot be verified without the
    backup password. A header alone is not proof of a restorable archive, so
    a v2 container always outranks an opaque file.
    """
    try:
        size = os.path.getsize(path)
        if size < _MIN_V1_CONTAINER_SIZE:
            return 0
        with open(path, 'rb') as fh:
            head = fh.read(10)
            if head[:4] != _CONTAINER_MAGIC:
                return 1 if len(head) == 10 else 0
            if len(head) < 10:
                return 0
            version, flags, kdf_id, reserved = head[4], head[5], head[6], head[7]
            if (version not in _KNOWN_FORMAT_VERSIONS
                    or flags not in _KNOWN_FLAGS
                    or kdf_id not in _KNOWN_KDF_IDS
                    or reserved != 0):
                return 0
            metadata_len = int.from_bytes(head[8:10], 'big')
            if metadata_len == 0 or size < 10 + metadata_len + _MIN_CIPHERTEXT_SIZE:
                return 0
            metadata = json.loads(fh.read(metadata_len).decode())
    except (OSError, ValueError, UnicodeDecodeError):
        return 0

    if not isinstance(metadata, dict):
        return 0
    if not _REQUIRED_METADATA_KEYS.issubset(metadata):
        return 0
    for field in ('salt_b64', 'nonce_b64'):
        try:
            if not base64.b64decode(metadata[field], validate=True):
                return 0
        except (ValueError, TypeError):
            return 0
    return 2


def _newest_restorable(paths: list[str]):
    """Return the most recent file that still looks like a usable archive.

    A complete v2 container wins over an older opaque file; an opaque file is
    only kept when no v2 container survives, so a truncated or overwritten
    archive written after the last good one cannot take its place as the
    thing retention protects.
    """
    ranked = []
    for path in paths:
        shape = _container_shape(path)
        if shape:
            try:
                ranked.append((shape, os.stat(path).st_mtime, path))
            except OSError:
                continue
    if not ranked:
        return None
    return max(ranked)[2]


def _apply_retention(retention_days: int) -> int:
    """Delete backup files older than retention_days. Returns count removed.

    The newest archive that still looks restorable is always kept, whatever
    its age: retention ran on a timer of its own, so a long export outage (a
    lost DB key, no configured password) ended with the last usable restore
    point deleted and nothing to replace it.
    """
    if not retention_days or retention_days < 1:
        return 0
    cutoff = utc_now().timestamp() - retention_days * 86400
    removed = 0
    paths = []
    for path in glob.glob(os.path.join(str(Config.BACKUP_DIR), _BACKUP_GLOB)):
        try:
            os.stat(path)
        except OSError:
            continue
        paths.append(path)

    keep = _newest_restorable(paths)
    for path in paths:
        if path == keep:
            continue
        try:
            if os.stat(path).st_mtime < cutoff:
                os.unlink(path)
                removed += 1
        except OSError:
            continue
    if removed:
        logger.info(f"Backup retention removed {removed} expired backup(s)")
    return removed


def run_backup_retention() -> int:
    """Apply backup retention independently of the scheduled-backup run.

    Registered as its own daily scheduler task so retention is enforced even when
    automatic backups are disabled (manual backups would otherwise accumulate
    forever). Honours `backup_retention_days` (0 / unset → no pruning).
    """
    try:
        retention = int(_get('backup_retention_days', '30'))
    except (ValueError, TypeError):
        retention = 30
    return _apply_retention(retention)


# Last attempt made by this process, whether or not its timestamp could be
# stored. `backup.last_run` is the source of truth across restarts; this guard
# only covers the case where writing that row fails, which used to leave the
# task due again 60 seconds later, once per minute, until the disk filled.
_LAST_ATTEMPT: dict = {'at': None}


def _record_last_run(ts: datetime) -> None:
    """Persist the run timestamp, or raise.

    The scheduler asks every 60 seconds whether a backup is due, and the
    answer is read from this row: a silent rollback left the task due again on
    the next tick, writing one archive per minute until the disk filled.
    """
    cfg = SystemConfig.query.filter_by(key=_LAST_RUN_KEY).first()
    if cfg:
        cfg.value = utc_isoformat(ts)
    else:
        db.session.add(SystemConfig(key=_LAST_RUN_KEY, value=utc_isoformat(ts)))
    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        raise ScheduledBackupError(
            f'Backup created, but its schedule timestamp could not be saved: {exc}'
        ) from exc


def _is_due(sched: dict, now: datetime) -> bool:
    period = _PERIOD_SECONDS.get(sched.get('frequency', 'daily'), 86400)
    attempted = _LAST_ATTEMPT.get('at')
    if attempted is not None:
        elapsed = (_naive_utc(now) - _naive_utc(attempted)).total_seconds()
        if elapsed < period - 300:
            return False

    last_run = sched.get('last_run')
    if not last_run:
        return True  # never run → run now
    try:
        prev = datetime.fromisoformat(last_run.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        return True
    # small slack so a ~daily timer doesn't drift a day each run
    return (_naive_utc(now) - _naive_utc(prev)).total_seconds() >= period - 300


def _naive_utc(value: datetime) -> datetime:
    """Normalise to naive UTC, which is what utc_now() returns."""
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def run_scheduled_backup() -> dict:
    """Scheduler task — creates an encrypted backup when one is due.

    Returns a structured result (`ok` / `skipped`) and raises on failure. Both
    matter to the scheduler: swallowing the exception left the task reporting
    "completed successfully", with a green view, a growing run count and no
    archive anywhere.
    """
    sched = get_schedule()
    if not sched.get('enabled'):
        return {'status': 'skipped', 'reason': 'disabled'}

    now = utc_now()
    if not _is_due(sched, now):
        return {'status': 'skipped', 'reason': 'not_due'}

    password = _get_backup_password()
    if not password or len(password) < 12:
        # Automatic backups are on and nothing can be produced: a failure the
        # administrator has to see, not a quiet log line.
        _audit_scheduled_backup(
            'scheduled', 'Scheduled backup failed: no valid backup password '
            'configured', success=False)
        raise ScheduledBackupError(
            'No valid backup password configured (set a 12+ character '
            'password under Settings > Backup).'
        )

    # Taken before the work starts: an archive written but not recorded must
    # not be written again on the next tick.
    _LAST_ATTEMPT['at'] = now

    try:
        backup_bytes = BackupService().create_backup(password)

        os.makedirs(str(Config.BACKUP_DIR), exist_ok=True)
        filename = f"ucm_backup_{now.strftime('%Y%m%d_%H%M%S')}.ucmbkp"
        filepath = os.path.join(str(Config.BACKUP_DIR), filename)
        with open(filepath, 'wb') as f:
            f.write(backup_bytes)
        try:
            os.chmod(filepath, 0o600)
        except OSError:
            pass

        logger.info(f"Scheduled backup created: {filename} ({len(backup_bytes)} bytes)")
        _audit_scheduled_backup(filename, f'Scheduled backup: {filename}',
                                success=True)

        removed = _apply_retention(sched.get('retention_days', 30))
        _record_last_run(now)
        return {
            'status': 'ok',
            'filename': filename,
            'size': len(backup_bytes),
            'retention_removed': removed,
        }
    except Exception as e:
        logger.error(f"Scheduled backup failed: {e}", exc_info=True)
        # A failure that only a log line reports is a backup nobody has:
        # the audit trail records it, as the successes are recorded
        _audit_scheduled_backup('scheduled', f'Scheduled backup failed: {e}',
                                success=False)
        raise


def _audit_scheduled_backup(resource_name: str, details: str, *,
                            success: bool) -> None:
    """Record a scheduled-backup outcome without masking it if audit is down."""
    try:
        from services.audit_service import AuditService
        AuditService.log_action(
            action='system_backup', resource_type='system',
            resource_name=resource_name, details=details,
            success=success, username='system',
        )
    except Exception:
        logger.exception("Scheduled backup outcome could not be audited")
