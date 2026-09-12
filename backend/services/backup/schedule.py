"""Scheduled backup support.

Runs unattended encrypted backups when due, applies retention, and lists
backup history from disk.

The source of truth is the General-settings keys the UI actually writes:
``auto_backup_enabled``, ``backup_frequency`` (daily/weekly/monthly),
``backup_retention_days`` and ``backup_password``. There is no time-of-day in
the UI, so cadence is driven by a stored ``backup.last_run`` timestamp.
"""
import os
import glob
import logging
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
# magic and a known format byte, v1 is a bare salt + nonce + GCM tag.
_CONTAINER_MAGIC = BackupService.MAGIC
_KNOWN_FORMAT_VERSIONS = frozenset({BackupService.FORMAT_VERSION_V2})
_MIN_V1_CONTAINER_SIZE = (
    BackupService.SALT_SIZE + BackupService.NONCE_SIZE + 16
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


def _looks_restorable(path: str) -> bool:
    """Cheap structural check that a file still is a backup container.

    Reads the header only: v2 archives start with the magic, v1 archives are a
    raw salt + nonce + GCM ciphertext and can only be recognised by size.
    """
    try:
        size = os.path.getsize(path)
        if size < _MIN_V1_CONTAINER_SIZE:
            return False
        with open(path, 'rb') as fh:
            head = fh.read(5)
    except OSError:
        return False
    if head[:4] == _CONTAINER_MAGIC:
        return len(head) == 5 and head[4] in _KNOWN_FORMAT_VERSIONS
    return True  # legacy v1 container: no magic to check


def _newest_restorable(paths: list[str]):
    """Return the most recent file that still looks like a usable archive."""
    for path in sorted(paths, key=lambda p: os.stat(p).st_mtime, reverse=True):
        if _looks_restorable(path):
            return path
    return None


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
    last_run = sched.get('last_run')
    if not last_run:
        return True  # never run → run now
    try:
        prev = datetime.fromisoformat(last_run.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        return True
    # Normalise to naive UTC to match utc_now() (which is naive UTC)
    if prev.tzinfo is not None:
        prev = prev.astimezone(timezone.utc).replace(tzinfo=None)
    now_naive = now.replace(tzinfo=None) if now.tzinfo is not None else now
    period = _PERIOD_SECONDS.get(sched.get('frequency', 'daily'), 86400)
    # small slack so a ~daily timer doesn't drift a day each run
    return (now_naive - prev).total_seconds() >= period - 300


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
