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

from . import storage
from .backup_service import BackupService
from .errors import ScheduledBackupError

logger = logging.getLogger(__name__)

_BACKUP_GLOB = 'ucm_backup_*.ucmbkp'
_LAST_RUN_KEY = 'backup.last_run'
_VALID_FREQUENCIES = ('daily', 'weekly', 'monthly')
_PERIOD_SECONDS = {'daily': 86400, 'weekly': 604800, 'monthly': 2592000}

# Archives with no validation record are kept in this number, newest first:
# nothing can be proven about them either way, so prudence decides.
_UNRECORDED_KEPT = 2


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


def _apply_retention(retention_days: int) -> int:
    """Delete backup files older than retention_days. Returns count removed.

    Two archives are never pruned, whatever their age. The most recent one
    that still matches its validation record is the last provable restore
    point: retention ran on a timer of its own, so a long export outage (a
    lost DB key, no configured password) used to end with nothing left to
    restore from. Archives with no record at all — written before records
    existed, or by another path — are kept in the two most recent, since
    nothing proves they are usable and nothing proves they are not.
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

    keep = set()
    validated = storage.newest_validated(paths)
    if validated:
        keep.add(validated)
    keep.update(storage.unrecorded(paths)[:_UNRECORDED_KEPT])

    for path in paths:
        if path in keep:
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


# Last archive this process published, whether or not its timestamp could be
# stored. `backup.last_run` is the source of truth across restarts; this guard
# only covers the case where writing that row fails, which used to leave the
# task due again 60 seconds later, once per minute, until the disk filled. It
# is set after publication, never before, so a failed attempt is retried.
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

    try:
        backup_bytes = BackupService().create_backup(password)

        filename = f"ucm_backup_{now.strftime('%Y%m%d_%H%M%S')}.ucmbkp"
        filepath = storage.write_archive_atomically(
            Config.BACKUP_DIR, filename, backup_bytes)
        storage.validate_and_record(filepath, backup_bytes)

        # Only now: the archive exists, it reads back as written, and it is
        # recorded. An export or write that failed before this point leaves
        # the run due again on the next tick, which is what should happen;
        # past it, a timestamp that cannot be stored must not produce a second
        # archive a minute later.
        _LAST_ATTEMPT['at'] = now

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
