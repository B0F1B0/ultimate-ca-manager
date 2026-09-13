"""One database migration at a time, across every worker process.

Switching backend is not one call but a sequence: check the target, snapshot
the source, copy every table, verify what landed, rewrite ``ucm.env``, ask
for a restart. Two of those sequences overlapping is the worst case this
subsystem has — the second one would find the target no longer empty, or
would copy a source the first one is still reading, and both would rewrite
the same configuration file. Nothing serialised them.

The lock is held from the first pre-flight check to the moment the restart is
requested, and released by the process dying at the restart. It lives in the
data directory rather than in the backup directory: a migration is not a
backup operation, and a thread holding one must still be able to take the
other (the migration takes a snapshot of its own).
"""
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import json
import logging
import os

from config.settings import DATA_DIR
from utils.process_lock import LockBusyError, lock_depth, process_lock

logger = logging.getLogger(__name__)

LOCK_NAME = '.ucm_db_migration.lock'

# Written once the configuration names a new backend and the restart has been
# asked for. The lock cannot cover that gap: the restart is asynchronous (a
# watcher unit picks up a signal file), so the request returns — and releases
# the lock — while the service is still running on the old backend. A second
# migration slipping into that window would rewrite the configuration again,
# and the service would come up on whichever one wrote last, while the first
# caller holds a proof about a database it will never use.
SWITCH_MARKER = '.ucm_db_switch_pending'

# What the refusal calls the operation it is protecting.
_SUBJECT = 'database migration'


class MigrationBusyError(LockBusyError):
    """Another migration or backend switch is already running.

    Raised rather than queueing: a second migration started behind the first
    would work on a target the first one is still filling. The message names
    no path and no credential, and is safe to return to the caller.
    """


def migration_lock_path() -> Path:
    """Return the lock file, in the data directory every worker can reach.

    It is created once and never deleted. Removing it would not release
    anything — it would let the next process create a *new* inode under the
    same name and take a second, independent lock, which is precisely the
    mutual exclusion this module exists to provide.
    """
    return Path(DATA_DIR) / LOCK_NAME


def migration_lock_depth() -> int:
    """How many nested migration blocks this thread currently holds."""
    return lock_depth(migration_lock_path())


@contextmanager
def database_migration_lock(*, timeout: float = 0,
                            purpose: str = 'the migration'):
    """Hold the migration lock for the duration of the block.

    ``timeout=0`` refuses immediately rather than waiting, because a migration
    lasts as long as the database is big and a caller blocked behind one has
    nothing useful to wait for.

    Unlike the backup lock, this one is fail-closed: if it cannot be taken at
    all — a lock file left owned by another user, a filesystem without flock —
    the migration is refused. A backup that cannot be taken is an
    inconvenience; two migrations running unprotected fill the same target and
    then each write their own answer into the configuration file, and the
    service restarts onto whichever wrote last.
    """
    with process_lock(migration_lock_path(), timeout=timeout, purpose=purpose,
                      subject=_SUBJECT, busy_error=MigrationBusyError,
                      fail_open=False):
        yield


def switch_pending_path() -> Path:
    """Where the pending-switch marker lives, next to the restart signal."""
    return Path(DATA_DIR) / SWITCH_MARKER


def mark_switch_pending(backend: str) -> None:
    """Record that the configuration now names a backend nobody runs yet.

    Written under the migration lock, right after the configuration is
    persisted. ``backend`` is already redacted by the caller: this file is
    read back and shown to whoever asks next.
    """
    path = switch_pending_path()
    payload = json.dumps({
        'backend': backend,
        'requested_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
    })
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as handle:
            handle.write(payload)
    except OSError:
        logger.warning("Could not record the pending backend switch")


def switch_pending() -> Optional[dict]:
    """What switch is waiting for a restart, or None.

    A marker whose content cannot be read still counts: the point is that a
    switch was requested, not what it said.
    """
    path = switch_pending_path()
    try:
        raw = path.read_text()
    except FileNotFoundError:
        return None
    except OSError:
        return {'backend': 'unknown', 'requested_at': 'unknown'}

    try:
        loaded = json.loads(raw)
    except ValueError:
        return {'backend': 'unknown', 'requested_at': 'unknown'}
    return loaded if isinstance(loaded, dict) else {
        'backend': 'unknown', 'requested_at': 'unknown'}


def clear_switch_pending() -> None:
    """Drop the marker. Called at startup: the restart it waited for happened."""
    try:
        switch_pending_path().unlink()
    except FileNotFoundError:
        return
    except OSError:
        logger.warning("Could not clear the pending backend switch marker")
    else:
        logger.info("A pending backend switch was applied by this restart")


def pending_switch_refusal() -> Optional[str]:
    """The sentence to refuse with while a switch is waiting for a restart.

    Returns None when nothing is pending. Any operation that writes to the
    database has to ask: between the configuration being written and the
    service restarting onto it, this instance is still running on the old
    backend, and everything written to it now stays there.
    """
    pending = switch_pending()
    if not pending:
        return None
    return (
        f"A backend switch to {pending.get('backend', 'another backend')} was "
        f"requested at {pending.get('requested_at', 'an unknown time')} and "
        "the service has not restarted yet. Restart it to apply that switch "
        "first: anything written now stays on the backend being left behind."
    )
