"""One backup operation at a time, across every worker process.

Three paths create, validate or delete archives: the scheduled task (which
wakes every 60 seconds), the "run now" button, and retention (a daily task
plus an on-demand route). Nothing serialised them, so two runs could pick the
same filename within the same second, delete what the other was still reading
back, and both record a success. UCM runs under gunicorn with several
workers, so an in-memory lock would only serialise the threads of one of
them: the exclusion has to live in the filesystem, which is what every worker
shares.

The lock is advisory (``flock``) and held for the whole operation, from
choosing a name to recording the archive or pruning the directory.
"""
from contextlib import contextmanager
from pathlib import Path
import errno
import logging
import os
import threading
import time

from config.settings import Config

try:
    import fcntl
except ImportError:  # pragma: no cover - UCM targets POSIX hosts
    fcntl = None

logger = logging.getLogger(__name__)

LOCK_NAME = '.ucm_backup_operation.lock'

# errno values flock uses to say "someone else holds it"; anything else is a
# system failure, which is handled very differently below.
_BUSY_ERRNOS = frozenset(filter(None, (
    errno.EACCES,
    errno.EAGAIN,
    getattr(errno, 'EWOULDBLOCK', None),
)))

# flock has no timed variant, so waiting is polling. The interval is short
# enough that a "run now" behind a scheduled backup feels immediate, and long
# enough not to spin a worker while a multi-second export finishes.
_POLL_INTERVAL = 0.05

_local = threading.local()


class BackupBusyError(RuntimeError):
    """Another backup operation holds the lock.

    Raised instead of waiting, so a caller can report plainly that nothing was
    started rather than queueing a second archive nobody asked for. The
    message names no path and no host, and is safe to return to the caller.
    """


def operation_lock_path() -> Path:
    """Return the lock file, which lives next to the archives it guards.

    The name is a dotfile and does not end in an archive extension, so
    neither the listing route (which filters on ``.ucmbkp``/``.json.enc``)
    nor the retention glob (``ucm_backup_*.ucmbkp``) can mistake it for a
    restore point.

    It is created once and never deleted. Removing it would not release
    anything — it would let the next process create a *new* inode under the
    same name and take a second, independent lock, which is precisely the
    mutual exclusion this module exists to provide.
    """
    return Path(Config.BACKUP_DIR) / LOCK_NAME


def _state() -> dict:
    """Return this thread's view of the lock.

    flock ownership belongs to the file descriptor, not to the caller: a
    process that already holds the lock and re-locks the same file simply
    succeeds, and the first release would then drop a lock the outer caller
    still believes it holds. So the depth is counted here, per thread —
    because two threads of one worker are two callers — and per process,
    because ``fork()`` copies this thread's counter into a child that owns no
    descriptor of its own.
    """
    state = getattr(_local, 'state', None)
    if state is None or state['pid'] != os.getpid():
        state = {'pid': os.getpid(), 'depth': 0}
        _local.state = state
    return state


def _open_lock_file() -> int:
    """Open (creating if needed) the lock file, private to the service."""
    path = operation_lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        # The file survives restarts, so a first creation under a wider umask
        # would keep its mode forever.
        os.fchmod(fd, 0o600)
    except OSError:
        logger.warning("Could not set 0600 on the backup lock %s", path)
    return fd


def _acquire(fd: int, timeout: float, purpose: str) -> None:
    """Take the exclusive lock, waiting at most ``timeout`` seconds."""
    deadline = time.monotonic() + max(timeout, 0.0)
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError as exc:
            if exc.errno not in _BUSY_ERRNOS:
                raise  # a system failure, not a busy lock

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BackupBusyError(_busy_message(timeout, purpose))
        time.sleep(min(_POLL_INTERVAL, remaining))


def _busy_message(timeout: float, purpose: str) -> str:
    if timeout > 0:
        return (f"Another backup operation is still in progress after "
                f"{timeout:g}s; {purpose} was not started.")
    return (f"Another backup operation is already in progress; "
            f"{purpose} was not started.")


@contextmanager
def backup_operation_lock(*, timeout: float = 0, purpose: str = 'backup'):
    """Hold the backup lock for the duration of the block.

    Every path that creates, validates or deletes an archive takes this same
    lock, so that only one of them is ever touching the backup directory.

    ``timeout=0`` (the default) does not wait: if another process holds the
    lock, :class:`BackupBusyError` is raised and the caller reports that
    nothing was started. A positive ``timeout`` waits that many seconds
    before raising. ``purpose`` only names the caller in the message and in
    the logs.

    Re-entering the lock from the same thread is free: the nested block does
    not re-lock, and the descriptor is released once the outermost block
    exits — a route that holds the lock and calls a helper which takes it
    again must not deadlock against itself.

    If the lock cannot be taken for a *system* reason — no permission on the
    directory, or a filesystem without flock (NFS without lockd, some SMB
    mounts) — the operation is logged as unprotected and **allowed through**.
    The alternative is an installation where no backup can ever be made
    again, which is a worse failure than a concurrent run: this is the
    trade-off ``_fsync_directory`` makes in ``storage.py`` for unsupported
    directory syncs.
    """
    state = _state()
    if state['depth'] > 0:
        # Already held by this thread: count the nesting, lock nothing.
        state['depth'] += 1
        try:
            yield
        finally:
            state['depth'] -= 1
        return

    fd = None
    held = False
    try:
        if fcntl is None:
            raise OSError(errno.ENOSYS, 'flock is unavailable on this platform')
        fd = _open_lock_file()
        _acquire(fd, timeout, purpose)
        held = True
    except BackupBusyError:
        _close(fd)
        logger.info("Backup lock is held by another process; %s refused", purpose)
        raise
    except OSError as exc:
        _close(fd)
        fd = None
        logger.error(
            "The backup lock could not be taken (%s); %s runs without "
            "protection against a concurrent backup operation", exc, purpose)

    state['depth'] = 1
    try:
        yield
    finally:
        state['depth'] = 0
        if fd is not None:
            if held:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    # Closing the descriptor releases it anyway.
                    logger.warning("Could not unlock the backup lock explicitly")
            _close(fd)


def _close(fd) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        logger.warning("Could not close the backup lock descriptor")
