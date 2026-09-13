"""Backups: one operation at a time, across processes.

The scheduled task, the "run now" button and retention all write in the same
directory, and UCM runs several gunicorn workers. Each test here pins one
half of the guarantee: a second process is kept out, the holder is never kept
out of its own lock, and an installation whose filesystem cannot lock still
gets its backups.
"""
import errno
import fcntl
import glob
import logging
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from config.settings import Config
from services.backup import locking
from services.backup.locking import (
    BackupBusyError,
    LOCK_NAME,
    backup_operation_lock,
    operation_lock_path,
)

BACKEND_DIR = str(Path(__file__).resolve().parents[1])

# A child that takes the lock, says so, and holds it until told to let go.
_HOLDER = """
import sys
from config.settings import Config
Config.BACKUP_DIR = sys.argv[1]
from services.backup.locking import backup_operation_lock
with backup_operation_lock(purpose='holder'):
    sys.stdout.write('locked\\n')
    sys.stdout.flush()
    sys.stdin.readline()
sys.stdout.write('released\\n')
sys.stdout.flush()
"""


@pytest.fixture(autouse=True)
def _clean_lock_state():
    """No test may inherit another's nesting depth."""
    def clear():
        if hasattr(locking._local, 'state'):
            del locking._local.state

    clear()
    yield
    clear()


@pytest.fixture
def backup_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, 'BACKUP_DIR', tmp_path, raising=False)
    return tmp_path


class _Holder:
    """Another process holding the backup lock for as long as we need."""

    def __init__(self, backup_dir):
        self._proc = subprocess.Popen(
            [sys.executable, '-c', _HOLDER, str(backup_dir)],
            cwd=BACKEND_DIR, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )

    def wait_until_locked(self):
        line = self._proc.stdout.readline()
        if line.strip() != 'locked':
            self._proc.kill()
            raise AssertionError(
                f"holder process did not take the lock: {line!r} "
                f"{self._proc.stderr.read()!r}")

    def release(self):
        self._proc.stdin.write('go\n')
        self._proc.stdin.flush()

    def close(self):
        if self._proc.poll() is None:
            self._proc.kill()
        self._proc.communicate()


@pytest.fixture
def holder(backup_dir):
    held = _Holder(backup_dir)
    try:
        held.wait_until_locked()
        yield held
    finally:
        held.close()


def _thread_result(target, *args, **kwargs):
    """Run target in another thread and return its outcome.

    Another thread is another caller: it opens its own descriptor, so flock
    keeps it out exactly as it keeps another process out.
    """
    out = {}

    def run():
        try:
            out['value'] = target(*args, **kwargs)
        except BaseException as exc:  # noqa: BLE001 - reported to the test
            out['error'] = exc

    thread = threading.Thread(target=run)
    thread.start()
    thread.join(10)
    assert not thread.is_alive(), "the lock never came free"
    return out


def _take_it(**kwargs):
    with backup_operation_lock(**kwargs):
        return 'taken'


class TestTheHolderIsNeverLockedOut:
    """flock belongs to the descriptor, not to the caller: a path that holds
    the lock and calls a helper that takes it again must not deadlock."""

    def test_two_successive_operations_both_get_the_lock(self, backup_dir):
        with backup_operation_lock(purpose='first'):
            pass
        with backup_operation_lock(purpose='second'):
            pass

    def test_a_nested_operation_does_not_block_itself(self, backup_dir):
        with backup_operation_lock(purpose='run now'):
            with backup_operation_lock(purpose='retention'):
                depth = locking.operation_lock_depth()
            assert depth == 2
            assert locking.operation_lock_depth() == 1

        assert locking.operation_lock_depth() == 0

    def test_the_lock_is_only_released_by_the_outermost_block(self, backup_dir):
        with backup_operation_lock():
            with backup_operation_lock():
                pass
            # The inner block left: the lock must still be ours.
            out = _thread_result(_take_it, timeout=0)
            assert isinstance(out.get('error'), BackupBusyError)

        assert _thread_result(_take_it, timeout=0).get('value') == 'taken'

    def test_reentrancy_is_per_thread_not_per_process(self, backup_dir):
        with backup_operation_lock(purpose='scheduled backup'):
            out = _thread_result(_take_it, timeout=0, purpose='run now')

        assert isinstance(out.get('error'), BackupBusyError)


class TestAnotherProcessIsKeptOut:
    """A worker holding the lock is invisible to an in-memory lock, which is
    why this one lives in the filesystem."""

    def test_a_second_process_cannot_take_the_lock(self, backup_dir, holder):
        with pytest.raises(BackupBusyError) as excinfo:
            with backup_operation_lock(purpose='run now'):
                pass

        message = str(excinfo.value)
        assert 'backup operation' in message
        assert 'in progress' in message
        assert 'run now' in message

    def test_the_lock_comes_free_when_the_other_process_is_done(
            self, backup_dir, holder):
        holder.release()

        # The child releases and exits; poll until its lock is gone.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with backup_operation_lock(purpose='run now'):
                    return
            except BackupBusyError:
                time.sleep(0.05)
        pytest.fail("the lock was never released")

    def test_waiting_gives_up_after_the_timeout(self, backup_dir, holder):
        started = time.monotonic()
        with pytest.raises(BackupBusyError) as excinfo:
            with backup_operation_lock(timeout=0.3, purpose='retention'):
                pass
        waited = time.monotonic() - started

        assert waited >= 0.3
        assert 'still in progress' in str(excinfo.value)

    def test_waiting_succeeds_when_the_holder_lets_go(self, backup_dir, holder):
        threading.Timer(0.3, holder.release).start()

        started = time.monotonic()
        with backup_operation_lock(timeout=20, purpose='run now'):
            waited = time.monotonic() - started

        assert waited >= 0.25, "the lock was taken before the holder let go"


class TestTheLockSurvivesFailures:
    def test_an_exception_in_the_block_still_releases_the_lock(self, backup_dir):
        with pytest.raises(RuntimeError):
            with backup_operation_lock(purpose='scheduled backup'):
                raise RuntimeError('export failed')

        assert locking.operation_lock_depth() == 0
        assert _thread_result(_take_it, timeout=0).get('value') == 'taken'

    def test_a_busy_lock_leaves_no_nesting_behind(self, backup_dir, holder):
        with pytest.raises(BackupBusyError):
            with backup_operation_lock():
                pass

        assert locking.operation_lock_depth() == 0


class TestTheLockFileIsNotAnArchive:
    """It lives among the archives, so nothing that lists or prunes them may
    take it for a restore point."""

    def test_the_lock_file_is_private_and_created_on_demand(self, tmp_path, monkeypatch):
        backup_dir = tmp_path / 'missing' / 'backups'
        monkeypatch.setattr(Config, 'BACKUP_DIR', backup_dir, raising=False)

        with backup_operation_lock():
            path = operation_lock_path()
            assert path.is_file()
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

        assert path.is_file(), "the lock file must outlive the operation"

    def test_the_listing_route_does_not_show_the_lock(self, backup_dir):
        # The extension rule moved to services.backup.storage when the two
        # families of backup routes were put on one implementation; the
        # listing route asks it the same question it asked its own copy.
        from services.backup.storage import is_archive_name

        with backup_operation_lock():
            pass

        assert not is_archive_name(LOCK_NAME)
        listed = [entry.name for entry in backup_dir.iterdir()
                  if is_archive_name(entry.name)]
        assert listed == []

    def test_retention_does_not_see_the_lock(self, backup_dir):
        from services.backup.schedule import _BACKUP_GLOB

        with backup_operation_lock():
            pass

        assert glob.glob(os.path.join(str(backup_dir), _BACKUP_GLOB)) == []


class TestASystemFailureDoesNotStopBackups:
    """No installation may be left unable to back up because its filesystem
    cannot lock: an unprotected run is logged, and allowed."""

    def test_an_unlockable_filesystem_lets_the_operation_through(
            self, backup_dir, monkeypatch, caplog):
        def refuse(*_args, **_kwargs):
            raise OSError(errno.ENOLCK, 'no locks available')

        monkeypatch.setattr(fcntl, 'flock', refuse)

        with caplog.at_level(logging.ERROR, logger='services.backup.locking'):
            with backup_operation_lock(purpose='scheduled backup'):
                ran = True

        assert ran
        assert 'without protection' in caplog.text

    def test_an_unusable_directory_lets_the_operation_through(
            self, tmp_path, monkeypatch, caplog):
        # A backup directory that cannot even be created: here its parent is
        # a regular file, so mkdir() fails for every user, root included.
        not_a_directory = tmp_path / 'not-a-directory'
        not_a_directory.write_text('')
        monkeypatch.setattr(Config, 'BACKUP_DIR', not_a_directory / 'backups',
                            raising=False)

        with caplog.at_level(logging.ERROR, logger='services.backup.locking'):
            with backup_operation_lock(purpose='retention'):
                ran = True

        assert ran
        assert 'without protection' in caplog.text
