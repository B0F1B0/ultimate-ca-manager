"""Migrations do not overlap, and do not block unrelated work.

Switching backend is a sequence, not a call: check the target, snapshot the
source, copy, verify, rewrite the configuration, restart. Two of them running
at once is the worst case this subsystem has, and nothing used to prevent it.
"""
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from config.settings import DATA_DIR
from services.backup.locking import backup_operation_lock
from services.database_admin.lock import (
    LOCK_NAME,
    MigrationBusyError,
    database_migration_lock,
    migration_lock_depth,
    migration_lock_path,
)

BACKEND_DIR = str(Path(__file__).resolve().parents[1])

# A child that takes the migration lock, says so, and holds it until told.
_HOLDER = """
import sys
from services.database_admin.lock import database_migration_lock
with database_migration_lock(purpose='holder'):
    sys.stdout.write('locked\\n')
    sys.stdout.flush()
    sys.stdin.readline()
sys.stdout.write('released\\n')
sys.stdout.flush()
"""


@pytest.fixture
def holder():
    """A separate process holding the lock for the duration of the test."""
    env = dict(os.environ, PYTHONPATH=BACKEND_DIR, DATA_DIR=str(DATA_DIR))
    child = subprocess.Popen(
        [sys.executable, '-c', _HOLDER], cwd=BACKEND_DIR, env=env,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'locked', \
            'the child never took the lock'
        yield child
    finally:
        if child.poll() is None:
            child.stdin.write('go\n')
            child.stdin.flush()
        child.wait(timeout=10)


class TestOnlyOneMigrationAtATime:
    def test_a_second_process_is_refused_rather_than_queued(self, holder):
        with pytest.raises(MigrationBusyError) as refused:
            with database_migration_lock(purpose='the migration'):
                pytest.fail('the lock was granted twice')

        message = str(refused.value)
        assert 'already in progress' in message
        assert 'the migration' in message

    def test_the_refusal_names_no_path_and_no_host(self, holder):
        with pytest.raises(MigrationBusyError) as refused:
            with database_migration_lock():
                pass

        assert str(migration_lock_path()) not in str(refused.value)
        assert '/' not in str(refused.value)

    def test_waiting_gives_up_after_the_timeout(self, holder):
        started = time.monotonic()
        with pytest.raises(MigrationBusyError):
            with database_migration_lock(timeout=0.3):
                pass

        assert time.monotonic() - started >= 0.3, 'it did not wait at all'

    def test_the_lock_is_released_when_the_block_raises(self):
        with pytest.raises(RuntimeError):
            with database_migration_lock():
                raise RuntimeError('the copy failed')

        assert migration_lock_depth() == 0
        with database_migration_lock():
            pass


class TestALockThatCannotBeTakenRefuses:
    """A backup that cannot be locked still runs, because an installation
    that can never take one again is worse. A migration is the opposite: two
    unprotected runs fill the same target and each write their own answer
    into the configuration file."""

    def test_a_lock_file_that_cannot_be_opened_refuses_the_migration(
            self, monkeypatch):
        import utils.process_lock as process_lock

        def denied(path):
            raise PermissionError(13, 'Permission denied', str(path))

        monkeypatch.setattr(process_lock, '_open_lock_file', denied)

        with pytest.raises(MigrationBusyError) as refused:
            with database_migration_lock(purpose='the migration'):
                pytest.fail('the migration ran without the lock')

        assert 'was not started' in str(refused.value)
        assert migration_lock_depth() == 0

    def test_the_backup_lock_still_runs_unprotected(self, monkeypatch):
        import utils.process_lock as process_lock

        def denied(path):
            raise PermissionError(13, 'Permission denied', str(path))

        monkeypatch.setattr(process_lock, '_open_lock_file', denied)

        ran = []
        with backup_operation_lock(purpose='the scheduled backup'):
            ran.append(True)

        assert ran == [True]


class TestItIsNotTheBackupLock:
    """The nesting depth used to be counted once for the process, so a thread
    holding one lock would walk straight through the other one."""

    def test_holding_the_migration_lock_does_not_grant_the_backup_lock(self):
        taken = {}

        def take_the_backup_lock():
            with backup_operation_lock(purpose='a backup'):
                taken['depth'] = migration_lock_depth()

        with database_migration_lock():
            thread = threading.Thread(target=take_the_backup_lock)
            thread.start()
            thread.join(timeout=5)

        assert taken == {'depth': 0}, \
            'the backup lock was taken under the migration depth'

    def test_a_migration_does_not_stop_a_backup(self, holder):
        """A migration running in another process must not make the scheduled
        backup refuse to run: they guard different things."""
        with backup_operation_lock(purpose='the scheduled backup'):
            pass

    def test_the_lock_file_is_not_in_the_backup_directory(self):
        from config.settings import Config

        path = migration_lock_path()
        assert path.name == LOCK_NAME
        assert Path(Config.BACKUP_DIR) not in path.parents


class TestNesting:
    def test_a_nested_block_does_not_deadlock_against_itself(self):
        with database_migration_lock(purpose='the migration'):
            assert migration_lock_depth() == 1
            with database_migration_lock(purpose='a helper'):
                assert migration_lock_depth() == 2
            assert migration_lock_depth() == 1
        assert migration_lock_depth() == 0


class TestTheRouteReportsTheConflict:
    def test_migrate_answers_409_while_another_migration_runs(
            self, auth_client, holder, tmp_path):
        # A path of this test's own, not a fixed one in /tmp: the lock is the
        # only thing standing between this request and a real migration, and
        # a target shared by every worker would be written by whichever of
        # them got through.
        target = tmp_path / 'never-used.db'
        response = auth_client.post(
            '/api/v2/database/migrate',
            data=json.dumps({'database_url': f'sqlite:///{target}'}),
            content_type='application/json')

        assert response.status_code == 409, response.data
        assert 'already in progress' in json.loads(response.data)['message']
        assert not target.exists(), 'the refused migration wrote to the target'

    def test_switch_answers_409_while_another_migration_runs(
            self, auth_client, holder, tmp_path):
        target = tmp_path / 'never-used.db'
        response = auth_client.post(
            '/api/v2/database/switch',
            data=json.dumps({'database_url': f'sqlite:///{target}'}),
            content_type='application/json')

        assert response.status_code == 409, response.data
        assert 'already in progress' in json.loads(response.data)['message']
        assert not target.exists(), 'the refused switch wrote to the target' 
