"""Backups: exposure and false-success findings of the 2026-09 review.

Each test here pins one behaviour the previous code got wrong: an archive
announced as successful while incomplete, an operator reading or pruning
archives, a DB password copied into the audit trail.
"""
import json
import os
import time

import pytest

from models import db, SystemConfig


def _service():
    from services.backup_service import BackupService
    return BackupService()


def _set(key, value):
    row = SystemConfig.query.filter_by(key=key).first()
    if row:
        row.value = value
    else:
        db.session.add(SystemConfig(key=key, value=value))
    db.session.commit()


@pytest.fixture(scope='module')
def operator_client(app, create_user):
    """A logged-in operator: holds read/write:settings, never admin:system."""
    create_user(username='op_backup_review', role='operator')
    c = app.test_client()
    r = c.post('/api/v2/auth/login',
               data=json.dumps({'username': 'op_backup_review',
                                'password': 'TestPass123!'}),
               content_type='application/json')
    assert r.status_code == 200, r.data
    return c


class TestArchivesAreAdminOnly:
    """An archive holds every key and secret: reading one is not an
    operator right, whatever the encryption password protects."""

    def test_operator_cannot_list_archives(self, operator_client):
        assert operator_client.get('/api/v2/system/backups').status_code == 403
        assert operator_client.get('/api/v2/system/backup/list').status_code == 403

    def test_operator_cannot_download_an_archive(self, operator_client):
        r = operator_client.get('/api/v2/system/backup/ucm_backup_x.ucmbkp/download')
        assert r.status_code == 403
        r = operator_client.get('/api/v2/settings/backup/ucm_backup_x.ucmbkp/download')
        assert r.status_code == 403

    def test_operator_cannot_read_backup_history(self, operator_client):
        assert operator_client.get('/api/v2/settings/backup/history').status_code == 403

    def test_admin_still_can(self, auth_client):
        assert auth_client.get('/api/v2/system/backups').status_code == 200
        assert auth_client.get('/api/v2/settings/backup/history').status_code == 200


class TestScheduleSettingsAreAdminOnly:
    """The dedicated schedule route requires admin:system; the General
    settings path must not be a way around it."""

    def test_operator_cannot_shorten_retention_through_general(
            self, app, auth_client, operator_client):
        with app.app_context():
            _set('backup_retention_days', '30')

        r = operator_client.patch(
            '/api/v2/settings/general',
            data=json.dumps({'backup_retention_days': 1,
                             'auto_backup_enabled': 'false',
                             'backup_frequency': 'daily'}),
            content_type='application/json')
        assert r.status_code == 403, r.data

        with app.app_context():
            row = SystemConfig.query.filter_by(key='backup_retention_days').first()
            assert row.value == '30'


class TestExportFailuresAbortTheBackup:
    def test_a_failing_exporter_names_its_section(self, app, monkeypatch):
        from services.backup.errors import BackupExportError
        with app.app_context():
            svc = _service()
            monkeypatch.setattr(type(svc), '_export_users',
                                lambda self, include: (_ for _ in ()).throw(
                                    RuntimeError('table is gone')))
            with pytest.raises(BackupExportError) as exc:
                svc.create_backup('Correct-Horse-Battery-9')
            assert 'users' in str(exc.value)
            assert 'table is gone' not in str(exc.value)

    def test_an_undecryptable_ca_key_aborts_instead_of_archiving_ciphertext(
            self, app, monkeypatch, create_ca):
        from services.backup.errors import BackupExportError
        create_ca(cn='Undecryptable Key CA')
        with app.app_context():
            import security.encryption as enc

            def boom(_data):
                raise ValueError('Failed to decrypt private key - wrong encryption key')

            monkeypatch.setattr(enc, 'decrypt_private_key', boom)
            with pytest.raises(BackupExportError) as exc:
                _service()._export_cas(True)
            assert 'could not be decrypted' in str(exc.value)

    def test_a_key_that_does_not_decrypt_to_a_pem_aborts(self, app, monkeypatch,
                                                         create_ca):
        from services.backup.errors import BackupExportError
        create_ca(cn='Not A Pem CA')
        with app.app_context():
            import security.encryption as enc
            # What the old fallback archived: the stored ciphertext, which a
            # restore would have re-encoded and stored as if it were the key.
            monkeypatch.setattr(enc, 'decrypt_private_key',
                                lambda data: 'gAAAAABm-not-a-pem')
            with pytest.raises(BackupExportError):
                _service()._export_cas(True)


class TestScheduledBackupPassword:
    def test_a_ciphertext_that_does_not_decrypt_is_not_used_as_the_password(
            self, app):
        from services.backup import schedule
        from services.backup.errors import ScheduledBackupError
        with app.app_context():
            stored = 'gAAAAA' + 'A' * 80  # Fernet-shaped, not our ciphertext
            _set('backup_password', stored)
            try:
                with pytest.raises(ScheduledBackupError):
                    schedule._get_backup_password()
            finally:
                SystemConfig.query.filter_by(key='backup_password').delete()
                db.session.commit()


class TestScheduledRunReportsOutcome:
    def test_a_failed_creation_is_raised_to_the_scheduler(self, app, monkeypatch):
        from services.backup import schedule
        with app.app_context():
            _set('auto_backup_enabled', 'true')
            _set('backup_frequency', 'daily')
            _set('backup_password', 'Correct-Horse-Battery-9')
            SystemConfig.query.filter_by(key='backup.last_run').delete()
            db.session.commit()
            monkeypatch.setattr(
                'services.backup.schedule.BackupService.create_backup',
                lambda self, pw, **k: (_ for _ in ()).throw(RuntimeError('disk full')))
            try:
                with pytest.raises(RuntimeError):
                    schedule.run_scheduled_backup()
                # Nothing was recorded as a run, so the next tick retries
                assert SystemConfig.query.filter_by(key='backup.last_run').first() is None
            finally:
                _set('auto_backup_enabled', 'false')
                SystemConfig.query.filter_by(key='backup_password').delete()
                db.session.commit()

    def test_scheduler_separates_failed_skipped_and_done(self):
        from services.scheduler_service import ScheduledTask, SchedulerService
        sched = SchedulerService()

        done = ScheduledTask('done', lambda: None, 60)
        skipped = ScheduledTask('skipped', lambda: {'status': 'skipped',
                                                    'reason': 'not_due'}, 60)
        failed = ScheduledTask('failed',
                               lambda: (_ for _ in ()).throw(RuntimeError('nope')), 60)
        for task in (done, skipped, failed):
            sched._run_task(task)

        assert done.to_dict()['last_status'] == 'ok'
        assert skipped.to_dict()['last_status'] == 'skipped'
        assert skipped.to_dict()['last_reason'] == 'not_due'
        assert failed.to_dict()['last_status'] == 'failed'
        assert 'nope' in failed.to_dict()['last_error']


class TestRetentionKeepsARestorePoint:
    def _mk(self, d, name, age_days, *, usable=True):
        path = d / name
        # v2 container header: magic + format version, padded past the v1 floor
        path.write_bytes(b'UCMB\x02' + b'\x00' * 80 if usable else b'x')
        ts = time.time() - age_days * 86400
        os.utime(path, (ts, ts))
        return path

    def test_the_last_usable_archive_survives_its_retention_age(
            self, app, tmp_path, monkeypatch):
        from services.backup import schedule
        from config.settings import Config
        with app.app_context():
            monkeypatch.setattr(Config, 'BACKUP_DIR', tmp_path, raising=False)
            _set('backup_retention_days', '7')
            only = self._mk(tmp_path, 'ucm_backup_20000101_000000.ucmbkp', 30)

            assert schedule.run_backup_retention() == 0
            assert only.exists()

    def test_older_archives_still_go_once_a_newer_one_exists(
            self, app, tmp_path, monkeypatch):
        from services.backup import schedule
        from config.settings import Config
        with app.app_context():
            monkeypatch.setattr(Config, 'BACKUP_DIR', tmp_path, raising=False)
            _set('backup_retention_days', '7')
            old = self._mk(tmp_path, 'ucm_backup_20000101_000000.ucmbkp', 30)
            older = self._mk(tmp_path, 'ucm_backup_19990101_000000.ucmbkp', 60)
            recent = self._mk(tmp_path, 'ucm_backup_20260101_000000.ucmbkp', 1)

            assert schedule.run_backup_retention() == 2
            assert recent.exists()
            assert not old.exists() and not older.exists()


class TestDatabaseCredentialsStayOutOfTheAudit:
    def test_a_failed_migration_redacts_the_password(self, app, auth_client,
                                                     monkeypatch):
        import api.v2.database as routes
        recorded = []
        monkeypatch.setattr(routes.AuditService, 'log_action',
                            lambda **kw: recorded.append(kw))
        monkeypatch.setattr(
            routes.svc, 'migrate_data',
            lambda url: (False, f'target not empty: {url}', {'tables': 0}))

        uri = 'postgresql://alice:S3cret-For-Review@db.example:5432/ucm'
        r = auth_client.post('/api/v2/database/migrate',
                             data=json.dumps({'database_url': uri}),
                             content_type='application/json')

        assert r.status_code == 409, r.data
        assert 'S3cret-For-Review' not in r.data.decode()
        assert recorded, 'the failed migration must still be audited'
        blob = json.dumps(recorded, default=str)
        assert 'S3cret-For-Review' not in blob
        assert 'alice' in blob  # user and host stay, only the secret goes

    def test_query_string_passwords_are_redacted_too(self):
        from services.database_admin import _redact_uri
        out = _redact_uri(
            'postgresql://alice@db.example/ucm?password=S3cret&sslmode=require')
        assert 'S3cret' not in out
        assert 'sslmode=require' in out
