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
    def _container(self) -> bytes:
        """A structurally complete v2 container (header + metadata + body)."""
        import base64 as b64, json as js, struct
        metadata = js.dumps({
            'format_version': 2, 'ucm_version': '2.230-dev',
            'created_at': '2026-01-01T00:00:00Z', 'backup_type': 'full',
            'kdf': {'type': 'argon2id', 'time_cost': 3, 'memory_cost': 65536,
                    'parallelism': 4, 'hash_len': 32},
            'salt_b64': b64.b64encode(b'S' * 16).decode(),
            'nonce_b64': b64.b64encode(b'N' * 12).decode(),
        }, separators=(',', ':')).encode()
        return (b'UCMB' + bytes([2, 1, 2, 0]) + struct.pack('>H', len(metadata))
                + metadata + b'C' * 512)

    def _mk(self, d, name, age_days, *, usable=True):
        path = d / name
        path.write_bytes(self._container() if usable else b'UCMB\x02' + b'\x00' * 80)
        ts = time.time() - age_days * 86400
        os.utime(path, (ts, ts))
        return path

    def test_a_corrupt_newer_file_does_not_displace_the_last_good_archive(
            self, app, tmp_path, monkeypatch):
        """Only a header away from being an archive is not a restore point."""
        from services.backup import schedule
        from config.settings import Config
        with app.app_context():
            monkeypatch.setattr(Config, 'BACKUP_DIR', tmp_path, raising=False)
            _set('backup_retention_days', '7')
            good = self._mk(tmp_path, 'ucm_backup_20000101_000000.ucmbkp', 30)
            corrupt = self._mk(tmp_path, 'ucm_backup_20260101_000000.ucmbkp', 20,
                               usable=False)

            removed = schedule.run_backup_retention()

            assert good.exists(), 'the last usable archive was pruned'
            assert not corrupt.exists() and removed == 1

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


class TestRedactionCoversEveryPasswordShape:
    """The authority form with no user, and libqp's query spellings."""

    def test_empty_user_and_ssl_password(self):
        from services.database_admin import _redact_uri
        out = _redact_uri('postgresql://:S3cret@db.example/ucm')
        assert 'S3cret' not in out and 'db.example' in out

        out = _redact_uri(
            'postgresql://alice@db.example/ucm?sslpassword=S3cret&sslmode=require')
        assert 'S3cret' not in out
        assert 'sslmode=require' in out

    def test_a_path_setting_is_not_redacted(self):
        from services.database_admin import _redact_uri
        out = _redact_uri('postgresql://alice@db.example/ucm?passfile=/etc/pgpass')
        assert out.endswith('passfile=/etc/pgpass')


class TestFailedTimestampStopsTheLoop:
    """An archive written but never recorded must not be written again a
    minute later, which is what filled the disk."""

    def test_the_run_does_not_come_due_again_on_the_next_tick(
            self, app, tmp_path, monkeypatch):
        from services.backup import schedule
        from config.settings import Config
        with app.app_context():
            monkeypatch.setattr(Config, 'BACKUP_DIR', tmp_path, raising=False)
            _set('auto_backup_enabled', 'true')
            _set('backup_frequency', 'daily')
            _set('backup_password', 'Correct-Horse-Battery-9')
            SystemConfig.query.filter_by(key='backup.last_run').delete()
            db.session.commit()
            schedule._LAST_ATTEMPT['at'] = None

            monkeypatch.setattr(
                'services.backup.schedule.BackupService.create_backup',
                lambda self, pw, **k: b'archive-bytes')
            monkeypatch.setattr(
                'services.backup.schedule._record_last_run',
                lambda ts: (_ for _ in ()).throw(
                    schedule.ScheduledBackupError('cannot write')))

            try:
                with pytest.raises(schedule.ScheduledBackupError):
                    schedule.run_scheduled_backup()
                written = list(tmp_path.glob('ucm_backup_*.ucmbkp'))
                assert len(written) == 1

                # Next scheduler tick, one minute later
                assert schedule.run_scheduled_backup() == {
                    'status': 'skipped', 'reason': 'not_due'}
                assert len(list(tmp_path.glob('ucm_backup_*.ucmbkp'))) == 1
            finally:
                schedule._LAST_ATTEMPT['at'] = None
                _set('auto_backup_enabled', 'false')
                SystemConfig.query.filter_by(key='backup_password').delete()
                db.session.commit()


class TestSecretsAndFilesCannotBeDroppedSilently:
    def test_an_undecryptable_dns_credential_aborts_the_backup(
            self, app, monkeypatch):
        from services.backup.errors import BackupExportError
        from models.acme_models import DnsProvider
        with app.app_context():
            provider = DnsProvider(name='review-dns', provider_type='cloudflare')
            provider.credentials = '{"api_token": "t0ken"}'
            db.session.add(provider)
            db.session.commit()
            try:
                import utils.encryption as enc
                stored = provider._credentials
                real_decrypt = enc.decrypt_value
                # Only this provider's value stops decrypting: the shared test
                # database holds other providers, and they must still export.
                monkeypatch.setattr(
                    enc, 'decrypt_value',
                    lambda value: None if value == stored else real_decrypt(value))
                with pytest.raises(BackupExportError) as exc:
                    _service()._export_dns_providers(True)
                assert 'review-dns' in str(exc.value)
            finally:
                db.session.delete(provider)
                db.session.commit()

    def test_an_unreadable_https_key_aborts_the_backup(self, app, monkeypatch,
                                                       tmp_path):
        from pathlib import Path
        from services.backup.errors import BackupExportError
        from config.settings import Config
        cert = tmp_path / 'server.crt'
        key = tmp_path / 'server.key'
        cert.write_text('-----BEGIN CERTIFICATE-----\n')
        key.write_text('-----BEGIN PRIVATE KEY-----\n')

        real_read_text = Path.read_text

        def read_text(self, *args, **kwargs):
            if self == key:
                raise OSError('Permission denied')
            return real_read_text(self, *args, **kwargs)

        with app.app_context():
            monkeypatch.setattr(Config, 'HTTPS_CERT_PATH', cert, raising=False)
            monkeypatch.setattr(Config, 'HTTPS_KEY_PATH', key, raising=False)
            monkeypatch.setattr(Path, 'read_text', read_text)
            with pytest.raises(BackupExportError):
                _service()._export_https_files()


class TestTaskReportedFailureIsNotGreen:
    def test_a_task_returning_failed_is_recorded_as_failed(self):
        from services.scheduler_service import ScheduledTask, SchedulerService
        task = ScheduledTask('reports-failure',
                             lambda: {'status': 'failed', 'reason': 'no password'},
                             60)
        SchedulerService()._run_task(task)

        recorded = task.to_dict()
        assert recorded['last_status'] == 'failed'
        assert 'no password' in (recorded['last_error'] or '')
        assert task.run_count == 0
