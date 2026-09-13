"""The history an archive carries comes back when it is asked for.

Five sections were listed as restored and no code path ever wrote them: the
export collected them, the restore counted them among the sections it
applies, and they went nowhere. An operator who asks for the audit log, the
discovery results or the enrolment history in their archive is asking to get
them back, and was told they had.
"""
import pytest
from sqlalchemy import inspect as sa_inspect, text

from models import db
from services.backup import manifest
from services.backup.export_generic import load_model
from services.backup.restore_core import GENERIC_SECTIONS, RESTORED_SECTIONS

PASSWORD = 'Correct-Horse-Battery-9'

# The sections that used to be announced and dropped.
HISTORY_SECTIONS = (
    'audit_logs', 'discovered_certificates', 'msca_requests', 'scan_runs',
    'scep_requests',
)


def _service():
    from services.backup_service import BackupService
    return BackupService()


def _only(*names):
    return {name: name in names for name in manifest.SECTIONS}


class TestNothingIsAnnouncedWithoutBeingWritten:
    def test_every_section_said_to_be_restored_has_a_writer(self):
        """The list is a promise made to the caller: a section in it that no
        code path writes is a restore reporting work it never did."""
        import glob

        sources = ''
        for path in (glob.glob('services/backup/restore*.py')
                     + glob.glob('services/backup/restore/*.py')):
            sources += open(path).read()

        unwritten = []
        for name in sorted(set(RESTORED_SECTIONS) - set(GENERIC_SECTIONS)):
            mentions = [line for line in sources.splitlines()
                        if f"'{name}'" in line
                        and 'RESTORED_SECTIONS' not in line
                        and not line.strip().startswith("'")]
            if not mentions:
                unwritten.append(name)

        assert unwritten == [], (
            'these sections are announced as restored and nothing writes '
            f'them: {unwritten}')

    @pytest.mark.parametrize('name', HISTORY_SECTIONS)
    def test_the_section_is_applied_from_the_manifest(self, name):
        assert name in GENERIC_SECTIONS, (
            f'{name} is not applied by the generic path, so nothing restores it')


class TestTheHistoryActuallyComesBack:
    def test_an_audit_entry_is_restored(self, app):
        """The audit log is the section an operator is most likely to ask
        for, and the one nothing was writing."""
        with app.app_context():
            db.session.execute(text(
                "INSERT INTO audit_logs (action, details, timestamp) "
                "VALUES ('zzhistory-restore', 'carried by the archive', "
                "'2026-01-01 00:00:00')"))
            db.session.commit()

            blob = _service().create_backup(
                PASSWORD, include=_only('audit_logs'))

            db.session.execute(text(
                "DELETE FROM audit_logs WHERE action = 'zzhistory-restore'"))
            db.session.commit()
            assert db.session.execute(text(
                "SELECT COUNT(*) FROM audit_logs "
                "WHERE action = 'zzhistory-restore'")).scalar() == 0

            try:
                results = _service().restore_backup(
                    blob, PASSWORD, mode='merge')

                assert db.session.execute(text(
                    "SELECT COUNT(*) FROM audit_logs "
                    "WHERE action = 'zzhistory-restore'")).scalar() == 1
                assert results.get('audit_logs', 0) >= 1
            finally:
                db.session.execute(text(
                    "DELETE FROM audit_logs WHERE action = 'zzhistory-restore'"))
                db.session.commit()

    def test_a_section_that_is_not_asked_for_is_not_restored(self, app):
        """They stay opt-in: an archive that does not carry the history does
        not empty it either."""
        with app.app_context():
            blob = _service().create_backup(
                PASSWORD, include=_only('groups'))
            _key, payload = _service()._decrypt_framed(blob, PASSWORD)

        assert not payload.get('audit_logs')
