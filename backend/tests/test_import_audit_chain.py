"""Entries written by the bundle import are sealed like every other.

The importer stages its audit entries rather than writing them through
`AuditService.log_action`, and that part is right: `log_action` commits the
session it is given, and the import is one transaction on purpose.

What it did not do was seal them. `prev_hash` and `entry_hash` were left
empty, so the chain restarted from its genesis at every imported object, and
`verify_integrity` walked across the break and reported a valid ledger. An
entry inserted or altered between two unsealed rows would not have been
noticed.
"""
import pytest

from models import db, AuditLog


class TestTheImportEntriesAreSealed:
    def _stage_one(self, app, name):
        from services.smart_import.importer import SmartImporter

        with app.app_context():
            importer = SmartImporter()
            importer._log_audit('import_certificate', 4242, name, 'tester')
            db.session.commit()
            return AuditLog.query.filter_by(resource_name=name).first()

    def test_the_entry_carries_a_hash_and_its_predecessor(self, app):
        entry = self._stage_one(app, 'import-chain-probe')
        assert entry is not None, 'the entry was not staged at all'
        assert entry.entry_hash, 'the entry is not sealed'
        assert entry.prev_hash, 'the entry does not name its predecessor'

    def test_the_chain_is_continuous_across_it(self, app):
        """The row before it must be the one it names."""
        with app.app_context():
            anchor = AuditLog.query.order_by(AuditLog.id.desc()).first()
            expected = anchor.entry_hash if anchor else '0' * 64

        entry = self._stage_one(app, 'import-chain-continuity')
        assert entry.prev_hash == expected, (
            'the chain restarts at this entry instead of continuing: it '
            f'names {entry.prev_hash[:12]} where the row before it seals to '
            f'{expected[:12]}')

    def test_the_integrity_check_would_see_a_break(self, app):
        """A sealed chain is one the verification can actually walk."""
        self._stage_one(app, 'import-chain-verified')
        with app.app_context():
            from services.audit_service import AuditService
            report = AuditService.verify_integrity()
            assert report['valid'], (
                f'the ledger does not verify: {report.get("errors")}')
            assert report['checked'] > 0
