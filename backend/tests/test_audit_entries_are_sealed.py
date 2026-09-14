"""Every audit entry is sealed, and the verification says what it cannot attest.

`AuditService.log_action` seals the entry it writes. Eight other places built
an `AuditLog` by hand and added it to the session, because they were in the
middle of a transaction they meant to commit themselves and `log_action`
would have committed it for them. All eight forgot the same thing.

An unsealed row is not merely unverified. `verify_integrity` skipped it and
restarted its chain there, so the ledger read as valid straight across the
gap, and a row inserted or altered between two unsealed ones would not have
been noticed.
"""
import ast
import os

import pytest

from models import db, AuditLog


ZONES = ('api', 'services', 'auth', 'utils', 'security', 'middleware',
         'websocket')


class TestNobodyBuildsAnEntryByHand:
    def test_the_only_way_in_is_the_shared_one(self):
        """`AuditLog(...)` outside the audit package means a row nobody sealed."""
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        built = []
        for zone in ZONES:
            base_dir = os.path.join(here, zone)
            if not os.path.isdir(base_dir):
                continue
            for base, _dirs, names in os.walk(base_dir):
                if '__pycache__' in base:
                    continue
                for name in names:
                    if not name.endswith('.py'):
                        continue
                    path = os.path.join(base, name)
                    rel = os.path.relpath(path, here)
                    if rel.startswith(os.path.join('services', 'audit')):
                        continue
                    try:
                        tree = ast.parse(open(path).read())
                    except SyntaxError:
                        continue
                    for node in ast.walk(tree):
                        if (isinstance(node, ast.Call)
                                and isinstance(node.func, ast.Name)
                                and node.func.id == 'AuditLog'):
                            built.append(f'{rel}:{node.lineno}')

        assert built == [], (
            'these places build an audit entry themselves, which means one '
            f'nobody seals: {built}. Use '
            'services.audit.staging.stage_audit_entry, which seals it and '
            'leaves the commit to you.')


class TestTheStagedEntryIsSealed:
    def test_it_carries_a_hash_and_names_its_predecessor(self, app):
        from services.audit.staging import stage_audit_entry

        with app.app_context():
            before = AuditLog.query.order_by(AuditLog.id.desc()).first()
            expected = before.entry_hash if before else '0' * 64

            entry = stage_audit_entry(
                action='staging_probe', resource_type='system',
                resource_name='staging-probe', username='tester')
            db.session.commit()

            assert entry is not None
            assert entry.entry_hash, 'the entry is not sealed'
            assert entry.prev_hash == expected, (
                'the chain restarts at this entry instead of continuing')

    def test_it_does_not_commit_for_its_caller(self, app):
        """The caller owns the transaction: that is the whole point."""
        from services.audit.staging import stage_audit_entry

        with app.app_context():
            stage_audit_entry(
                action='staging_rollback_probe', resource_type='system',
                resource_name='staging-rollback-probe', username='tester')
            db.session.rollback()
            assert AuditLog.query.filter_by(
                resource_name='staging-rollback-probe').first() is None, (
                'the helper committed the entry, so it would commit whatever '
                'else the caller had staged')


class TestTheVerificationReportsWhatItCannotAttest:
    def test_an_unsealed_row_is_named_rather_than_stepped_over(self, app):
        from services.audit_service import AuditService

        with app.app_context():
            orphan = AuditLog(action='unsealed_probe', resource_type='system',
                              resource_name='unsealed-probe',
                              username='tester', success=True)
            db.session.add(orphan)
            db.session.commit()
            orphan_id = orphan.id

            report = AuditService.verify_integrity()
            assert orphan_id in report['unsealed'], (
                'the verification walked across an entry it cannot attest '
                'without saying so')
            assert report['attested'] == report['checked'] - len(
                report['unsealed'])

            AuditLog.query.filter_by(id=orphan_id).delete()
            db.session.commit()
