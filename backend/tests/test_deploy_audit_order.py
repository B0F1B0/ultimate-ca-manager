"""When the audit entry is written, relative to the row it describes.

`AuditService.log_action` commits the session it is given, and rolls the whole
of it back when it cannot write its own entry. Called before the business
commit, it is therefore the call that decides whether the row survives: an
audit failure took the deploy target with it, `safe_commit` then committed an
empty session and answered that all was well, and the route returned 201 with
a complete, credible payload for a target that is not in the database.

The same file already states the rule for bindings: audit after the business
commit, so its internal commit and rollback can no longer undo the row.
"""
import pytest

from models import db


@pytest.fixture
def audit_always_fails(monkeypatch):
    """Break the audit entry the way a hash chain failure would.

    The failure is raised inside `log_action`'s own try block, which is what
    triggers its rollback of the caller's session.
    """
    from models.audit_log import AuditLog

    def failing_hash(self, *args, **kwargs):
        raise RuntimeError('audit hash chain unavailable')

    monkeypatch.setattr(AuditLog, 'compute_hash', failing_hash, raising=False)


class TestARouteDoesNotAnnounceARowTheAuditUndid:
    def test_the_answer_and_the_database_agree_when_the_audit_fails(
            self, app, auth_client, audit_always_fails):
        """The invariant, whichever way it is satisfied.

        A 201 must mean the target is there. Answering 201 for a row the
        audit entry rolled back is the failure; refusing the creation would
        be acceptable too. What the route may not do is disagree with its own
        database.
        """
        payload = {'name': 'audit-order-target', 'host': '192.0.2.10',
                   'username': 'deploy', 'auth_method': 'password',
                   'password': 'x' * 12}
        try:
            response = auth_client.post('/api/v2/deploy/targets', json=payload)

            with app.app_context():
                from models.deploy import DeployTarget
                present = DeployTarget.query.filter_by(
                    name='audit-order-target').count() == 1

            announced = response.status_code == 201
            assert announced == present, (
                f'the route answered {response.status_code} and the target is '
                f'{"" if present else "not "}in the database: an audit entry '
                'that could not be written decided the fate of the row and '
                'nothing told the caller')
        finally:
            with app.app_context():
                from models.deploy import DeployTarget
                DeployTarget.query.filter_by(
                    name='audit-order-target').delete(synchronize_session=False)
                db.session.commit()

    def test_a_target_is_created_when_the_audit_works(self, app, auth_client):
        """The other direction: the ordinary path still creates and audits."""
        payload = {'name': 'audit-order-ok', 'host': '192.0.2.11',
                   'username': 'deploy', 'auth_method': 'password',
                   'password': 'x' * 12}
        try:
            response = auth_client.post('/api/v2/deploy/targets', json=payload)
            assert response.status_code == 201, response.data

            with app.app_context():
                from models.deploy import DeployTarget
                assert DeployTarget.query.filter_by(
                    name='audit-order-ok').count() == 1
        finally:
            with app.app_context():
                from models.deploy import DeployTarget
                DeployTarget.query.filter_by(
                    name='audit-order-ok').delete(synchronize_session=False)
                db.session.commit()
