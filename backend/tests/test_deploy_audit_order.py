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


# (route, comment se lit la présence de la ligne après coup)
ROUTES_THAT_WRITE_THEN_RECORD = (
    'create_target', 'update_target', 'delete_target', 'test_target',
    'create_binding', 'update_binding', 'delete_binding',
    'create_crl_binding', 'update_crl_binding', 'delete_crl_binding',
)


class TestEveryRouteOfThePageRecordsAfterItWrites:
    def test_no_route_audits_before_its_commit(self):
        """Read from the parsed source: on this page the audit entry commits
        the caller's session, so writing it before the business commit makes
        it the call that decides whether the row survives. Five routes had it
        the right way round and three did not; nothing but this test says so
        for the next one."""
        import ast
        import os

        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'api', 'v2', 'deploy.py')
        tree = ast.parse(open(path).read())

        wrong = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name not in ROUTES_THAT_WRITE_THEN_RECORD:
                continue
            audit_at = commit_at = None
            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                func = child.func
                if (isinstance(func, ast.Attribute)
                        and func.attr == 'log_action' and audit_at is None):
                    audit_at = child.lineno
                if (isinstance(func, ast.Name)
                        and func.id == 'safe_commit' and commit_at is None):
                    commit_at = child.lineno
            if audit_at and commit_at and audit_at < commit_at:
                wrong.append(f'{node.name} (audit line {audit_at}, '
                             f'commit line {commit_at})')
        assert wrong == [], (
            'these routes record the change before writing it, so an audit '
            f'entry that cannot be written undoes the change: {wrong}')


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


class TestARecordThatCouldNotBeSavedIsNotAnnouncedAsOne:
    """A push that happened and was not written down is not a success.

    The delivery row is committed before the entry that describes it, because
    that entry commits the session itself. But the commit was made through a
    helper that swallowed its own failure and returned nothing, so a caller
    whose commit had just been rolled back went on to record "Deployed
    certificate X to Y" with `success=True` and return True. The delivery
    stayed pending for a certificate already on the remote host, and the next
    pass pushed it again.
    """

    def test_a_failed_commit_is_reported_in_the_entry(self, app, monkeypatch):
        from services.deploy import service as deploy_service

        with app.app_context():
            monkeypatch.setattr(
                deploy_service.db.session, 'commit',
                lambda: (_ for _ in ()).throw(RuntimeError('no')),
                raising=False)
            assert deploy_service._safe_commit('probe') is False, (
                'the helper swallowed the failure and said nothing')

    def test_a_successful_commit_is_reported_too(self, app):
        from services.deploy import service as deploy_service

        with app.app_context():
            assert deploy_service._safe_commit('probe') is True
