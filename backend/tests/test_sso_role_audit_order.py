"""A role change is recorded once it has been made, not before.

`_get_or_create_sso_user` synchronises the role an identity provider reports
onto the local account. The entry saying the role changed used to be written
before the assignment and before the commit, and `AuditService.log_action`
commits the session it is given: the entry decided whether the identity
binding made a few lines above survived, while the assignment it described
had not happened yet.

Two things are pinned here: the entry names the change that was actually
made, and it is not written at all when the change is rolled back.
"""
import pytest

from models import db, AuditLog, User


def _provider(app, **overrides):
    from models.sso import SSOProvider

    settings = {
        'name': 'role-order-probe',
        'provider_type': 'ldap',
        'enabled': True,
        'auto_create_users': True,
        'default_role': 'viewer',
    }
    settings.update(overrides)
    with app.app_context():
        row = SSOProvider(**settings)
        db.session.add(row)
        db.session.commit()
        return row.id


class TestTheRoleChangeIsRecordedAfterItIsMade:
    def test_the_entry_names_the_change_that_was_committed(self, app):
        """The account really holds the new role, and the entry says so."""
        from api.v2.sso.ldap_routes import _get_or_create_sso_user
        from models.sso import SSOProvider

        provider_id = _provider(
            app, role_mapping='{"pki-admins": "admin"}',
            sync_role_on_login=True)

        with app.app_context():
            existing = User(username='role-order-probe-user',
                            email='probe@example.test', role='viewer',
                            active=True, auth_source='sso')
            existing.set_password('unused-by-sso-logins')
            existing.sso_provider_id = provider_id
            db.session.add(existing)
            db.session.commit()

            provider = db.session.get(SSOProvider, provider_id)
            user, err = _get_or_create_sso_user(
                provider, 'role-order-probe-user', 'probe@example.test',
                'Probe User', {'groups': ['pki-admins']})
            assert err is None, err
            assert user.role == 'admin', (
                f'the role was not actually changed: {user.role}')

            entry = AuditLog.query.filter_by(
                action='role_change',
                resource_name='role-order-probe-user').first()
            assert entry is not None, 'the change was made and not recorded'
            assert 'viewer' in entry.details and 'admin' in entry.details, (
                f'the entry does not name the change made: {entry.details}')

    def test_the_ledger_never_claims_a_role_the_account_does_not_hold(
            self, app, monkeypatch):
        """The distinguishing case: the audit's own commit succeeds and the
        one after it fails.

        Written first, the entry went in on its own commit and the assignment
        that followed was rolled back, so the ledger said the account was an
        administrator while the account was still a viewer. Written after, the
        assignment is what committed first; an entry that cannot then be
        written is a missing line, not a false one.

        Failing the *second* commit is what separates the two. Failing every
        commit proves nothing, because `log_action` commits too and simply
        writes nothing when it cannot.
        """
        from api.v2.sso.ldap_routes import _get_or_create_sso_user
        from models.sso import SSOProvider

        provider_id = _provider(
            app, name='role-order-probe-2',
            role_mapping='{"pki-admins": "admin"}', sync_role_on_login=True)

        with app.app_context():
            existing = User(username='role-order-refused',
                            email='refused@example.test', role='viewer',
                            active=True, auth_source='sso')
            existing.set_password('unused-by-sso-logins')
            existing.sso_provider_id = provider_id
            db.session.add(existing)
            db.session.commit()

            real_commit = db.session.commit
            calls = {'n': 0}

            def _second_one_fails():
                calls['n'] += 1
                if calls['n'] == 2:
                    raise RuntimeError('commit refused')
                return real_commit()

            provider = db.session.get(SSOProvider, provider_id)
            monkeypatch.setattr(db.session, 'commit', _second_one_fails,
                                raising=False)
            _get_or_create_sso_user(
                provider, 'role-order-refused', 'refused@example.test',
                'Refused User', {'groups': ['pki-admins']})
            monkeypatch.undo()

            db.session.expire_all()
            held = db.session.query(User).filter_by(
                username='role-order-refused').first().role
            entry = AuditLog.query.filter_by(
                action='role_change',
                resource_name='role-order-refused').first()

            if entry is not None:
                assert held == 'admin', (
                    'the ledger records a role change the account does not '
                    f'hold: it says {entry.details!r} and the account is '
                    f'{held!r}')
