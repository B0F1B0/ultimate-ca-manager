"""Every authenticated-session response carries the same session fields.

Six endpoints describe the same thing to the SPA: the five login routes
(password, 2FA, mTLS, WebAuthn, LDAP) and ``GET /api/v2/auth/verify``. They
were six hand-written dicts, and they had drifted:
``force_password_change`` was on the five login responses and missing from
``/verify``.

That gap is not cosmetic. ``AuthContext.checkSession`` calls ``/verify`` on
every mount, so a page reload replaced the login response with one that had
no opinion about the forced change, and the modal — which is the whole
enforcement — went away. The SSO flows never saw it at all: they redirect to
``/login/sso-complete`` and the SPA builds its state from ``/verify`` alone.
"""
from __future__ import annotations

import pytest

from models import User, db

# The session fields that belong to every authenticated-session response.
SESSION_FIELDS = frozenset({
    'user', 'role', 'permissions', 'auth_method', 'csrf_token',
    'force_password_change', 'timezone', 'date_format', 'show_time',
})


@pytest.fixture
def forced_admin(app):
    """The admin account with a pending forced password change."""
    with app.app_context():
        user = User.query.filter_by(username='admin').first()
        previous = user.force_password_change
        user.force_password_change = True
        db.session.commit()
    yield
    with app.app_context():
        user = User.query.filter_by(username='admin').first()
        user.force_password_change = previous
        db.session.commit()


def _login(client):
    return client.post('/api/v2/auth/login',
                       json={'username': 'admin', 'password': 'changeme123'})


class TestVerifyReportsForcedPasswordChange:
    def test_verify_matches_login(self, app, forced_admin):
        """Same session, same user: both must say the change is forced."""
        client = app.test_client()

        login = _login(client)
        assert login.status_code == 200, login.get_data(as_text=True)
        login_data = login.get_json()['data']
        assert login_data['force_password_change'] is True

        verify = client.get('/api/v2/auth/verify')
        assert verify.status_code == 200
        verify_data = verify.get_json()['data']
        assert verify_data['authenticated'] is True
        assert verify_data['force_password_change'] is True, (
            '/verify dropped the forced-change state, so reloading the page '
            'skips the modal that enforces it')

    def test_verify_says_false_when_nothing_is_forced(self, app):
        client = app.test_client()
        with app.app_context():
            user = User.query.filter_by(username='admin').first()
            user.force_password_change = False
            db.session.commit()

        assert _login(client).status_code == 200
        data = client.get('/api/v2/auth/verify').get_json()['data']
        assert data['force_password_change'] is False


class TestSessionFieldParity:
    def test_login_and_verify_agree_on_the_session_fields(self, app):
        client = app.test_client()
        login_data = _login(client).get_json()['data']
        verify_data = client.get('/api/v2/auth/verify').get_json()['data']

        missing_from_login = SESSION_FIELDS - set(login_data)
        missing_from_verify = SESSION_FIELDS - set(verify_data)
        assert not missing_from_login, f'login is missing {missing_from_login}'
        assert not missing_from_verify, f'/verify is missing {missing_from_verify}'

        for field in ('role', 'permissions', 'force_password_change',
                      'timezone', 'date_format', 'show_time'):
            assert login_data[field] == verify_data[field], (
                f'{field} differs between login and /verify')

    def test_every_login_route_builds_its_body_from_the_shared_helper(self):
        """No endpoint may go back to hand-rolling the session dict."""
        import inspect

        from api.v2 import auth, auth_methods
        from api.v2.sso import ldap_routes

        for module in (auth, auth_methods, ldap_routes):
            source = inspect.getsource(module)
            assert 'auth_session_payload' in source, (
                f'{module.__name__} no longer uses the shared session payload')
            assert "'force_password_change':" not in source, (
                f'{module.__name__} hand-writes force_password_change again')


class TestPreservedContract:
    def test_verify_keeps_its_own_fields(self, app):
        client = app.test_client()
        assert _login(client).status_code == 200
        data = client.get('/api/v2/auth/verify').get_json()['data']
        for field in ('authenticated', 'user_id', 'must_enroll_2fa',
                      'session_timeout', 'preferences'):
            assert field in data, f'/verify lost {field}'
        # /verify has always returned a narrower user block than login does.
        assert set(data['user']) == {'id', 'username', 'role'}

    def test_login_keeps_the_wide_user_block(self, app):
        client = app.test_client()
        data = _login(client).get_json()['data']
        assert set(data['user']) == {
            'id', 'username', 'email', 'full_name', 'role', 'active'}

    def test_unauthenticated_verify_is_unchanged(self, app):
        client = app.test_client()
        r = client.get('/api/v2/auth/verify')
        assert r.status_code == 200
        data = r.get_json()['data']
        assert data['authenticated'] is False
        assert 'force_password_change' not in data
