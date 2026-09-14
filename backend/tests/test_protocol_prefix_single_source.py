"""The public protocol path list has one definition, and ``/tsa`` is exact.

Six places used to carry their own copy of "which paths belong to a PKI
protocol client rather than to the admin UI": the classifier in
``utils.public_endpoints``, the HTTPS-redirect exemption and the safe-mode
allowlist in ``app.py``, the CSRF exemption list, the SPA catch-all in
``api/ui_routes.py``, and the rate-limiter policy table.

They had drifted. ``/tsa`` was written as a bare prefix, so ``/tsa-config``
— the admin UI page for the timestamping settings — matched it. A protocol
path skips the canonical-admin redirect, skips the admin-vs-ACME host-role
check, and skips the http→https upgrade, so that one missing slash exposed
an admin page on the ACME public vhost and over cleartext HTTP, while the
SPA router happily served it as an ordinary admin page.
"""
from __future__ import annotations

import pytest

from models import SystemConfig
from security.csrf import CSRFProtection
from utils.public_endpoints import (
    PROTOCOL_PREFIXES,
    check_host_access,
    is_admin_ui_path,
    is_protocol_path,
)

# The admin UI pages whose names begin with a protocol endpoint's name.
_ADMIN_PAGES = ('/tsa-config', '/scep-config', '/est-config', '/crl-ocsp', '/acme')

# The protocol endpoints themselves, exactly as the routes declare them.
_PROTOCOL_PATHS = (
    '/tsa',
    '/ocsp',
    '/ocsp/MEkwRzBFMEMwQTAJBgUrDgMCGgUA',
    '/cdp/root.crl',
    '/ca/root.crt',
    '/scep/pkiclient.exe',
    '/.well-known/est/cacerts',
    '/.well-known/acme-challenge/token',
    '/ssh/setup/abc',
    '/ADPolicyProvider_CEP_UsernamePassword/service.svc',
    '/ADCertificateService_CES_Kerberos/service.svc',
)


@pytest.fixture
def split_topology(app):
    keys = ('base_url', 'acme_public_vhost')
    from models import db

    with app.app_context():
        SystemConfig.query.filter(SystemConfig.key.in_(keys)).delete()
        db.session.add(SystemConfig(key='base_url',
                                    value='https://admin.ucm.example.com:8443'))
        db.session.add(SystemConfig(key='acme_public_vhost',
                                    value='acme.ucm.example.com'))
        db.session.commit()
    yield
    with app.app_context():
        SystemConfig.query.filter(SystemConfig.key.in_(keys)).delete()
        db.session.commit()


def test_protocol_endpoints_are_protocol_paths():
    for path in _PROTOCOL_PATHS:
        assert is_protocol_path(path), f'{path} must stay a protocol path'
        assert not is_admin_ui_path(path), f'{path} must not be admin UI'


def test_admin_pages_are_not_protocol_paths():
    """``/tsa-config`` is an admin page, not a timestamping endpoint."""
    for path in _ADMIN_PAGES:
        assert not is_protocol_path(path), f'{path} is an admin UI route'


def test_tsa_config_is_blocked_on_the_acme_vhost(split_topology, app):
    """The host-role check must refuse an admin page on the ACME vhost.

    ``check_host_access`` returns early for protocol paths, so while
    ``/tsa-config`` counted as one it was reachable there — unlike every
    other admin page.
    """
    with app.app_context():
        assert check_host_access('/', 'acme.ucm.example.com') == (
            404, 'Admin interface is not available on the ACME public vhost')
        assert check_host_access('/tsa-config', 'acme.ucm.example.com') == (
            404, 'Admin interface is not available on the ACME public vhost')


def test_tsa_config_still_reachable_on_the_admin_vhost(split_topology, app):
    with app.app_context():
        assert check_host_access('/tsa-config', 'admin.ucm.example.com') is None


def test_acme_directory_still_allowed_on_the_acme_vhost(split_topology, app):
    with app.app_context():
        assert check_host_access('/acme/directory', 'acme.ucm.example.com') is None


def test_https_redirect_exemption_uses_the_shared_list():
    """``app.py`` must not keep a second copy of the prefixes."""
    import inspect

    import app as app_module

    source = inspect.getsource(app_module.create_app)
    assert "'/ADPolicyProvider_CEP_', '/ADCertificateService_CES_'," not in source, (
        'app.py still inlines its own protocol prefix tuple')
    assert 'PROTOCOL_PREFIXES' in source or 'is_public_protocol_path' in source


def test_spa_catch_all_uses_the_shared_list():
    import inspect

    from api import ui_routes

    source = inspect.getsource(ui_routes)
    assert "'ADPolicyProvider_CEP_', 'ADCertificateService_CES_'," not in source, (
        'ui_routes.py still inlines its own protocol prefix tuple')


def test_csrf_exemption_covers_every_protocol_path():
    for path in _PROTOCOL_PATHS:
        assert CSRFProtection.is_exempt(path), f'{path} must be CSRF-exempt'


def test_csrf_exemption_does_not_cover_admin_pages():
    for path in ('/tsa-config', '/scep-config', '/est-config'):
        assert not CSRFProtection.is_exempt(path), f'{path} must not be CSRF-exempt'


def test_shared_prefixes_are_slash_terminated_or_unambiguous():
    """No bare prefix may swallow a sibling admin route again."""
    for prefix in PROTOCOL_PREFIXES:
        assert prefix.startswith('/')
        assert prefix.endswith('/') or prefix.endswith('_'), (
            f'{prefix!r} is a bare prefix and will match sibling paths; '
            'list it as an exact path instead')
