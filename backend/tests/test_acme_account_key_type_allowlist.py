"""An unknown account key type is refused, not quietly turned into another one.

``POST /api/v2/acme/accounts`` compared ``key_type`` to nothing. An EC label it
did not know fell through ``curve_map.get(key_type, ec.SECP256R1())`` to P-256,
so an operator who asked for EC-P521 got a P-256 account key and a JWK saying
``crv: P-256``; anything else at all fell through to the RSA branch, where
``int(key_type.replace('RSA-', ''))`` sized the key with no ceiling. The
settings route next door answered 400 for the very same labels.
"""

import json

import pytest

from services.acme.acme_client_service import ACCOUNT_KEY_TYPES, CERT_KEY_TYPES

SETTINGS = '/api/v2/acme/client/settings'
ACCOUNTS = '/api/v2/acme/accounts'


def _create(auth_client, email, key_type):
    return auth_client.post(ACCOUNTS, data=json.dumps({
        'email': email, 'key_type': key_type, 'agree_tos': True,
    }), content_type='application/json')


@pytest.mark.parametrize('key_type', ['EC-P521', 'EC', 'EdDSA', 'PS256',
                                      'none', 'foo', '', 'RSA-8192',
                                      'RSA-65536'])
def test_unknown_key_type_is_refused(auth_client, key_type):
    r = _create(auth_client, f'allowlist-{abs(hash(key_type))}@example.test',
                key_type)

    assert r.status_code == 400
    assert 'Key type must be one of' in r.get_json()['message']


@pytest.mark.parametrize('key_type,kty,crv', [
    ('RSA-2048', 'RSA', None),
    ('RSA-4096', 'RSA', None),
    ('EC-P256', 'EC', 'P-256'),
    ('EC-P384', 'EC', 'P-384'),
])
def test_known_key_types_still_work(auth_client, app, key_type, kty, crv):
    """Contract kept for every label the UI can send."""
    from models.acme_models import AcmeAccount

    email = f'allowlist-ok-{key_type}@example.test'
    r = _create(auth_client, email, key_type)
    assert r.status_code in (200, 201)

    with app.app_context():
        account = AcmeAccount.query.filter(
            AcmeAccount.contact.like(f'%{email}%')).first()
        jwk = json.loads(account.jwk) if isinstance(account.jwk, str) else account.jwk

    assert jwk['kty'] == kty
    if crv:
        assert jwk['crv'] == crv


def test_the_key_type_default_is_unchanged(auth_client, app):
    """No key_type at all still means RSA-2048."""
    from models.acme_models import AcmeAccount

    email = 'allowlist-default@example.test'
    r = auth_client.post(ACCOUNTS, data=json.dumps({
        'email': email, 'agree_tos': True,
    }), content_type='application/json')
    assert r.status_code in (200, 201)

    with app.app_context():
        account = AcmeAccount.query.filter(
            AcmeAccount.contact.like(f'%{email}%')).first()
        jwk = json.loads(account.jwk) if isinstance(account.jwk, str) else account.jwk

    assert jwk['kty'] == 'RSA'


@pytest.mark.parametrize('field,table', [
    ('key_type', CERT_KEY_TYPES),
    ('account_key_type', ACCOUNT_KEY_TYPES),
])
def test_the_settings_route_reads_the_generator_table(auth_client, field, table):
    """The list in the message is the table, not a copy of it that can drift."""
    r = auth_client.patch(SETTINGS, data=json.dumps({field: 'definitely-not'}),
                          content_type='application/json')

    assert r.status_code == 400
    message = r.get_json()['message']
    for label in table:
        assert label in message


def test_the_two_doors_agree_on_what_a_key_type_is(auth_client):
    """Same label, same verdict, whichever route is asked."""
    for label in ['EC-P521', 'EdDSA', 'foo']:
        settings = auth_client.patch(
            SETTINGS, data=json.dumps({'key_type': label}),
            content_type='application/json')
        account = _create(auth_client, f'agree-{label}@example.test', label)

        assert settings.status_code == 400
        assert account.status_code == 400
