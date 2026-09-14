"""One RFC 7638 thumbprint, two failure styles, no second canonicalization.

Three copies computed it: the ACME service mixin (RSA and EC, raising on
anything else), the proxy front door (RSA, EC and OKP, returning None), and an
inline copy in the account-creation route. The two dict-taking copies answered
differently for the same key -- an OKP JWK got a thumbprint on one side and a
ValueError on the other -- which is exactly the value the proxy compares
against what the service stored.

The variant that takes a cryptography key object rather than a JWK dict stays
separate on purpose: it has to build the JWK first, and that is a different
job. It now builds it and hands it here, so the canonicalization is not
written twice.
"""

import pytest

from services.acme.acme_service import AcmeService
from services.acme.jwk_thumbprint import (
    jwk_thumbprint,
    jwk_thumbprint_or_none,
)
from api.acme.acme_proxy_api import _jwk_thumbprint as proxy_thumbprint

RSA_JWK = {'kty': 'RSA', 'e': 'AQAB', 'n': 'sXchDaQ'}
EC_JWK = {'kty': 'EC', 'crv': 'P-256', 'x': 'abc', 'y': 'def'}
OKP_JWK = {'kty': 'OKP', 'crv': 'Ed25519', 'x': 'AAAABBBBCCCCDDDD'}


@pytest.mark.parametrize('jwk', [RSA_JWK, EC_JWK, OKP_JWK])
def test_every_door_computes_the_same_thumbprint(jwk):
    expected = jwk_thumbprint(jwk)

    assert jwk_thumbprint_or_none(jwk) == expected
    assert proxy_thumbprint(jwk) == expected
    assert AcmeService()._compute_jwk_thumbprint(jwk) == expected


@pytest.mark.parametrize('jwk', [RSA_JWK, EC_JWK])
def test_known_thumbprints_are_unchanged(jwk):
    """Contract kept: the values already stored still match."""
    import base64
    import hashlib
    import json

    members = {'RSA': ('e', 'kty', 'n'), 'EC': ('crv', 'kty', 'x', 'y')}
    canonical = json.dumps({m: jwk[m] for m in members[jwk['kty']]},
                           separators=(',', ':'), sort_keys=True)
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(canonical.encode()).digest()).rstrip(b'=').decode()

    assert jwk_thumbprint(jwk) == expected


def test_optional_members_do_not_change_the_thumbprint():
    """RFC 7638 §3.2: required members only."""
    noisy = dict(RSA_JWK, alg='RS256', kid='whatever', use='sig')

    assert jwk_thumbprint(noisy) == jwk_thumbprint(RSA_JWK)


@pytest.mark.parametrize('jwk', [
    {'kty': 'oct', 'k': 'secret'},
    {'kty': 'RSA', 'e': 'AQAB'},          # missing 'n'
    {'crv': 'P-256', 'x': 'a', 'y': 'b'},  # missing 'kty'
])
def test_the_raising_door_still_raises(jwk):
    """Contract kept for the callers that catch ValueError."""
    with pytest.raises(ValueError):
        jwk_thumbprint(jwk)
    with pytest.raises(ValueError):
        AcmeService()._compute_jwk_thumbprint(jwk)


@pytest.mark.parametrize('jwk', [
    {'kty': 'oct', 'k': 'secret'},
    {'kty': 'RSA', 'e': 'AQAB'},
    'not a dict',
    None,
])
def test_the_lenient_door_still_answers_none(jwk):
    """Contract kept for the ownership checks that fail closed on None."""
    assert jwk_thumbprint_or_none(jwk) is None
    assert proxy_thumbprint(jwk) is None


def test_the_key_object_variant_agrees_with_the_shared_rule():
    from cryptography.hazmat.primitives.asymmetric import ec
    from services.acme.acme_client_service import AcmeClientService

    service = AcmeClientService.__new__(AcmeClientService)
    key = ec.generate_private_key(ec.SECP256R1())

    assert service._jwk_thumbprint(key) == jwk_thumbprint(service._build_jwk(key))


def test_the_account_route_stores_the_shared_thumbprint(auth_client, app):
    """The inline copy in the account-creation route is the same value."""
    import json as _json
    from models.acme_models import AcmeAccount

    email = 'shared-thumbprint@example.test'
    r = auth_client.post('/api/v2/acme/accounts', data=_json.dumps({
        'email': email, 'key_type': 'EC-P256', 'agree_tos': True,
    }), content_type='application/json')
    assert r.status_code in (200, 201)

    with app.app_context():
        account = AcmeAccount.query.filter(
            AcmeAccount.contact.like(f'%{email}%')).first()
        stored_jwk = _json.loads(account.jwk)
        stored_thumbprint = account.jwk_thumbprint

    assert stored_thumbprint == jwk_thumbprint(stored_jwk)
