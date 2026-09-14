"""The key-change inner JWS goes through the same gate as every other JWS.

RFC 8555 §7.3.5 wraps an inner JWS (signed with the new account key) inside
an outer JWS (signed with the old one). The outer one is checked by
``verify_jws``: an explicit algorithm allowlist, RSA/EC keys only, and the
set of accepted ``url`` values that ``get_acme_expected_urls`` computes so a
client reaching UCM on a non-canonical origin still works.

The inner one used to be verified by a handful of inline josepy calls that
did none of that. Two consequences, both exercised here: a legitimate client
on a non-canonical origin had its key rotation refused, and a symmetric
``oct`` key with ``HS256`` — neither of which UCM accepts anywhere else —
was good enough to install as an account key.
"""
import base64 as b64
import json

import pytest

from models import db, SystemConfig
from models.acme_models import AcmeAccount

from tests.test_acme_security_paths import (  # noqa: F401
    _b64json,
    _build_jws,
    _gen_key_and_jwk,
    _nonce,
    _sign,
    _thumbprint,
    acme_account,
)

KC_PATH = '/acme/key-change'
LOCAL_URL = 'http://localhost/acme/key-change'


def _inner_jws(new_key, new_jwk, url, account_url, old_jwk, alg='RS256'):
    protected_b64 = _b64json({'alg': alg, 'jwk': new_jwk, 'url': url})
    payload_b64 = _b64json({'account': account_url, 'oldKey': old_jwk})
    return {
        'protected': protected_b64,
        'payload': payload_b64,
        'signature': _sign(new_key, protected_b64, payload_b64),
    }


def _post(client, outer):
    return client.post(KC_PATH, data=json.dumps(outer),
                       content_type='application/jose+json')


@pytest.fixture
def acme_vhost(app):
    """Canonical ACME origin that is not the origin the test client uses."""
    keys = ('acme_public_vhost', 'acme_public_port')
    with app.app_context():
        SystemConfig.query.filter(SystemConfig.key.in_(keys)).delete()
        db.session.add(SystemConfig(key='acme_public_vhost',
                                    value='acme.ucm.example.com'))
        db.session.add(SystemConfig(key='acme_public_port', value='443'))
        db.session.commit()
    yield 'https://acme.ucm.example.com/acme/key-change'
    with app.app_context():
        SystemConfig.query.filter(SystemConfig.key.in_(keys)).delete()
        db.session.commit()


class TestInnerJwsAcceptedOrigins:
    """The inner JWS accepts exactly what the outer one accepts."""

    def test_rotation_works_on_a_non_canonical_origin(self, app, client,
                                                      acme_account, acme_vhost):
        """Outer and inner both sign the origin the client actually reached.

        ``get_acme_expected_urls`` exists so a client that reaches UCM on the
        inbound origin keeps working across an ``acme_public_vhost`` change.
        The outer JWS honoured that list; the inner one compared against the
        canonical URL alone, so the rotation was refused halfway through.
        """
        old_key = acme_account['key']
        old_jwk = acme_account['jwk']
        acct_id = acme_account['account_id']
        new_key, new_jwk = _gen_key_and_jwk()
        account_url = f'http://localhost/acme/acct/{acct_id}'

        inner = _inner_jws(new_key, new_jwk, LOCAL_URL, account_url, old_jwk)
        outer = _build_jws(LOCAL_URL, inner, old_key,
                           kid=account_url, nonce=_nonce(client))

        r = _post(client, outer)
        assert r.status_code == 200, r.get_data(as_text=True)

        with app.app_context():
            acct = AcmeAccount.query.filter_by(account_id=acct_id).first()
            assert json.loads(acct.jwk) == new_jwk

    def test_inner_url_must_match_the_outer_url(self, app, client, acme_account,
                                                acme_vhost):
        """Mixing the two accepted origins across the two layers is refused.

        RFC 8555 §7.3.5: the inner ``url`` must match the outer ``url``. Both
        values below are individually acceptable, which is exactly why they
        have to be compared against each other and not against a list.
        """
        old_key = acme_account['key']
        old_jwk = acme_account['jwk']
        acct_id = acme_account['account_id']
        new_key, new_jwk = _gen_key_and_jwk()
        account_url = f'http://localhost/acme/acct/{acct_id}'

        inner = _inner_jws(new_key, new_jwk, acme_vhost, account_url, old_jwk)
        outer = _build_jws(LOCAL_URL, inner, old_key,
                           kid=account_url, nonce=_nonce(client))

        r = _post(client, outer)
        assert r.status_code == 400, r.get_data(as_text=True)
        assert 'url does not match outer' in r.get_data(as_text=True)

        with app.app_context():
            acct = AcmeAccount.query.filter_by(account_id=acct_id).first()
            assert json.loads(acct.jwk) == old_jwk


class TestInnerJwsAlgorithmAllowlist:
    """RFC 8555 §6.2 — the inner JWS is asymmetric-only, like the outer one."""

    def test_symmetric_oct_key_cannot_become_an_account_key(self, app, client,
                                                            acme_account):
        """An ``oct`` key signed with ``HS256`` must be refused.

        josepy verifies the MAC quite happily, so the inner signature check
        passed and the request walked on into the rotation. Nothing but the
        thumbprint helper's own key-type guard stopped it, several steps
        later, as an uncaught error — a 500 where RFC 8555 wants a
        ``malformed`` 400. The outer JWS has rejected MAC algorithms and
        non-RSA/EC keys all along; now so does the inner one, up front.
        """
        old_key = acme_account['key']
        old_jwk = acme_account['jwk']
        acct_id = acme_account['account_id']
        account_url = f'http://localhost/acme/acct/{acct_id}'

        secret = b64.urlsafe_b64encode(b'0123456789abcdef').rstrip(b'=').decode()
        oct_jwk = {'kty': 'oct', 'k': secret}

        import josepy as jose

        inner_protected_b64 = _b64json(
            {'alg': 'HS256', 'jwk': oct_jwk, 'url': LOCAL_URL})
        inner_payload_b64 = _b64json({'account': account_url, 'oldKey': old_jwk})
        signing_input = f'{inner_protected_b64}.{inner_payload_b64}'.encode('ascii')
        mac = jose.JWASignature.from_json('HS256').sign(
            jose.JWK.from_json(oct_jwk).key, signing_input)
        inner = {
            'protected': inner_protected_b64,
            'payload': inner_payload_b64,
            'signature': b64.urlsafe_b64encode(mac).rstrip(b'=').decode(),
        }

        outer = _build_jws(LOCAL_URL, inner, old_key,
                           kid=account_url, nonce=_nonce(client))
        r = _post(client, outer)
        assert r.status_code == 400, r.get_data(as_text=True)

        with app.app_context():
            acct = AcmeAccount.query.filter_by(account_id=acct_id).first()
            assert json.loads(acct.jwk) == old_jwk, (
                'a symmetric key was installed as the ACME account key')

    def test_rsa_pss_is_refused_like_on_the_outer_jws(self, app, client,
                                                      acme_account):
        """PS256 is deliberately outside UCM's allowlist.

        ``verify_jws`` only implements RSASSA-PKCS1-v1_5, and says so. The
        inner path handed the algorithm straight to josepy, which does
        implement PSS — so the two layers disagreed about what UCM supports.
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        old_key = acme_account['key']
        old_jwk = acme_account['jwk']
        acct_id = acme_account['account_id']
        new_key, new_jwk = _gen_key_and_jwk()
        account_url = f'http://localhost/acme/acct/{acct_id}'

        inner_protected_b64 = _b64json(
            {'alg': 'PS256', 'jwk': new_jwk, 'url': LOCAL_URL})
        inner_payload_b64 = _b64json({'account': account_url, 'oldKey': old_jwk})
        signing_input = f'{inner_protected_b64}.{inner_payload_b64}'.encode('ascii')
        sig = new_key.sign(
            signing_input,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
        inner = {
            'protected': inner_protected_b64,
            'payload': inner_payload_b64,
            'signature': b64.urlsafe_b64encode(sig).rstrip(b'=').decode(),
        }

        outer = _build_jws(LOCAL_URL, inner, old_key,
                           kid=account_url, nonce=_nonce(client))
        r = _post(client, outer)
        assert r.status_code == 400, r.get_data(as_text=True)
        assert 'not permitted' in r.get_data(as_text=True)

        with app.app_context():
            acct = AcmeAccount.query.filter_by(account_id=acct_id).first()
            assert json.loads(acct.jwk) == old_jwk


class TestInnerJwsStillWorks:
    """The ordinary rotation a real client performs is untouched."""

    def test_plain_rs256_rotation(self, app, client, acme_account):
        old_key = acme_account['key']
        old_jwk = acme_account['jwk']
        acct_id = acme_account['account_id']
        new_key, new_jwk = _gen_key_and_jwk()
        account_url = f'http://localhost/acme/acct/{acct_id}'

        inner = _inner_jws(new_key, new_jwk, LOCAL_URL, account_url, old_jwk)
        outer = _build_jws(LOCAL_URL, inner, old_key,
                           kid=account_url, nonce=_nonce(client))

        r = _post(client, outer)
        assert r.status_code == 200, r.get_data(as_text=True)
        with app.app_context():
            acct = AcmeAccount.query.filter_by(account_id=acct_id).first()
            assert json.loads(acct.jwk) == new_jwk
            assert acct.jwk_thumbprint == _thumbprint(new_jwk)

    def test_inner_signed_with_the_wrong_key_is_refused(self, app, client,
                                                        acme_account):
        old_key = acme_account['key']
        old_jwk = acme_account['jwk']
        acct_id = acme_account['account_id']
        new_key, new_jwk = _gen_key_and_jwk()
        other_key, _ = _gen_key_and_jwk()
        account_url = f'http://localhost/acme/acct/{acct_id}'

        # Announces new_jwk but signs with a third key.
        inner = _inner_jws(other_key, new_jwk, LOCAL_URL, account_url, old_jwk)
        outer = _build_jws(LOCAL_URL, inner, old_key,
                           kid=account_url, nonce=_nonce(client))

        r = _post(client, outer)
        assert r.status_code == 400, r.get_data(as_text=True)
        with app.app_context():
            acct = AcmeAccount.query.filter_by(account_id=acct_id).first()
            assert json.loads(acct.jwk) == old_jwk
