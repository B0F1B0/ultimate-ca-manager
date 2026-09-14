"""What the administration route writes into the file gunicorn reads.

Applying a managed certificate to HTTPS exists twice: the route under
`/api/v2/system/https/apply`, and `services/https_binding.materialize_https_cert`,
which the renewal subscriber calls. The second decrypts the stored private key
through `load_pem_bytes`; the first only base64-decoded it.

On an installation with a key-encryption key, the column holds
`base64("ENC:" + token)`, so decoding it yields `ENC:gAAAAA…` and that is what
went into `https_key.pem`, in 0600, over a backup of the working one, followed
by a restart. The answer was 200 and the service did not come back.
"""
import base64

import pytest

from models import db


@pytest.fixture
def https_paths(tmp_path, monkeypatch):
    cert_path = tmp_path / 'https_cert.pem'
    key_path = tmp_path / 'https_key.pem'
    monkeypatch.setenv('HTTPS_CERT_PATH', str(cert_path))
    monkeypatch.setenv('HTTPS_KEY_PATH', str(key_path))
    return cert_path, key_path


@pytest.fixture
def no_restart(monkeypatch):
    """The route asks for a restart; the test is about what it wrote first."""
    import api.v2.system.https as route

    monkeypatch.setattr(route, 'restart_service', lambda *a, **k: True,
                        raising=False)


@pytest.fixture
def encrypted_certificate(app):
    """A certificate whose stored key is written the way the product writes
    it: `store_pem_bytes`, which is base64 then the key-encryption layer, so
    the column holds `base64("ENC:" + token)`. Its reader is `load_pem_bytes`,
    and pairing anything else with it is how this defect looks from the
    inside."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from security.encryption import key_encryption
    from utils.key_codec import store_pem_bytes
    from models import CA, Certificate
    from utils.datetime_utils import utc_now
    from datetime import timedelta

    with app.app_context():
        if not key_encryption.is_enabled:
            pytest.skip('at-rest key encryption is off on this installation')

        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())

        authority = CA.query.first()
        cert = Certificate(
            refid='https-apply-material', descr='https apply material',
            caref=authority.refid if authority else None,
            crt=base64.b64encode(b'-----BEGIN CERTIFICATE-----\nx\n'
                                 b'-----END CERTIFICATE-----\n').decode(),
            prv=store_pem_bytes(pem),
            subject_cn='https-apply.example.test',
            valid_from=utc_now(), valid_to=utc_now() + timedelta(days=30))
        db.session.add(cert)
        db.session.commit()
        yield cert.id, pem

        db.session.delete(db.session.get(Certificate, cert.id))
        db.session.commit()


class TestTheKeyOnDiskIsAKey:
    def test_the_route_writes_the_decrypted_key(
            self, app, auth_client, https_paths, no_restart,
            encrypted_certificate):
        cert_path, key_path = https_paths
        cert_id, pem = encrypted_certificate

        with app.app_context():
            from models import Certificate
            stored = db.session.get(Certificate, cert_id).prv
            assert not stored.startswith('-----BEGIN'), (
                'the fixture must store the key the way the product does')

        response = auth_client.post('/api/v2/system/https/apply',
                                    json={'cert_id': cert_id})
        assert response.status_code == 200, response.data

        written = key_path.read_text()
        assert not written.startswith('ENC:'), (
            'the ciphertext was written into the file gunicorn reads as the '
            'private key: HTTPS cannot come back up')
        assert written.strip() == pem.decode().strip(), (
            'the file does not hold the key of the certificate that was applied')
