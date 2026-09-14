"""An offline CA does not get its CRL regenerated locally.

Its CRL is signed next to the key and uploaded (#302). The CDP route used to
call the generator on any CA holding a key, offline included.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from tests.conftest import assert_success, get_json
from tests.test_external_crl import (
    _build_crl, _import_root_cert_only, _make_offline_root, _upload_pem,
)


@pytest.fixture()
def offline_ca_with_key(app, auth_client):
    """A CA flagged offline whose private key is still readable in the row.

    The supported offline flows encrypt the key under a passphrase or wipe it,
    so the generator fails on the key rather than on the flag. Pinning the
    flag alone keeps the guard honest if either flow ever leaves a usable key.
    """
    root_key, root_cert = _make_offline_root('Offline CDP Root')
    ca = _import_root_cert_only(auth_client, root_cert, name='Offline CDP CA')

    with app.app_context():
        from models import CA, db
        from utils.key_codec import store_pem_bytes
        row = db.session.get(CA, ca['id'])
        row.prv = store_pem_bytes(root_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        row.offline = True
        row.offline_mode = 'password_protected'
        row.cdp_enabled = True
        db.session.commit()
        assert row.has_private_key is True

    yield root_key, root_cert, ca

    with app.app_context():
        from models import CA, db
        from models.crl import CRLMetadata
        CRLMetadata.query.filter_by(ca_id=ca['id']).delete()
        row = db.session.get(CA, ca['id'])
        if row:
            db.session.delete(row)
        db.session.commit()


def _stale_external_crl(auth_client, ca_id, root_key, root_cert, serial):
    """Upload a CRL that is already past nextUpdate, listing `serial`."""
    past = datetime.now(timezone.utc) - timedelta(days=30)
    pem = _build_crl(root_key, root_cert, entries=[(serial, past, None)],
                     number=7, days_valid=1, this_update=past)
    assert_success(_upload_pem(auth_client, ca_id, pem))


class TestOfflineCaCdp:
    def test_stale_external_crl_survives_cdp_requests(
            self, app, auth_client, client, offline_ca_with_key):
        root_key, root_cert, ca = offline_ca_with_key
        _stale_external_crl(auth_client, ca['id'], root_key, root_cert, 0xBEEF)

        for _ in range(3):
            r = client.get(f"/cdp/{ca['refid']}.crl")
            assert r.status_code == 200, r.data[:200]
            served = x509.load_der_x509_crl(r.data, default_backend())
            assert served.get_revoked_certificate_by_serial_number(0xBEEF) is not None

        with app.app_context():
            from models.crl import CRLMetadata
            rows = CRLMetadata.query.filter_by(ca_id=ca['id']).all()
            assert len(rows) == 1
            assert rows[0].is_external is True

    def test_generator_refuses_offline_ca(self, app, offline_ca_with_key):
        from services.crl_service import CRLService
        _root_key, _root_cert, ca = offline_ca_with_key
        with app.app_context():
            with pytest.raises(ValueError, match='offline'):
                CRLService.generate_crl(ca['id'])

    def test_delta_generator_refuses_offline_ca(self, app, offline_ca_with_key):
        from services.crl_service import CRLService
        _root_key, _root_cert, ca = offline_ca_with_key
        with app.app_context():
            from models import CA, db
            row = db.session.get(CA, ca['id'])
            row.delta_crl_enabled = True
            db.session.commit()
            with pytest.raises(ValueError, match='offline'):
                CRLService.generate_delta_crl(ca['id'])

    def test_api_regenerate_still_refuses(self, auth_client, offline_ca_with_key):
        _root_key, _root_cert, ca = offline_ca_with_key
        r = auth_client.post(f"/api/v2/crl/{ca['id']}/regenerate")
        assert r.status_code == 400
        assert 'offline' in get_json(r)['message'].lower()
