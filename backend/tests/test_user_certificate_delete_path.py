"""Deleting a user certificate deletes what the certificate owns.

The route removed the `Certificate` row with a bare `session.delete`: the
files stayed on disk, the approval requests, deploy bindings and ACME orders
kept pointing at a row that was gone, and the revocation records kept a
dangling foreign key that PostgreSQL refuses outright.

There is deliberately no revoke-first gate, unlike the certificate routes:
removing the enrolment is what withdraws the access.
"""
import json

import pytest

from models import db
from tests.test_user_certificate_key_export_guard import _enrolment_for


@pytest.fixture
def an_operator(app, create_user):
    create_user(username='op_delete_probe', role='operator')
    client = app.test_client()
    answer = client.post(
        '/api/v2/auth/login',
        data=json.dumps({'username': 'op_delete_probe',
                         'password': 'TestPass123!'}),
        content_type='application/json')
    assert answer.status_code == 200, answer.data
    return client


@pytest.fixture
def an_enrolment(app, create_user, create_cert):
    create_user(username='owner_delete_probe', role='viewer')
    enrolment_id, _owner = _enrolment_for(
        app, create_cert, 'owner_delete_probe', 'delete-path-probe')
    yield enrolment_id
    with app.app_context():
        from models.auth_certificate import AuthCertificate
        row = db.session.get(AuthCertificate, enrolment_id)
        if row:
            db.session.delete(row)
            db.session.commit()


def _certificate_id_of(app, enrolment_id):
    with app.app_context():
        from models.auth_certificate import AuthCertificate
        from services.mtls_enrollment import certificate_row_for
        row = db.session.get(AuthCertificate, enrolment_id)
        certificate = certificate_row_for(row)
        return certificate.id if certificate else None


class TestTheEnrolmentIsRemovedEitherWay:
    def test_a_valid_certificate_can_still_be_removed(
            self, app, an_operator, an_enrolment):
        answer = an_operator.delete(f'/api/v2/user-certificates/{an_enrolment}')
        assert answer.status_code in (200, 204), answer.data[:300]
        with app.app_context():
            from models.auth_certificate import AuthCertificate
            assert db.session.get(AuthCertificate, an_enrolment) is None


class TestTheCertificateGoesWithIt:
    def test_both_rows_are_deleted(self, app, an_operator, an_enrolment):
        certificate_id = _certificate_id_of(app, an_enrolment)
        assert certificate_id is not None

        answer = an_operator.delete(f'/api/v2/user-certificates/{an_enrolment}')
        assert answer.status_code in (200, 204), answer.data[:300]

        with app.app_context():
            from models import Certificate
            from models.auth_certificate import AuthCertificate
            assert db.session.get(AuthCertificate, an_enrolment) is None
            # The bare session.delete removed this row too; what it did not
            # do is everything CertificateService does around it.
            assert db.session.get(Certificate, certificate_id) is None

    def test_the_files_on_disk_go_with_it(self, app, an_operator, an_enrolment):
        certificate_id = _certificate_id_of(app, an_enrolment)

        with app.app_context():
            from models import Certificate
            from utils.file_naming import cert_cert_path, cert_key_path
            certificate = db.session.get(Certificate, certificate_id)
            paths = [cert_cert_path(certificate), cert_key_path(certificate)]
            written = [path for path in paths if path.exists()]

        an_operator.delete(f'/api/v2/user-certificates/{an_enrolment}')
        assert written, 'the fixture wrote no file, nothing to prove'
        assert [path for path in written if path.exists()] == []
