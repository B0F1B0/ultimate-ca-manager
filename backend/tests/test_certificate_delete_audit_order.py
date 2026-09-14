"""Deleting a certificate leaves the database and the disk agreeing.

The order was: detach the foreign keys other tables hold on this certificate,
delete its files, write the audit entry, then delete the row and commit.

Writing the audit entry commits the session it is given and rolls all of it
back when it cannot write its own. Called there, it undid the detachment that
had not been committed yet, **after** the files were already gone. The delete
that followed then hit the foreign keys it had just un-detached, so the row
survived with no certificate, no request and no key on disk.

The files are still removed before the commit, which is its own question; what
this pins is that an audit entry never decides the outcome.
"""
import pytest

from models import db


@pytest.fixture
def audit_always_fails(monkeypatch):
    from models.audit_log import AuditLog

    def failing_hash(self, *args, **kwargs):
        raise RuntimeError('audit hash chain unavailable')

    monkeypatch.setattr(AuditLog, 'compute_hash', failing_hash, raising=False)


class TestTheDetachmentSurvivesTheAudit:
    """Pinned on the detachment rather than on the final outcome.

    SQLite enforces no foreign key, so the delete goes through there whether
    or not the detachment was rolled back, and the damage only shows on
    PostgreSQL. What both backends share is the invariant: once the files are
    gone, the rows that pointed at the certificate must stay detached.
    """

    def test_a_failed_audit_does_not_put_the_references_back(
            self, app, auth_client, create_ca, create_cert,
            audit_always_fails):
        import secrets

        from models import Certificate
        from models.acme_models import AcmeAccount, AcmeOrder
        from services.cert_service import CertificateService

        ca = create_ca(cn='Delete Audit Order CA')
        cert = create_cert(cn='delete-audit-order.example.test',
                           ca_id=ca['id'])

        with app.app_context():
            account_id = f'delaudit-{secrets.token_hex(4)}'
            db.session.add(AcmeAccount(account_id=account_id, jwk='{}',
                                       jwk_thumbprint=secrets.token_hex(8),
                                       status='valid'))
            db.session.flush()
            order = AcmeOrder(order_id=secrets.token_urlsafe(16),
                              account_id=account_id,
                              identifiers='[{"type":"dns","value":"d.test"}]',
                              status='valid', certificate_id=cert['id'])
            db.session.add(order)
            db.session.commit()
            order_id = order.order_id

        try:
            with app.app_context():
                CertificateService.delete_certificate(cert['id'],
                                                      username='tester')
                db.session.expire_all()
                still_pointing = AcmeOrder.query.filter_by(
                    order_id=order_id).one().certificate_id

            assert still_pointing is None, (
                'an order still points at the certificate: the audit entry '
                'rolled the detachment back after the files were deleted, and '
                'a database that enforces its foreign keys then refuses the '
                'delete outright')
        finally:
            with app.app_context():
                AcmeOrder.query.filter_by(order_id=order_id).delete(
                    synchronize_session=False)
                AcmeAccount.query.filter_by(account_id=account_id).delete(
                    synchronize_session=False)
                row = db.session.get(Certificate, cert['id'])
                if row is not None:
                    db.session.delete(row)
                db.session.commit()
