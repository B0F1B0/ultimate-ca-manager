"""
CA CRUD operations
"""
import logging
from typing import List, Optional

from models import CA, Certificate, db
from services.audit_service import AuditService
from .helpers import delete_ca_files

logger = logging.getLogger(__name__)


class CAcrudMixin:
    """CA Create, Read, Update, Delete operations"""

    @staticmethod
    def get_ca(ca_id: int) -> Optional[CA]:
        """Get CA by ID"""
        return db.session.get(CA, ca_id)

    @staticmethod
    def get_ca_by_refid(refid: str) -> Optional[CA]:
        """Get CA by refid"""
        return CA.query.filter_by(refid=refid).first()

    @staticmethod
    def list_cas() -> List[CA]:
        """List all CAs, ordered by creation date descending"""
        return CA.query.order_by(CA.created_at.desc()).all()

    @staticmethod
    def delete_ca(ca_id: int, username: str = 'system') -> bool:
        """
        Delete a CA and its associated files.

        Args:
            ca_id: CA ID
            username: User deleting

        Returns:
            True if deleted, False if not found

        Raises:
            ValueError: If CA is used by certificates or is parent of other CAs
        """
        ca = db.session.get(CA, ca_id)
        if not ca:
            return False

        # Check if CA is used by certificates
        cert_count = Certificate.query.filter_by(caref=ca.refid).count()
        if cert_count > 0:
            raise ValueError(f"CA is used by {cert_count} certificate(s)")

        # Check if CA is parent of other CAs
        child_ca_count = CA.query.filter_by(caref=ca.refid).count()
        if child_ca_count > 0:
            raise ValueError(f"CA is parent of {child_ca_count} intermediate CA(s)")

        # Snapshot for the webhook payload before the row is gone
        _ca_snapshot = ca.to_dict()
        # And for the audit entry, which is written once the row actually is
        # gone: by then the instance raises on every attribute read.
        _ca_id, _ca_descr = ca.id, ca.descr

        # Delete files
        delete_ca_files(ca)

        # Delete from database
        db.session.delete(ca)
        try:
            db.session.commit()
        except Exception as _commit_err:
            db.session.rollback()
            logger.error(f"Commit failed in services/ca/ca_crud.py:69: {_commit_err}", exc_info=True)
            raise

        # Audit after the delete has committed, not before it. `log_action`
        # commits the session it is given, so an entry written first said the
        # authority had been deleted and was durable while the deletion still
        # was not. Anything failing after it -- and the files on disk are
        # already unlinked by then -- left the trail asserting a deletion the
        # database contradicts, in the one place left that could say what
        # happened. Same fields `log_ca` would have built, read from the
        # object while it still answered.
        AuditService.log_action(
            action='ca_deleted',
            resource_type='ca',
            resource_id=_ca_id,
            resource_name=_ca_descr,
            details=f'Deleted CA: {_ca_descr}',
        )

        from services.webhook_service import emit_ca_deleted
        emit_ca_deleted(_ca_snapshot, actor=username)

        return True
