"""
CAs Bulk Operations
"""

from . import bp
from flask import request, g, Response
import base64
import subprocess
import tempfile
import os
import logging

from auth.unified import require_auth
from utils.response import success_response, error_response
from services.audit_service import AuditService
from services.ca_service import CAService
from services.deletion_blockers import (
    MAX_BULK_IDS, ca_deletion_blockers, first_blocker, parse_bulk_ids,
)
from models import CA, db
from utils.cert_status import holds_certificate

logger = logging.getLogger(__name__)

# Cap bulk operations to keep latency bounded and prevent DoS via huge id lists.
_MAX_BULK_IDS = MAX_BULK_IDS


@bp.route('/api/v2/cas/bulk/delete', methods=['POST'])
@require_auth(['delete:cas'])
def bulk_delete_cas():
    """Bulk delete CAs"""

    ids, err = parse_bulk_ids(request.get_json())
    if err:
        return err
    username = g.current_user.username if hasattr(g, 'current_user') else 'system'
    results = {'success': [], 'failed': []}

    for ca_id in ids:
        try:
            ca = db.session.get(CA, ca_id)
            if not ca:
                results['failed'].append({'id': ca_id, 'error': 'Not found'})
                continue

            blocker = first_blocker(ca_deletion_blockers(ca))
            if blocker:
                results['failed'].append({'id': ca_id, 'error': blocker.brief})
                continue

            # Through the service, like the unit route: the files on disk and
            # the dependent rows go with the authority instead of being
            # orphaned, and the deletion is audited per CA.
            CAService.delete_ca(ca_id=ca_id, username=username)
            results['success'].append(ca_id)
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to delete CA {ca_id}: {e}")
            results['failed'].append({'id': ca_id, 'error': 'Deletion failed'})

    AuditService.log_action(
        action='cas_bulk_deleted',
        resource_type='ca',
        resource_id=','.join(str(i) for i in results['success']),
        resource_name=f"{len(results['success'])} CAs",
        details=f'Bulk deleted {len(results["success"])} CAs',
        success=True
    )

    return success_response(data=results, message=f"{len(results['success'])} CAs deleted")


@bp.route('/api/v2/cas/bulk/export', methods=['POST'])
@require_auth(['read:cas'])
def bulk_export_cas():
    """Export selected CAs"""

    data = request.get_json()
    if not data or not data.get('ids'):
        return error_response('ids array required', 400)

    ids = data['ids']
    if not isinstance(ids, list):
        return error_response('ids must be an array', 400)
    if len(ids) > _MAX_BULK_IDS:
        return error_response(f'Too many ids (max {_MAX_BULK_IDS} per request)', 400)

    export_format = data.get('format', 'pem').lower()
    # A CA awaiting its external certificate holds the empty sentinel,
    # which is not a certificate to export (#298)
    cas = CA.query.filter(CA.id.in_(ids), holds_certificate(CA)).all()

    if not cas:
        return error_response('No CAs found', 404)

    try:
        if export_format == 'pem':
            pem_data = b''
            for ca in cas:
                if not ca.crt:
                    continue  # pending external-CSR CA — nothing to export
                pem_data += base64.b64decode(ca.crt)
                if not pem_data.endswith(b'\n'):
                    pem_data += b'\n'
            return Response(pem_data, mimetype='application/x-pem-file',
                headers={'Content-Disposition': 'attachment; filename="ca-certificates.pem"'})
        elif export_format in ('pkcs7', 'p7b'):
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
                for ca in cas:
                    if not ca.crt:
                        continue  # pending external-CSR CA — nothing to export
                    f.write(base64.b64decode(ca.crt))
                    f.write(b'\n')
                pem_file = f.name
            try:
                p7b_output = subprocess.check_output(
                    ['openssl', 'crl2pkcs7', '-nocrl', '-certfile', pem_file, '-outform', 'DER'],
                    stderr=subprocess.DEVNULL, timeout=30)
                return Response(p7b_output, mimetype='application/x-pkcs7-certificates',
                    headers={'Content-Disposition': 'attachment; filename="ca-certificates.p7b"'})
            finally:
                os.unlink(pem_file)
        else:
            return error_response('Supported formats: pem, p7b', 400)
    except Exception as e:
        logger.error(f"Export failed: {e}")
        return error_response('Export failed', 500)
