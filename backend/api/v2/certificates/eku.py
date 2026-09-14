"""
Certificate vocabularies, served from the modules that define them.

/api/v2/eku/known and /api/v2/revocation-reasons. Both lists existed in the
backend, in the UI and in the API description, and the description had
drifted on each; publishing them is what stops a fourth copy appearing.
"""

from flask import request
from auth.unified import require_auth
from utils.response import success_response
from utils.eku_validation import EKU_NAMES
from utils.revocation_reasons import REVOCATION_REASONS
from . import bp


@bp.route('/api/v2/eku/known', methods=['GET'])
@require_auth(['read:certificates'])
def list_known_ekus():
    """Return the catalog of well-known Extended Key Usage OIDs.

    Used by the frontend to populate the EKU dropdown when issuing
    certificates or signing CSRs (RFC 5280 §4.2.1.12).
    """
    return success_response(data={
        'ekus': [
            {'oid': oid, 'name': name}
            for oid, name in EKU_NAMES.items()
        ]
    })


@bp.route('/api/v2/revocation-reasons', methods=['GET'])
@require_auth(['read:certificates'])
def list_revocation_reasons():
    """The CRLReason names the revocation APIs accept (RFC 5280 §5.3.1).

    The API description carried six of them, with `caCompromise` misspelled
    and `certificateHold` missing, so a client generated from it could not
    place a certificate on hold at all.

    `removeFromCRL` is deliberately absent: it is written by the unhold path
    only, never by a revocation request (see utils/revocation_reasons).
    """
    return success_response(data={'reasons': list(REVOCATION_REASONS)})
