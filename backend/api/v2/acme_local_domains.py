"""
ACME Local Domains API Routes
Manages domain-to-CA mappings for the Local ACME server.
"""
import re
import logging
from flask import Blueprint, request, g
from auth.unified import require_auth
from utils.response import success_response, error_response
from utils.db_transaction import safe_commit
from models import db, AcmeLocalDomain, CA
from services.acme import domain_match
from services.audit_service import AuditService

logger = logging.getLogger(__name__)

bp = Blueprint('acme_local_domains', __name__)


@bp.route('/api/v2/acme/local-domains', methods=['GET'])
@require_auth(['read:acme'])
def list_local_domains():
    """List all local ACME domain mappings"""
    domains = AcmeLocalDomain.query.order_by(AcmeLocalDomain.domain).all()
    return success_response(data=[d.to_dict() for d in domains])


@bp.route('/api/v2/acme/local-domains/<int:domain_id>', methods=['GET'])
@require_auth(['read:acme'])
def get_local_domain(domain_id):
    """Get a specific local domain"""
    domain = db.get_or_404(AcmeLocalDomain, domain_id)
    return success_response(data=domain.to_dict())


@bp.route('/api/v2/acme/local-domains', methods=['POST'])
@require_auth(['write:acme'])
def create_local_domain():
    """Create a new local domain mapping"""
    data = request.json
    if not data:
        return error_response('Request body required', 400)
    
    domain_name = data.get('domain', '').strip().lower()
    if not domain_name:
        return error_response('Domain is required', 400)
    
    if not _is_valid_domain(domain_name):
        return error_response('Invalid domain format', 400)
    
    issuing_ca_id = data.get('issuing_ca_id')
    if not issuing_ca_id:
        return error_response('Issuing CA is required', 400)
    
    ca = db.session.get(CA, issuing_ca_id)
    if not ca:
        return error_response('Issuing CA not found', 404)
    if not ca.has_private_key:
        return error_response('Selected CA has no private key', 400)
    if not ca.crt:
        return error_response('Selected CA is awaiting its certificate', 400)
    
    # `custom` and `*.custom` name the same zone, so they cannot be two
    # entries: the second would never be reached and the operator could not
    # tell which one was in force.
    bare = domain_match.normalize(domain_name)
    existing = AcmeLocalDomain.query.filter(
        AcmeLocalDomain.domain.in_([bare, f'*.{bare}'])).first()
    if existing:
        return error_response(
            f'Domain {existing.domain} is already registered', 409)
    
    domain = AcmeLocalDomain(
        domain=domain_name,
        issuing_ca_id=issuing_ca_id,
        auto_approve=data.get('auto_approve', False),
        created_by=g.user.username if hasattr(g, 'user') and g.user else None
    )
    
    db.session.add(domain)
    ok, _err = safe_commit(logger, "Failed to create local ACME domain")
    if not ok:
        return _err
    
    AuditService.log_action(
        action='acme_local_domain_create',
        resource_type='acme_local_domain',
        resource_id=str(domain.id),
        resource_name=domain_name,
        details=f'Registered local ACME domain: {domain_name} -> CA {ca.common_name}',
        success=True
    )
    
    return success_response(
        data=domain.to_dict(),
        message=f'Domain {domain_name} registered successfully',
        status=201
    )


@bp.route('/api/v2/acme/local-domains/<int:domain_id>', methods=['PUT'])
@require_auth(['write:acme'])
def update_local_domain(domain_id):
    """Update a local domain mapping"""
    domain = db.get_or_404(AcmeLocalDomain, domain_id)
    data = request.json
    
    if not data:
        return error_response('Request body required', 400)
    
    if 'issuing_ca_id' in data:
        ca = db.session.get(CA, data['issuing_ca_id'])
        if not ca:
            return error_response('Issuing CA not found', 404)
        if not ca.has_private_key:
            return error_response('Selected CA has no private key', 400)
        if not ca.crt:
            return error_response('Selected CA is awaiting its certificate', 400)
        domain.issuing_ca_id = data['issuing_ca_id']
    
    if 'auto_approve' in data:
        domain.auto_approve = bool(data['auto_approve'])
    
    ok, _err = safe_commit(logger, "Failed to update local ACME domain")
    if not ok:
        return _err
    
    AuditService.log_action(
        action='acme_local_domain_update',
        resource_type='acme_local_domain',
        resource_id=str(domain_id),
        resource_name=domain.domain,
        details=f'Updated local ACME domain: {domain.domain}',
        success=True
    )
    
    return success_response(
        data=domain.to_dict(),
        message='Domain updated successfully'
    )


@bp.route('/api/v2/acme/local-domains/<int:domain_id>', methods=['DELETE'])
@require_auth(['delete:acme'])
def delete_local_domain(domain_id):
    """Delete a local domain mapping"""
    domain = db.get_or_404(AcmeLocalDomain, domain_id)
    domain_name = domain.domain
    
    db.session.delete(domain)
    ok, _err = safe_commit(logger, "Failed to delete local ACME domain")
    if not ok:
        return _err
    
    AuditService.log_action(
        action='acme_local_domain_delete',
        resource_type='acme_local_domain',
        resource_id=str(domain_id),
        resource_name=domain_name,
        details=f'Removed local ACME domain: {domain_name}',
        success=True
    )
    
    return success_response(message=f'Domain {domain_name} removed')


def find_local_domain_ca(domain: str) -> int | None:
    """Find which CA should sign for a local ACME domain.

    Hierarchical matching, most specific first, and either spelling of each
    level: an entry registered as ``*.custom`` used to match nothing at all,
    so its orders went to the default CA (#352).

    Returns issuing_ca_id or None.
    """
    local = domain_match.find(AcmeLocalDomain, domain)
    return local.issuing_ca_id if local else None


def _is_valid_domain(domain: str) -> bool:
    """Validate domain format.

    Accepts standard domains, subdomains and wildcards, plus bare TLDs
    (e.g. "local", "internal") so admins can register a whole private TLD
    and let find_local_domain_ca's parent-walking cover every subdomain.

    Accepted: local, *.local, example.com, *.example.com, foo.example.com
    Rejected: *, ..com, com., single-char or numeric-only TLDs
    """
    pattern = r'^(\*\.)?(([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+)?[a-zA-Z]{2,}\Z'
    return bool(re.match(pattern, domain))
