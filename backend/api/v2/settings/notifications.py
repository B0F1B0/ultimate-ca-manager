"""
Settings - Notification settings + audit logs routes
"""

from flask import request
from auth.unified import require_auth
from utils.pagination import parse_request_pagination
from utils.response import success_response, error_response
from models import db
from services.audit_service import AuditService
from utils.datetime_utils import utc_isoformat
import json
import logging

from . import bp

logger = logging.getLogger(__name__)


# ============================================================================
# Notification Settings
# ============================================================================

@bp.route('/api/v2/settings/notifications', methods=['GET'])
@require_auth(['read:settings'])
def get_notification_settings():
    """Get notification configurations"""
    from models.email_notification import NotificationConfig

    configs = NotificationConfig.query.all()
    return success_response(data={
        'configs': [{
            'id': c.id,
            'notification_type': c.type,  # Model uses 'type'
            'enabled': c.enabled,
            'recipients': json.loads(c.recipients) if c.recipients else [],
            'threshold_days': c.days_before,  # Model uses 'days_before'
            'alert_days': c.get_alert_days() if c.type == 'cert_expiring' else None,
            'cooldown_hours': c.cooldown_hours,
            'description': c.description
        } for c in configs]
    })


@bp.route('/api/v2/settings/notifications', methods=['PATCH'])
@require_auth(['write:settings'])
def update_notification_settings():
    """Update notification configuration"""
    from models.email_notification import NotificationConfig

    data = request.json
    if not data:
        return error_response('No data provided', 400)

    config_id = data.get('id')
    if config_id:
        config = db.session.get(NotificationConfig, config_id)
        if not config:
            return error_response('Configuration not found', 404)
    else:
        notification_type = data.get('notification_type')
        if not notification_type:
            return error_response('notification_type required', 400)
        config = NotificationConfig.query.filter_by(type=notification_type).first()  # Model uses 'type'
        if not config:
            config = NotificationConfig(type=notification_type)
            db.session.add(config)

    # Update fields
    if 'enabled' in data:
        config.enabled = bool(data['enabled'])
    if 'recipients' in data:
        # Store as JSON string
        recipients = data['recipients']
        config.recipients = json.dumps(recipients) if isinstance(recipients, list) else recipients
    if 'threshold_days' in data:
        threshold_days = data['threshold_days']
        # Same rule as the expiry endpoint: a real integer (not a bool),
        # 1..3650; larger values overflow the scheduler's date arithmetic.
        if isinstance(threshold_days, bool) or not isinstance(threshold_days, int):
            return error_response('threshold_days must be an integer', 400)
        if threshold_days < 1 or threshold_days > NotificationConfig.MAX_ALERT_DAYS:
            return error_response(
                f'threshold_days must be between 1 and {NotificationConfig.MAX_ALERT_DAYS}', 400)
        if config.type == 'cert_expiring':
            # The expiry job reads the alert_days list (#323); a single
            # threshold set here replaces it so both endpoints stay in sync.
            config.set_alert_days([threshold_days])
        else:
            config.days_before = threshold_days  # Model uses 'days_before'
    if 'cooldown_hours' in data:
        cooldown_hours = data['cooldown_hours']
        if isinstance(cooldown_hours, bool) or not isinstance(cooldown_hours, int) \
                or cooldown_hours < 0 or cooldown_hours > 8760:
            return error_response('cooldown_hours must be an integer between 0 and 8760', 400)
        config.cooldown_hours = cooldown_hours

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update notification settings: {e}")
        return error_response('Failed to update notification settings', 500)

    AuditService.log_action(
        action='settings_update',
        resource_type='settings',
        resource_name='Notification Settings',
        details='Updated notification settings',
        success=True
    )

    return success_response(
        data={'id': config.id},
        message='Notification settings updated'
    )


@bp.route('/api/v2/settings/notifications/logs', methods=['GET'])
@require_auth(['read:settings'])
def get_notification_logs():
    """Get notification logs"""
    from models.email_notification import NotificationLog

    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)
    notification_type = request.args.get('type')

    query = NotificationLog.query.order_by(NotificationLog.sent_at.desc())

    if notification_type:
        query = query.filter_by(type=notification_type)  # Model uses 'type'

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return success_response(data={
        'logs': [{
            'id': log.id,
            'notification_type': log.type,  # Model uses 'type'
            'recipient': log.recipient,
            'subject': log.subject,
            'sent_at': utc_isoformat(log.sent_at),
            'status': log.status,  # Model uses 'status' not 'success'
            'error_message': log.error_message,
            'retry_count': log.retry_count
        } for log in pagination.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': pagination.total,
            'pages': pagination.pages
        }
    })


# ============================================================================
# Audit Logs
# ============================================================================

@bp.route('/api/v2/settings/audit-logs', methods=['GET'])
@require_auth(['admin:system'])
def get_audit_logs():
    """Get system audit logs"""
    from models import AuditLog
    from datetime import datetime

    # Through the shared helper: asked for a million rows, this route loaded
    # the whole audit table into memory and serialised it. The page size stays
    # fifty here -- a log line is not a certificate -- only the ceiling is
    # common.
    page, per_page = parse_request_pagination(default_per_page=50)
    user_id = request.args.get('user_id', type=int)
    action = request.args.get('action')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = AuditLog.query

    if user_id:
        query = query.filter_by(user_id=user_id)
    if action:
        query = query.filter_by(action=action)
    if start_date:
        try:
            start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            query = query.filter(AuditLog.timestamp >= start)
        except ValueError:
            pass
    if end_date:
        try:
            end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            query = query.filter(AuditLog.timestamp <= end)
        except ValueError:
            pass

    query = query.order_by(AuditLog.timestamp.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return success_response(
        data=[log.to_dict() for log in pagination.items],
        meta={'total': pagination.total, 'page': page, 'per_page': per_page}
    )
