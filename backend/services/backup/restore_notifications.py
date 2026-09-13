"""Notification-related restore methods mixin for BackupService.

Both sections are applied through `apply_columns`, from the manifest the
export was written from. What the hand-written assignments did to the SMTP
configuration is the clearest case in the whole restore:

* `smtp._smtp_password = ...` wrote to the column the `smtp_password`
  property encrypts into, so the mail password came back readable in the
  database;
* `smtp_oauth_client_secret` and `smtp_oauth_refresh_token` were on no list at
  all, so an installation authenticating to its mail server with OAuth2 was
  restored with nothing to authenticate with, and only found out the next time
  a notification failed to leave.

`plan` is what turns a reference into the row it names *here*. Neither section
declares one, so an empty plan answers everything `apply_columns` asks; the
parameter is there so the restore can hand its own down the day one does.
"""
import logging
from typing import Dict, Optional

from models import db

from .restore import RestorePlan
from .restore.apply import apply_columns

logger = logging.getLogger(__name__)


class RestoreNotificationsMixin:
    def _restore_smtp_config(self, backup_data: Dict, results: Dict,
                             plan: Optional[RestorePlan] = None) -> None:
        """Restore SMTP configuration from backup data.

        The secrets go back through the model's properties, which re-encrypt
        them with this installation's key.
        """
        from models.email_notification import SMTPConfig
        plan = plan if plan is not None else RestorePlan()
        for smtp_data in backup_data.get('smtp_config', []):
            # A single row by design: the archive names it by id, which means
            # nothing here, so the one row this installation holds is the one
            # the archive describes.
            smtp = SMTPConfig.query.first()
            if smtp is None:
                smtp = SMTPConfig()
                db.session.add(smtp)
            apply_columns(smtp, 'smtp_config', smtp_data, plan)
            results['smtp_config'] += 1

    def _restore_notification_config(self, backup_data: Dict, results: Dict,
                                     plan: Optional[RestorePlan] = None) -> None:
        """Restore notification configuration from backup data.

        Matched on `type`, which is what identifies a rule across two
        installations; the archive's id is the source's own and is skipped.
        """
        from models.email_notification import NotificationConfig
        plan = plan if plan is not None else RestorePlan()
        for nc_data in backup_data.get('notification_config', []):
            config = NotificationConfig.query.filter_by(
                type=nc_data['type']).first()
            if config is None:
                config = NotificationConfig(type=nc_data['type'])   # NOT NULL
                db.session.add(config)
            apply_columns(config, 'notification_config', nc_data, plan)
            results['notification_config'] += 1
