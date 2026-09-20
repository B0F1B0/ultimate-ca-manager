"""Delivery history stops growing for ever.

Three tables record what was sent and how it went: webhook deliveries,
deployment deliveries and the notification log. Each row is written once and
was never deleted by anything: not by a scheduled task, not by a retention
rule, not even by deleting the endpoint the rows belong to. On one instance,
three months of ordinary use left 14946 webhook rows carrying 47.8 MiB of
payloads, about 61% of the whole database, because a webhook payload embeds
the certificate it describes.

The product already knows how to do this. Audit entries expire through
``RetentionPolicy``; local ACME orders expire through ``acme.order_purge``
(#303, written for the same sentence: "orders, authorizations and challenges
accumulated forever"). These three tables are what nobody came back to.

Two windows rather than one, because the two kinds of row are read for
different reasons: a delivered row is history and goes early, a failed one is
what an operator opens when asked why something never arrived, and is kept
longer. A row still in flight (pending, or waiting for a retry) is never
touched, whatever its age: it is work, not history.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import FrozenSet, List

from models import db
from utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)

# Rows deleted per statement, so one pass cannot turn into a single enormous
# transaction on an instance that has been accumulating for a year.
BATCH_LIMIT = 500

# And per run, so the first pass on a large backlog gives the database back
# rather than holding it for minutes. What is left goes at the next run.
MAX_ROWS_PER_RUN = 20_000

SUCCEEDED_DAYS_KEY = 'deliveries.retention.succeeded_days'
FAILED_DAYS_KEY = 'deliveries.retention.failed_days'


@dataclass(frozen=True)
class _Trace:
    """One table of delivery history, and what its rows mean."""

    label: str
    model: type
    timestamp: str
    succeeded: FrozenSet[str]
    failed: FrozenSet[str]


def _traces() -> List[_Trace]:
    """The three tables, imported here so importing this module is cheap."""
    from models.deploy import DeployDelivery
    from models.email_notification import NotificationLog
    from models.webhook_delivery import WebhookDelivery

    return [
        _Trace('webhook_deliveries', WebhookDelivery, 'created_at',
               frozenset({WebhookDelivery.STATUS_DELIVERED}),
               frozenset({WebhookDelivery.STATUS_FAILED})),
        _Trace('deploy_deliveries', DeployDelivery, 'created_at',
               frozenset({DeployDelivery.STATUS_DELIVERED}),
               frozenset({DeployDelivery.STATUS_FAILED})),
        # This one stamps `sent_at` and calls a success `sent`; `retry` is a
        # row still being attempted and is left alone with `pending`.
        _Trace('notification_log', NotificationLog, 'sent_at',
               frozenset({'sent'}), frozenset({'failed'})),
    ]


def retention_days() -> tuple:
    """``(succeeded_days, failed_days)`` as configured."""
    from services import settings_registry

    return (settings_registry.effective(SUCCEEDED_DAYS_KEY),
            settings_registry.effective(FAILED_DAYS_KEY))


def _delete_older_than(trace: _Trace, statuses: FrozenSet[str], days: int,
                       budget: int) -> int:
    """Delete up to *budget* rows of *statuses* older than *days*.

    ``days <= 0`` keeps them for ever, which is how an operator turns one of
    the two windows off without turning the task off.
    """
    if days <= 0 or budget <= 0 or not statuses:
        return 0
    cutoff = utc_now() - timedelta(days=days)
    column = getattr(trace.model, trace.timestamp)
    removed = 0
    while removed < budget:
        ids = [row.id for row in (
            trace.model.query
            .filter(trace.model.status.in_(statuses), column < cutoff)
            .order_by(trace.model.id)
            .limit(min(BATCH_LIMIT, budget - removed))
            .all())]
        if not ids:
            break
        removed += (trace.model.query
                    .filter(trace.model.id.in_(ids))
                    .delete(synchronize_session=False))
        db.session.commit()
    return removed


def purge_delivery_history(max_rows: int = MAX_ROWS_PER_RUN) -> dict:
    """Delete finished delivery rows past their window. Returns counters."""
    succeeded_days, failed_days = retention_days()
    stats = {}
    budget = max_rows
    for trace in _traces():
        removed = 0
        try:
            removed += _delete_older_than(
                trace, trace.succeeded, succeeded_days, budget - removed)
            removed += _delete_older_than(
                trace, trace.failed, failed_days, budget - removed)
        except Exception as exc:                   # noqa: BLE001
            db.session.rollback()
            logger.warning('delivery retention: %s left untouched: %s',
                           trace.label, exc)
        stats[trace.label] = removed
        budget -= removed
        if budget <= 0:
            break
    total = sum(stats.values())
    if total:
        logger.info('delivery retention: removed %d row(s) %s', total, stats)
    return stats


def delete_endpoint_deliveries(endpoint_id: int) -> int:
    """Every delivery row of a webhook endpoint, staged for the caller's commit.

    ``endpoint_id`` is a plain Integer with no foreign key, deliberately, so
    nothing cascades: deleting an endpoint used to leave its whole history
    behind, pointing at an id that no longer names anything.
    """
    from models.webhook_delivery import WebhookDelivery

    return (WebhookDelivery.query
            .filter_by(endpoint_id=endpoint_id)
            .delete(synchronize_session=False))


def delete_binding_deliveries(binding_id: int, binding_type: str = 'certificate') -> int:
    """The same for a deployment binding."""
    from models.deploy import DeployDelivery

    return (DeployDelivery.query
            .filter_by(binding_id=binding_id, binding_type=binding_type)
            .delete(synchronize_session=False))


def scheduled_purge():
    """Scheduler entry point."""
    return purge_delivery_history()
