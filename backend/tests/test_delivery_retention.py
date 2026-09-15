"""Delivery history stops growing for ever.

Nothing ever deleted a webhook delivery, a deployment delivery or a
notification log entry: no scheduled task, no retention rule, and not even
deleting the endpoint the rows belong to. Three months of ordinary use on one
instance left 14946 webhook rows carrying 47.8 MiB of payloads, about 61% of
that database, because the payload embeds the certificate it describes.

What is pinned here: finished rows past their window go, rows still in flight
never do whatever their age, the two windows are separate, and deleting an
endpoint takes its history with it.
"""
from datetime import timedelta

import pytest

from models import db
from models.webhook_delivery import WebhookDelivery
from services import settings_registry
from services.delivery_retention import (
    FAILED_DAYS_KEY,
    SUCCEEDED_DAYS_KEY,
    delete_endpoint_deliveries,
    purge_delivery_history,
)
from utils.datetime_utils import utc_now

ENDPOINT_ID = 987654


def _delivery(app, status, age_days, endpoint_id=ENDPOINT_ID):
    row = WebhookDelivery(
        endpoint_id=endpoint_id,
        event_type='certificate.issued',
        payload='{"certificate": {}}',
        event_timestamp=utc_now().isoformat(),
        status=status,
        created_at=utc_now() - timedelta(days=age_days),
        next_attempt_at=utc_now(),
    )
    db.session.add(row)
    db.session.commit()
    return row.id


@pytest.fixture()
def clean_slate(app):
    """Only this test's rows, before and after."""
    with app.app_context():
        WebhookDelivery.query.filter(
            WebhookDelivery.endpoint_id >= ENDPOINT_ID).delete(
                synchronize_session=False)
        db.session.commit()
    yield
    with app.app_context():
        WebhookDelivery.query.filter(
            WebhookDelivery.endpoint_id >= ENDPOINT_ID).delete(
                synchronize_session=False)
        db.session.commit()


def _ids(endpoint_id=ENDPOINT_ID):
    return {row.id for row in
            WebhookDelivery.query.filter_by(endpoint_id=endpoint_id).all()}


class TestWhatGoesAndWhatStays:
    def test_a_delivered_row_past_its_window_is_deleted(self, app, clean_slate):
        with app.app_context():
            old = _delivery(app, WebhookDelivery.STATUS_DELIVERED, 60)
            purge_delivery_history()
            assert old not in _ids()

    def test_a_delivered_row_inside_its_window_is_kept(self, app, clean_slate):
        with app.app_context():
            recent = _delivery(app, WebhookDelivery.STATUS_DELIVERED, 5)
            purge_delivery_history()
            assert recent in _ids()

    def test_a_failed_row_outlives_a_delivered_one(self, app, clean_slate):
        """60 days: past the delivered window (30), inside the failed one (90)."""
        with app.app_context():
            delivered = _delivery(app, WebhookDelivery.STATUS_DELIVERED, 60)
            failed = _delivery(app, WebhookDelivery.STATUS_FAILED, 60)
            purge_delivery_history()
            remaining = _ids()
            assert delivered not in remaining
            assert failed in remaining, (
                'the row an operator opens to see why nothing arrived was '
                'deleted on the delivered window')

    def test_a_failed_row_past_its_own_window_goes_too(self, app, clean_slate):
        with app.app_context():
            ancient = _delivery(app, WebhookDelivery.STATUS_FAILED, 200)
            purge_delivery_history()
            assert ancient not in _ids()

    def test_a_pending_row_is_never_deleted_whatever_its_age(
            self, app, clean_slate):
        """It is work, not history: the queue is what the sender reads."""
        with app.app_context():
            pending = _delivery(app, WebhookDelivery.STATUS_PENDING, 500)
            purge_delivery_history()
            assert pending in _ids(), 'a delivery still owed was purged'


class TestTheWindowsAreConfigurable:
    @pytest.fixture()
    def window(self, app):
        from models import SystemConfig

        def _set(key, value):
            with app.app_context():
                row = SystemConfig.query.filter_by(key=key).first()
                if row:
                    row.value = str(value)
                else:
                    db.session.add(SystemConfig(key=key, value=str(value)))
                db.session.commit()

        yield _set
        with app.app_context():
            for key in (SUCCEEDED_DAYS_KEY, FAILED_DAYS_KEY):
                row = SystemConfig.query.filter_by(key=key).first()
                if row:
                    db.session.delete(row)
            db.session.commit()

    def test_a_shorter_window_removes_more(self, app, clean_slate, window):
        window(SUCCEEDED_DAYS_KEY, 3)
        with app.app_context():
            row = _delivery(app, WebhookDelivery.STATUS_DELIVERED, 10)
            purge_delivery_history()
            assert row not in _ids()

    def test_zero_keeps_them_for_ever(self, app, clean_slate, window):
        """How one window is turned off without turning the task off."""
        window(SUCCEEDED_DAYS_KEY, 0)
        with app.app_context():
            row = _delivery(app, WebhookDelivery.STATUS_DELIVERED, 900)
            purge_delivery_history()
            assert row in _ids()

    def test_the_defaults_are_the_documented_ones(self, app):
        with app.app_context():
            assert settings_registry.default_for(SUCCEEDED_DAYS_KEY) == 30
            assert settings_registry.default_for(FAILED_DAYS_KEY) == 90


class TestDeletingAnEndpointTakesItsHistory:
    def test_the_rows_of_that_endpoint_go(self, app, clean_slate):
        with app.app_context():
            mine = _delivery(app, WebhookDelivery.STATUS_DELIVERED, 1)
            delete_endpoint_deliveries(ENDPOINT_ID)
            db.session.commit()
            assert mine not in _ids()

    def test_another_endpoint_is_untouched(self, app, clean_slate):
        with app.app_context():
            other = _delivery(app, WebhookDelivery.STATUS_DELIVERED, 1,
                              endpoint_id=ENDPOINT_ID + 1)
            delete_endpoint_deliveries(ENDPOINT_ID)
            db.session.commit()
            assert other in _ids(ENDPOINT_ID + 1)

    def test_the_route_deletes_them(self, app, auth_client):
        """End to end, through the route an operator actually uses."""
        created = auth_client.post('/api/v2/webhooks', json={
            'name': 'Retention Route Target',
            'url': 'https://hook.example.com/retention',
            'events': ['certificate.issued'],
        })
        assert created.status_code == 201, created.data[:200]
        endpoint_id = created.get_json()['data']['id']

        with app.app_context():
            row_id = _delivery(app, WebhookDelivery.STATUS_DELIVERED, 1,
                               endpoint_id=endpoint_id)

        assert auth_client.delete(
            f'/api/v2/webhooks/{endpoint_id}').status_code == 204
        with app.app_context():
            assert db.session.get(WebhookDelivery, row_id) is None, (
                'the endpoint is gone and its history is still there, '
                'pointing at an id that no longer names anything')


class TestTheOtherTwoTables:
    def test_all_three_are_covered(self):
        from services.delivery_retention import _traces

        assert {trace.label for trace in _traces()} == {
            'webhook_deliveries', 'deploy_deliveries', 'notification_log'}

    def test_each_one_knows_which_column_carries_its_date(self, app):
        from services.delivery_retention import _traces

        with app.app_context():
            for trace in _traces():
                assert hasattr(trace.model, trace.timestamp), (
                    f'{trace.label} has no {trace.timestamp} column')

    def test_a_notification_past_its_window_goes(self, app):
        from models.email_notification import NotificationLog

        with app.app_context():
            entry = NotificationLog(
                type='expiry', recipient='ops@example.com', status='sent',
                sent_at=utc_now() - timedelta(days=120))
            db.session.add(entry)
            db.session.commit()
            entry_id = entry.id

            purge_delivery_history()
            assert db.session.get(NotificationLog, entry_id) is None


class TestTheTaskIsRegistered:
    def test_the_scheduler_runs_it(self, app):
        """A purge nobody calls is the situation this replaces."""
        import app as app_module

        source = open(app_module.__file__).read()
        assert 'delivery_retention' in source
        assert 'name="delivery_retention"' in source
