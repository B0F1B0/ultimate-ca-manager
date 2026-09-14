"""Every producer of "days left" answers the same number.

`utils/days_remaining` settled the rule: time left rounds up, time past rounds
down, and a row with no date answers None. Four places still computed their
own, three of them with `timedelta.days`, which floors. The visible cost was
at the boundary: a certificate expiring in twelve hours read 1 on the list and
0 in the expiry pass, where `d > 0` gates the webhook, so the last day before
expiry emitted nothing at all.
"""
from datetime import timedelta

import pytest

from utils.datetime_utils import utc_now
from utils.days_remaining import days_remaining


@pytest.fixture()
def twelve_hours_left():
    now = utc_now()
    return now, now + timedelta(hours=12)


class TestTheHelperIsTheRule:
    def test_time_left_rounds_up(self, twelve_hours_left):
        now, valid_to = twelve_hours_left
        assert days_remaining(valid_to, now) == 1

    def test_time_past_rounds_down(self):
        now = utc_now()
        assert days_remaining(now - timedelta(hours=12), now) == -1

    def test_no_date_has_no_answer(self):
        assert days_remaining(None) is None


class TestTheProducersAgree:
    def test_the_expiry_pass_sees_the_last_day(self, app, create_cert):
        """`d > 0` gates the expiring webhook; a floor made it 0."""
        from models import Certificate, db
        from services.expiry_alert_service import get_expiring_certificates

        cert = create_cert(cn='last-day-probe.example')
        with app.app_context():
            row = db.session.get(Certificate, cert['id'])
            row.valid_to = utc_now() + timedelta(hours=12)
            db.session.commit()

            listed = [c for c in get_expiring_certificates(days=30)
                      if c['id'] == cert['id']]
            assert listed, 'the certificate should be listed as expiring'
            assert listed[0]['days_until_expiry'] == 1

    def test_the_notification_scheduler_uses_the_helper(self):
        import inspect
        from services.notification import scheduler
        source = inspect.getsource(scheduler)
        assert 'compute_days_remaining(cert.valid_to, now)' in source
        assert 'math.ceil' not in source

    def test_a_discovered_certificate_uses_the_helper(self, app):
        from models.discovered_certificate import DiscoveredCertificate
        row = DiscoveredCertificate()
        row.not_after = utc_now() + timedelta(hours=12)
        assert row.days_until_expiry == 1
        row.not_after = None
        assert row.days_until_expiry is None

    def test_the_inspection_tool_uses_the_helper(self):
        import inspect
        from api.v2 import tools
        source = inspect.getsource(tools)
        assert 'compute_days_remaining(cert.not_valid_after_utc, now)' in source
        assert '.not_valid_after_utc - now).days' not in source
