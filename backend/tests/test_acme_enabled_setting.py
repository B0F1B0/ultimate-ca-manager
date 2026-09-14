"""Turning ACME off in the settings turns the ACME server off.

`acme.enabled` was written by the settings page, read back by that page and
by the dashboard tile, and consulted by no endpoint under /acme: an operator
who disabled ACME kept an ACME server that issued certificates.
"""
import json

import pytest

from models import db


@pytest.fixture
def acme_setting(app):
    """Set `acme.enabled` for the duration of a test, then put it back."""
    from models import SystemConfig

    def set_to(value):
        with app.app_context():
            row = SystemConfig.query.filter_by(key='acme.enabled').first()
            if row:
                row.value = value
            else:
                db.session.add(SystemConfig(key='acme.enabled', value=value))
            db.session.commit()

    with app.app_context():
        existing = SystemConfig.query.filter_by(key='acme.enabled').first()
        previous = existing.value if existing else None

    yield set_to

    with app.app_context():
        row = SystemConfig.query.filter_by(key='acme.enabled').first()
        if previous is None:
            if row:
                db.session.delete(row)
        else:
            row.value = previous
        db.session.commit()


class TestDisabled:
    def test_the_directory_is_unavailable(self, client, acme_setting):
        acme_setting('false')
        answer = client.get('/acme/directory')
        assert answer.status_code == 503, answer.data[:200]
        assert answer.mimetype == 'application/problem+json'
        assert json.loads(answer.data)['type'].startswith(
            'urn:ietf:params:acme:error:')

    def test_a_new_account_is_refused(self, client, acme_setting):
        acme_setting('false')
        answer = client.post('/acme/new-account', data=json.dumps({
            'protected': 'e30', 'payload': 'e30', 'signature': 'x'}),
            content_type='application/jose+json')
        assert answer.status_code == 503, answer.data[:200]

    def test_a_new_nonce_is_refused(self, client, acme_setting):
        acme_setting('false')
        assert client.head('/acme/new-nonce').status_code == 503


class TestEnabled:
    def test_the_directory_answers_when_the_setting_says_so(
            self, client, acme_setting):
        acme_setting('true')
        answer = client.get('/acme/directory')
        assert answer.status_code == 200, answer.data[:200]
        assert 'newOrder' in json.loads(answer.data)

    def test_an_unreadable_value_leaves_the_server_on(
            self, client, acme_setting):
        # The registry reads this key forgivingly: only an explicit off
        # turns it off, so a stray value must not take ACME down.
        acme_setting('yes')
        assert client.get('/acme/directory').status_code == 200
