"""One answer for "does this instance show the time", whoever asks.

The clock preference is a single global row, and three places read it: the
settings screen, the session payload the SPA restores itself from, and the
registry that is supposed to say what the row means. The settings screen and
the session payload did not agree, because the payload tested the row against
one literal word:

    'show_time': st_row.value != 'false' if st_row else True

while the registry reads it forgivingly, `0`/`no`/`off` included. Store `0`
-- which is what `PATCH /api/v2/settings/general {"show_time": 0}` wrote,
because `isinstance(0, bool)` is False in Python and the boolean branch was
skipped -- and the screen showed the box unticked while every date in the
product kept its time. Ticking the box and unticking it "fixed" it, which is
what made it look like a fluke.

The write side is the other half: the row took any string at all, so the two
readers were being asked to agree about values the UI never offers.
"""
import json

import pytest

from models import SystemConfig, db
from auth.session_payload import display_settings
from services.settings_registry import effective

# Every spelling the permissive reader knows, plus one it does not.
STORED_WORDS = ('true', 'false', 'yes', 'no', 'on', 'off', '0', '1',
                'banana', None)


def _set_show_time(value):
    row = SystemConfig.query.filter_by(key='show_time').first()
    if value is None:
        if row:
            db.session.delete(row)
    elif row:
        row.value = value
    else:
        db.session.add(SystemConfig(key='show_time', value=value))
    db.session.commit()


@pytest.fixture
def stored_show_time(app):
    """Put a raw value in the row and restore whatever was there."""
    with app.app_context():
        row = SystemConfig.query.filter_by(key='show_time').first()
        before = row.value if row else None

    def _apply(value):
        with app.app_context():
            _set_show_time(value)

    yield _apply

    with app.app_context():
        _set_show_time(before)


class TestTheReadersAgree:
    @pytest.mark.parametrize('stored', STORED_WORDS)
    def test_the_session_payload_says_what_the_registry_says(
            self, app, stored_show_time, stored):
        stored_show_time(stored)
        with app.app_context():
            assert display_settings()['show_time'] == effective('show_time'), (
                f'stored {stored!r}: the session payload and the registry '
                'give the SPA and the settings screen different answers about '
                'the same row')

    @pytest.mark.parametrize('stored', STORED_WORDS)
    def test_the_settings_screen_says_what_the_session_says(
            self, app, auth_client, stored_show_time, stored):
        stored_show_time(stored)
        screen = json.loads(
            auth_client.get('/api/v2/settings/general').data)['data']['show_time']
        with app.app_context():
            session = display_settings()['show_time']
        assert screen == session, (
            f'stored {stored!r}: the settings screen shows {screen} and the '
            f'session hands the SPA {session}')


class TestTheRowOnlyEverHoldsABoolean:
    """The screen offers a tick box, so the row should never hold anything
    a tick box cannot produce."""

    @pytest.mark.parametrize('sent,expected', [
        (True, 'true'),
        (False, 'false'),
        (0, 'false'),
        (1, 'true'),
        ('false', 'false'),
        ('no', 'false'),
        ('off', 'false'),
        ('yes', 'true'),
        ('1', 'true'),
    ])
    def test_a_boolean_arrives_as_a_boolean(self, app, auth_client,
                                            stored_show_time, sent, expected):
        stored_show_time('true')
        r = auth_client.patch('/api/v2/settings/general',
                              data=json.dumps({'show_time': sent}),
                              content_type='application/json')
        assert r.status_code == 200, r.data
        with app.app_context():
            row = SystemConfig.query.filter_by(key='show_time').first()
            assert row.value == expected, (
                f'sent {sent!r}: the row holds {row.value!r}, which is not a '
                'value the tick box can produce')

    def test_a_value_that_is_not_a_boolean_at_all_is_refused(
            self, auth_client, stored_show_time):
        stored_show_time('true')
        r = auth_client.patch('/api/v2/settings/general',
                              data=json.dumps({'show_time': 'banana'}),
                              content_type='application/json')
        assert r.status_code == 400, (
            'the row took the word banana and both readers then had to guess '
            f'what it meant (answered {r.status_code})')


class TestTheDateFormatIsOneOfTheOnesThatRender:
    """`stores/dateFormatStore.js` honours five names and silently ignores
    anything else, leaving the settings dropdown blank while dates keep
    rendering in the previous format."""

    @pytest.mark.parametrize('fmt', ['short', 'iso', 'eu', 'us', 'long'])
    def test_the_five_the_ui_offers_are_accepted(self, auth_client, fmt):
        r = auth_client.patch('/api/v2/settings/general',
                              data=json.dumps({'date_format': fmt}),
                              content_type='application/json')
        assert r.status_code == 200, r.data

    @pytest.mark.parametrize('fmt', ['banana', 'YYYY-MM-DD', '', 'Short'])
    def test_anything_else_is_refused(self, auth_client, fmt):
        r = auth_client.patch('/api/v2/settings/general',
                              data=json.dumps({'date_format': fmt}),
                              content_type='application/json')
        assert r.status_code == 400, (
            f'{fmt!r} was stored; the dropdown has no such option and the '
            'store ignores it, so the screen goes blank and dates do not '
            'change')

    def test_the_accepted_format_is_restored(self, auth_client):
        auth_client.patch('/api/v2/settings/general',
                          data=json.dumps({'date_format': 'short'}),
                          content_type='application/json')


class TestAGlobalPreferenceIsNotOfferedAsAPersonalOne:
    """`GET /api/v2/auth/verify` carried the same three names twice: once at
    the top level from the global rows, once inside `preferences` from the
    user's own blob. Only the first is ever applied, so the second was a
    value the API accepted, stored and echoed back while nothing acted on it.
    """

    @pytest.mark.parametrize('key,value', [
        ('show_time', False),
        ('date_format', 'iso'),
        ('timezone', 'Europe/Paris'),
    ])
    def test_it_is_not_kept_in_the_personal_blob(self, auth_client, key, value):
        r = auth_client.put('/api/v2/account/preferences',
                            data=json.dumps({key: value, 'density': 'compact'}),
                            content_type='application/json')
        assert r.status_code == 200, r.data

        stored = json.loads(
            auth_client.get('/api/v2/account/preferences').data)['data']
        assert key not in stored, (
            f'{key} was stored against the user and handed back by the API, '
            'and nothing anywhere applies it -- the instance-wide row decides')
        assert stored.get('density') == 'compact', (
            'the preferences that are real must still go through')
