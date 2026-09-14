"""One opinion about how strong a password is, and it is the server's.

`POST /api/v2/users/password-strength` has scored passwords since long
before this, and nothing in the UI called it. The meter in
`components/Input.jsx` counted five properties of its own instead, and the
two disagreed on most passwords a person actually types -- always with the
browser reading higher, which is the direction that matters for a meter:

    Ab1!Ab1!      browser "strong"  server "fair"   (50)
    Tr0ub4dor&3   browser "strong"  server "good"   (70)
    Passw0rd!     browser "strong"  server "good"   (70)
    aaaaaaaaaaaa  browser "fair"    server "weak"   (20)

This pins the endpoint's vocabulary and the verdicts the browser is now
reporting. `frontend/src/lib/__tests__/passwordStrength.test.js` is the
other half.
"""
import json

import pytest

from security.password_policy import get_password_strength

LEVELS = ('weak', 'fair', 'good', 'strong')

# The ones the old browser heuristic got wrong, and by how much.
OVERSTATED_BY_THE_BROWSER = {
    'Ab1!Ab1!': 'fair',
    'Tr0ub4dor&3': 'good',
    'Passw0rd!': 'good',
    'aaaaaaaaaaaa': 'weak',
    'aaaaaaaaaaaaaaaaaaaa': 'weak',
    'correct horse battery staple': 'fair',
}


class TestTheEndpointIsTheOneToAsk:
    def test_it_needs_no_session(self, client):
        r = client.post('/api/v2/users/password-strength',
                        data=json.dumps({'password': 'Str0ng@Pass!XY'}),
                        content_type='application/json')
        assert r.status_code == 200, (
            'the meter renders on the login and reset screens, where there '
            'is no session to authenticate with')

    def test_it_answers_with_a_score_and_a_level(self, client):
        data = (client.post('/api/v2/users/password-strength',
                            data=json.dumps({'password': 'Str0ng@Pass!XY'}),
                            content_type='application/json')
                .get_json() or {}).get('data') or {}
        assert isinstance(data.get('score'), int)
        assert 0 <= data['score'] <= 100
        assert data.get('level') in LEVELS

    def test_the_vocabulary_is_the_one_the_meter_paints(self, client):
        """`lib/passwordStrength.js` has a colour for each of these and only
        these; an unknown level would paint as weak."""
        seen = set()
        for password in ('', 'x', 'abcdefgh', 'Ab1!Ab1!', 'Str0ng@Pass!XY',
                         'Password123!', 'aaaaaaaaaaaa'):
            data = (client.post('/api/v2/users/password-strength',
                                data=json.dumps({'password': password}),
                                content_type='application/json')
                    .get_json() or {}).get('data') or {}
            assert data['level'] in LEVELS, (password, data)
            seen.add(data['level'])
        assert len(seen) > 1, 'every password scored the same; nothing is pinned'

    def test_an_absent_password_is_not_an_error(self, client):
        r = client.post('/api/v2/users/password-strength',
                        data=json.dumps({}),
                        content_type='application/json')
        assert r.status_code == 200
        assert (r.get_json() or {})['data']['level'] == 'weak'


class TestTheVerdictsTheBrowserUsedToGetWrong:
    @pytest.mark.parametrize('password,level',
                             sorted(OVERSTATED_BY_THE_BROWSER.items()))
    def test_the_server_says_what_the_meter_now_shows(self, password, level):
        assert get_password_strength(password)['level'] == level

    @pytest.mark.parametrize('password,level',
                             sorted(OVERSTATED_BY_THE_BROWSER.items()))
    def test_the_endpoint_agrees_with_the_scorer(self, client, password, level):
        data = (client.post('/api/v2/users/password-strength',
                            data=json.dumps({'password': password}),
                            content_type='application/json')
                .get_json() or {}).get('data') or {}
        assert data['level'] == level

    def test_repetition_is_seen(self):
        """The five-property count could not see this at all."""
        assert (get_password_strength('aaaaaaaaaaaa')['score']
                < get_password_strength('Str0ng@Pass!XY')['score'])

    def test_a_run_of_characters_costs_something(self):
        with_run = get_password_strength('Abcd1234!xyz')['score']
        without = get_password_strength('Axbq1739!zmv')['score']
        assert with_run < without, (
            'a sequential run scored the same as a scattered password, so '
            'the browser heuristic was not the only thing not looking')
