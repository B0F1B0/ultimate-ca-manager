"""A redirect is where a validated request stopped being one.

The wrappers resolved the first host, vetted it and pinned the connection to
the addresses that came back. Then the upstream answered 302 and `requests`
followed it on its own: the second host was never resolved through the guard,
never vetted against the cloud-metadata deny-list, and never pinned. One
redirect was enough to reach what the first check had refused.
"""
import pytest

from utils import ssrf_protection


class _Answer:
    def __init__(self, status_code=200, location=None, url=None):
        self.status_code = status_code
        self.headers = {'Location': location} if location else {}
        self.url = url
        self.closed = False

    def close(self):
        self.closed = True


@pytest.fixture()
def wire(monkeypatch):
    """Records every hop, and answers whatever the scenario says."""
    import requests

    hops = []
    answers = {}

    def _send(url, **kwargs):
        hops.append((url, kwargs))
        return answers.get(url, _Answer())

    for method in ('get', 'post', 'head', 'put'):
        monkeypatch.setattr(requests, method,
                            lambda url, _m=method, **kw: _send(url, method=_m, **kw))

    vetted = []
    original = ssrf_protection._resolve_and_validate

    def _watched(url, allow_loopback=False):
        vetted.append(url)
        return original(url, allow_loopback)

    monkeypatch.setattr(ssrf_protection, '_resolve_and_validate', _watched)
    return {'hops': hops, 'answers': answers, 'vetted': vetted}


FIRST = 'https://93.184.216.34/start'
SECOND = 'https://93.184.216.35/next'


class TestEveryHopIsChecked:
    def test_the_second_hop_goes_through_the_guard(self, wire):
        wire['answers'][FIRST] = _Answer(302, location=SECOND)
        ssrf_protection.safe_request_get(FIRST)
        assert wire['vetted'] == [FIRST, SECOND]
        assert [url for url, _ in wire['hops']] == [FIRST, SECOND]

    def test_a_redirect_to_a_refused_address_is_refused(self, wire):
        wire['answers'][FIRST] = _Answer(302, location='http://169.254.169.254/latest/meta-data/')
        with pytest.raises(ValueError):
            ssrf_protection.safe_request_get(FIRST)

    def test_a_relative_location_is_resolved_against_the_current_url(self, wire):
        wire['answers'][FIRST] = _Answer(302, location='/elsewhere')
        ssrf_protection.safe_request_get(FIRST)
        assert wire['vetted'][-1] == 'https://93.184.216.34/elsewhere'

    def test_a_redirect_loop_is_cut(self, wire):
        import requests
        wire['answers'][FIRST] = _Answer(302, location=FIRST)
        # The same exception requests raises, so the callers that already
        # catch RequestException keep reporting it as a network failure.
        with pytest.raises(requests.TooManyRedirects):
            ssrf_protection.safe_request_get(FIRST)
        assert len(wire['hops']) == ssrf_protection.MAX_REDIRECTS + 1


class TestTheSemanticsFollowRequests:
    def test_a_303_turns_a_post_into_a_get_and_drops_the_body(self, wire):
        wire['answers'][FIRST] = _Answer(303, location=SECOND)
        ssrf_protection.safe_request_post(FIRST, json={'secret': 'value'})
        first, second = wire['hops']
        assert first[1]['method'] == 'post'
        assert second[1]['method'] == 'get'
        assert 'json' not in second[1]

    def test_a_307_keeps_the_method_and_the_body_within_one_origin(self, wire):
        same_origin = 'https://93.184.216.34/moved'
        wire['answers'][FIRST] = _Answer(307, location=same_origin)
        ssrf_protection.safe_request_post(FIRST, json={'keep': 'this'})
        _first, second = wire['hops']
        assert second[1]['method'] == 'post'
        assert second[1]['json'] == {'keep': 'this'}

    def test_a_caller_that_refuses_to_follow_gets_the_redirect(self, wire):
        wire['answers'][FIRST] = _Answer(302, location=SECOND)
        answer = ssrf_protection.safe_request_get(FIRST, allow_redirects=False)
        assert answer.status_code == 302
        assert len(wire['hops']) == 1

    def test_a_redirect_without_a_location_is_returned_as_is(self, wire):
        wire['answers'][FIRST] = _Answer(302)
        assert ssrf_protection.safe_request_get(FIRST).status_code == 302

    def test_the_hops_are_never_followed_by_requests_itself(self, wire):
        wire['answers'][FIRST] = _Answer(302, location=SECOND)
        ssrf_protection.safe_request_get(FIRST)
        for _url, kwargs in wire['hops']:
            assert kwargs['allow_redirects'] is False


class TestCredentialsDoNotFollowTheHop:
    """`requests.Session.rebuild_auth` drops them; this must too."""

    def test_authorization_is_dropped_when_the_origin_changes(self, wire):
        wire['answers'][FIRST] = _Answer(302, location=SECOND)
        ssrf_protection.safe_request_get(
            FIRST, headers={'Authorization': 'Bearer operator-token',
                            'Accept': 'application/json'})
        _first, second = wire['hops']
        assert 'Authorization' not in second[1]['headers']
        # What is not a credential still travels.
        assert second[1]['headers']['Accept'] == 'application/json'

    @pytest.mark.parametrize('header', [
        'X-API-Key', 'x-api-key', 'Api-Key', 'X-Auth-Token', 'X-UCM-Signature',
        'X-Client-Secret', 'Private-Token', 'X-Amz-Security-Token',
    ])
    def test_a_credential_under_any_name_is_dropped(self, wire, header):
        """`requests` only knows Authorization; an API key is named freely."""
        wire['answers'][FIRST] = _Answer(302, location=SECOND)
        ssrf_protection.safe_request_get(FIRST, headers={header: 'secret'})
        _first, second = wire['hops']
        assert header not in second[1]['headers'], header

    def test_a_307_does_not_replay_the_body_to_another_origin(self, wire):
        """The body carries the client secret of a token exchange."""
        wire['answers'][FIRST] = _Answer(307, location=SECOND)
        ssrf_protection.safe_request_post(
            FIRST, data={'client_secret': 's3cret', 'refresh_token': 'r3fresh'})
        _first, second = wire['hops']
        assert 'data' not in second[1]
        assert second[1]['method'] == 'get'

    def test_the_query_does_not_follow_either(self, wire):
        """Some providers put the key and the token in the query string."""
        wire['answers'][FIRST] = _Answer(302, location=SECOND)
        ssrf_protection.safe_request_get(FIRST, params={'api_key': 'secret'})
        _first, second = wire['hops']
        assert 'params' not in second[1]

    def test_a_cookie_and_an_auth_tuple_go_with_it(self, wire):
        wire['answers'][FIRST] = _Answer(302, location=SECOND)
        ssrf_protection.safe_request_get(
            FIRST, auth=('user', 'secret'), cookies={'session': 'abc'},
            headers={'Cookie': 'session=abc'})
        _first, second = wire['hops']
        assert 'auth' not in second[1]
        assert 'cookies' not in second[1]
        assert 'Cookie' not in second[1]['headers']

    def test_they_survive_a_hop_within_the_same_origin(self, wire):
        same_origin = 'https://93.184.216.34/other'
        wire['answers'][FIRST] = _Answer(302, location=same_origin)
        ssrf_protection.safe_request_get(
            FIRST, headers={'Authorization': 'Bearer operator-token'})
        _first, second = wire['hops']
        assert second[1]['headers']['Authorization'] == 'Bearer operator-token'

    def test_a_301_on_a_put_keeps_its_method_within_one_origin(self, wire):
        """requests only rewrites POST on a 301; a PUT stays a PUT."""
        same_origin = 'https://93.184.216.34/moved'
        wire['answers'][FIRST] = _Answer(301, location=same_origin)
        ssrf_protection.safe_request('PUT', FIRST, json={'keep': 'this'})
        _first, second = wire['hops']
        assert second[1]['method'] == 'put'
        assert second[1]['json'] == {'keep': 'this'}

    def test_the_dropped_body_takes_its_content_type_with_it(self, wire):
        """Within one origin, only the body headers go with the body."""
        same_origin = 'https://93.184.216.34/next'
        wire['answers'][FIRST] = _Answer(303, location=same_origin)
        ssrf_protection.safe_request_post(
            FIRST, json={'a': 1}, headers={'Content-Type': 'application/json',
                                           'X-Keep': 'yes'})
        _first, second = wire['hops']
        assert 'Content-Type' not in second[1]['headers']
        assert second[1]['headers']['X-Keep'] == 'yes'

    @pytest.mark.parametrize('header', [
        'X-Access-Key', 'X-API-Key', 'Private-Token', 'X-Shopify-Access-Token',
        'Fastly-Key', 'X-Figma-Token', 'Circle-Token', 'X-Whatever-Custom',
        'Ocp-Apim-Subscription-Key', 'X-Goog-Api-Key',
    ])
    def test_no_custom_header_crosses_an_origin(self, wire, header):
        """An allowlist, because a credential is named however its provider
        chose and a list of suspicious names is a game that cannot be won."""
        wire['answers'][FIRST] = _Answer(302, location=SECOND)
        ssrf_protection.safe_request_get(FIRST, headers={header: 'SECRET'})
        _first, second = wire['hops']
        assert header not in second[1]['headers'], header
        assert 'SECRET' not in str(second[1]), header

    def test_the_harmless_headers_still_cross(self, wire):
        wire['answers'][FIRST] = _Answer(302, location=SECOND)
        ssrf_protection.safe_request_get(FIRST, headers={
            'Accept': 'application/json', 'User-Agent': 'ucm/1.0',
            'X-Access-Key': 'SECRET'})
        _first, second = wire['hops']
        assert second[1]['headers'] == {'Accept': 'application/json',
                                        'User-Agent': 'ucm/1.0'}

    def test_the_intermediate_response_is_closed(self, wire):
        hop = _Answer(302, location=SECOND)
        wire['answers'][FIRST] = hop
        ssrf_protection.safe_request_get(FIRST)
        assert hop.closed, 'the redirect kept its socket out of the pool'
