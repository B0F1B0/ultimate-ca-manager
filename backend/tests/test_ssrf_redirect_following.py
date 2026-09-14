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


@pytest.fixture()
def wire(monkeypatch):
    """Records every hop, and answers whatever the scenario says."""
    import requests

    hops = []
    answers = {}

    def _send(url, **kwargs):
        hops.append((url, kwargs))
        return answers.get(url, _Answer())

    for method in ('get', 'post', 'head'):
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
        wire['answers'][FIRST] = _Answer(302, location=FIRST)
        with pytest.raises(ValueError, match='Too many redirects'):
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

    def test_a_307_keeps_the_method_and_the_body(self, wire):
        wire['answers'][FIRST] = _Answer(307, location=SECOND)
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
