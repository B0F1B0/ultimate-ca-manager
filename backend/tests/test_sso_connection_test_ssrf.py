"""What the OAuth2 reachability test does with the URL it was given.

The route validates the administrator's authorization URL against the
cloud-metadata deny-list, then fetched it with a bare `requests.head` and
`allow_redirects=True`. Two things escaped that validation:

* the address was resolved a second time by the connection, so a name that
  answers differently between the two lookups reaches whatever it likes;
* a redirect went to a host nobody validated at all, since `pin_host` pins the
  host that was checked and only that one.

`requests.head` does not follow redirects by default: this call asked for it.
A 3xx already proves the endpoint answers, which is all a reachability test
needs.
"""
import pytest

from models import db


@pytest.fixture
def oauth2_provider(app):
    """Created and cleaned up in their own contexts: holding one open across
    the yield makes a later commit inside a nested context disappear, and the
    route then reads the row as it was."""
    from models.sso import SSOProvider

    with app.app_context():
        provider = SSOProvider(
            name='ssrf-connection-test', provider_type='oauth2',
            oauth2_auth_url='https://idp.example.test/authorize',
            oauth2_token_url='https://idp.example.test/token',
            oauth2_client_id='x', enabled=True)
        db.session.add(provider)
        db.session.commit()
        provider_id = provider.id

    yield provider_id

    with app.app_context():
        row = db.session.get(SSOProvider, provider_id)
        if row is not None:
            db.session.delete(row)
            db.session.commit()


class TestTheReachabilityTestDoesNotWanderOff:
    def test_it_goes_through_the_pinning_helper_and_does_not_follow_redirects(
            self, app, auth_client, oauth2_provider, monkeypatch):
        import api.v2.sso.connection_tests as route

        seen = {}

        def fake_safe_head(url, allow_loopback=False, **kwargs):
            seen['url'] = url
            seen['kwargs'] = kwargs

            class Answer:
                status_code = 302
            return Answer()

        def forbidden_head(*args, **kwargs):
            raise AssertionError(
                'the route called requests.head directly: the address is '
                'resolved a second time and a redirect leaves the validated '
                'host behind')

        monkeypatch.setattr(route, 'safe_request_head', fake_safe_head,
                            raising=False)
        monkeypatch.setattr(route.http_requests, 'head', forbidden_head)

        response = auth_client.post(
            f'/api/v2/sso/providers/{oauth2_provider}/test')

        assert response.status_code == 200, response.data
        assert seen.get('url') == 'https://idp.example.test/authorize'
        assert seen['kwargs'].get('allow_redirects') is not True, (
            'the reachability test asked to follow redirects, and a redirect '
            'goes to a host the validation never saw')

    def test_a_cloud_metadata_url_is_still_refused_with_its_reason(
            self, app, auth_client, oauth2_provider):
        """The precise refusal must survive: swallowed by the generic handler
        it becomes "connection failed", which sends the operator looking at
        their network instead of at their URL."""
        from models.sso import SSOProvider

        with app.app_context():
            provider = db.session.get(SSOProvider, oauth2_provider)
            provider.oauth2_auth_url = 'http://169.254.169.254/latest/meta-data/'
            db.session.commit()

        response = auth_client.post(
            f'/api/v2/sso/providers/{oauth2_provider}/test')

        assert response.status_code == 400, response.data
        assert b'metadata' in response.data.lower()


class TestTheHelperItselfDoesNotFollowRedirects:
    """The route's test replaces the helper with a double, so it proves the
    wiring and not the wire. This one asks the helper what it actually does,
    so that giving it a redirect-following default one day fails here rather
    than passing everywhere.
    """

    def test_it_does_not_ask_for_redirects(self, monkeypatch):
        import requests

        from utils import ssrf_protection

        seen = {}

        def fake_head(url, **kwargs):
            seen.update(kwargs)

            class Answer:
                status_code = 302
            return Answer()

        monkeypatch.setattr(ssrf_protection, '_resolve_and_validate',
                            lambda url, allow_loopback: ('example.test',
                                                         ['192.0.2.1']))
        monkeypatch.setattr(requests, 'head', fake_head)

        ssrf_protection.safe_request_head('https://example.test/a')

        assert seen.get('allow_redirects') is not True, (
            'the helper asked requests to follow redirects, which leaves the '
            'host it pinned')
