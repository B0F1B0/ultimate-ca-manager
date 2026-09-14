"""The URL that is validated must be the URL that is requested.

Both OPNsense routes checked `https://{host}` against the cloud-metadata
deny-list, then connected to `https://{host}:{port}`. The port came from the
request body and was never looked at, so it carried the rest of the authority:

    host = "example.com", port = "443@169.254.169.254"
    validated : https://example.com                      -> example.com
    requested : https://example.com:443@169.254.169.254  -> 169.254.169.254

The `@` turns everything before it into userinfo. One request, no hostile DNS,
no redirect. The routes are guarded by `write:certificates`, which the
operator role holds.

A malformed host had the same root cause with a milder symptom: an IPv6
literal, or a host that already carries a port, built a URL the client
refused, and the route answered 500.
"""
import pytest


ROUTES = ('/api/v2/import/opnsense/test', '/api/v2/import/opnsense/import')


def _payload(**overrides):
    body = {'host': 'opnsense.example.test', 'port': 443,
            'api_key': 'k', 'api_secret': 's', 'verify_ssl': False,
            'items': []}
    body.update(overrides)
    return body


@pytest.fixture(autouse=True)
def attempted(monkeypatch):
    """Every URL the route tries to reach, recorded rather than raised.

    Raising would prove the same thing only where the route lets the
    exception through; both of these wrap their work in a try block and would
    answer 500, which reads as a refusal without being one.
    """
    urls = []

    class Recorder:
        verify = False

        def _record(self, url, **kwargs):
            urls.append(url)
            raise RuntimeError('no network in tests')

        get = _record
        post = _record

    import api.v2.import_opnsense as route
    monkeypatch.setattr(route, 'create_session', lambda **kw: Recorder())
    return urls


class TestThePortIsAPort:
    @pytest.mark.parametrize('route', ROUTES)
    @pytest.mark.parametrize('port', [
        '443@169.254.169.254',      # the authority takeover
        '443/../..',
        'https://evil.test',
        0,
        65536,
        -1,
        'eighty',
    ])
    def test_a_port_that_is_not_a_port_is_refused(self, auth_client, attempted,
                                                  route, port):
        response = auth_client.post(route, json=_payload(port=port))

        assert response.status_code == 400, (
            f'{route} accepted port={port!r} and answered '
            f'{response.status_code}')
        assert attempted == [], f'{route} connected to {attempted}'

    @pytest.mark.parametrize('route', ROUTES)
    def test_an_ordinary_port_is_reached(self, auth_client, attempted, route):
        """The refusal must not reach a legitimate appliance on 8443."""
        auth_client.post(route, json=_payload(port=8443))

        assert attempted, f'{route} refused a legitimate port'
        assert attempted[0].startswith('https://opnsense.example.test:8443/')

    @pytest.mark.parametrize('route', ROUTES)
    def test_a_port_written_with_spaces_is_taken(self, auth_client, attempted,
                                                 route):
        """Tolerated on purpose: the number is parsed and the URL is built
        from the number, so the spaces never reach the authority."""
        auth_client.post(route, json=_payload(port=' 8443 '))

        assert attempted, f'{route} refused a port written with spaces'
        assert attempted[0].startswith('https://opnsense.example.test:8443/')


class TestTheHostIsAHost:
    @pytest.mark.parametrize('route', ROUTES)
    @pytest.mark.parametrize('host', [
        'opnsense.example.test:8443',   # a port already in the host
        '[::1]',
        'opnsense.example.test/path',
        'user@opnsense.example.test',
    ])
    def test_a_host_that_carries_more_than_a_host_is_refused(
            self, auth_client, attempted, route, host):
        response = auth_client.post(route, json=_payload(host=host))

        assert response.status_code == 400, (
            f'{route} accepted host={host!r} and answered '
            f'{response.status_code}')
        assert attempted == [], f'{route} connected to {attempted}'


class TestWhatIsCheckedIsWhatIsAsked:
    @pytest.mark.parametrize('route', ROUTES)
    def test_the_metadata_address_is_refused_through_the_port(
            self, auth_client, attempted, route):
        """The case that was reachable: the deny-list saw `example.com` and
        the connection went to the metadata service."""
        response = auth_client.post(
            route, json=_payload(host='example.com',
                                 port='443@169.254.169.254'))

        assert response.status_code == 400, response.data
        assert attempted == [], (
            'the deny-list saw example.com and the connection went to '
            f'{attempted}')

    @pytest.mark.parametrize('route', ROUTES)
    def test_the_metadata_address_is_still_refused_as_a_host(
            self, auth_client, route):
        response = auth_client.post(
            route, json=_payload(host='169.254.169.254'))

        assert response.status_code == 400, response.data
        assert b'metadata' in response.data.lower()


class TestARedirectIsNotFollowed:
    """The appliance answers JSON on its API; a redirect there is not a normal
    condition, and following it reads the answer of a host the deny-list never
    saw as if it were the appliance's inventory of certificates.

    Refused rather than walked: the hop policy the ACME challenge follower
    carries does not fit here (it allows ports 80 and 443 only and turns TLS
    verification off), and giving it parameters to fit would build the
    flag-driven abstraction this audit exists to avoid.
    """

    @pytest.mark.parametrize('route', ROUTES)
    def test_the_call_asks_for_no_redirects(self, auth_client, monkeypatch,
                                            route):
        import api.v2.import_opnsense as opnsense

        seen = {}

        class Recorder:
            verify = False

            def get(self, url, **kwargs):
                seen.update(kwargs)
                raise RuntimeError('no network in tests')

        monkeypatch.setattr(opnsense, 'create_session', lambda **kw: Recorder())

        auth_client.post(route, json=_payload(port=8443))

        assert seen, f'{route} made no request'
        assert seen.get('allow_redirects') is False, (
            'the import follows redirects, so a 3xx sends it to a host the '
            'deny-list never saw and its answer is read as the inventory')


class TestTheNameCheckedIsTheNameResolved:
    """The same defect as the port, one notch further along.

    The deny-list resolves through `socket.getaddrinfo`, which converts a
    unicode name with IDNA 2003; the HTTP client converts it with IDNA 2008.
    They disagree, so a caller owning two records has the first name checked
    and the second one reached, with no hostile resolver and no race.
    """

    UNICODE_HOST = 'fa\N{LATIN SMALL LETTER SHARP S}.example.test'

    def test_the_two_encoders_really_disagree(self):
        """Kept as a test: the day they agree, the case below proves nothing
        and someone should know why it is still here."""
        import idna

        assert (self.UNICODE_HOST.encode('idna').decode()
                != idna.encode(self.UNICODE_HOST, strict=True,
                               std3_rules=True).decode())

    @pytest.mark.parametrize('route', ROUTES)
    def test_the_request_carries_the_name_the_client_resolves(
            self, auth_client, attempted, route):
        import idna

        auth_client.post(route, json=_payload(host=self.UNICODE_HOST,
                                              port=8443))

        if not attempted:
            return      # refused outright is a sound answer too
        expected = idna.encode(self.UNICODE_HOST, strict=True,
                               std3_rules=True).decode()
        assert attempted[0].startswith(f'https://{expected}:8443/'), (
            f'the request went to {attempted[0]}, which is not the name the '
            'deny-list was asked about')


class TestTheOrdinaryFormsStillWork:
    @pytest.mark.parametrize('route', ROUTES)
    @pytest.mark.parametrize('host, reached', [
        ('OPNSENSE.Example.Test', 'opnsense.example.test'),
        ('opnsense.example.test.', 'opnsense.example.test.'),
        ('192.0.2.10', '192.0.2.10'),
        ('[2001:db8::1]', '[2001:db8::1]'),
        ('2001:db8::1', '[2001:db8::1]'),
    ])
    def test_a_legitimate_appliance_is_still_reached(
            self, auth_client, attempted, route, host, reached):
        auth_client.post(route, json=_payload(host=host, port=8443))

        assert attempted, f'{route} refused host={host!r}'
        assert attempted[0].startswith(f'https://{reached}:8443/'), (
            f'host={host!r} was contacted as {attempted[0]}')

    @pytest.mark.parametrize('route', ROUTES)
    @pytest.mark.parametrize('host', ['[abc]', '[]', '[', '[169.254.169.254]'])
    def test_a_bracketed_value_that_is_not_an_address_is_named(
            self, auth_client, attempted, route, host):
        """These made `urlparse` raise, so the caller saw a server error
        instead of being told what was wrong with their host."""
        response = auth_client.post(route, json=_payload(host=host))

        assert response.status_code == 400, (
            f'{route} answered {response.status_code} for host={host!r}')
        assert attempted == []
