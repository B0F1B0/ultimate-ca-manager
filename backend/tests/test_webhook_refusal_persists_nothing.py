"""A refused update to a webhook leaves the webhook as it was.

The route applies the fields it was given -- the URL, the signing secret, the
events, the headers -- and only then validates the authentication block. When
that block is wrong it records the refusal and answers 400, and recording it
commits the session: everything applied before the check was written down,
so a request answered as rejected changed the endpoint's URL and its signing
secret anyway.
"""
import pytest

from models import db


@pytest.fixture
def an_endpoint(app):
    from services.webhook_service import WebhookEndpoint

    with app.app_context():
        endpoint = WebhookEndpoint(
            name='refusal-endpoint',
            url='https://original.example.test/hook',
            events='["certificate.issued"]')
        db.session.add(endpoint)
        db.session.commit()
        made = endpoint.id

    yield made

    with app.app_context():
        row = db.session.get(WebhookEndpoint, made)
        if row is not None:
            db.session.delete(row)
            db.session.commit()


class TestARefusalChangesNothing:
    def test_a_rejected_auth_block_does_not_move_the_url(self, app,
                                                         auth_client,
                                                         an_endpoint):
        from services.webhook_service import WebhookEndpoint

        response = auth_client.put(
            f'/api/v2/webhooks/{an_endpoint}',
            json={'url': 'https://moved.example.test/hook',
                  'auth_type': 'not-a-real-auth-type'})

        assert response.status_code == 400, response.data

        with app.app_context():
            url = db.session.get(WebhookEndpoint, an_endpoint).url

        assert url == 'https://original.example.test/hook', (
            'the update was answered as refused and the endpoint now posts to '
            f'{url}: the refusal was recorded, and recording it committed '
            'everything applied before the check')
