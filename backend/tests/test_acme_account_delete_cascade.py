"""Deleting a local ACME account takes its orders, authorizations and
challenges with it.

Two of the three deletions compared a text column to an integer primary key.
`AcmeChallenge.authorization_id` and `AcmeAuthorization.order_id` hold the
identifiers RFC 8555 puts in URLs, generated with `secrets.token_urlsafe`;
`authz.id` and `order.id` are the table's own integer keys. The predicate
therefore asked whether a token equals a number.

On SQLite that deletes nothing and the rows are left behind, pointing at an
account that is gone. On PostgreSQL there is no operator comparing text to an
integer, so the statement fails and the account is not deleted at all: the
same archive, the same click, two different outcomes depending on the backend
underneath.

The sibling route that deletes a single order does it correctly
(`api/v2/acme/orders.py:120`), which is where the right column can be read.
"""
import secrets

import pytest

from models import db


@pytest.fixture
def an_account_with_a_challenge(app):
    """One account, one order, one authorization, one challenge."""
    from models.acme_models import (
        AcmeAccount, AcmeAuthorization, AcmeChallenge, AcmeOrder)

    with app.app_context():
        account_id = f'cascade-{secrets.token_hex(4)}'
        account = AcmeAccount(account_id=account_id, jwk='{}',
                              jwk_thumbprint=secrets.token_hex(8),
                              status='valid')
        db.session.add(account)
        db.session.flush()

        order = AcmeOrder(order_id=secrets.token_urlsafe(16),
                          account_id=account_id,
                          identifiers='[{"type":"dns","value":"a.test"}]',
                          status='pending')
        db.session.add(order)
        db.session.flush()

        authz = AcmeAuthorization(
            authorization_id=secrets.token_urlsafe(16),
            order_id=order.order_id, account_id=account_id,
            identifier='{"type":"dns","value":"a.test"}', status='pending')
        db.session.add(authz)
        db.session.flush()

        challenge = AcmeChallenge(
            challenge_id=secrets.token_urlsafe(16),
            authorization_id=authz.authorization_id,
            type='http-01', status='pending', token=secrets.token_urlsafe(16))
        db.session.add(challenge)
        db.session.commit()

        made = {'account_id': account_id,
                'order_id': order.order_id,
                'authorization_id': authz.authorization_id,
                'challenge_id': challenge.challenge_id}

    yield made

    with app.app_context():
        AcmeChallenge.query.filter_by(
            authorization_id=made['authorization_id']).delete(
                synchronize_session=False)
        AcmeAuthorization.query.filter_by(
            authorization_id=made['authorization_id']).delete(
                synchronize_session=False)
        AcmeOrder.query.filter_by(order_id=made['order_id']).delete(
            synchronize_session=False)
        AcmeAccount.query.filter_by(account_id=made['account_id']).delete(
            synchronize_session=False)
        db.session.commit()


class TestNothingIsLeftPointingAtAnAccountThatIsGone:
    def test_the_account_goes(self, app, auth_client,
                              an_account_with_a_challenge):
        made = an_account_with_a_challenge
        response = auth_client.delete(
            f'/api/v2/acme/accounts/{made["account_id"]}')

        assert response.status_code in (200, 204), response.data

        with app.app_context():
            from models.acme_models import AcmeAccount
            assert AcmeAccount.query.filter_by(
                account_id=made['account_id']).count() == 0

    def test_its_authorizations_and_challenges_go_with_it(
            self, app, auth_client, an_account_with_a_challenge):
        made = an_account_with_a_challenge
        auth_client.delete(f'/api/v2/acme/accounts/{made["account_id"]}')

        with app.app_context():
            from models.acme_models import (
                AcmeAuthorization, AcmeChallenge, AcmeOrder)

            left = {
                'orders': AcmeOrder.query.filter_by(
                    order_id=made['order_id']).count(),
                'authorizations': AcmeAuthorization.query.filter_by(
                    authorization_id=made['authorization_id']).count(),
                'challenges': AcmeChallenge.query.filter_by(
                    challenge_id=made['challenge_id']).count(),
            }

        assert left == {'orders': 0, 'authorizations': 0, 'challenges': 0}, (
            f'rows left pointing at an account that is gone: {left}')


@pytest.fixture
def an_account_with_a_preauthorization(app):
    """An authorization that belongs to no order.

    RFC 8555 §7.4.1 lets a client ask for one before it has an order, and the
    column is nullable for exactly that. Walking the account's orders to find
    its authorizations therefore misses them.
    """
    from models.acme_models import AcmeAccount, AcmeAuthorization, AcmeChallenge

    with app.app_context():
        account_id = f'preauthz-{secrets.token_hex(4)}'
        db.session.add(AcmeAccount(account_id=account_id, jwk='{}',
                                   jwk_thumbprint=secrets.token_hex(8),
                                   status='valid'))
        db.session.flush()

        authz = AcmeAuthorization(
            authorization_id=secrets.token_urlsafe(16),
            order_id=None, account_id=account_id,
            identifier='{"type":"dns","value":"pre.test"}', status='pending')
        db.session.add(authz)
        db.session.flush()
        db.session.add(AcmeChallenge(
            challenge_id=secrets.token_urlsafe(16),
            authorization_id=authz.authorization_id,
            type='http-01', status='pending', token=secrets.token_urlsafe(16)))
        db.session.commit()
        made = {'account_id': account_id,
                'authorization_id': authz.authorization_id}

    yield made

    with app.app_context():
        AcmeChallenge.query.filter_by(
            authorization_id=made['authorization_id']).delete(
                synchronize_session=False)
        AcmeAuthorization.query.filter_by(
            authorization_id=made['authorization_id']).delete(
                synchronize_session=False)
        AcmeAccount.query.filter_by(account_id=made['account_id']).delete(
            synchronize_session=False)
        db.session.commit()


@pytest.fixture
def an_account_with_a_client_order(app):
    """A client order naming the local account that started it.

    It is a different thing from the account: the order lives at an external
    authority. Deleting the account must let go of it, not take it along, and
    must not leave it pointing at a row that is gone -- which PostgreSQL
    refuses outright, since the column carries a foreign key.
    """
    from models.acme_models import AcmeAccount, AcmeClientOrder

    with app.app_context():
        account_id = f'clientorder-{secrets.token_hex(4)}'
        db.session.add(AcmeAccount(account_id=account_id, jwk='{}',
                                   jwk_thumbprint=secrets.token_hex(8),
                                   status='valid'))
        db.session.flush()
        order = AcmeClientOrder(
            order_url=f'https://acme.example.test/{secrets.token_hex(4)}',
            domains='["client.test"]', challenge_type='http-01',
            environment='production', key_source='generate',
            status='valid', account_id=account_id)
        db.session.add(order)
        db.session.commit()
        made = {'account_id': account_id, 'order_url': order.order_url}

    yield made

    with app.app_context():
        AcmeClientOrder.query.filter_by(order_url=made['order_url']).delete(
            synchronize_session=False)
        AcmeAccount.query.filter_by(account_id=made['account_id']).delete(
            synchronize_session=False)
        db.session.commit()


class TestEverythingThatNamesTheAccountIsDealtWith:
    def test_a_preauthorization_does_not_survive_its_account(
            self, app, auth_client, an_account_with_a_preauthorization):
        made = an_account_with_a_preauthorization
        auth_client.delete(f'/api/v2/acme/accounts/{made["account_id"]}')

        with app.app_context():
            from models.acme_models import AcmeAuthorization, AcmeChallenge
            left = {
                'authorizations': AcmeAuthorization.query.filter_by(
                    authorization_id=made['authorization_id']).count(),
                'challenges': AcmeChallenge.query.filter_by(
                    authorization_id=made['authorization_id']).count(),
            }
        assert left == {'authorizations': 0, 'challenges': 0}, (
            'an authorization asked for before any order was left behind: '
            f'{left}')

    def test_a_client_order_lets_go_of_the_account(
            self, app, auth_client, an_account_with_a_client_order):
        made = an_account_with_a_client_order
        response = auth_client.delete(
            f'/api/v2/acme/accounts/{made["account_id"]}')

        assert response.status_code in (200, 204), response.data

        with app.app_context():
            from models.acme_models import AcmeClientOrder
            order = AcmeClientOrder.query.filter_by(
                order_url=made['order_url']).one()
            assert order.account_id is None, (
                'the client order still names an account that is gone, which '
                'a database enforcing its foreign keys refuses')
