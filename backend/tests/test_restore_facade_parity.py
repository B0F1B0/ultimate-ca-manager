"""The two ways of asking for a restore must refuse the same things.

A restore rewrites the whole database, which is the largest concurrent write
a backend migration could be reading through, and an instance that has
written a new backend's configuration but not yet restarted onto it is still
running on the one it is leaving. The system route refuses both cases: it
takes the migration lock, and it declines while a switch is pending.

The settings route did neither, so which of the two an operator reached
decided whether their restore could land in the middle of a migration, or
onto a backend the next restart throws away.

The settings route always replaces, as its own docstring says. What it must
not do is accept a `mode` and ignore it: the same request then merged an
archive into a live instance from one page and overwrote the whole database
from the other, with nothing said either way.
"""
import io

import pytest


def _upload(client, route, payload=b'not a real archive'):
    return client.post(
        route,
        data={'file': (io.BytesIO(payload), 'x.ucmbkp'),
              'password': 'a-password-that-is-long-enough'},
        content_type='multipart/form-data')


ROUTES = ('/api/v2/system/restore', '/api/v2/settings/backup/restore')


class TestASwitchThatHasNotHappenedYetHoldsBothRoutes:
    @pytest.mark.parametrize('route', ROUTES)
    def test_a_pending_switch_refuses_the_restore(self, app, auth_client,
                                                  monkeypatch, route):
        import importlib

        refusal = 'A backend switch is written and waiting for a restart.'
        patched = 0
        for module in ('api.v2.system.backup', 'api.v2.settings.backup'):
            loaded = importlib.import_module(module)
            if hasattr(loaded, 'pending_switch_refusal'):
                monkeypatch.setattr(loaded, 'pending_switch_refusal',
                                    lambda: refusal)
                patched += 1
        assert patched, (
            f'{route} does not even ask whether a switch is pending')

        response = _upload(auth_client, route)

        assert response.status_code == 409, (
            f'{route} answered {response.status_code}: a restore landing now '
            'is thrown away by the restart the switch is waiting for')


class TestAMigrationHoldsBothRoutes:
    @pytest.mark.parametrize('route', ROUTES)
    def test_a_busy_lock_refuses_the_restore(self, app, auth_client,
                                             monkeypatch, route):
        import importlib

        from services.database_admin.lock import MigrationBusyError

        def busy(*args, **kwargs):
            raise MigrationBusyError('A migration is running.')

        for module in ('api.v2.system.backup', 'api.v2.settings.backup'):
            loaded = importlib.import_module(module)
            if hasattr(loaded, 'database_migration_lock'):
                monkeypatch.setattr(loaded, 'database_migration_lock', busy)

        response = _upload(auth_client, route)

        assert response.status_code == 409, (
            f'{route} answered {response.status_code}: the restore ran while '
            'a migration was reading the database it rewrites')


class TestAModeThatIsNotHonouredIsRefused:
    def test_the_settings_route_refuses_merge(self, app, auth_client):
        response = auth_client.post(
            '/api/v2/settings/backup/restore',
            data={'file': (io.BytesIO(b'not a real archive'), 'x.ucmbkp'),
                  'password': 'a-password-that-is-long-enough',
                  'mode': 'merge'},
            content_type='multipart/form-data')

        assert response.status_code == 400, (
            f'the route answered {response.status_code} for a mode it does '
            'not honour: the caller believes their archive was merged and it '
            'replaced the instance')
        assert b'merge' in response.data.lower(), (
            'the refusal must point at the route that does honour it')

    def test_the_system_route_still_honours_merge(self, app, auth_client):
        """The other direction: refusing everywhere would be just as wrong."""
        response = auth_client.post(
            '/api/v2/system/restore',
            data={'file': (io.BytesIO(b'not a real archive'), 'x.ucmbkp'),
                  'password': 'a-password-that-is-long-enough',
                  'mode': 'merge'},
            content_type='multipart/form-data')

        # The archive is nonsense, so the answer is a refusal about the file,
        # never about the mode.
        assert response.status_code != 400 or b'always replaces' not in \
            response.data.lower()
