"""No listing route hands back as many rows as it is asked for.

The page size is a matter of taste per listing: twenty-five certificates and
fifty log lines are not the same density, and the audit's own decision was
that only the ceiling has to be shared. Three routes had none at all, so
`per_page=1000000` loaded the whole table into memory and serialised it, from
an ordinary account in two of the three cases.

`utils/pagination.parse_request_pagination` is where the ceiling lives.
"""
import pytest

from utils.pagination import parse_request_pagination


# (route, whether an ordinary account reaches it)
UNBOUNDED_BEFORE = (
    '/api/v2/settings/audit-logs',
    '/api/v2/account/activity',
    '/api/v2/settings/backup/history',
)


class TestTheCeilingIsShared:
    def test_the_helper_is_where_it_is_written(self, app):
        with app.test_request_context('/?per_page=1000000'):
            _page, per_page = parse_request_pagination()
        assert per_page == 100

    def test_a_page_below_one_is_brought_back(self, app):
        with app.test_request_context('/?page=0&per_page=0'):
            page, per_page = parse_request_pagination()
        assert (page, per_page) == (1, 1)


class TestNoRouteHandsBackWhatItIsAskedFor:
    @pytest.mark.parametrize('route', UNBOUNDED_BEFORE)
    def test_an_enormous_page_is_capped(self, app, auth_client, route):
        response = auth_client.get(f'{route}?per_page=1000000')

        assert response.status_code == 200, response.data
        meta = (response.get_json() or {}).get('meta') or {}
        asked = meta.get('per_page')
        assert asked is not None, (
            f'{route} does not say what page size it used, so nothing can '
            'check it')
        assert asked <= 100, (
            f'{route} answered with per_page={asked}: the whole table is '
            'loaded and serialised for one request')


class TestNoListingRouteIsLeftWithoutACeiling:
    """A source scan, because an unbounded page size is invisible until the
    day someone asks for a million rows.

    Read from the parsed source: a route that takes `per_page` from the query
    string itself, rather than through the shared helper, is one that has to
    bound it on its own, and three of them did not.
    """

    def test_every_route_taking_per_page_bounds_it(self):
        import ast
        import os

        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        unbounded = []

        for base, _dirs, names in os.walk(os.path.join(here, 'api')):
            if '__pycache__' in base:
                continue
            for name in names:
                if not name.endswith('.py'):
                    continue
                path = os.path.join(base, name)
                tree = ast.parse(open(path).read())
                for node in ast.walk(tree):
                    if not isinstance(node, ast.FunctionDef):
                        continue
                    body = ast.dump(node)
                    takes_it = "'per_page'" in body and 'args' in body
                    bounds_it = ('min' in body or 'max_per_page' in body
                                 or 'parse_request_pagination' in body
                                 or 'paginate' in body)
                    if takes_it and not bounds_it:
                        unbounded.append(
                            f'{os.path.relpath(path, here)}:{node.lineno} '
                            f'{node.name}')

        assert unbounded == [], (
            'these routes read per_page from the request and put no ceiling '
            f'on it: {unbounded}. Use parse_request_pagination.')
