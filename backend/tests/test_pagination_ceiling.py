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

    Read from the syntax tree, and from the nodes rather than from the text of
    a dump: a first version matched substrings, so a route calling
    `query.paginate(...)` looked bounded because the word appeared, and one
    guarded by `admin:system` looked bounded because the word contains `min`.
    It flagged none of the three routes it was written for.
    """

    @staticmethod
    def _reads_per_page_from_the_request(fn):
        """The name a function binds `request.args.get('per_page', ...)` to."""
        import ast

        for node in ast.walk(fn):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            call = node.value
            if not isinstance(target, ast.Name) or not isinstance(call, ast.Call):
                continue
            func = call.func
            if not (isinstance(func, ast.Attribute) and func.attr == 'get'):
                continue
            owner = func.value
            if not (isinstance(owner, ast.Attribute) and owner.attr == 'args'):
                continue
            if call.args and isinstance(call.args[0], ast.Constant) \
                    and call.args[0].value == 'per_page':
                return target.id
        return None

    @staticmethod
    def _is_bounded(fn, name):
        """Whether that name is clamped before it reaches the query."""
        import ast

        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # min(per_page, ...) or min(..., per_page)
            if isinstance(func, ast.Name) and func.id == 'min':
                if any(isinstance(a, ast.Name) and a.id == name
                       for a in node.args):
                    return True
            # paginate(..., max_per_page=...)
            if any(kw.arg == 'max_per_page' for kw in node.keywords):
                return True
        return False

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
                for fn in ast.walk(tree):
                    if not isinstance(fn, ast.FunctionDef):
                        continue
                    bound_to = self._reads_per_page_from_the_request(fn)
                    if bound_to is None:
                        continue    # through the helper, or not paginated
                    if not self._is_bounded(fn, bound_to):
                        unbounded.append(
                            f'{os.path.relpath(path, here)}:{fn.lineno} '
                            f'{fn.name}')

        assert unbounded == [], (
            'these routes read per_page from the request and put no ceiling '
            f'on it: {unbounded}. Use parse_request_pagination.')
