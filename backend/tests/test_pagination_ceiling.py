"""No listing route hands back as many rows as it is asked for.

The page size is a matter of taste per listing: twenty-five certificates and
fifty log lines are not the same density, and the audit's own decision was
that only the ceiling has to be shared. Three routes had none at all, so
`per_page=1000000` loaded the whole table into memory and serialised it, from
an ordinary account for the activity log; the other two want an administrator.

`utils/pagination.parse_request_pagination` is where the ceiling lives.
"""
import json
import pytest

from utils.pagination import parse_request_pagination


# The three routes that had no ceiling at all.
UNBOUNDED_BEFORE = (
    '/api/v2/settings/audit-logs',
    '/api/v2/account/activity',
    '/api/v2/settings/backup/history',
)



def _asks_for_per_page(node):
    """Whether this expression is `request.args.get('per_page', ...)`."""
    import ast

    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not (isinstance(func, ast.Attribute) and func.attr == 'get'):
        return False
    owner = func.value
    if not (isinstance(owner, ast.Attribute) and owner.attr == 'args'):
        return False
    return bool(node.args) and isinstance(node.args[0], ast.Constant) \
        and node.args[0].value == 'per_page'


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

    _asks_the_request_for_per_page = staticmethod(
        lambda node: _asks_for_per_page(node))

    @classmethod
    def _reads_per_page_from_the_request(cls, fn):
        """The assignment that binds the requested page size, or None.

        The call does not have to be the whole right-hand side. Written
        `per_page = min(request.args.get('per_page', 50, type=int), 100)` the
        read is buried inside the clamp, and looking only at the top of the
        assignment walked straight past four routes, one of them the listing
        the audit page itself uses.
        """
        import ast

        for node in ast.walk(fn):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            if not isinstance(node.targets[0], ast.Name):
                continue
            if any(cls._asks_the_request_for_per_page(sub)
                   for sub in ast.walk(node.value)):
                return node
        return None

    @staticmethod
    def _is_bounded(fn, assignment):
        """Whether the page size is clamped at both ends before the query.

        A ceiling alone is not enough. `min(per_page, 100)` leaves a negative
        page size untouched, and a negative LIMIT means no limit at all on
        SQLite while PostgreSQL refuses the statement, so the same request
        returned the whole table on one backend and an error on the other.
        The floor is the half that was missing everywhere it was missing.

        The clamp counts whether it wraps the read in place, as
        `min(max(1, request.args.get(...)), 100)`, or comes later by name.
        """
        import ast

        name = assignment.targets[0].id
        has_ceiling = has_floor = False

        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            if any(kw.arg == 'max_per_page' for kw in node.keywords):
                return True     # paginate() clamps both ends itself
            func = node.func
            if not (isinstance(func, ast.Name) and func.id in ('min', 'max')):
                continue
            # Either this clamp wraps the request read, or it names the
            # variable the read was bound to.
            about_it = any(
                isinstance(sub, ast.Name) and sub.id == name
                for sub in ast.walk(node))
            if not about_it:
                for sub in ast.walk(node):
                    if sub is not node and isinstance(sub, ast.Call) \
                            and _asks_for_per_page(sub):
                        about_it = True
                        break
            if not about_it:
                continue
            if func.id == 'min':
                has_ceiling = True
            else:
                has_floor = True

        return has_ceiling and has_floor

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
                    if not isinstance(fn, (ast.FunctionDef,
                                          ast.AsyncFunctionDef)):
                        continue
                    assignment = self._reads_per_page_from_the_request(fn)
                    if assignment is None:
                        continue    # through the helper, or not paginated
                    if not self._is_bounded(fn, assignment):
                        unbounded.append(
                            f'{os.path.relpath(path, here)}:{fn.lineno} '
                            f'{fn.name}')

        assert unbounded == [], (
            'these routes read per_page from the request and do not put both '
            f'a floor and a ceiling on it: {unbounded}. Use '
            'parse_request_pagination, which does both.')


class TestAFloorAsWellAsACeiling:
    """A page size below one is not a small page, it is no limit at all.

    `min(per_page, 100)` reads as a bound and is only half of one. A negative
    value passed through it untouched and reached the query, where SQLite
    reads `LIMIT -1` as no limit and hands back the whole table, while
    PostgreSQL refuses the statement and the route answers 500. The same
    request, two backends, two different wrong answers.
    """

    @pytest.mark.parametrize("route", [
        '/api/v2/audit/logs',
        '/api/v2/settings/notifications/logs',
        '/api/v2/user-certificates',
        '/api/v2/acme/history',
    ])
    def test_a_negative_page_size_is_not_an_unlimited_one(
            self, auth_client, route):
        r = auth_client.get(f'{route}?per_page=-1')
        assert r.status_code == 200, f'{route} answered {r.status_code}'
        body = json.loads(r.data)
        # Some of these report the page size in `meta`, others inside `data`.
        meta = body.get('meta') or {}
        data = body.get('data')
        reported = meta.get('per_page')
        if reported is None and isinstance(data, dict):
            reported = data.get('per_page')
            if reported is None:
                reported = (data.get('pagination') or {}).get('per_page')
        assert reported is not None, f'{route} reports no page size at all'
        assert reported >= 1, (
            f'{route} passed a page size of {reported} to the query; on '
            'SQLite that is the whole table and on PostgreSQL it is an error')
