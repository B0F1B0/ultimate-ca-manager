"""One place decides CSRF (DUP-SEC-003).

``security/csrf.py`` carried two enforcement bodies: the ``before_request``
middleware every request goes through, and a ``csrf_protect`` decorator with
the same body *minus* the ``X-API-Key`` skip. No route ever wore the
decorator, so nothing enforced the stricter rule — but a route that picked it
up later would have answered 403 to integration traffic the middleware admits,
and the discrepancy was invisible from the route.

The decorator is gone. These tests pin what the middleware actually does, so
the rule that survived is written down, and catch a second enforcement path
coming back.
"""
import ast
import pathlib

import pytest
from flask import g


def _middleware(app):
    return next(
        f for f in app.before_request_funcs.get(None, [])
        if f.__name__ == 'check_csrf'
    )


@pytest.fixture
def csrf_on(monkeypatch):
    """CSRF is disabled in the test app; these tests need the real rule."""
    monkeypatch.setenv('CSRF_DISABLED', 'false')


def test_an_api_key_request_needs_no_csrf_token(app, csrf_on):
    with app.test_request_context(
        '/api/v2/users', method='POST', headers={'X-API-Key': 'an-integration-key'}
    ):
        g.user_id = 1
        assert _middleware(app)() is None


def test_a_session_request_without_a_token_is_refused(app, csrf_on):
    with app.test_request_context('/api/v2/users', method='POST'):
        g.user_id = 1
        response, status = _middleware(app)()
        assert status == 403
        assert 'CSRF validation failed' in response.get_json()['message']


def test_a_session_request_with_its_token_is_admitted(app, csrf_on):
    from security.csrf import CSRFProtection

    with app.test_request_context('/api/v2/users', method='POST'):
        token = CSRFProtection.generate_token(1)
    with app.test_request_context(
        '/api/v2/users', method='POST', headers={'X-CSRF-Token': token}
    ):
        g.user_id = 1
        assert _middleware(app)() is None


def test_there_is_only_one_csrf_enforcement_path():
    """A decorator that duplicates the middleware minus one exemption is how
    two answers to the same request came back last time."""
    import security
    import security.csrf as csrf_module

    assert not hasattr(csrf_module, 'csrf_protect')
    assert 'csrf_protect' not in getattr(security, '__all__', [])

    root = pathlib.Path(__file__).resolve().parent.parent
    hits = []
    for path in root.rglob('*.py'):
        if '__pycache__' in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding='utf-8'))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            for dec in getattr(node, 'decorator_list', []):
                target = dec.func if isinstance(dec, ast.Call) else dec
                name = getattr(target, 'id', None) or getattr(target, 'attr', None)
                if name == 'csrf_protect':
                    hits.append(f'{path.relative_to(root)}:{node.lineno}')
    assert hits == []
