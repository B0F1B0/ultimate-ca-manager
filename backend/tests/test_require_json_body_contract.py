"""One require_json_body decorator, and it answers what its docstring promises.

Two copies of the decorator existed side by side: ``utils.decorators`` gated on
``request.is_json or request.json is None`` — and ``request.json`` raises
Werkzeug's BadRequest on a malformed body, so the generic 400 handler answered
instead of the decorator, with "Bad request" rather than the documented
"Request body must be valid JSON". ``utils.request_helpers`` used
``get_json(silent=True)`` and answered as documented. Same request, two
answers.
"""

import json

import pytest
from flask import g

from utils.response import success_response

MALFORMED = '{"a": '
DOCUMENTED = 'Request body must be valid JSON'
IMPORT_PATHS = ['utils.decorators', 'utils.request_helpers']


def _decorated(import_path):
    """The echo handler, wrapped by the decorator from *import_path*."""
    import importlib

    decorator = getattr(importlib.import_module(import_path), 'require_json_body')

    @decorator
    def _echo():
        return success_response(data={'body': g.json_data})

    return _echo


def _call(app, import_path, **request_kwargs):
    """Run the decorated handler against a request, without mounting a route.

    The suite's ``app`` fixture is session-scoped and has already served a
    request by the time this runs, so a blueprint cannot be registered on it.
    """
    with app.test_request_context('/json-body-contract', method='POST',
                                  **request_kwargs):
        return app.make_response(_decorated(import_path)())


def test_decorator_has_a_single_definition():
    """Both import paths resolve to the same function object."""
    from utils.decorators import require_json_body as from_decorators
    from utils.request_helpers import require_json_body as from_helpers

    assert from_decorators is from_helpers


@pytest.mark.parametrize('import_path', IMPORT_PATHS)
def test_malformed_body_gets_the_documented_message(app, import_path):
    """A malformed body is the decorator's own 400, not the generic one."""
    r = _call(app, import_path, data=MALFORMED,
              content_type='application/json')

    assert r.status_code == 400
    assert json.loads(r.get_data())['message'] == DOCUMENTED


@pytest.mark.parametrize('import_path', IMPORT_PATHS)
def test_missing_content_type_is_rejected(app, import_path):
    """Contract kept: a body without the JSON content type is still a 400."""
    r = _call(app, import_path, data='{"a": 1}')

    assert r.status_code == 400
    assert json.loads(r.get_data())['message'] == DOCUMENTED


@pytest.mark.parametrize('import_path', IMPORT_PATHS)
def test_json_null_is_rejected(app, import_path):
    """Contract kept: a literal ``null`` body carries no fields to read."""
    r = _call(app, import_path, data='null', content_type='application/json')

    assert r.status_code == 400
    assert json.loads(r.get_data())['message'] == DOCUMENTED


@pytest.mark.parametrize('import_path', IMPORT_PATHS)
def test_empty_object_reaches_the_handler(app, import_path):
    """Contract kept: ``{}`` is valid JSON, so the handler decides.

    This is why the decorator cannot be dropped onto a route guarded by
    ``if not data: return error_response(..., 400)`` — that guard rejects
    ``{}`` and the decorator does not.
    """
    r = _call(app, import_path, data='{}', content_type='application/json')

    assert r.status_code == 200
    assert json.loads(r.get_data())['data']['body'] == {}


def test_a_decorated_route_answers_the_same_way(auth_client):
    """End to end on a route that actually uses it."""
    r = auth_client.post('/api/v2/webhooks', data=MALFORMED,
                         content_type='application/json')

    assert r.status_code == 400
    assert r.get_json()['message'] == DOCUMENTED
