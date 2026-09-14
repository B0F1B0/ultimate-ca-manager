"""One require_json_body decorator, and it answers what its docstring promises.

Two copies of the decorator existed side by side: ``utils.decorators`` gated on
``request.is_json or request.json is None`` — and ``request.json`` raises
Werkzeug's BadRequest on a malformed body, so the generic 400 handler answered
instead of the decorator, with "Bad request" rather than the documented
"Request body must be valid JSON". ``utils.request_helpers`` used
``get_json(silent=True)`` and answered as documented. Same request, two
answers.
"""

import pytest
from flask import Blueprint, g

from utils.response import success_response

MALFORMED = '{"a": '
DOCUMENTED = 'Request body must be valid JSON'


@pytest.fixture(scope='module')
def json_body_client(app):
    """Two routes, one per import path of the decorator."""
    from utils.decorators import require_json_body as from_decorators
    from utils.request_helpers import require_json_body as from_helpers

    bp = Blueprint('json_body_contract', __name__)

    @bp.route('/api/test-json-body/decorators', methods=['POST'])
    @from_decorators
    def _decorators_route():
        return success_response(data={'body': g.json_data})

    @bp.route('/api/test-json-body/helpers', methods=['POST'])
    @from_helpers
    def _helpers_route():
        return success_response(data={'body': g.json_data})

    app.register_blueprint(bp)
    return app.test_client()


def test_decorator_has_a_single_definition():
    """Both import paths resolve to the same function object."""
    from utils.decorators import require_json_body as from_decorators
    from utils.request_helpers import require_json_body as from_helpers

    assert from_decorators is from_helpers


@pytest.mark.parametrize('route', ['decorators', 'helpers'])
def test_malformed_body_gets_the_documented_message(json_body_client, route):
    """A malformed body is the decorator's own 400, not the generic one."""
    r = json_body_client.post(f'/api/test-json-body/{route}', data=MALFORMED,
                              content_type='application/json')

    assert r.status_code == 400
    assert r.get_json()['message'] == DOCUMENTED


@pytest.mark.parametrize('route', ['decorators', 'helpers'])
def test_missing_content_type_is_rejected(json_body_client, route):
    """Contract kept: a body without the JSON content type is still a 400."""
    r = json_body_client.post(f'/api/test-json-body/{route}', data='{"a": 1}')

    assert r.status_code == 400
    assert r.get_json()['message'] == DOCUMENTED


@pytest.mark.parametrize('route', ['decorators', 'helpers'])
def test_json_null_is_rejected(json_body_client, route):
    """Contract kept: a literal ``null`` body carries no fields to read."""
    r = json_body_client.post(f'/api/test-json-body/{route}', data='null',
                              content_type='application/json')

    assert r.status_code == 400
    assert r.get_json()['message'] == DOCUMENTED


@pytest.mark.parametrize('route', ['decorators', 'helpers'])
def test_empty_object_reaches_the_handler(json_body_client, route):
    """Contract kept: ``{}`` is valid JSON, so the handler decides.

    This is why the decorator cannot be dropped onto a route guarded by
    ``if not data: return error_response(..., 400)`` — that guard rejects
    ``{}`` and the decorator does not.
    """
    r = json_body_client.post(f'/api/test-json-body/{route}', data='{}',
                              content_type='application/json')

    assert r.status_code == 200
    assert r.get_json()['data']['body'] == {}
