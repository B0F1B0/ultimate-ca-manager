"""
Request decorators for UCM API handlers.
"""

import functools
from flask import request, g
from utils.response import error_response


def require_json_body(f):
    """
    Decorator that returns 400 if the request body is missing or not valid JSON.

    On success, stores the parsed JSON in ``g.json_data`` for the handler to use.

    Parsing goes through ``get_json(silent=True)``: ``request.json`` raises
    Werkzeug's BadRequest on a malformed body, so the generic 400 handler
    answered "Bad request" and the message below was never the one a client
    saw. A body of ``{}`` is valid JSON and reaches the handler -- which is
    why this cannot replace a route's own ``if not data: ... 400`` guard,
    since that guard refuses ``{}``.

    Usage::

        @bp.route('/api/v2/things', methods=['POST'])
        @require_auth(['write:things'])
        @require_json_body
        def create_thing():
            data = g.json_data
            ...
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        data = request.get_json(silent=True)
        if data is None:
            return error_response('Request body must be valid JSON', 400)
        g.json_data = data
        return f(*args, **kwargs)
    return decorated
