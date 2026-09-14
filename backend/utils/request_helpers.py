"""
Request validation decorators.
"""

import logging

# ``require_json_body`` is defined in utils.decorators, the import path the
# handlers use. A second copy lived here and gated on ``request.get_json``
# while that one gated on ``request.json``, which raises on a malformed body:
# the same request got "Request body must be valid JSON" through one import
# and the generic "Bad request" through the other. Re-exported so the callers
# that import it from here keep working.
from utils.decorators import require_json_body  # noqa: F401

logger = logging.getLogger(__name__)


def safe_call(fn, *args, **kwargs):
    """
    Call fn(*args, **kwargs) silently returning None on any Exception.

    Use for best-effort non-critical operations where failure should not
    propagate (e.g. cleanup, optional cache writes, resource release).
    Logs the exception at DEBUG level so it remains discoverable.

    Usage:
        safe_call(self._socket.close)
        safe_call(os.unlink, tmp_path)
        result = safe_call(parse_optional_field, raw)  # None on failure

    NOT appropriate for:
        - DB commits (use commit_or_rollback)
        - API responses (surface the error to the caller)
        - Mutations where partial failure corrupts state
    """
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        logger.debug("safe_call(%s) suppressed: %s", getattr(fn, '__name__', fn), e)
        return None
