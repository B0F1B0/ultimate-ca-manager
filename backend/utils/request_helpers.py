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


# ``safe_call`` is defined in utils.safe_call, the module the name belongs to.
# A second copy lived here and the two drifted on one parameter. Re-exported
# so the callers that import it from here keep working.
from utils.safe_call import safe_call  # noqa: F401,E402
