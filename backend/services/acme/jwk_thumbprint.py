"""The RFC 7638 JWK thumbprint, computed in one place.

A thumbprint identifies an ACME account key: the server stores it on the
account, the proxy derives it from a request header and compares the two, and
the challenge response is built from it. Three copies computed it, and two of
them disagreed — an OKP key got a thumbprint from the proxy and a ValueError
from the service, for the same JWK.

Two entry points rather than one because the callers want different things
from a key they cannot hash: the service raises, so the ACME error path can
report a malformed key, while the ownership checks want a value they can
compare and fail closed on. Same bytes either way.
"""

import base64
import hashlib
import json
from typing import Any, Dict, Optional

# RFC 7638 §3.2: the required members of each key type, and nothing else.
# Optional members ('alg', 'kid', 'use', …) must not take part, or a client
# that sends one turns a legitimate owner into a thumbprint mismatch.
_REQUIRED_MEMBERS = {
    'RSA': ('e', 'kty', 'n'),
    'EC': ('crv', 'kty', 'x', 'y'),
    'OKP': ('crv', 'kty', 'x'),
}


def jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    """The base64url SHA-256 thumbprint of *jwk*.

    Raises ValueError when the key type is not one this computes, or when a
    required member is missing.
    """
    if not isinstance(jwk, dict):
        raise ValueError('JWK must be an object')

    members = _REQUIRED_MEMBERS.get(jwk.get('kty'))
    if not members:
        raise ValueError(f"Unsupported key type: {jwk.get('kty')}")

    try:
        required = {member: jwk[member] for member in members}
    except KeyError as missing:
        raise ValueError(f'JWK is missing required member: {missing.args[0]}') from missing

    canonical = json.dumps(required, separators=(',', ':'), sort_keys=True)
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()


def jwk_thumbprint_or_none(jwk: Any) -> Optional[str]:
    """The same thumbprint, or None when it cannot be computed.

    For the ownership checks, where an uncomputable thumbprint is not an error
    to report but a comparison that must not match.
    """
    try:
        return jwk_thumbprint(jwk)
    except (ValueError, TypeError):
        return None
