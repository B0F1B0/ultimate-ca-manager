"""One ceiling for certificate validity, and one idea of what a day count is.

``3650`` was written out eleven times across the issuance paths, each with its
own comment and none with a source. The number itself never diverged — what
diverged is the rule around it. The same request body reached three answers:

    {"validity_days": true}

``int(True)`` is ``1``, so ``POST /api/v2/certificates`` issued a certificate
valid until tomorrow and ``POST /api/v2/csrs`` accepted the CSR, while the mTLS
enrolment door refused with a 400 — it was the only one that had thought about
booleans.

So this module holds two things: the bound, and the shape. Range *reporting*
stays with each caller, because the doors word their refusals differently and
those messages are part of their contract.

Not in here, deliberately: audit-log retention, notification alert days, report
windows and backup retention also cap at 3650 days. They are different
quantities that happen to share a number, and folding them together would mean
one of them could never move on its own.
"""
from __future__ import annotations

import re
from typing import Optional

MIN_VALIDITY_DAYS = 1
# ~10 years. The CA/Browser Forum caps public TLS far lower (398 days), but an
# internal PKI routinely issues device and infrastructure certificates well
# past that; beyond ten years the scheduler's date arithmetic is the next
# thing to give way.
MAX_VALIDITY_DAYS = 3650

_INTEGER_TEXT_RE = re.compile(r'^[+-]?\d+$')


def coerce_validity_days(value) -> Optional[int]:
    """The integer number of days *value* denotes, or None.

    Shape only: a value out of range comes back as the integer it is, and the
    caller decides what to say about it.

    Refused: ``True``/``False`` (a JSON boolean is not a day count, however
    happily ``int()`` turns it into one), a fractional float, and any string
    that is not a plain integer. Accepted: an int, an integral float such as
    ``30.0``, and a decimal string such as ``"30"`` or ``"-5"`` — the negative
    reaches the caller's range check, which is where it was always reported.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    if isinstance(value, str):
        text = value.strip()
        return int(text) if _INTEGER_TEXT_RE.match(text) else None
    return None


def validity_days_in_range(value: int) -> bool:
    """Whether an already-coerced day count is within the issuance bounds."""
    return MIN_VALIDITY_DAYS <= value <= MAX_VALIDITY_DAYS


__all__ = [
    'MIN_VALIDITY_DAYS',
    'MAX_VALIDITY_DAYS',
    'coerce_validity_days',
    'validity_days_in_range',
]

# Two defaults, named apart because they answer different questions: a
# template carries the published CA/B maximum, a certificate created without
# one gets a year. Exporting a template without `validity_days` and importing
# it back used to change it from one to the other.
DEFAULT_TEMPLATE_VALIDITY_DAYS = 397
DEFAULT_CERTIFICATE_VALIDITY_DAYS = 365
