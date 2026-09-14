"""How long a certificate has left, computed once.

Three answers to the same question were in circulation:

* ``Certificate.days_remaining`` clamped at zero and returned ``-1`` when the
  row had no expiry date at all;
* ``api/v2/user_certificates`` and ``api/v2/truststore`` returned the signed
  difference, so the same field meant something different depending on which
  endpoint served the row;
* the notification scheduler rounded up where everything else rounded down.

The clamp is the one that did damage, because the screens were written for a
signed number. ``details.expiredDaysAgo`` -- "Certificate expired {{count}}
days ago" -- ships in all nine locales and could never be reached: the value
never went below zero. Four branches in the CSR page testing ``days < 0``
were dead for the same reason, so a certificate that expired a year ago drew
an amber "0 days remaining" instead of a red "Expired". And the one value
that *was* negative, the ``-1`` standing for "no expiry date", fired those
branches -- labelling a certificate that never expires as expired, and
scoring it 0/25 for validity in the compliance report.

So: signed, and ``None`` rather than a magic number for "no expiry date".

Rounding follows the sign, which is what makes the boundary readable:

* time left rounds **up**, so twelve hours left is ``1`` and not ``0``. With
  a floor, a certificate still valid for most of a day was reported as
  ``0`` and the detail panel called it expired while the status badge next
  to it said expiring.
* time past rounds **down**, so twelve hours past expiry is ``-1``.

``0`` is therefore the instant of expiry and nothing else, and ``<= 0`` and
``< 0`` agree everywhere it matters.
"""
from __future__ import annotations

import math
from datetime import datetime
from typing import Optional

from utils.datetime_utils import to_naive_utc, utc_now

# A row with no expiry date has no answer to give. The clamp hid this behind
# `-1`, which every reader testing `< 0` then read as "long expired".
NO_EXPIRY = None


def days_remaining(valid_to: Optional[datetime],
                   now: Optional[datetime] = None) -> Optional[int]:
    """Whole days until *valid_to*, negative once it is past, None if absent."""
    if not valid_to:
        return NO_EXPIRY
    reference = to_naive_utc(now) if now is not None else utc_now()
    seconds = (to_naive_utc(valid_to) - reference).total_seconds()
    if seconds > 0:
        return int(math.ceil(seconds / 86400.0))
    return int(math.floor(seconds / 86400.0))


def has_expired(valid_to: Optional[datetime],
                now: Optional[datetime] = None) -> bool:
    """Whether *valid_to* is in the past. A row with no date has not expired."""
    left = days_remaining(valid_to, now)
    return left is not None and left <= 0
