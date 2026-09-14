"""One shape for every authenticated-session response.

Password login, 2FA login, mTLS login, WebAuthn login, LDAP login and
``GET /api/v2/auth/verify`` all hand the SPA the same picture of the session:
who the user is, what they may do, the CSRF token to use next, the display
settings, and whether a password change is being forced.

Six hand-written copies of that body had drifted. ``force_password_change``
was on the five login responses and missing from ``/verify`` — and the SPA
restores its session through ``/verify`` (``AuthContext.checkSession``), so
reloading the page, or arriving through the SSO redirect, dropped the forced
change on the floor. The modal is the whole enforcement, so it was a reload
away from being skipped.
"""
from __future__ import annotations

from models import SystemConfig
from services.settings_registry import effective


def display_settings() -> dict:
    """Timezone, date format and time visibility, as the SPA expects them.

    These are instance-wide rows, and the settings screen shows the same
    three. It resolves them through the registry while this read tested
    `show_time` against the one literal word `'false'`, so a row holding
    `0`, `no` or `off` -- all of which the screen reports as off -- came out
    of here as on and every timestamp in the product kept its clock.
    """
    tz_row = SystemConfig.query.filter_by(key='timezone').first()
    return {
        'timezone': tz_row.value if tz_row else 'UTC',
        'date_format': effective('date_format'),
        'show_time': effective('show_time'),
    }


def user_summary(user) -> dict:
    """The user block the login responses carry."""
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'full_name': user.full_name,
        'role': user.role,
        'active': user.active,
    }


def auth_session_payload(user, *, permissions, auth_method, csrf_token,
                         user_block=None, **extra) -> dict:
    """Body shared by every authenticated-session response.

    ``user_block`` overrides the user summary for ``/auth/verify``, which has
    always returned a narrower one. ``extra`` carries the fields that belong
    to a single endpoint (the mTLS certificate, the LDAP enrolment flag, the
    session bookkeeping ``/verify`` adds).
    """
    payload = {
        'user': user_summary(user) if user_block is None else user_block,
        'role': user.role,
        'permissions': permissions,
        'auth_method': auth_method,
        'csrf_token': csrf_token,
        'force_password_change': user.force_password_change or False,
        **display_settings(),
    }
    payload.update(extra)
    return payload
