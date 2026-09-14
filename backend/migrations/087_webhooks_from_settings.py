"""Migration 087: carry settings-stored webhooks into webhook_endpoints.

Two webhook subsystems coexisted. ``/api/v2/settings/webhooks`` stored its
entries as a JSON blob in ``system_config['webhooks']``; nothing ever read
that blob back, so those subscriptions accepted an operator's events and
delivered none of them. ``/api/v2/webhooks`` stores rows in
``webhook_endpoints``, which is what the event bus fans out to.

The settings-backed API is gone. Anything an operator configured through it
is moved here so it starts being delivered instead of being dropped, and the
blob is removed so the move happens once. Entries are matched on name+url so
a re-run, or a duplicate already created through the surviving API, does not
create a second endpoint.
"""

import json
import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True

_CONFIG_KEY = 'webhooks'


def _entries(raw):
    """Legacy rows worth migrating: a name and a url are the minimum."""
    try:
        parsed = json.loads(raw) if raw else []
    except Exception:
        logger.warning("087: system_config['webhooks'] is not JSON, skipping")
        return []
    if not isinstance(parsed, list):
        return []
    out = []
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        name = (entry.get('name') or '').strip()
        url = (entry.get('url') or '').strip()
        if not name or not url:
            continue
        events = entry.get('events')
        if not isinstance(events, list):
            events = []
        out.append({
            'name': name[:100],
            'url': url[:500],
            'events': json.dumps([str(e) for e in events]),
            'enabled': bool(entry.get('enabled', True)),
        })
    return out


def _upgrade_sqlite(conn):
    row = conn.execute(
        "SELECT value FROM system_config WHERE key = ?", (_CONFIG_KEY,)).fetchone()
    if not row:
        return
    moved = 0
    for entry in _entries(row[0]):
        exists = conn.execute(
            "SELECT 1 FROM webhook_endpoints WHERE name = ? AND url = ?",
            (entry['name'], entry['url'])).fetchone()
        if exists:
            continue
        conn.execute(
            "INSERT INTO webhook_endpoints "
            "(name, url, events, enabled, auth_type, failure_count) "
            "VALUES (?, ?, ?, ?, 'none', 0)",
            (entry['name'], entry['url'], entry['events'],
             1 if entry['enabled'] else 0))
        moved += 1
    conn.execute("DELETE FROM system_config WHERE key = ?", (_CONFIG_KEY,))
    conn.commit()
    logger.info("087: moved %d settings webhook(s) to webhook_endpoints (SQLite)", moved)


def _upgrade_pg(conn):
    from sqlalchemy import text

    row = conn.execute(
        text("SELECT value FROM system_config WHERE key = :k"),
        {'k': _CONFIG_KEY}).fetchone()
    if not row:
        return
    moved = 0
    for entry in _entries(row[0]):
        exists = conn.execute(
            text("SELECT 1 FROM webhook_endpoints WHERE name = :n AND url = :u"),
            {'n': entry['name'], 'u': entry['url']}).fetchone()
        if exists:
            continue
        conn.execute(
            text("INSERT INTO webhook_endpoints "
                 "(name, url, events, enabled, auth_type, failure_count) "
                 "VALUES (:n, :u, :e, :en, 'none', 0)"),
            {'n': entry['name'], 'u': entry['url'], 'e': entry['events'],
             'en': entry['enabled']})
        moved += 1
    conn.execute(text("DELETE FROM system_config WHERE key = :k"), {'k': _CONFIG_KEY})
    logger.info("087: moved %d settings webhook(s) to webhook_endpoints (PostgreSQL)",
                moved)


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    # The endpoints are ordinary rows now, and the settings-backed API that
    # read the blob no longer exists. Putting the blob back would recreate a
    # store nothing reads.
    logger.info("087: downgrade is a no-op (endpoints stay in webhook_endpoints)")
