"""Migration 088: switch off the example policies nobody adapted.

Migration 031 seeded five policies as examples, but seeded them active and
unscoped: no ``ca_id``, no ``template_id``, an empty ``dns_pattern``. Their
ceilings contradict each other (397, 730, 90, 365), which is what examples do
and what simultaneous rules must not do. They bound nothing until #335 made
issuance read the rules; from then on the lowest ceiling among them applied to
every request, so a certificate asked for three years came back valid for the
ninety days of "Short-Lived Automation" with nothing said about it.

A policy is switched off only if it is still exactly what 031 wrote: the same
name, created by ``system``, no scope, and rules equal to the seed. Anything
an administrator renamed, scoped, rewrote or created themselves is left alone,
including a policy that deliberately caps validity.

The rows stay, so the examples remain in the interface to be scoped and
enabled on purpose.
"""

import json
import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True

# The rules exactly as migration 031 wrote them.
SEEDED_RULES = {
    'Web Server TLS (Public)': {
        'max_validity_days': 397,
        'allowed_key_types': ['RSA-2048', 'RSA-4096', 'EC-P256', 'EC-P384'],
        'required_extensions': ['keyUsage', 'extendedKeyUsage', 'subjectAltName'],
        'san_restrictions': {
            'max_dns_names': 100,
            'dns_pattern': '',
            'require_approval_for_external': False,
        },
    },
    'Internal PKI (Private)': {
        'max_validity_days': 730,
        'allowed_key_types': ['RSA-2048', 'RSA-4096', 'EC-P256', 'EC-P384', 'EC-P521'],
        'required_extensions': ['keyUsage'],
        'san_restrictions': {
            'max_dns_names': 250,
            'dns_pattern': '',
            'require_approval_for_external': False,
        },
    },
    'Short-Lived Automation': {
        'max_validity_days': 90,
        'allowed_key_types': ['RSA-2048', 'RSA-4096', 'EC-P256', 'EC-P384'],
        'required_extensions': ['keyUsage', 'extendedKeyUsage'],
        'san_restrictions': {
            'max_dns_names': 50,
            'dns_pattern': '',
            'require_approval_for_external': False,
        },
    },
    'Code Signing': {
        'max_validity_days': 365,
        'allowed_key_types': ['RSA-4096', 'EC-P256', 'EC-P384'],
        'required_extensions': ['keyUsage', 'extendedKeyUsage'],
        'san_restrictions': {
            'max_dns_names': 0,
            'dns_pattern': '',
            'require_approval_for_external': False,
        },
    },
    'Wildcard Certificates': {
        'max_validity_days': 397,
        'allowed_key_types': ['RSA-2048', 'RSA-4096', 'EC-P256', 'EC-P384'],
        'required_extensions': ['keyUsage', 'extendedKeyUsage', 'subjectAltName'],
        'san_restrictions': {
            'max_dns_names': 10,
            'dns_pattern': '*.',
            'require_approval_for_external': True,
        },
    },
}


def _is_untouched(name, rules_text, ca_id, template_id, created_by):
    """Whether this row is still exactly what 031 wrote.

    The rules are compared as parsed JSON: a round trip through the API
    reorders the keys, which is not an edit."""
    if created_by != 'system' or ca_id is not None or template_id is not None:
        return False
    expected = SEEDED_RULES.get(name)
    if expected is None:
        return False
    try:
        return json.loads(rules_text or '{}') == expected
    except (ValueError, TypeError):
        return False


def _upgrade_sqlite(conn):
    try:
        rows = conn.execute(
            "SELECT id, name, rules, ca_id, template_id, created_by, is_active "
            "FROM certificate_policies").fetchall()
    except sqlite3.OperationalError:
        logger.info("088: no certificate_policies table, nothing to do")
        return
    off = 0
    for pid, name, rules, ca_id, template_id, created_by, is_active in rows:
        if not is_active or not _is_untouched(name, rules, ca_id, template_id, created_by):
            continue
        conn.execute("UPDATE certificate_policies SET is_active = 0 WHERE id = ?", (pid,))
        off += 1
    conn.commit()
    logger.info("088: switched off %d unadapted example policy/policies (SQLite)", off)


def _upgrade_pg(conn):
    from sqlalchemy import text
    from sqlalchemy.exc import ProgrammingError

    try:
        rows = conn.execute(text(
            "SELECT id, name, rules, ca_id, template_id, created_by, is_active "
            "FROM certificate_policies")).fetchall()
    except ProgrammingError:
        logger.info("088: no certificate_policies table, nothing to do")
        return
    off = 0
    for pid, name, rules, ca_id, template_id, created_by, is_active in rows:
        if not is_active or not _is_untouched(name, rules, ca_id, template_id, created_by):
            continue
        conn.execute(text(
            "UPDATE certificate_policies SET is_active = false WHERE id = :id"),
            {'id': pid})
        off += 1
    logger.info("088: switched off %d unadapted example policy/policies (PostgreSQL)", off)


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    # Turning them back on would re-impose a ninety-day ceiling on every
    # issuance, which is the defect this migration exists to remove.
    logger.info("088: downgrade is a no-op (example policies stay off)")
