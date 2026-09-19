"""Migration 089: make root inclusion in deployed fullchains optional.

New bindings default to the safer TLS fullchain (leaf + intermediates). Existing
bindings retain the pre-089 behaviour until an administrator changes them, so
an upgrade never silently changes files deployed by an established binding.
"""

import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True


def _upgrade_sqlite(conn):
    tables = {
        row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    if 'deploy_bindings' not in tables:
        logger.info("089: no deploy_bindings table, nothing to do (SQLite)")
        return
    cols = {row[1] for row in conn.execute("PRAGMA table_info(deploy_bindings)")}
    if 'include_root' not in cols:
        conn.execute(
            "ALTER TABLE deploy_bindings ADD COLUMN "
            "include_root BOOLEAN NOT NULL DEFAULT 0")
        conn.execute("UPDATE deploy_bindings SET include_root = 1")
        conn.commit()
        logger.info(
            "089: added deploy_bindings.include_root and preserved existing "
            "binding behaviour (SQLite)")


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text

    inspector = inspect(conn)
    if 'deploy_bindings' not in inspector.get_table_names():
        logger.info("089: no deploy_bindings table, nothing to do (PostgreSQL)")
        return
    cols = {column['name'] for column in inspector.get_columns('deploy_bindings')}
    if 'include_root' not in cols:
        conn.execute(text(
            "ALTER TABLE deploy_bindings ADD COLUMN "
            "include_root BOOLEAN NOT NULL DEFAULT FALSE"))
        conn.execute(text("UPDATE deploy_bindings SET include_root = TRUE"))
        logger.info(
            "089: added deploy_bindings.include_root and preserved existing "
            "binding behaviour (PostgreSQL)")


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    # Added columns are harmless if left behind, matching nearby migrations.
    pass
