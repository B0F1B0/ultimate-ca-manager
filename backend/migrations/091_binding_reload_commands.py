"""Migration 091: move reload commands from targets to deploy bindings.

A target is a reusable SSH/SFTP connection. Commands are properties of the
certificate or CRL deployment because one host can run several services.
The legacy target column is intentionally retained for downgrade compatibility
but is no longer exposed or executed by the application.
"""

import sqlite3

pg_compatible = True


def _upgrade_sqlite(conn):
    cert_columns = {row[1] for row in conn.execute(
        "PRAGMA table_info(deploy_bindings)")}
    if 'reload_command' not in cert_columns:
        conn.execute(
            "ALTER TABLE deploy_bindings ADD COLUMN reload_command VARCHAR(512)")

    crl_columns = {row[1] for row in conn.execute(
        "PRAGMA table_info(crl_deploy_bindings)")}
    if 'reload_command' not in crl_columns:
        conn.execute(
            "ALTER TABLE crl_deploy_bindings ADD COLUMN reload_command VARCHAR(512)")

    conn.execute("""
        UPDATE deploy_bindings
           SET reload_command = (
               SELECT reload_command FROM deploy_targets
                WHERE deploy_targets.id = deploy_bindings.target_id
           )
         WHERE reload_command IS NULL
    """)
    conn.execute("""
        UPDATE crl_deploy_bindings
           SET reload_command = (
               SELECT reload_command FROM deploy_targets
                WHERE deploy_targets.id = crl_deploy_bindings.target_id
           )
         WHERE reload_command IS NULL
    """)
    conn.commit()


def _upgrade_pg(conn):
    from sqlalchemy import text

    conn.execute(text(
        "ALTER TABLE deploy_bindings ADD COLUMN IF NOT EXISTS "
        "reload_command VARCHAR(512)"))
    conn.execute(text(
        "ALTER TABLE crl_deploy_bindings ADD COLUMN IF NOT EXISTS "
        "reload_command VARCHAR(512)"))
    conn.execute(text("""
        UPDATE deploy_bindings AS binding
           SET reload_command = target.reload_command
          FROM deploy_targets AS target
         WHERE target.id = binding.target_id
           AND binding.reload_command IS NULL
    """))
    conn.execute(text("""
        UPDATE crl_deploy_bindings AS binding
           SET reload_command = target.reload_command
          FROM deploy_targets AS target
         WHERE target.id = binding.target_id
           AND binding.reload_command IS NULL
    """))


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    # Keep the nullable columns. SQLite cannot drop them safely on every
    # supported version, and older application versions simply ignore them.
    pass
