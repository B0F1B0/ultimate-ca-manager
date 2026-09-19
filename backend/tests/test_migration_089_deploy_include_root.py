"""Migration 089 adds an opt-in root flag to deploy bindings."""

import importlib
import sqlite3


def test_migration_preserves_existing_bindings_and_is_idempotent():
    migration = importlib.import_module('migrations.089_deploy_binding_include_root')
    conn = sqlite3.connect(':memory:')
    conn.execute("""
        CREATE TABLE deploy_bindings (
            id INTEGER PRIMARY KEY,
            target_id INTEGER NOT NULL,
            certificate_id INTEGER NOT NULL,
            fullchain_path VARCHAR(512)
        )
    """)
    conn.execute(
        "INSERT INTO deploy_bindings "
        "(id, target_id, certificate_id, fullchain_path) VALUES (1, 1, 1, '/tmp/fullchain.pem')")

    migration.upgrade(conn)

    columns = {row[1]: row for row in conn.execute(
        'PRAGMA table_info(deploy_bindings)').fetchall()}
    assert 'include_root' in columns
    assert conn.execute(
        'SELECT include_root FROM deploy_bindings WHERE id = 1').fetchone()[0] == 1

    # A retry must not overwrite a choice made after the first upgrade.
    conn.execute('UPDATE deploy_bindings SET include_root = 0 WHERE id = 1')
    migration.upgrade(conn)
    assert conn.execute(
        'SELECT include_root FROM deploy_bindings WHERE id = 1').fetchone()[0] == 0
