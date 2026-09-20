"""Migration 091 preserves target reload commands on every existing binding."""

import importlib.util
import sqlite3


def _migration():
    spec = importlib.util.spec_from_file_location(
        'm091', 'migrations/091_binding_reload_commands.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_target_command_is_copied_to_certificate_and_crl_bindings():
    conn = sqlite3.connect(':memory:')
    conn.executescript("""
        CREATE TABLE deploy_targets (
            id INTEGER PRIMARY KEY, reload_command VARCHAR(512));
        CREATE TABLE deploy_bindings (
            id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL);
        CREATE TABLE crl_deploy_bindings (
            id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL);
        INSERT INTO deploy_targets VALUES
            (1, 'nginx -t && nginx -s reload'), (2, NULL);
        INSERT INTO deploy_bindings VALUES (10, 1), (11, 2);
        INSERT INTO crl_deploy_bindings VALUES (20, 1), (21, 2);
    """)

    migration = _migration()
    migration.upgrade(conn)

    cert = dict(conn.execute(
        'SELECT id, reload_command FROM deploy_bindings').fetchall())
    crl = dict(conn.execute(
        'SELECT id, reload_command FROM crl_deploy_bindings').fetchall())
    assert cert == {10: 'nginx -t && nginx -s reload', 11: None}
    assert crl == {20: 'nginx -t && nginx -s reload', 21: None}


def test_migration_is_idempotent_and_keeps_binding_override():
    conn = sqlite3.connect(':memory:')
    conn.executescript("""
        CREATE TABLE deploy_targets (
            id INTEGER PRIMARY KEY, reload_command VARCHAR(512));
        CREATE TABLE deploy_bindings (
            id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL,
            reload_command VARCHAR(512));
        CREATE TABLE crl_deploy_bindings (
            id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL,
            reload_command VARCHAR(512));
        INSERT INTO deploy_targets VALUES (1, 'legacy reload');
        INSERT INTO deploy_bindings VALUES (10, 1, 'certificate reload');
        INSERT INTO crl_deploy_bindings VALUES (20, 1, 'crl reload');
    """)

    migration = _migration()
    migration.upgrade(conn)
    migration.upgrade(conn)

    assert conn.execute(
        'SELECT reload_command FROM deploy_bindings').fetchone()[0] == 'certificate reload'
    assert conn.execute(
        'SELECT reload_command FROM crl_deploy_bindings').fetchone()[0] == 'crl reload'
