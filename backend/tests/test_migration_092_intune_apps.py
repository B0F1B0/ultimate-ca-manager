"""Migration 092 gives every Intune profile a shared app registration."""

import importlib.util
import sqlite3


def _migration():
    spec = importlib.util.spec_from_file_location(
        'm092', 'migrations/092_intune_apps.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _schema(conn):
    conn.executescript("""
        CREATE TABLE scep_profiles (
            id INTEGER PRIMARY KEY, name VARCHAR(100) NOT NULL,
            intune_enabled BOOLEAN NOT NULL DEFAULT 0,
            intune_tenant_id VARCHAR(255), intune_client_id VARCHAR(255),
            intune_client_secret TEXT,
            intune_last_test_at DATETIME, intune_last_test_result VARCHAR(255));
    """)


def test_profiles_sharing_a_tenant_and_client_share_one_app():
    conn = sqlite3.connect(':memory:')
    _schema(conn)
    conn.executemany(
        "INSERT INTO scep_profiles VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [
            (1, 'Windows devices', 1, 'contoso', 'client-1', 'ENC:one', None, 'success'),
            (2, 'iOS devices', 1, 'contoso', 'client-1', 'ENC:two', None, None),
            (3, 'Other tenant', 1, 'fabrikam', 'client-9', 'ENC:nine', None, None),
            (4, 'Static challenge', 0, None, None, None, None, None),
            (5, 'Half configured', 1, 'contoso', None, 'ENC:x', None, None),
        ])
    _migration().upgrade(conn)

    apps = conn.execute(
        'SELECT id, name, tenant_id, client_id, client_secret, last_test_result '
        'FROM intune_apps ORDER BY id').fetchall()
    assert apps == [
        (1, 'Windows devices', 'contoso', 'client-1', 'ENC:one', 'success'),
        (2, 'Other tenant', 'fabrikam', 'client-9', 'ENC:nine', None),
    ]
    bound = dict(conn.execute('SELECT id, intune_app_id FROM scep_profiles').fetchall())
    assert bound == {1: 1, 2: 1, 3: 2, 4: None, 5: None}
    # The frozen columns are emptied on the profiles that got an app
    cleared = conn.execute(
        'SELECT id FROM scep_profiles WHERE intune_app_id IS NOT NULL AND '
        '(intune_tenant_id IS NOT NULL OR intune_client_id IS NOT NULL '
        'OR intune_client_secret IS NOT NULL)').fetchall()
    assert cleared == []


def test_migration_is_idempotent_and_names_never_collide():
    conn = sqlite3.connect(':memory:')
    _schema(conn)
    conn.executemany(
        "INSERT INTO scep_profiles VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [
            (1, 'Devices', 1, 'contoso', 'client-1', 'ENC:one', None, None),
            (2, 'Devices', 1, 'contoso', 'client-2', 'ENC:two', None, None),
        ])
    migration = _migration()
    migration.upgrade(conn)
    migration.upgrade(conn)

    names = [r[0] for r in conn.execute('SELECT name FROM intune_apps ORDER BY id')]
    assert names == ['Devices', 'Devices (2)']
    assert conn.execute('SELECT COUNT(*) FROM intune_apps').fetchone()[0] == 2
