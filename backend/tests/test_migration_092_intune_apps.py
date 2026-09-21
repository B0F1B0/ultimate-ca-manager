"""Migration 092 gives every Intune profile an app registration, sharing one
only between profiles that carried the same credentials: a different secret
for the same tenant and client is kept, never discarded."""

import importlib.util
import logging
import sqlite3

from utils.encryption import encrypt_value


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


def _profiles(conn, rows):
    conn.executemany("INSERT INTO scep_profiles VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)


def _apps(conn):
    return conn.execute(
        'SELECT id, name, tenant_id, client_id, client_secret FROM intune_apps ORDER BY id'
    ).fetchall()


def _bound(conn):
    return dict(conn.execute('SELECT id, intune_app_id FROM scep_profiles').fetchall())


def test_profiles_with_the_same_credentials_share_one_app(app):
    same = encrypt_value('shared-secret')
    conn = sqlite3.connect(':memory:')
    _schema(conn)
    _profiles(conn, [
        (1, 'Windows devices', 1, 'contoso', 'client-1', same, None, 'success'),
        (2, 'iOS devices', 1, 'contoso', 'client-1', same, None, None),
        (3, 'Other tenant', 1, 'fabrikam', 'client-9', encrypt_value('nine'), None, None),
        (4, 'Static challenge', 0, None, None, None, None, None),
        (5, 'Half configured', 1, 'contoso', None, encrypt_value('x'), None, None),
    ])
    with app.app_context():
        _migration().upgrade(conn)

    apps = _apps(conn)
    assert [(a[1], a[2], a[3]) for a in apps] == [
        ('Windows devices', 'contoso', 'client-1'), ('Other tenant', 'fabrikam', 'client-9')]
    assert apps[0][4] == same
    assert _bound(conn) == {1: 1, 2: 1, 3: 2, 4: None, 5: None}
    # The frozen columns are emptied on the profiles that got an app
    assert conn.execute(
        'SELECT COUNT(*) FROM scep_profiles WHERE intune_app_id IS NOT NULL AND '
        '(intune_tenant_id IS NOT NULL OR intune_client_id IS NOT NULL '
        'OR intune_client_secret IS NOT NULL)').fetchone()[0] == 0


def test_the_same_secret_encrypted_twice_still_shares(app):
    """Two profiles set up by hand hold two ciphertexts of one secret."""
    conn = sqlite3.connect(':memory:')
    _schema(conn)
    first, second = encrypt_value('rotated-once'), encrypt_value('rotated-once')
    assert first != second
    _profiles(conn, [
        (1, 'Windows devices', 1, 'contoso', 'client-1', first, None, None),
        (2, 'iOS devices', 1, 'contoso', 'client-1', second, None, None),
    ])
    with app.app_context():
        _migration().upgrade(conn)
    assert len(_apps(conn)) == 1
    assert _bound(conn) == {1: 1, 2: 1}


def test_a_different_secret_keeps_its_own_app_and_is_reported(app, caplog):
    """Entra allows several secrets during a rotation: the profile on the
    other secret must keep enrolling, so nothing is merged away."""
    conn = sqlite3.connect(':memory:')
    _schema(conn)
    _profiles(conn, [
        (1, 'Windows devices', 1, 'contoso', 'client-1', encrypt_value('old-secret'), None, None),
        (2, 'iOS devices', 1, 'contoso', 'client-1', encrypt_value('new-secret'), None, None),
    ])
    with app.app_context(), caplog.at_level(logging.WARNING):
        _migration().upgrade(conn)
    apps = _apps(conn)
    assert [(a[1], a[2], a[3]) for a in apps] == [
        ('Windows devices', 'contoso', 'client-1'), ('iOS devices', 'contoso', 'client-1')]
    assert _bound(conn) == {1: 1, 2: 2}
    assert any('iOS devices' in r.message and 'merge them by hand' in r.message
               for r in caplog.records)


def test_an_unreadable_secret_is_never_merged(app):
    """A ciphertext this key cannot open compares only to itself."""
    conn = sqlite3.connect(':memory:')
    _schema(conn)
    _profiles(conn, [
        (1, 'A', 1, 'contoso', 'client-1', 'ENC:opaque-one', None, None),
        (2, 'B', 1, 'contoso', 'client-1', 'ENC:opaque-two', None, None),
        (3, 'C', 1, 'contoso', 'client-1', 'ENC:opaque-one', None, None),
    ])
    with app.app_context():
        _migration().upgrade(conn)
    assert _bound(conn) == {1: 1, 2: 2, 3: 1}


def test_migration_is_idempotent_and_names_never_collide(app):
    conn = sqlite3.connect(':memory:')
    _schema(conn)
    _profiles(conn, [
        (1, 'Devices', 1, 'contoso', 'client-1', encrypt_value('one'), None, None),
        (2, 'Devices', 1, 'contoso', 'client-2', encrypt_value('two'), None, None),
    ])
    migration = _migration()
    with app.app_context():
        migration.upgrade(conn)
        migration.upgrade(conn)
    names = [r[0] for r in conn.execute('SELECT name FROM intune_apps ORDER BY id')]
    assert names == ['Devices', 'Devices (2)']
