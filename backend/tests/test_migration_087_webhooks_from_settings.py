"""Migration 087 on both backends.

All of the decision logic is shared, and six tests cover it; what had never
run is `_upgrade_pg`. It is the branch that moves an operator's webhook
subscriptions onto the table the event bus reads, so a failure there is a
silent one: the settings blob is deleted either way.
"""
import importlib
import json
import os
import sqlite3

import pytest
from sqlalchemy import create_engine, text

PG_URL = os.getenv('UCM_TEST_PG_URL')

BLOB = json.dumps([
    {'name': 'Ops channel', 'url': 'https://hooks.example/ops',
     'events': ['cert_issued', 'cert_revoked'], 'enabled': True},
    {'name': 'Quiet channel', 'url': 'https://hooks.example/quiet',
     'events': [], 'enabled': False},
    {'name': '', 'url': 'https://hooks.example/nameless'},
])

SQLITE_SCHEMA = (
    "CREATE TABLE system_config (key TEXT PRIMARY KEY, value TEXT)",
    "CREATE TABLE webhook_endpoints ("
    " id INTEGER PRIMARY KEY, name TEXT, url TEXT, events TEXT,"
    " enabled INTEGER, auth_type TEXT, failure_count INTEGER)",
)

PG_SCHEMA = (
    "CREATE TABLE system_config (key VARCHAR(255) PRIMARY KEY, value TEXT)",
    "CREATE TABLE webhook_endpoints ("
    " id SERIAL PRIMARY KEY, name VARCHAR(100), url VARCHAR(500), events TEXT,"
    " enabled BOOLEAN, auth_type VARCHAR(20), failure_count INTEGER)",
)


def _migration():
    return importlib.import_module('migrations.087_webhooks_from_settings')


def test_sqlite_moves_the_entries_and_drops_the_blob():
    connection = sqlite3.connect(':memory:')
    for statement in SQLITE_SCHEMA:
        connection.execute(statement)
    connection.execute("INSERT INTO system_config VALUES ('webhooks', ?)", (BLOB,))
    migration = _migration()
    migration.upgrade(connection)
    migration.upgrade(connection)

    rows = connection.execute(
        "SELECT name, url, events, enabled FROM webhook_endpoints ORDER BY name").fetchall()
    assert [row[0] for row in rows] == ['Ops channel', 'Quiet channel']
    assert json.loads(rows[0][2]) == ['cert_issued', 'cert_revoked']
    assert connection.execute(
        "SELECT 1 FROM system_config WHERE key = 'webhooks'").fetchone() is None


@pytest.mark.postgres
@pytest.mark.skipif(not PG_URL, reason='UCM_TEST_PG_URL not set')
class TestPostgres:
    @pytest.fixture()
    def connection(self):
        """A schema of its own, named per worker.

        The bench is one database shared with the other PostgreSQL tests, and
        a fixed schema name has two xdist workers dropping each other's.
        """
        worker = os.getenv('PYTEST_XDIST_WORKER', 'main')
        schema = f'migtest_087_{worker}'
        engine = create_engine(PG_URL)
        conn = engine.connect()
        conn.execute(text(f"DROP SCHEMA IF EXISTS {schema} CASCADE"))
        conn.execute(text(f"CREATE SCHEMA {schema}"))
        conn.execute(text(f"SET search_path TO {schema}"))
        for statement in PG_SCHEMA:
            conn.execute(text(statement))
        conn.execute(text("INSERT INTO system_config VALUES ('webhooks', :v)"),
                     {'v': BLOB})
        conn.commit()
        try:
            yield conn
        finally:
            conn.rollback()
            conn.execute(text(f"DROP SCHEMA IF EXISTS {schema} CASCADE"))
            conn.commit()
            conn.close()
            engine.dispose()

    def test_the_entries_are_moved(self, connection):
        _migration().upgrade(connection)
        rows = connection.execute(text(
            "SELECT name, url, events, enabled FROM webhook_endpoints "
            "ORDER BY name")).fetchall()
        assert [row[0] for row in rows] == ['Ops channel', 'Quiet channel']
        assert rows[0][1] == 'https://hooks.example/ops'
        assert json.loads(rows[0][2]) == ['cert_issued', 'cert_revoked']
        # BOOLEAN, not the 1/0 the SQLite branch writes.
        assert rows[0][3] is True
        assert rows[1][3] is False

    def test_the_blob_is_removed(self, connection):
        _migration().upgrade(connection)
        assert connection.execute(text(
            "SELECT 1 FROM system_config WHERE key = 'webhooks'")).fetchone() is None

    def test_a_second_run_creates_nothing(self, connection):
        migration = _migration()
        migration.upgrade(connection)
        # The blob is gone, so the re-run is the no-op an interrupted upgrade
        # depends on.
        migration.upgrade(connection)
        count = connection.execute(text(
            "SELECT count(*) FROM webhook_endpoints")).scalar()
        assert count == 2

    def test_an_endpoint_already_there_is_not_duplicated(self, connection):
        connection.execute(text(
            "INSERT INTO webhook_endpoints (name, url, events, enabled, "
            "auth_type, failure_count) VALUES "
            "('Ops channel', 'https://hooks.example/ops', '[]', true, 'none', 0)"))
        _migration().upgrade(connection)
        names = [row[0] for row in connection.execute(text(
            "SELECT name FROM webhook_endpoints ORDER BY id")).fetchall()]
        assert names == ['Ops channel', 'Quiet channel']
