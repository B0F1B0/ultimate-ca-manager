"""Migration 088 on both backends.

Migration 031 seeded five example policies active and unscoped, so the lowest
``max_validity_days`` among them capped every issuance once #335 started
reading the rules. 088 switches off the ones an administrator never adapted,
and must leave alone anything that was adapted.
"""
import importlib
import json
import os
import sqlite3

import pytest
from sqlalchemy import create_engine, text

PG_URL = os.getenv('UCM_TEST_PG_URL')

SHORT_LIVED_RULES = {
    'max_validity_days': 90,
    'allowed_key_types': ['RSA-2048', 'RSA-4096', 'EC-P256', 'EC-P384'],
    'required_extensions': ['keyUsage', 'extendedKeyUsage'],
    'san_restrictions': {
        'max_dns_names': 50,
        'dns_pattern': '',
        'require_approval_for_external': False,
    },
}

SQLITE_SCHEMA = (
    "CREATE TABLE certificate_policies ("
    " id INTEGER PRIMARY KEY, name TEXT, policy_type TEXT, priority INTEGER,"
    " is_active INTEGER, ca_id INTEGER, template_id INTEGER, rules TEXT,"
    " created_by TEXT)",
)

PG_SCHEMA = (
    "CREATE TABLE certificate_policies ("
    " id SERIAL PRIMARY KEY, name VARCHAR(100), policy_type VARCHAR(50),"
    " priority INTEGER, is_active BOOLEAN, ca_id INTEGER, template_id INTEGER,"
    " rules TEXT, created_by VARCHAR(100))",
)


def _migration():
    return importlib.import_module('migrations.088_default_policies_off')


def _rows_sqlite(conn):
    return {name: active for name, active in conn.execute(
        "SELECT name, is_active FROM certificate_policies").fetchall()}


@pytest.fixture()
def sqlite_conn():
    conn = sqlite3.connect(':memory:')
    for statement in SQLITE_SCHEMA:
        conn.execute(statement)
    yield conn
    conn.close()


def _seed_sqlite(conn, **overrides):
    row = {
        'name': 'Short-Lived Automation', 'policy_type': 'issuance', 'priority': 15,
        'is_active': 1, 'ca_id': None, 'template_id': None,
        'rules': json.dumps(SHORT_LIVED_RULES), 'created_by': 'system',
    }
    row.update(overrides)
    conn.execute(
        "INSERT INTO certificate_policies (name, policy_type, priority, is_active,"
        " ca_id, template_id, rules, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        tuple(row[k] for k in ('name', 'policy_type', 'priority', 'is_active',
                               'ca_id', 'template_id', 'rules', 'created_by')))
    conn.commit()


class TestSqlite:
    def test_an_untouched_seed_policy_is_switched_off(self, sqlite_conn):
        _seed_sqlite(sqlite_conn)
        _migration().upgrade(sqlite_conn)
        assert _rows_sqlite(sqlite_conn)['Short-Lived Automation'] == 0

    def test_the_rules_are_left_as_they_are(self, sqlite_conn):
        _seed_sqlite(sqlite_conn)
        _migration().upgrade(sqlite_conn)
        stored = sqlite_conn.execute(
            "SELECT rules FROM certificate_policies").fetchone()[0]
        assert json.loads(stored) == SHORT_LIVED_RULES

    def test_a_key_order_difference_still_counts_as_untouched(self, sqlite_conn):
        # A round trip through the API rewrites the JSON; that is not an edit.
        reordered = dict(reversed(list(SHORT_LIVED_RULES.items())))
        _seed_sqlite(sqlite_conn, rules=json.dumps(reordered))
        _migration().upgrade(sqlite_conn)
        assert _rows_sqlite(sqlite_conn)['Short-Lived Automation'] == 0

    def test_edited_rules_are_left_on(self, sqlite_conn):
        edited = dict(SHORT_LIVED_RULES, max_validity_days=120)
        _seed_sqlite(sqlite_conn, rules=json.dumps(edited))
        _migration().upgrade(sqlite_conn)
        assert _rows_sqlite(sqlite_conn)['Short-Lived Automation'] == 1

    def test_a_policy_given_a_scope_is_left_on(self, sqlite_conn):
        _seed_sqlite(sqlite_conn, ca_id=3)
        _migration().upgrade(sqlite_conn)
        assert _rows_sqlite(sqlite_conn)['Short-Lived Automation'] == 1

    def test_a_policy_someone_else_created_is_left_on(self, sqlite_conn):
        _seed_sqlite(sqlite_conn, created_by='admin')
        _migration().upgrade(sqlite_conn)
        assert _rows_sqlite(sqlite_conn)['Short-Lived Automation'] == 1

    def test_a_policy_of_another_name_is_left_on(self, sqlite_conn):
        _seed_sqlite(sqlite_conn, name='Our 90 day rule')
        _migration().upgrade(sqlite_conn)
        assert _rows_sqlite(sqlite_conn)['Our 90 day rule'] == 1

    def test_a_second_run_changes_nothing(self, sqlite_conn):
        _seed_sqlite(sqlite_conn)
        migration = _migration()
        migration.upgrade(sqlite_conn)
        migration.upgrade(sqlite_conn)
        assert _rows_sqlite(sqlite_conn)['Short-Lived Automation'] == 0

    def test_it_survives_a_database_without_the_table(self, sqlite_conn):
        sqlite_conn.execute("DROP TABLE certificate_policies")
        _migration().upgrade(sqlite_conn)


@pytest.mark.postgres
@pytest.mark.skipif(not PG_URL, reason='UCM_TEST_PG_URL not set')
class TestPostgres:
    @pytest.fixture()
    def connection(self):
        engine = create_engine(PG_URL)
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE IF EXISTS certificate_policies"))
            for statement in PG_SCHEMA:
                conn.execute(text(statement))
        with engine.begin() as conn:
            yield conn
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE IF EXISTS certificate_policies"))
        engine.dispose()

    def _seed(self, conn, **overrides):
        row = {
            'name': 'Short-Lived Automation', 'policy_type': 'issuance',
            'priority': 15, 'is_active': True, 'ca_id': None, 'template_id': None,
            'rules': json.dumps(SHORT_LIVED_RULES), 'created_by': 'system',
        }
        row.update(overrides)
        conn.execute(text(
            "INSERT INTO certificate_policies (name, policy_type, priority,"
            " is_active, ca_id, template_id, rules, created_by) VALUES"
            " (:name, :policy_type, :priority, :is_active, :ca_id, :template_id,"
            " :rules, :created_by)"), row)

    def _active(self, conn, name='Short-Lived Automation'):
        return conn.execute(text(
            "SELECT is_active FROM certificate_policies WHERE name = :n"),
            {'n': name}).scalar()

    def test_an_untouched_seed_policy_is_switched_off(self, connection):
        self._seed(connection)
        _migration().upgrade(connection)
        # BOOLEAN, not the 1/0 the SQLite branch writes.
        assert self._active(connection) is False

    def test_edited_rules_are_left_on(self, connection):
        self._seed(connection, rules=json.dumps(
            dict(SHORT_LIVED_RULES, max_validity_days=120)))
        _migration().upgrade(connection)
        assert self._active(connection) is True

    def test_a_policy_given_a_scope_is_left_on(self, connection):
        self._seed(connection, ca_id=3)
        _migration().upgrade(connection)
        assert self._active(connection) is True

    def test_a_second_run_changes_nothing(self, connection):
        self._seed(connection)
        migration = _migration()
        migration.upgrade(connection)
        migration.upgrade(connection)
        assert self._active(connection) is False
