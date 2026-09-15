"""Migration 077: allow multiple external ACME client accounts per directory URL.

Issue #276 — UCM historically enforced one ``AcmeClientAccount`` row per
``directory_url`` (inline UNIQUE constraint). Administrators running several
unrelated domains through the same ACME CA (e.g. dns-persist-01) need
administrative separation: several accounts registered with the same CA
directory. This drops the UNIQUE constraint, keeps a plain index for lookup,
and lets ``id`` remain the identity of an account.

SQLite stores the inline UNIQUE in the table schema and cannot drop a column
constraint in place — the table is rebuilt (rename → recreate → copy → drop).
Columns are read dynamically from PRAGMA table_info so the copy stays correct
regardless of which earlier migrations already ran.

PostgreSQL drops the auto-named ``acme_client_accounts_directory_url_key``
constraint and re-adds a plain index.

Idempotent and dual-backend (SQLite + PostgreSQL).
"""
import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True

_INDEX_NAME = 'idx_acme_client_accounts_directory_url'


def _sqlite_directory_url_is_unique(conn) -> bool:
    """True if the table schema declares UNIQUE on directory_url."""
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE name = 'acme_client_accounts'"
    ).fetchone()
    if not row or not row[0]:
        return False
    sql = row[0]
    # INLINE form: "directory_url VARCHAR(500) NOT NULL UNIQUE" or
    # "directory_url ... UNIQUE NOT NULL".
    compiled = ' '.join(line.strip().rstrip(',') for line in sql.splitlines())
    return ('directory_url VARCHAR(500) NOT NULL UNIQUE' in compiled
            or 'directory_url VARCHAR(500) UNIQUE' in compiled)


def _upgrade_sqlite(conn):
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE name = 'acme_client_accounts'"
    ).fetchone()
    if not row:
        logger.info('[077] acme_client_accounts missing: nothing to do (SQLite)')
        return

    if _sqlite_directory_url_is_unique(conn):
        columns = [r[1] for r in conn.execute(
            'PRAGMA table_info(acme_client_accounts)'
        ).fetchall()]
        col_list = ', '.join(columns)

        new_schema = row[0].replace(
            'NOT NULL UNIQUE', 'NOT NULL', 1
        ).replace('acme_client_accounts', 'acme_client_accounts_new', 1)

        conn.execute(
            'ALTER TABLE acme_client_accounts RENAME TO acme_client_accounts_old'
        )
        conn.execute(new_schema)
        conn.execute(
            f'INSERT INTO acme_client_accounts_new ({col_list}) '
            f'SELECT {col_list} FROM acme_client_accounts_old'
        )
        conn.execute('DROP TABLE acme_client_accounts_old')
        conn.execute(
            'ALTER TABLE acme_client_accounts_new RENAME TO acme_client_accounts'
        )
        logger.info(
            '[077] dropped UNIQUE on acme_client_accounts.directory_url (SQLite)'
        )

    conn.execute(
        f'CREATE INDEX IF NOT EXISTS {_INDEX_NAME} '
        'ON acme_client_accounts(directory_url)'
    )
    conn.commit()


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text
    insp = inspect(conn)
    if 'acme_client_accounts' not in insp.get_table_names():
        logger.info(
            '[077] acme_client_accounts missing: nothing to do (PostgreSQL)'
        )
        return
    uniques = {
        c['name'] for c in insp.get_unique_constraints('acme_client_accounts')
        if c['name']
    }
    if 'acme_client_accounts_directory_url_key' in uniques:
        conn.execute(text(
            'ALTER TABLE acme_client_accounts '
            'DROP CONSTRAINT IF EXISTS acme_client_accounts_directory_url_key'
        ))
        logger.info(
            '[077] dropped UNIQUE on acme_client_accounts.directory_url (PostgreSQL)'
        )
    conn.execute(text(
        f'CREATE INDEX IF NOT EXISTS {_INDEX_NAME} '
        'ON acme_client_accounts(directory_url)'
    ))
    # No commit / begin — the runner manages the transaction.


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    """No-op: existing rows may already contain duplicate directory_url values
    and cannot be re-uniqued reliably. Operator must resolve duplicates by
    hand before any future re-addition of a UNIQUE constraint."""
    pass
