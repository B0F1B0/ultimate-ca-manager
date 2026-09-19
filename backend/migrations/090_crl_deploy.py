"""Migration 090: deploy generated CRLs to SSH targets.

CRL bindings reuse the certificate deployment transport and durable delivery
queue.  ``binding_type`` disambiguates the two independent binding tables;
existing rows remain certificate deliveries.
"""

import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True


def _upgrade_sqlite(conn):
    columns = {row[1] for row in conn.execute("PRAGMA table_info(deploy_deliveries)")}
    if 'binding_type' not in columns:
        conn.execute(
            "ALTER TABLE deploy_deliveries ADD COLUMN binding_type VARCHAR(16) "
            "NOT NULL DEFAULT 'certificate'")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_deploy_deliveries_binding_type "
        "ON deploy_deliveries (binding_type)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS crl_deploy_bindings (
            id INTEGER NOT NULL PRIMARY KEY,
            target_id INTEGER NOT NULL,
            ca_id INTEGER NOT NULL,
            crl_path VARCHAR(512) NOT NULL,
            format VARCHAR(8) NOT NULL DEFAULT 'pem',
            include_parent_crls BOOLEAN NOT NULL DEFAULT 0,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            created_at DATETIME,
            created_by VARCHAR(80),
            CONSTRAINT uq_crl_deploy_binding UNIQUE (target_id, ca_id),
            FOREIGN KEY(target_id) REFERENCES deploy_targets (id),
            FOREIGN KEY(ca_id) REFERENCES certificate_authorities (id)
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_crl_deploy_bindings_target_id "
        "ON crl_deploy_bindings (target_id)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_crl_deploy_bindings_ca_id "
        "ON crl_deploy_bindings (ca_id)")
    conn.commit()


def _upgrade_pg(conn):
    from sqlalchemy import text

    conn.execute(text(
        "ALTER TABLE deploy_deliveries ADD COLUMN IF NOT EXISTS "
        "binding_type VARCHAR(16) NOT NULL DEFAULT 'certificate'"))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_deploy_deliveries_binding_type "
        "ON deploy_deliveries (binding_type)"))
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS crl_deploy_bindings (
            id SERIAL PRIMARY KEY,
            target_id INTEGER NOT NULL REFERENCES deploy_targets(id),
            ca_id INTEGER NOT NULL REFERENCES certificate_authorities(id),
            crl_path VARCHAR(512) NOT NULL,
            format VARCHAR(8) NOT NULL DEFAULT 'pem',
            include_parent_crls BOOLEAN NOT NULL DEFAULT false,
            enabled BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMP,
            created_by VARCHAR(80),
            CONSTRAINT uq_crl_deploy_binding UNIQUE (target_id, ca_id)
        )
    """))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_crl_deploy_bindings_target_id "
        "ON crl_deploy_bindings (target_id)"))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_crl_deploy_bindings_ca_id "
        "ON crl_deploy_bindings (ca_id)"))


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        conn.execute("DROP TABLE IF EXISTS crl_deploy_bindings")
        conn.commit()
    else:
        from sqlalchemy import text
        conn.execute(text("DROP TABLE IF EXISTS crl_deploy_bindings"))
    # SQLite cannot safely drop the binding_type column in every supported
    # version. Leaving the backwards-compatible discriminator is harmless.
