"""The manifest and the models must agree.

A column is exported unless the manifest says, in writing, why it is not. These
tests fail when a model gains a table or a column that nobody decided about,
which is what let the export quietly lose MFA secrets, HSM links and OAuth2
credentials for several releases.
"""
import importlib

import pytest

from models import db
from services.backup import manifest


def _model_of(section):
    module_name, class_name = section.model.split(':')
    return getattr(importlib.import_module(module_name), class_name)


@pytest.fixture(scope='module')
def registered_tables(app):
    with app.app_context():
        import services.database_admin.helpers as helpers
        helpers._force_register_all_models()
        return set(db.metadata.tables)


class TestEveryTableIsDecidedAbout:
    def test_no_table_is_silently_absent(self, app, registered_tables):
        with app.app_context():
            exported = set()
            for name, section in manifest.SECTIONS.items():
                exported.add(_model_of(section).__tablename__)

            undecided = sorted(
                registered_tables - exported - set(manifest.EXCLUDED_TABLES))
            assert not undecided, (
                "these tables are neither exported nor excluded on purpose: "
                + ", ".join(undecided))

    def test_exclusions_carry_a_reason(self):
        for table, reason in manifest.EXCLUDED_TABLES.items():
            assert reason and len(reason) > 10, f"{table} is excluded without a reason"

    def test_excluded_tables_still_exist(self, registered_tables):
        stale = sorted(set(manifest.EXCLUDED_TABLES) - registered_tables
                       - {'schema_migrations', 'alembic_version'})
        assert not stale, f"the manifest excludes tables that are gone: {stale}"


class TestEveryColumnIsDecidedAbout:
    def test_no_column_is_silently_absent(self, app):
        with app.app_context():
            problems = []
            for name, section in manifest.SECTIONS.items():
                model = _model_of(section)
                columns = {c.key for c in model.__table__.columns}
                undecided = columns - set(section.exclude) - set(section.handled)
                # every remaining column is exported by construction; what we
                # check here is that the exclusions name real columns
                unknown = (set(section.exclude) | set(section.handled)) - columns
                if unknown:
                    problems.append(f"{name}: excludes unknown columns {sorted(unknown)}")
                if not undecided:
                    problems.append(f"{name}: excludes every column")
            assert not problems, "; ".join(problems)

    def test_exclusions_carry_a_reason(self):
        for name, section in manifest.SECTIONS.items():
            for column, reason in section.exclude.items():
                assert reason and len(reason) > 10, \
                    f"{name}.{column} is excluded without a reason"

    def test_handled_columns_name_where_they_are_written(self):
        for name, section in manifest.SECTIONS.items():
            assert not section.handled or section.custom, \
                f"{name} declares handled columns but has no dedicated exporter"
            for column, written_as in section.handled.items():
                assert written_as, f"{name}.{column} says nothing about where it goes"

    def test_identities_are_real_columns_and_never_only_the_surrogate_key(self, app):
        with app.app_context():
            for name, section in manifest.SECTIONS.items():
                model = _model_of(section)
                columns = {c.key for c in model.__table__.columns}
                assert section.identity, f"{name} has no stable identity"
                unknown = set(section.identity) - columns
                assert not unknown, f"{name}: identity names unknown columns {sorted(unknown)}"
                if section.identity == ('id',):
                    # Only singleton configuration rows may be identified by id
                    assert name in {'smtp_config', 'notification_config', 'ad_connector'}, \
                        f"{name} identifies rows by primary key alone"

    def test_secrets_and_references_name_real_columns(self, app):
        with app.app_context():
            for name, section in manifest.SECTIONS.items():
                model = _model_of(section)
                columns = {c.key for c in model.__table__.columns}
                # secrets may be declared under the property name (totp_secret)
                # or the stored column (_credentials)
                for secret in section.secrets:
                    assert secret in columns or f'_{secret}' in columns, \
                        f"{name}: secret {secret!r} is not a column"
                for column, target in section.references.items():
                    assert column in columns, f"{name}: reference {column!r} is not a column"
                    assert target in manifest.SECTIONS, \
                        f"{name}.{column} points at unknown section {target!r}"
