"""Every reference a restore resolves, proved on a backend that enforces them.

A restore has to point each link at the row the archive *names*, never at the
number the source happened to give that row. SQLite never says otherwise: it
enforces no foreign key, so a column written with the source's id sits there
unchallenged until `relink_references`, at the very end of the restore, puts
it right. Seven sections were restored exactly that way -- an API key, a
client certificate, a policy, an ACME domain, an SSH authority and its
certificates, an HSM key -- and passed the cross-installation round trip on
SQLite while PostgreSQL refused the insert as it happened and took the whole
restore down with it. The same archive restored on one backend and not on the
other, and the only thing in the suite that said so was a table naming the
seven as known to fail.

This file is the half that was missing: the same round trip, onto a
PostgreSQL installation whose ids are its own, with every section the archive
carries rather than the subset PostgreSQL used to tolerate. It asks of the
target exactly what the manifest promises -- every declared reference lands on
the row the archive names, and no identifier from the source is ever written
into a column here, as a primary key or as a link.

Neither installation is the suite's own database. The source is a throwaway
SQLite file under keys this suite never held, and the target is a schema of
this file's own on the shared bench, dropped when the module is done: another
file may be restoring into `public` at the same time, and a round trip that
emptied the bench under it would fail something that has nothing to do with
it.

Opt-in through `UCM_TEST_PG_URL`, like `tests/test_database_migration_matrix.py`:
without a bench there is nothing here to prove, since SQLite is precisely the
backend that cannot tell.
"""
import os
from contextlib import contextmanager

import pytest
from sqlalchemy import create_engine, inspect as sa_inspect, text
from sqlalchemy.types import Integer

from services.backup import manifest
from tests.test_backup_cross_installation import (
    PASSWORD,
    RESTORABLE_SECTIONS,
    SOURCE_ID_BASE,
    Keys,
    Restored,
    Source,
    _attribute_of,
    _installation,
    _model,
    _references_carried_by,
    _seed_source,
    _seed_target_history,
    _service,
    _where_the_reference_landed,
)

_PG_URL = os.environ.get('UCM_TEST_PG_URL')

pytestmark = pytest.mark.skipif(
    not _PG_URL,
    reason='UCM_TEST_PG_URL not set; skipping the PostgreSQL reference round trip')

# The schema this file restores into. Named rather than `public` so the bench
# stays usable by whatever else is running against it.
SCHEMA = 'restore_reference_resolution'


@contextmanager
def _a_schema_of_our_own(name=SCHEMA):
    """A PostgreSQL database URL pointing at a schema nothing else uses.

    Dropped on the way in as well as on the way out: a run killed halfway
    through leaves its tables behind, and the next one must not inherit rows
    it did not write. Two round trips in this file take two schemas, so
    neither empties the other's target under it.
    """
    admin = create_engine(_PG_URL, pool_pre_ping=True)
    try:
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS {name} CASCADE'))
            connection.execute(text(f'CREATE SCHEMA {name}'))
        separator = '&' if '?' in _PG_URL else '?'
        yield f'{_PG_URL}{separator}options=-csearch_path%3D{name}'
    finally:
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS {name} CASCADE'))
        admin.dispose()


@pytest.fixture(scope='module')
def source(app, tmp_path_factory):
    """The installation the archive is taken from, under its own keys."""
    installation = Source(app, tmp_path_factory.mktemp('reference-resolution'))
    with installation.bound(), app.app_context():
        installation.seeded = _seed_source()
    return installation


@pytest.fixture(scope='module')
def restored_on_postgresql(app, source):
    """One round trip onto PostgreSQL, with every restorable section.

    The target already holds a history of its own before the restore starts,
    so the ids it hands out are its own and a reference that merely copied the
    source's number lands on nothing -- or, here, is refused outright.
    """
    with _a_schema_of_our_own() as url:
        blob, archive = source.archive_of(*RESTORABLE_SECTIONS)
        keys = Keys(source.directory, 'reference-resolution-target')
        with _installation(app, url, keys, is_postgresql=True), app.app_context():
            _seed_target_history()
            results = _service().restore_backup(blob, PASSWORD)
        yield Restored(source, keys, url, True, archive, results)


def _identifier_columns(section_name):
    """The columns of a section that hold the id of a row, and nothing else.

    The primary key, the foreign keys the schema declares, and the references
    the manifest declares -- which is wider than either on its own: a column
    can carry a link the schema never constrained (`api_keys.user_id` before
    it had a foreign key) or one the manifest alone knows about. Integer
    columns only: a link carried as a natural key (an ACME account id, a
    certificate refid) means the same thing on every installation and is
    supposed to come back unchanged.
    """
    model = _model(section_name)
    mapper = sa_inspect(model)
    wanted = {column.key for column in mapper.primary_key}
    wanted.update(column.key for column in mapper.columns if column.foreign_keys)
    wanted.update(manifest.SECTIONS[section_name].references)
    return [column for column in mapper.columns
            if column.key in wanted and isinstance(column.type, Integer)]


class TestTheRestoreItselfIsAcceptedByPostgreSQL:
    """It used to be refused, and only on this backend.

    Seven sections wrote the source's numeric id and counted on the repair
    pass that runs once everything is written. PostgreSQL checks the
    reference where the row is inserted, so the transaction died there: the
    restore was announced as failed and an administrator moving an
    installation to PostgreSQL could not move it at all.
    """

    def test_every_section_the_archive_carries_arrives(
            self, app, restored_on_postgresql):
        with restored_on_postgresql.open(app):
            missing = []
            for section_name in RESTORABLE_SECTIONS:
                archived = restored_on_postgresql.archived(section_name)
                if not archived:
                    continue
                held = _model(section_name).query.count()
                if held < len(archived):
                    missing.append(
                        f'{section_name}: the archive carries {len(archived)} '
                        f'row(s) and the target holds {held}')
            assert not missing, (
                'sections the archive carries and PostgreSQL did not end up '
                'with:\n  ' + '\n  '.join(missing))

    def test_nothing_was_announced_as_restored_without_being_applied(
            self, restored_on_postgresql):
        """A restore that passed a section over says which one, and this
        round trip asks for nothing this version cannot apply."""
        assert restored_on_postgresql.results['sections_not_restored'] == []


class TestEveryDeclaredReferenceLandsOnTheRowTheArchiveNames:
    """The same walk the SQLite round trip does, where it can be enforced.

    On SQLite a reference that resolved to the wrong row is still written, and
    the repair pass hides the difference between "resolved" and "repaired
    afterwards". Here the database itself is the witness: a reference is
    checked against the row the archive names, on an installation whose
    numbering has nothing in common with the source's.
    """

    def test_every_reference_the_archive_carries_landed(
            self, app, restored_on_postgresql):
        carried = _references_carried_by(restored_on_postgresql.archive)
        assert carried, 'the archive carries no reference at all to check'

        with restored_on_postgresql.open(app):
            failures = []
            for (section_name, column), rows in sorted(carried.items()):
                target = manifest.SECTIONS[section_name].references[column]
                if not restored_on_postgresql.archived(target):
                    # The archive does not carry the section pointed at, so
                    # there is no row here the reference could have landed on.
                    continue
                for row in rows:
                    problem = _where_the_reference_landed(section_name, column, row)
                    if problem:
                        failures.append(problem)
            assert not failures, (
                'references that did not land on the row the archive names:\n  '
                + '\n  '.join(failures))

    def test_no_identifier_from_the_source_reaches_the_target(
            self, app, restored_on_postgresql):
        """Not one id column here may hold a number from the source's range.

        The point of the source numbering its rows where no fresh
        installation reaches: a column holding one of those numbers is a
        column the restore copied instead of resolving. On SQLite it would
        have been left there, pointing at nothing or at somebody else's row;
        the assertion is the same either way, and it covers the links no test
        thought to name as well as the ones the manifest declares.
        """
        with restored_on_postgresql.open(app):
            carried_over = []
            for section_name in RESTORABLE_SECTIONS:
                model = _model(section_name)
                columns = _identifier_columns(section_name)
                if not columns:
                    continue
                for row in model.query.all():
                    for column in columns:
                        value = getattr(
                            row, _attribute_of(model, column.key), None)
                        if isinstance(value, int) and value >= SOURCE_ID_BASE:
                            carried_over.append(
                                f'{section_name}.{column.key} = {value}')
            assert not carried_over, (
                "the target holds identifiers from the source's range, so "
                'these were copied rather than resolved: '
                f'{sorted(carried_over)}')


class TestALinkTheProtocolNamesComesBackAsItself:
    """The two links that were dropped *because* they had been declared.

    An EAB credential and an ACME client order name the account they belong
    to by its account id: the string the protocol itself uses, the same on
    every installation that holds the account. The manifest declared both
    columns as references to `acme_accounts`, which is indexed by primary
    key, so no identity was ever written beside them -- and the restore,
    finding none, cleared a link that needed no translation at all.

    PostgreSQL is where it can be said properly: the order's column is a
    foreign key onto `acme_accounts.account_id`, so a value written there
    either names an account this installation holds or the restore does not
    happen.
    """

    @pytest.mark.parametrize('section_name, column, identity', [
        ('acme_eab_credentials', 'used_by_account_id', {'kid': 'xinst-eab-kid'}),
        ('acme_client_orders', 'account_id',
         {'order_url': 'https://acme-b.example.test/order/1'}),
    ])
    def test_the_account_the_archive_names_is_still_named(
            self, app, restored_on_postgresql, section_name, column, identity):
        archived = restored_on_postgresql.archived_row(section_name, **identity)
        assert archived[column] == 'xinst-acct-b', \
            'the archive carries the account id, as text and unambiguous'

        with restored_on_postgresql.open(app):
            row = _model(section_name).query.filter_by(**identity).one()
            assert getattr(row, column) == 'xinst-acct-b', (
                f'{section_name}.{column} no longer names the account the '
                'archive named')
            assert _model('acme_accounts').query.filter_by(
                account_id=getattr(row, column)).one(), \
                'and the account it names is one this installation holds'


class TestTheSameArchiveRestoredTwiceWritesTheRowOnce:
    """A section can be identified by what it points at, and that is the
    identity the archive carries as the source's numbers.

    An HSM key is its provider and its key identifier; a membership is its
    group and its user. Once those columns are resolved to the target's own
    numbers -- which is the whole point -- the identity the archive carries
    no longer matches the one the row has here, and the restore stops
    recognising the row it wrote itself: the second restore adds a second
    copy of it, and the replacing pass, seeing an identity the archive "does
    not hold", is left to decide between them. The plan translates the
    archived identity through itself before looking it up, so the row is
    found and updated instead.
    """

    def test_a_section_identified_by_a_reference_is_recognised_again(
            self, app, source):
        identified_by_a_reference = sorted(
            name for name in RESTORABLE_SECTIONS
            if any(field in manifest.SECTIONS[name].references
                   for field in manifest.SECTIONS[name].identity))
        assert identified_by_a_reference, \
            'no section of this round trip is identified by what it points at'

        with _a_schema_of_our_own(f'{SCHEMA}_twice') as url:
            blob, _archive = source.archive_of(*RESTORABLE_SECTIONS)
            keys = Keys(source.directory, 'reference-resolution-twice')
            with _installation(app, url, keys, is_postgresql=True), app.app_context():
                _seed_target_history()
                _service().restore_backup(blob, PASSWORD)
                once = {name: _model(name).query.count()
                        for name in identified_by_a_reference}
                _service().restore_backup(blob, PASSWORD)
                twice = {name: _model(name).query.count()
                         for name in identified_by_a_reference}

        written_again = {name: (once[name], twice[name])
                         for name in once if once[name] != twice[name]}
        assert not written_again, (
            'these sections hold more rows after restoring the same archive a '
            f'second time: {written_again}')
