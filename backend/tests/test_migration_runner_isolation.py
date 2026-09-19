"""The migration runner a test builds the app with must only ever see the
test's own database. settings.py loads /etc/ucm/ucm.env at import and
create_app() gives the runner whatever DATABASE_PATH says, so on a machine
that runs UCM as a service, an unpinned test suite migrated the live database
(migrations 088 and 089 landed there from pytest runs, not from the service).
"""
import os
from pathlib import Path


def test_migration_runner_targets_the_test_data_dir(app):
    import migration_runner

    url = migration_runner._get_db_url()
    assert url.startswith('sqlite:///'), url
    target = Path(url[len('sqlite:///'):]).resolve()
    data_dir = Path(os.environ['DATA_DIR']).resolve()
    assert data_dir in target.parents, (
        f"the runner would migrate {target}, outside the test data dir {data_dir}")
