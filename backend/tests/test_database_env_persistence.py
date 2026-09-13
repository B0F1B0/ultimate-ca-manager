"""
Publishing DATABASE_URL into ucm.env without losing the rest of the file.

ucm.env is shared installation state (key-encryption key, listen address,
HTTPS port…). The contract proven here: a DATABASE_URL change never costs a
single other byte, the publication is atomic, it leaves no temporary file
behind, a failed or unverifiable write rolls back, and no password reaches a
log line.

No Flask app is needed — the module only touches a path and the filesystem.
"""
import logging
import os
import stat

import pytest

from services.database_admin import persistence


PASSWORD = 'sup3r-s3cr3t-pw'
OLD_URL = f'postgresql://ucm:{PASSWORD}@localhost:5432/ucm'
NEW_URL = f'postgresql://ucm:{PASSWORD}@db.internal:5432/ucm_new'

BASE_ENV = (
    "# UCM system configuration — do not edit while the service runs\n"
    "KEY_ENCRYPTION_KEY=Zm9vYmFyYmF6\n"
    "HOST=::\n"
    "\n"
    "# Database\n"
    f"DATABASE_URL={OLD_URL}\n"
    "#DATABASE_URL=sqlite:///old-disabled.db\n"
    "\n"
    "# Web\n"
    "HTTPS_PORT=8443\n"
)


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    """A 0640 ucm.env the module is pointed at, outside /etc."""
    path = tmp_path / 'ucm.env'
    path.write_text(BASE_ENV)
    os.chmod(path, 0o640)
    monkeypatch.setattr(persistence, 'UCM_ENV_PATH', path)
    monkeypatch.setattr(persistence, 'is_docker', lambda: False)
    return path


def leftovers(tmp_path):
    """Anything in the directory that is not the env file itself."""
    return sorted(p.name for p in tmp_path.iterdir() if p.name != 'ucm.env')


def file_mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


# ---------------------------------------------------------------------------
# What survives a change
# ---------------------------------------------------------------------------

def test_other_variables_and_comments_survive(env_file, tmp_path):
    ok, msg = persistence.persist_database_url(NEW_URL)
    assert ok, msg

    lines = env_file.read_text().splitlines()
    assert lines == [
        "# UCM system configuration — do not edit while the service runs",
        "KEY_ENCRYPTION_KEY=Zm9vYmFyYmF6",
        "HOST=::",
        "",
        "# Database",
        f"DATABASE_URL={NEW_URL}",
        "#DATABASE_URL=sqlite:///old-disabled.db",
        "",
        "# Web",
        "HTTPS_PORT=8443",
    ]
    assert leftovers(tmp_path) == []


def test_export_prefixed_definition_is_replaced_not_duplicated(env_file):
    env_file.write_text("export DATABASE_URL=sqlite:///old.db\nHOST=::\n")

    ok, msg = persistence.persist_database_url(NEW_URL)
    assert ok, msg
    # The prefix stays: dotenv and systemd ignore it, but a shell that sources
    # the file does not, and this edit has no business changing that.
    assert env_file.read_text() == f"export DATABASE_URL={NEW_URL}\nHOST=::\n"


def test_file_mode_is_preserved(env_file):
    ok, _ = persistence.persist_database_url(NEW_URL)
    assert ok
    assert file_mode(env_file) == 0o640


def test_non_default_mode_is_preserved(env_file):
    os.chmod(env_file, 0o600)

    ok, _ = persistence.persist_database_url(NEW_URL)
    assert ok
    assert file_mode(env_file) == 0o600


def test_missing_file_is_created_with_0640(tmp_path, monkeypatch):
    path = tmp_path / 'ucm.env'
    monkeypatch.setattr(persistence, 'UCM_ENV_PATH', path)
    monkeypatch.setattr(persistence, 'is_docker', lambda: False)

    ok, msg = persistence.persist_database_url(NEW_URL)
    assert ok, msg
    assert path.read_text() == f"DATABASE_URL={NEW_URL}\n"
    assert file_mode(path) == 0o640
    assert leftovers(tmp_path) == []


# ---------------------------------------------------------------------------
# Removing the variable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('value', [None, ''])
def test_removing_the_url_leaves_everything_else(env_file, tmp_path, value):
    ok, msg = persistence.persist_database_url(value)
    assert ok, msg

    expected = BASE_ENV.replace(f"DATABASE_URL={OLD_URL}\n", "")
    assert env_file.read_text() == expected
    assert PASSWORD not in env_file.read_text()
    assert leftovers(tmp_path) == []


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------

def test_failed_replace_leaves_the_original_untouched(env_file, tmp_path, monkeypatch):
    original = env_file.read_bytes()

    def boom(src, dst):
        raise OSError(28, f"No space left on device writing {NEW_URL}")

    monkeypatch.setattr(os, 'replace', boom)

    ok, msg = persistence.persist_database_url(NEW_URL)
    assert not ok
    assert env_file.read_bytes() == original
    assert file_mode(env_file) == 0o640
    assert leftovers(tmp_path) == []
    assert PASSWORD not in msg


def test_readback_mismatch_restores_and_fails(env_file, tmp_path, monkeypatch):
    original = env_file.read_bytes()
    monkeypatch.setattr(persistence, '_read_back', lambda path: "GARBAGE\n")

    ok, msg = persistence.persist_database_url(NEW_URL)
    assert not ok
    assert 'restored' in msg.lower()
    assert env_file.read_bytes() == original
    assert file_mode(env_file) == 0o640
    assert leftovers(tmp_path) == []


def test_readback_error_restores_and_fails(env_file, tmp_path, monkeypatch):
    original = env_file.read_bytes()

    def unreadable(path):
        raise OSError(5, "I/O error")

    monkeypatch.setattr(persistence, '_read_back', unreadable)

    ok, msg = persistence.persist_database_url(NEW_URL)
    assert not ok
    assert env_file.read_bytes() == original
    assert leftovers(tmp_path) == []


def test_docker_is_refused(env_file, monkeypatch):
    original = env_file.read_bytes()
    monkeypatch.setattr(persistence, 'is_docker', lambda: True)

    ok, msg = persistence.persist_database_url(NEW_URL)
    assert not ok
    assert 'Docker' in msg
    assert env_file.read_bytes() == original


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------

def test_rollback_restores_the_previous_content_exactly(env_file, tmp_path):
    original = env_file.read_bytes()

    ok, msg, backup = persistence.persist_database_url_with_backup(NEW_URL)
    assert ok, msg
    assert backup is not None
    assert env_file.read_bytes() != original

    ok, msg = persistence.restore_previous_database_url(backup)
    assert ok, msg
    assert env_file.read_bytes() == original
    assert file_mode(env_file) == 0o640
    assert leftovers(tmp_path) == []


def test_rollback_removes_a_file_that_did_not_exist(tmp_path, monkeypatch):
    path = tmp_path / 'ucm.env'
    monkeypatch.setattr(persistence, 'UCM_ENV_PATH', path)
    monkeypatch.setattr(persistence, 'is_docker', lambda: False)

    ok, _, backup = persistence.persist_database_url_with_backup(NEW_URL)
    assert ok and path.exists()

    ok, msg = persistence.restore_previous_database_url(backup)
    assert ok, msg
    assert not path.exists()
    assert leftovers(tmp_path) == []


def test_rollback_without_backup_is_refused(env_file):
    ok, msg = persistence.restore_previous_database_url(None)
    assert not ok
    assert 'backup' in msg.lower()


def test_failed_persist_returns_no_backup(env_file, monkeypatch):
    monkeypatch.setattr(os, 'replace', lambda src, dst: (_ for _ in ()).throw(OSError("nope")))

    ok, _, backup = persistence.persist_database_url_with_backup(NEW_URL)
    assert not ok
    assert backup is None


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

def test_no_password_is_logged_on_success(env_file, caplog):
    with caplog.at_level(logging.DEBUG):
        ok, msg = persistence.persist_database_url(NEW_URL)

    assert ok
    assert PASSWORD not in caplog.text
    assert PASSWORD not in msg


def test_no_password_is_logged_when_the_write_fails(env_file, caplog, monkeypatch):
    def boom(src, dst):
        raise OSError(f"cannot write DATABASE_URL={NEW_URL}")

    monkeypatch.setattr(os, 'replace', boom)

    with caplog.at_level(logging.DEBUG):
        ok, msg = persistence.persist_database_url(NEW_URL)

    assert not ok
    assert PASSWORD not in caplog.text
    assert PASSWORD not in msg
    assert '***' in msg


class TestAValueTheReaderWouldChange:
    """python-dotenv expands ``${NAME}`` when the service reads this file at
    startup, so a password containing one reaches the driver as something
    else. The write itself would verify — the file holds what we put in it —
    and the service would simply fail to connect after the restart."""

    @pytest.mark.parametrize('url', [
        'postgresql://ucm:p${HOME}w@db.example/ucm',
        'postgresql://ucm:p$HOME@db.example/ucm',
    ])
    def test_a_url_the_reader_would_expand_is_refused(self, env_file, url):
        before = env_file.read_text()

        ok, message, backup = persistence.persist_database_url_with_backup(url)

        assert ok is False
        assert backup is None
        assert '%24' in message
        assert env_file.read_text() == before, 'nothing may be written'

    def test_a_percent_encoded_dollar_is_accepted(self, env_file):
        ok, message, backup = persistence.persist_database_url_with_backup(
            'postgresql://ucm:p%24ss@db.example/ucm')

        assert ok is True, message
        assert 'p%24ss' in env_file.read_text()


class TestTheSuiteCannotReachTheRealFile:
    """The suite runs as root on a machine that hosts a UCM instance. The
    module holding this path must never resolve to the installed service's
    configuration, and that has to be true without any fixture being asked
    for: a test that reaches it takes the machine's instance down."""

    def test_the_module_path_is_not_the_installed_one(self):
        # No fixture requested on purpose: this is what the redirection has
        # to survive.
        assert not str(persistence.UCM_ENV_PATH).startswith('/etc/')
        assert not str(persistence._env_path()).startswith('/etc/')

    def test_the_helpers_copy_of_the_path_is_redirected_too(self):
        from services.database_admin import helpers

        assert not str(helpers.UCM_ENV_PATH).startswith('/etc/')
        assert helpers.UCM_ENV_PATH == persistence.UCM_ENV_PATH
