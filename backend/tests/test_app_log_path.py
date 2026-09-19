"""The application log goes to a file UCM can read back, on every deployment.

Docker wrote nothing to disk and the native path fell back to stderr when it
could not be opened, so in both cases the log existed only somewhere the
service could not read: `docker logs`, or a journal the service user has no
membership to read. Resolution now ends at the data directory, which is
writable everywhere, and the chosen path is recorded so the diagnostic bundle
and the log viewer read what the logging setup writes.
"""

import logging

import pytest

from config.settings import Config
from utils import app_log


@pytest.fixture(autouse=True)
def reset_resolved():
    app_log._resolved_path = None
    yield
    app_log._resolved_path = None


@pytest.fixture
def not_docker(monkeypatch):
    monkeypatch.setattr(app_log, 'is_docker', lambda: False)


@pytest.fixture
def docker(monkeypatch):
    monkeypatch.setattr(app_log, 'is_docker', lambda: True)


class TestCandidatePaths:

    def test_docker_only_offers_the_data_directory(self, docker, monkeypatch):
        monkeypatch.delenv('UCM_LOG_FILE', raising=False)
        assert app_log.candidate_paths() == [Config.LOG_FILE]

    def test_native_prefers_var_log_then_falls_back_to_data(self, not_docker, monkeypatch):
        monkeypatch.delenv('UCM_LOG_FILE', raising=False)
        assert app_log.candidate_paths() == [app_log.NATIVE_LOG_PATH, Config.LOG_FILE]

    def test_ucm_log_file_overrides_the_native_path(self, not_docker, monkeypatch, tmp_path):
        override = tmp_path / 'custom.log'
        monkeypatch.setenv('UCM_LOG_FILE', str(override))
        assert app_log.candidate_paths() == [override, Config.LOG_FILE]

    def test_the_data_path_is_not_offered_twice(self, not_docker, monkeypatch):
        monkeypatch.setenv('UCM_LOG_FILE', str(Config.LOG_FILE))
        assert app_log.candidate_paths() == [Config.LOG_FILE]


class TestInstallFileHandler:

    def _logger(self, name):
        logger = logging.getLogger(name)
        logger.handlers = []
        return logger

    def test_writes_to_the_first_usable_path(self, not_docker, monkeypatch, tmp_path):
        target = tmp_path / 'ucm.log'
        monkeypatch.setenv('UCM_LOG_FILE', str(target))
        logger = self._logger('test.app_log.first')

        assert app_log.install_file_handler(logger, logging.Formatter('%(message)s')) == target

        logger.error('written to the resolved file')
        for handler in logger.handlers:
            handler.flush()
        assert 'written to the resolved file' in target.read_text()

    def test_falls_back_when_the_preferred_path_is_unusable(self, not_docker, monkeypatch, tmp_path):
        blocked = tmp_path / 'blocked'
        blocked.write_text('a file where a directory would have to be')
        data_path = tmp_path / 'data' / 'ucm.log'
        monkeypatch.setenv('UCM_LOG_FILE', str(blocked / 'ucm.log'))
        monkeypatch.setattr(Config, 'LOG_FILE', data_path)
        logger = self._logger('test.app_log.fallback')

        assert app_log.install_file_handler(logger, logging.Formatter('%(message)s')) == data_path
        assert app_log.resolved_path() == data_path

    def test_reports_none_when_no_candidate_can_be_opened(self, not_docker, monkeypatch, tmp_path):
        blocked = tmp_path / 'blocked'
        blocked.write_text('a file where a directory would have to be')
        monkeypatch.setenv('UCM_LOG_FILE', str(blocked / 'ucm.log'))
        monkeypatch.setattr(Config, 'LOG_FILE', blocked / 'data' / 'ucm.log')
        logger = self._logger('test.app_log.none')

        assert app_log.install_file_handler(logger, logging.Formatter('%(message)s')) is None
        assert app_log.resolved_path() is None
        assert logger.handlers == []

    def test_rotation_limits_come_from_the_environment(self, not_docker, monkeypatch, tmp_path):
        monkeypatch.setenv('UCM_LOG_FILE', str(tmp_path / 'ucm.log'))
        monkeypatch.setenv('UCM_LOG_MAX_BYTES', '4096')
        monkeypatch.setenv('UCM_LOG_BACKUPS', '2')
        logger = self._logger('test.app_log.rotation')

        app_log.install_file_handler(logger, logging.Formatter('%(message)s'))

        handler = logger.handlers[0]
        assert handler.maxBytes == 4096
        assert handler.backupCount == 2

    @pytest.mark.parametrize('value', ['0', '-1', 'not-a-number'])
    def test_an_unusable_rotation_limit_keeps_the_default(self, not_docker, monkeypatch,
                                                          tmp_path, value):
        monkeypatch.setenv('UCM_LOG_FILE', str(tmp_path / 'ucm.log'))
        monkeypatch.setenv('UCM_LOG_MAX_BYTES', value)
        logger = self._logger('test.app_log.bad_rotation')

        app_log.install_file_handler(logger, logging.Formatter('%(message)s'))

        assert logger.handlers[0].maxBytes == app_log.DEFAULT_MAX_BYTES


def test_audit_log_file_setting_is_gone():
    """The audit trail is a hash-chained table shipped off-box by syslog; the
    unused file path beside LOG_FILE read like a feature that existed."""
    assert not hasattr(Config, 'AUDIT_LOG_FILE')
