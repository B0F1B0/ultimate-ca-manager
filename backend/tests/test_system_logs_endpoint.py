"""GET /api/v2/system/logs serves the application log to administrators only.

Reading the log is a privileged read — it exposes whatever the server has
written about every request — so it sits behind the same admin:system scope as
the diagnostic bundle.

It is deliberately the one privileged read that leaves no audit entry: the
audit trail echoes to this same log, and the page polls, so auditing a read
would write into the log being read and bury the lines the page exists to
surface. `test_a_read_leaves_no_audit_entry` below holds that line. The bundle
download, rare and deliberate, stays audited.
"""

import json

import pytest

from models import AuditLog, db
from services import log_reader

FORMATTED = (
    '2026-09-19 13:41:36 [services.scep.scep_service] WARNING SCEP error response\n'
    '2026-09-19 13:41:37 [api.v2.system.logs] INFO Application log read\n'
)


@pytest.fixture(autouse=True)
def forget_the_journal_probe():
    """Whether the journal answers is cached for the life of the process."""
    log_reader.reset_journal_probe()
    yield
    log_reader.reset_journal_probe()


@pytest.fixture
def log_file(tmp_path, monkeypatch):
    path = tmp_path / 'ucm.log'
    path.write_text(FORMATTED)
    monkeypatch.setattr(log_reader, 'resolved_path', lambda: path)
    return path


def _get(client, query=''):
    return client.get(f'/api/v2/system/logs{query}')


class TestAuthorisation:

    def test_anonymous_is_refused(self, app, log_file):
        response = _get(app.test_client())
        assert response.status_code in (401, 403)

    def test_a_viewer_is_refused(self, viewer_client, log_file):
        assert _get(viewer_client).status_code == 403

    def test_an_admin_may_read(self, auth_client, log_file):
        assert _get(auth_client).status_code == 200


class TestPayload:

    def test_returns_the_parsed_records(self, auth_client, log_file):
        body = json.loads(_get(auth_client).data)['data']
        assert body['exists'] is True
        assert [line['level'] for line in body['lines']] == ['WARNING', 'INFO']

    def test_the_level_floor_is_applied(self, auth_client, log_file):
        body = json.loads(_get(auth_client, '?level=WARNING').data)['data']
        assert [line['level'] for line in body['lines']] == ['WARNING']

    def test_the_query_is_applied(self, auth_client, log_file):
        body = json.loads(_get(auth_client, '?q=scep').data)['data']
        assert len(body['lines']) == 1

    def test_a_missing_log_is_reported_not_an_error(self, auth_client, tmp_path, monkeypatch):
        monkeypatch.setattr(log_reader, 'resolved_path', lambda: tmp_path / 'absent.log')
        response = _get(auth_client)
        assert response.status_code == 200
        assert json.loads(response.data)['data']['exists'] is False


class TestRequestValidation:

    @pytest.mark.parametrize('query', ['?lines=0', '?lines=99999', '?lines=abc'])
    def test_an_unusable_line_count_is_refused(self, auth_client, log_file, query):
        assert _get(auth_client, query).status_code == 400

    def test_an_unknown_level_is_refused(self, auth_client, log_file):
        assert _get(auth_client, '?level=LOUD').status_code == 400

    def test_a_known_level_in_any_casing_is_accepted(self, auth_client, log_file):
        assert _get(auth_client, '?level=warning').status_code == 200


class TestDefaults:
    """The level is a floor, and the interface opens on INFO. Left to the
    absence of the parameter it meant no floor at all, so a caller that omitted
    it read a noisier log than the one described to it."""

    DEBUG_AND_INFO = (
        '2026-09-19 13:41:36 [services.scep] DEBUG Parsed PKCS#7 envelope\n'
        '2026-09-19 13:41:37 [services.scep] INFO Certificate issued\n'
    )

    def _levels(self, client, query=''):
        body = json.loads(_get(client, query).data)['data']
        return [line['level'] for line in body['lines']]

    def test_the_floor_is_info_when_no_level_is_asked_for(self, auth_client, log_file):
        log_file.write_text(self.DEBUG_AND_INFO)
        assert self._levels(auth_client) == ['INFO']

    def test_debug_is_there_for_the_asking(self, auth_client, log_file):
        log_file.write_text(self.DEBUG_AND_INFO)
        assert self._levels(auth_client, '?level=DEBUG') == ['DEBUG', 'INFO']


class TestSearchIsASubstring:
    """One gevent worker answers every protocol this server speaks, so the
    search cannot be a caller-supplied regular expression: `(a+)+b` over a line
    of twenty-nine characters takes fifteen seconds, and while it runs ACME,
    SCEP and OCSP answer nothing."""

    def test_a_metacharacter_is_matched_as_itself(self, auth_client, log_file):
        log_file.write_text(
            '2026-09-19 13:41:36 [api] INFO SCEP error response\n'
            '2026-09-19 13:41:37 [api] INFO literal .* in the message\n'
        )
        body = json.loads(_get(auth_client, '?q=.*').data)['data']
        assert [line['message'] for line in body['lines']] == [
            'literal .* in the message'
        ]

    @pytest.mark.parametrize('value', ['true', 'false', '1', '0', ''])
    def test_the_regex_parameter_is_refused_rather_than_ignored(self, auth_client,
                                                                log_file, value):
        """The parameter lived between two commits of this feature and no
        release ever answered it. Answering it as a substring search would give
        a different answer to the question that was asked, quietly."""
        assert _get(auth_client, f'?q=fail&regex={value}').status_code == 400

    def test_the_search_itself_still_works_without_it(self, auth_client, log_file):
        log_file.write_text('2026-09-19 13:41:36 [api] INFO failInfo=1\n')
        body = json.loads(_get(auth_client, '?q=fail').data)['data']
        assert [line['message'] for line in body['lines']] == ['failInfo=1']


def test_a_read_leaves_no_audit_entry(app, auth_client, log_file):
    """AuditService echoes every entry to the application logger, so auditing a
    read of that log writes a line into the log being read, which the next read
    shows, for ever. Following a log polls, so the viewer would bury the lines
    it exists to surface under a record of itself."""
    with app.app_context():
        before = AuditLog.query.count()

    assert _get(auth_client).status_code == 200
    assert _get(auth_client).status_code == 200

    with app.app_context():
        db.session.expire_all()
        assert AuditLog.query.filter_by(action='application_log_read').count() == 0
        assert AuditLog.query.count() == before


def test_the_bundle_download_is_still_audited(app, auth_client):
    """The rare, deliberate action that leaves with a copy of the file keeps its
    trail — only the routine read was dropped."""
    with app.app_context():
        before = AuditLog.query.filter_by(action='log_bundle_downloaded').count()

    assert auth_client.get('/api/v2/system/logs/bundle').status_code == 200

    with app.app_context():
        db.session.expire_all()
        after = AuditLog.query.filter_by(action='log_bundle_downloaded').count()
    assert after == before + 1


class TestSourceSelection:

    @pytest.fixture(autouse=True)
    def gunicorn_logs(self, tmp_path, monkeypatch):
        monkeypatch.setattr(log_reader, 'LOG_DIR', tmp_path)
        monkeypatch.setattr(log_reader, 'collect_journal', lambda: None)
        (tmp_path / 'access.log').write_text('10.0.0.1 - - "GET /api HTTP/1.1" 200\n')
        return tmp_path

    def test_an_unknown_source_is_refused(self, auth_client, log_file):
        assert _get(auth_client, '?source=passwd').status_code == 400

    def test_the_access_log_can_be_read(self, auth_client, log_file):
        body = json.loads(_get(auth_client, '?source=access').data)['data']
        assert body['source'] == 'access'
        assert 'GET /api' in body['lines'][0]['message']

    def test_the_response_says_which_sources_this_host_has(self, auth_client, log_file):
        body = json.loads(_get(auth_client).data)['data']
        assert body['available_sources'] == ['app', 'access']

    def test_a_source_with_nothing_behind_it_reports_absence(self, auth_client, log_file):
        body = json.loads(_get(auth_client, '?source=journal').data)['data']
        assert body['exists'] is False
