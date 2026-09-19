"""GET /api/v2/system/logs serves the application log to administrators only.

Reading the log is a privileged read — it exposes whatever the server has
written about every request — so it sits behind the same admin:system scope as
the diagnostic bundle, and every read leaves an audit entry saying who looked.
"""

import json

import pytest

from models import AuditLog, db
from services import log_reader

FORMATTED = (
    '2026-09-19 13:41:36 [services.scep.scep_service] WARNING SCEP error response\n'
    '2026-09-19 13:41:37 [api.v2.system.logs] INFO Application log read\n'
)


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


def test_every_read_is_audited(app, auth_client, log_file):
    with app.app_context():
        before = AuditLog.query.filter_by(action='application_log_read').count()

    assert _get(auth_client).status_code == 200

    with app.app_context():
        db.session.expire_all()
        after = AuditLog.query.filter_by(action='application_log_read').count()
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
