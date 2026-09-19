"""The application log reads back as records, without leaking what the bundle
redacts and without dropping the lines someone is hunting for.

A traceback carries its prefix only on the first line, so the rest has to
continue that record rather than arrive as four unparseable entries or vanish.
A line matching nothing at all is still returned: those are usually the ones
being looked for, and a level filter cannot judge a severity it never saw.
"""

import logging

import pytest

from services import log_reader
from utils import app_log

FORMATTED = (
    '2026-09-19 13:41:36 [services.scep.scep_service] WARNING SCEP error response: failInfo=1\n'
    '2026-09-19 13:41:37 [api.v2.system.logs] INFO Application log read\n'
    '2026-09-19 13:41:38 [app] ERROR Traceback (most recent call last):\n'
    '  File "app.py", line 1, in <module>\n'
    '    raise ValueError("boom")\n'
    'ValueError: boom\n'
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
    monkeypatch.setattr(log_reader, 'resolved_path', lambda: path)
    return path


class TestParse:

    def test_reads_timestamp_logger_level_and_message(self):
        first = log_reader.parse(FORMATTED)[0]
        assert first['ts'] == '2026-09-19 13:41:36'
        assert first['logger'] == 'services.scep.scep_service'
        assert first['level'] == 'WARNING'
        assert first['message'] == 'SCEP error response: failInfo=1'

    def test_a_traceback_continues_the_record_above_it(self):
        records = log_reader.parse(FORMATTED)
        assert len(records) == 3
        assert records[-1]['level'] == 'ERROR'
        assert 'ValueError: boom' in records[-1]['message']
        assert 'line 1, in <module>' in records[-1]['message']

    def test_an_orphan_line_is_kept_with_no_level(self):
        records = log_reader.parse('gunicorn starting, not our format\n')
        assert records == [{'ts': None, 'logger': None, 'level': None,
                            'message': 'gunicorn starting, not our format'}]

    def test_blank_lines_do_not_become_records(self):
        assert log_reader.parse('\n\n') == []


class TestFilter:

    def test_level_acts_as_a_floor(self):
        records = log_reader.filter_records(log_reader.parse(FORMATTED), level='WARNING')
        assert [r['level'] for r in records] == ['WARNING', 'ERROR']

    def test_an_unknown_level_does_not_filter_anything_out(self):
        records = log_reader.filter_records(log_reader.parse(FORMATTED), level='LOUD')
        assert len(records) == 3

    def test_a_record_with_no_level_survives_the_floor(self):
        records = log_reader.parse('orphan line\n')
        assert log_reader.filter_records(records, level='ERROR') == records

    def test_the_query_matches_the_message(self):
        records = log_reader.filter_records(log_reader.parse(FORMATTED), query='failinfo')
        assert len(records) == 1
        assert 'failInfo=1' in records[0]['message']

    def test_the_query_matches_the_logger_name(self):
        records = log_reader.filter_records(log_reader.parse(FORMATTED), query='scep_service')
        assert len(records) == 1


class TestRead:

    def test_reports_absence_rather_than_failing(self, log_file):
        result = log_reader.read()
        assert result['exists'] is False
        assert result['lines'] == []

    def test_returns_the_records_in_the_file(self, log_file):
        log_file.write_text(FORMATTED)
        result = log_reader.read()
        assert result['exists'] is True
        assert result['path'] == str(log_file)
        assert len(result['lines']) == 3

    def test_keeps_the_newest_lines_and_says_it_truncated(self, log_file):
        log_file.write_text(FORMATTED)
        result = log_reader.read(lines=1)
        assert result['truncated'] is True
        assert result['lines'][0]['level'] == 'ERROR'

    def test_secrets_are_redacted_before_they_leave(self, log_file):
        log_file.write_text(
            '2026-09-19 13:41:36 [api] INFO login with password=hunter2 token=abcdef\n'
        )
        message = log_reader.read()['lines'][0]['message']
        assert 'hunter2' not in message
        assert 'abcdef' not in message
        assert '[redacted]' in message

    def test_only_the_tail_is_read(self, log_file, monkeypatch):
        monkeypatch.setattr(log_reader, 'MAX_TAIL_BYTES', 200)
        log_file.write_text(FORMATTED * 40)
        result = log_reader.read(lines=log_reader.MAX_LINES)
        assert result['scan_truncated'] is True
        assert len(result['lines']) < 120

    def test_the_two_cuts_are_reported_apart(self, log_file):
        """The line cap is what the reader chose and can raise; the byte cap is
        how far back the file was read at all. Reporting one number for both
        leaves no way to know which one to change."""
        log_file.write_text(FORMATTED * 30)   # 90 records, well under the byte cap
        result = log_reader.read(lines=10)
        assert result['truncated'] is True         # the line cap cut it
        assert result['scan_truncated'] is False   # the whole file was read

    def test_neither_cut_is_claimed_when_everything_fitted(self, log_file):
        log_file.write_text(FORMATTED)
        result = log_reader.read(lines=log_reader.MAX_LINES)
        assert result['truncated'] is False
        assert result['scan_truncated'] is False

    def test_a_request_beyond_the_cap_is_clamped(self, log_file):
        log_file.write_text(FORMATTED)
        assert log_reader.read(lines=10 ** 6)['lines']


def test_the_reader_and_the_bundle_share_one_redaction_pass():
    """Two redaction implementations would drift, and the weaker one decides."""
    from services import log_bundle
    assert log_reader.redact is log_bundle.redact


def test_the_reader_follows_the_path_the_logging_setup_chose():
    assert log_reader.resolved_path is app_log.resolved_path


class TestSources:

    @pytest.fixture
    def no_journal(self, monkeypatch):
        monkeypatch.setattr(log_reader, 'collect_journal', lambda: None)

    def test_the_gunicorn_streams_come_from_the_log_directory(self, monkeypatch, tmp_path):
        monkeypatch.setattr(log_reader, 'LOG_DIR', tmp_path)
        assert log_reader.source_path(log_reader.ACCESS) == tmp_path / 'access.log'
        assert log_reader.source_path(log_reader.ERROR) == tmp_path / 'error.log'

    def test_the_journal_is_not_a_file(self):
        assert log_reader.source_path(log_reader.JOURNAL) is None

    def test_only_sources_that_exist_are_offered(self, monkeypatch, tmp_path, log_file, no_journal):
        monkeypatch.setattr(log_reader, 'LOG_DIR', tmp_path)
        log_file.write_text(FORMATTED)
        (tmp_path / 'access.log').write_text('GET / 200\n')
        assert log_reader.available_sources() == [log_reader.APP, log_reader.ACCESS]

    def test_the_journal_is_offered_when_it_answers(self, monkeypatch, tmp_path, log_file):
        monkeypatch.setattr(log_reader, 'LOG_DIR', tmp_path)
        monkeypatch.setattr(log_reader, 'collect_journal', lambda: b'Sep 19 13:41:36 host ucm[1]: up\n')
        log_file.write_text(FORMATTED)
        assert log_reader.JOURNAL in log_reader.available_sources()

    def test_reads_the_access_log(self, monkeypatch, tmp_path, log_file, no_journal):
        monkeypatch.setattr(log_reader, 'LOG_DIR', tmp_path)
        (tmp_path / 'access.log').write_text('10.0.0.1 - - "GET /api HTTP/1.1" 200\n')
        result = log_reader.read(source=log_reader.ACCESS)
        assert result['source'] == log_reader.ACCESS
        assert result['exists'] is True
        assert result['lines'][0]['level'] is None
        assert 'GET /api' in result['lines'][0]['message']

    def test_reads_the_journal(self, monkeypatch, tmp_path, log_file, no_journal):
        monkeypatch.setattr(log_reader, 'LOG_DIR', tmp_path)
        monkeypatch.setattr(log_reader, 'collect_journal',
                            lambda: b'2026-09-19T13:41:36+0000 host ucm[1]: started\n')
        result = log_reader.read(source=log_reader.JOURNAL)
        assert result['exists'] is True
        assert result['path'] is None
        assert 'started' in result['lines'][0]['message']

    def test_an_unavailable_journal_reports_absence(self, monkeypatch, tmp_path, log_file, no_journal):
        monkeypatch.setattr(log_reader, 'LOG_DIR', tmp_path)
        result = log_reader.read(source=log_reader.JOURNAL)
        assert result['exists'] is False
        assert result['lines'] == []

    def test_an_unknown_source_falls_back_to_the_application_log(self, log_file, no_journal):
        log_file.write_text(FORMATTED)
        assert log_reader.read(source='nonsense')['source'] == log_reader.APP

    def test_secrets_are_redacted_on_every_source(self, monkeypatch, tmp_path, log_file, no_journal):
        monkeypatch.setattr(log_reader, 'LOG_DIR', tmp_path)
        (tmp_path / 'error.log').write_text('worker boot token=deadbeef\n')
        message = log_reader.read(source=log_reader.ERROR)['lines'][0]['message']
        assert 'deadbeef' not in message

    def test_gunicorn_logs_follow_the_env_vars_gunicorn_itself_reads(self, tmp_path, monkeypatch):
        """An install that moves the access log must not read as not having one."""
        access = tmp_path / 'somewhere' / 'access.log'
        access.parent.mkdir()
        access.write_text('127.0.0.1 - - "GET /api/v2/health HTTP/1.1" 200\n')
        monkeypatch.setenv('ACCESS_LOG', str(access))

        assert log_reader.source_path('access') == access
        assert 'access' in log_reader.available_sources()

    def test_gunicorn_logs_fall_back_to_the_log_dir(self, monkeypatch):
        monkeypatch.delenv('ACCESS_LOG', raising=False)
        monkeypatch.delenv('ERROR_LOG', raising=False)

        assert log_reader.source_path('access') == log_reader.LOG_DIR / 'access.log'
        assert log_reader.source_path('error') == log_reader.LOG_DIR / 'error.log'


def test_the_reader_and_the_bundle_share_one_journal_collector():
    from services import log_bundle
    assert log_reader.collect_journal is log_bundle.collect_journal


class TestGunicornFormats:
    """gunicorn writes neither of its logs in UCM's format."""

    ACCESS = (
        '127.0.0.1 - - [19/Sep/2026:16:16:26 +0300] "GET /api/v2/auth/methods HTTP/1.1" 200 888\n'
        '10.0.0.5 - - [19/Sep/2026:16:16:32 +0300] "GET /api/health HTTP/1.1" 200 825\n'
    )
    ERROR = (
        '[2026-09-19 16:16:24 +0300] [150704] [INFO] Starting gunicorn 25.1.0\n'
        '[2026-09-19 16:16:25 +0300] [150723] [ERROR] Exception in worker\n'
        'Traceback (most recent call last):\n'
        '  File "wsgi.py", line 1, in <module>\n'
        '[2026-09-19 16:19:00 +0300] [150704] [INFO] Handling signal: term\n'
    )

    def test_each_access_line_is_its_own_record(self):
        """Not one record carrying the whole file, which is what folding gives."""
        records = log_reader.parse(self.ACCESS, log_reader.ACCESS)

        assert len(records) == 2
        assert records[0]['ts'] == '2026-09-19 16:16:26'
        assert records[0]['logger'] == '127.0.0.1'
        assert records[0]['message'].startswith('"GET /api/v2/auth/methods')
        assert records[1]['logger'] == '10.0.0.5'

    def test_an_access_line_carries_no_level_rather_than_a_made_up_one(self):
        assert log_reader.parse(self.ACCESS, log_reader.ACCESS)[0]['level'] is None

    def test_an_error_line_carries_its_worker_and_level(self):
        records = log_reader.parse(self.ERROR, log_reader.ERROR)

        assert len(records) == 3
        assert records[0]['ts'] == '2026-09-19 16:16:24'
        assert records[0]['logger'] == '150704'
        assert records[0]['level'] == 'INFO'

    def test_a_traceback_still_folds_into_the_line_that_raised_it(self):
        raised = log_reader.parse(self.ERROR, log_reader.ERROR)[1]

        assert raised['level'] == 'ERROR'
        assert 'Traceback (most recent call last):' in raised['message']
        assert 'File "wsgi.py"' in raised['message']

    def test_gunicorn_timestamps_are_comparable_with_the_application_log(self):
        """The time filters compare strings, so one format has to serve both."""
        records = (log_reader.parse(self.ACCESS, log_reader.ACCESS)
                   + log_reader.parse(self.ERROR, log_reader.ERROR))

        assert all(log_reader.TS_FORMAT and len(r['ts']) == 19 for r in records)

    def test_an_unreadable_timestamp_leaves_the_line_standing(self, tmp_path, monkeypatch):
        records = log_reader.parse('[not a date] [150704] [INFO] Starting gunicorn\n',
                                   log_reader.ERROR)

        assert len(records) == 1
        assert records[0]['ts'] is None
        assert records[0]['level'] == 'INFO'

    def test_only_the_application_log_offers_components(self, tmp_path, monkeypatch):
        """Client addresses are not subsystems, and gunicorn has no loggers."""
        access = tmp_path / 'access.log'
        access.write_text(self.ACCESS)
        monkeypatch.setenv('ACCESS_LOG', str(access))

        assert log_reader.read(source=log_reader.ACCESS)['components'] == []


class TestEmptyJournal:
    """journalctl answers `-- No entries --` on stdout with a zero exit status
    when the unit has never logged, or when the service user cannot read the
    system journal. Offering that as a source shows a Journal pane whose only
    line says there is no journal."""

    @pytest.fixture(autouse=True)
    def only_the_app_log(self, monkeypatch, tmp_path, log_file):
        monkeypatch.setattr(log_reader, 'LOG_DIR', tmp_path)
        log_file.write_text(FORMATTED)

    def test_the_no_entries_marker_is_not_content(self, monkeypatch):
        monkeypatch.setattr(log_reader, 'collect_journal', lambda: b'-- No entries --\n')
        assert log_reader.journal_text() is None
        assert log_reader.JOURNAL not in log_reader.available_sources()

    def test_the_marker_is_matched_whatever_its_casing_and_spacing(self, monkeypatch):
        monkeypatch.setattr(log_reader, 'collect_journal', lambda: b'  --  no entries  --  \n\n')
        assert log_reader.journal_text() is None

    def test_a_journal_with_real_lines_is_offered(self, monkeypatch):
        monkeypatch.setattr(
            log_reader, 'collect_journal',
            lambda: b'-- No entries --\n2026-09-19T13:41:36+0000 host ucm[1]: started\n')
        assert log_reader.JOURNAL in log_reader.available_sources()

    def test_reading_an_empty_journal_reports_absence(self, monkeypatch):
        monkeypatch.setattr(log_reader, 'collect_journal', lambda: b'-- No entries --\n')
        result = log_reader.read(source=log_reader.JOURNAL)
        assert result['exists'] is False
        assert result['lines'] == []


class TestComponents:
    """The logger name is the subsystem that wrote the line, and it is a dotted
    hierarchy. An operator narrowing to `services.scep` means the subtree, and
    a dropdown of every leaf name is not a usable list."""

    RECORDS = [
        {'ts': 't', 'logger': 'services.scep.scep_service', 'level': 'INFO', 'message': 'a'},
        {'ts': 't', 'logger': 'services.scep.intune_client', 'level': 'INFO', 'message': 'b'},
        {'ts': 't', 'logger': 'api.v2.system.logs', 'level': 'INFO', 'message': 'c'},
        {'ts': None, 'logger': None, 'level': None, 'message': 'orphan'},
    ]

    def test_a_branching_parent_is_offered_beside_its_leaves(self):
        offered = log_reader.components(self.RECORDS)
        assert 'services.scep' in offered
        assert 'services.scep.scep_service' in offered
        assert 'services.scep.intune_client' in offered

    def test_a_parent_with_one_child_is_not_offered_twice(self):
        offered = log_reader.components(self.RECORDS)
        assert 'api.v2' not in offered
        assert 'api.v2.system.logs' in offered

    def test_records_without_a_logger_contribute_nothing(self):
        assert None not in log_reader.components(self.RECORDS)

    def test_filtering_on_a_parent_takes_the_whole_subtree(self):
        kept = log_reader.filter_records(self.RECORDS, logger='services.scep')
        assert [r['message'] for r in kept] == ['a', 'b']

    def test_filtering_on_a_leaf_takes_only_that_leaf(self):
        kept = log_reader.filter_records(self.RECORDS, logger='services.scep.intune_client')
        assert [r['message'] for r in kept] == ['b']

    def test_a_prefix_that_is_not_a_name_boundary_does_not_match(self):
        assert log_reader.filter_records(self.RECORDS, logger='services.sce') == []

    def test_the_components_offered_ignore_the_active_filters(self, log_file):
        """Choosing a component must not empty the list it was chosen from."""
        log_file.write_text(FORMATTED)
        result = log_reader.read(logger='services.scep.scep_service')
        assert len(result['lines']) == 1
        assert 'api.v2.system.logs' in result['components']


class TestTimeRange:
    """A reader narrowing to the minute an incident happened should not have to
    scroll. The bounds are read in the log's own format, which is the server's
    local time with no zone — the same instants the lines carry."""

    RECORDS = [
        {'ts': '2026-09-19 10:00:00', 'logger': 'a', 'level': 'INFO', 'message': 'early'},
        {'ts': '2026-09-19 12:30:00', 'logger': 'a', 'level': 'INFO', 'message': 'middle'},
        {'ts': '2026-09-19 15:00:00', 'logger': 'a', 'level': 'INFO', 'message': 'late'},
        {'ts': None, 'logger': None, 'level': None, 'message': 'timeless'},
    ]

    def _messages(self, **kw):
        return [r['message'] for r in log_reader.filter_records(self.RECORDS, **kw)]

    def test_since_keeps_that_instant_and_later(self):
        assert self._messages(since='2026-09-19 12:30:00') == ['middle', 'late']

    def test_until_keeps_that_instant_and_earlier(self):
        assert self._messages(until='2026-09-19 12:30:00') == ['early', 'middle']

    def test_both_bounds_make_a_window(self):
        assert self._messages(since='2026-09-19 11:00', until='2026-09-19 13:00') == ['middle']

    def test_a_date_alone_is_read_as_its_midnight(self):
        assert self._messages(since='2026-09-19') == ['early', 'middle', 'late']

    def test_the_browser_datetime_local_form_is_accepted(self):
        assert self._messages(since='2026-09-19T12:30') == ['middle', 'late']

    def test_an_unreadable_bound_is_ignored_rather_than_emptying_the_view(self):
        assert self._messages(since='not a time') == ['early', 'middle', 'late', 'timeless']

    def test_a_record_with_no_time_cannot_answer_a_time_question(self):
        """Unlike the level floor, which keeps records of unknown severity: a
        window asks for an instant, and this record has none."""
        assert 'timeless' not in self._messages(since='2026-09-19 00:00:00')

    def test_no_bounds_keeps_everything_including_the_timeless_one(self):
        assert self._messages() == ['early', 'middle', 'late', 'timeless']


def test_the_timezone_the_lines_are_written_in_is_reported(log_file):
    """asctime is local time with no offset, so the reader is told which zone."""
    log_file.write_text(FORMATTED)
    tz = log_reader.read()['timezone']
    assert set(tz) == {'name', 'offset'}
    assert tz['offset'] == '' or __import__('re').match(r'^[+-]\d{2}:\d{2}$', tz['offset'])


class TestSummaryCounts:
    """The summary describes what the filters matched, not the tail of it that
    fitted on screen — otherwise raising the line count would appear to change
    how many errors the server had."""

    def test_counts_every_level_including_the_unknown_ones(self):
        records = [
            {'ts': 't', 'logger': 'a', 'level': 'ERROR', 'message': '1'},
            {'ts': 't', 'logger': 'a', 'level': 'ERROR', 'message': '2'},
            {'ts': 't', 'logger': 'a', 'level': 'INFO', 'message': '3'},
            {'ts': None, 'logger': None, 'level': None, 'message': 'orphan'},
        ]
        counts = log_reader.level_counts(records)
        assert counts['ERROR'] == 2
        assert counts['INFO'] == 1
        assert counts['UNKNOWN'] == 1
        assert counts['DEBUG'] == 0

    def test_matched_is_counted_before_the_line_cap(self, log_file):
        log_file.write_text(FORMATTED * 30)   # 90 records
        result = log_reader.read(lines=10)
        assert len(result['lines']) == 10
        assert result['matched'] == 90
        assert result['truncated'] is True

    def test_the_counts_describe_the_filtered_set(self, log_file):
        log_file.write_text(FORMATTED)
        result = log_reader.read(level='ERROR')
        assert result['matched'] == 1
        assert result['levels']['ERROR'] == 1
        assert result['levels']['INFO'] == 0


class TestSubsystemsAreAlwaysOffered:
    """Built only from the lines read, the component list left a quiet
    subsystem impossible to select: you could not ask for SCEP until SCEP had
    already said something."""

    def test_the_backend_tree_decides_what_counts_as_ours(self):
        own = log_reader._own_top_level()
        for package in ('services', 'api', 'utils', 'security'):
            assert package in own
        for stranger in ('sqlalchemy', 'urllib3', 'flask'):
            assert stranger not in own

    def test_third_party_loggers_are_not_offered(self):
        logging.getLogger('sqlalchemy.engine.Engine')
        logging.getLogger('urllib3.connectionpool')
        offered = log_reader.subsystems()
        assert 'sqlalchemy' not in offered
        assert 'urllib3' not in offered

    def test_a_subsystem_is_offered_before_it_has_logged(self, log_file):
        """The loggers registered are the modules imported, so the test creates
        its own rather than assuming which of UCM's the test run happened to
        import. Under gunicorn the app is preloaded, so all of them are."""
        logging.getLogger('services.quiet_subsystem_for_test')
        logging.getLogger('api.quiet_subsystem_for_test')
        log_file.write_text(FORMATTED)
        offered = log_reader.read()['components']
        assert 'services' in offered          # selectable though it is quiet
        assert 'api' in offered

    def test_the_lines_read_still_contribute_their_own_loggers(self, log_file):
        log_file.write_text(FORMATTED)
        offered = log_reader.read()['components']
        assert 'services.scep.scep_service' in offered
        assert 'api.v2.system.logs' in offered

    def test_picking_a_subsystem_takes_everything_under_it(self):
        records = [
            {'ts': 't', 'logger': 'services.scep.scep_service', 'level': 'INFO', 'message': 'a'},
            {'ts': 't', 'logger': 'services.acme.client', 'level': 'INFO', 'message': 'b'},
            {'ts': 't', 'logger': 'api.v2.system.logs', 'level': 'INFO', 'message': 'c'},
        ]
        kept = log_reader.filter_records(records, logger='services')
        assert [r['message'] for r in kept] == ['a', 'b']


class TestAdvancedMatching:
    """Triage is as much about hiding the noise as finding the line: the
    heartbeat that repeats every minute is what buries the one error."""

    RECORDS = [
        {'ts': 't', 'logger': 'services.scheduler_service', 'level': 'INFO',
         'message': "Task 'discovery_scan' completed successfully"},
        {'ts': 't', 'logger': 'services.scep', 'level': 'ERROR', 'message': 'failInfo=1'},
        {'ts': 't', 'logger': 'api.v2', 'level': 'INFO', 'message': 'login ok'},
    ]

    def _messages(self, **kw):
        return [r['message'] for r in log_reader.filter_records(self.RECORDS, **kw)]

    def test_exclude_hides_the_lines_that_match_it(self):
        assert self._messages(exclude='completed successfully') == ['failInfo=1', 'login ok']

    def test_exclude_reads_the_logger_name_too(self):
        assert self._messages(exclude='scheduler') == ['failInfo=1', 'login ok']

    def test_include_and_exclude_compose(self):
        assert self._messages(query='services', exclude='scheduler') == ['failInfo=1']

    def test_regex_applies_to_both_patterns(self):
        assert self._messages(query=r'fail\w+=\d', regex=True) == ['failInfo=1']
        assert self._messages(exclude=r'^Task', regex=True) == ['failInfo=1', 'login ok']

    def test_a_half_written_regex_matches_nothing_rather_than_raising(self):
        """The reader is typing; an unbalanced bracket should not 500."""
        assert self._messages(query='[unclosed', regex=True) == []
        assert self._messages(exclude='[unclosed', regex=True) == [r['message'] for r in self.RECORDS]

    def test_without_the_flag_a_regex_is_read_literally(self):
        assert self._messages(query=r'fail\w+=\d') == []
        assert self._messages(query='failInfo=1') == ['failInfo=1']


class TestJournalFormat:
    """`journalctl --output=short-iso` writes neither UCM's format nor
    gunicorn's, and its own is what the collector asks for. Read with another
    source's parser it matched nothing, so every line continued the one above it
    and a whole journal came back as a single record carrying no timestamp."""

    JOURNAL = (
        '2026-09-19T21:30:08+02:00 host ucm[409576]: Starting gunicorn 25.1.0\n'
        '2026-09-19T21:30:08+02:00 host ucm[409576]: Listening at: http://0.0.0.0:8000\n'
        '2026-09-19T21:30:09+02:00 host ucm[409581]: Booting worker with pid: 409581\n'
        '2026-09-19T21:30:11+02:00 host systemd[1]: Started ucm.service.\n'
    )

    def _records(self):
        return log_reader.parse(self.JOURNAL, log_reader.JOURNAL)

    def test_every_line_is_its_own_record(self):
        assert len(self._records()) == len(self.JOURNAL.splitlines())

    def test_every_record_carries_the_instant_its_line_was_written(self):
        assert [r['ts'] for r in self._records()] == [
            '2026-09-19 21:30:08', '2026-09-19 21:30:08',
            '2026-09-19 21:30:09', '2026-09-19 21:30:11',
        ]

    def test_the_identifier_stands_in_for_the_component(self):
        assert [r['logger'] for r in self._records()] == [
            'ucm[409576]', 'ucm[409576]', 'ucm[409581]', 'systemd[1]',
        ]

    def test_the_message_is_what_follows_the_syslog_framing(self):
        assert self._records()[0]['message'] == 'Starting gunicorn 25.1.0'

    def test_no_level_is_invented_for_a_format_that_carries_none(self):
        assert all(r['level'] is None for r in self._records())

    def test_an_offset_written_without_its_colon_is_read_too(self):
        """systemd wrote `+0200` before v247 and `+02:00` since."""
        line = '2026-09-19T21:30:08+0200 host ucm[1]: up\n'
        assert log_reader.parse(line, log_reader.JOURNAL)[0]['ts'] == '2026-09-19 21:30:08'

    def test_the_journal_source_reads_the_journal_format(self, monkeypatch):
        monkeypatch.setattr(log_reader, 'collect_journal',
                            lambda: self.JOURNAL.encode())
        result = log_reader.read(source=log_reader.JOURNAL)
        assert len(result['lines']) == 4
        assert result['lines'][0]['ts'] == '2026-09-19 21:30:08'


class TestEachSourceIsReadWithItsOwnFormat:
    """Every format tried against every source matches by accident as readily as
    it fails: a journal line was taken for a gunicorn access line, which reports
    a timestamp and a client the line never carried."""

    def test_the_application_log_does_not_read_gunicorn_lines(self):
        gunicorn = '[2026-09-19 16:16:24 +0300] [150704] [INFO] Starting gunicorn\n'
        assert log_reader.parse(gunicorn, log_reader.APP)[0]['level'] is None

    def test_the_error_stream_reads_both_formats_it_is_written_in(self):
        """gunicorn logs its own lines there, and an unhandled traceback that
        reaches its logger arrives in UCM's."""
        mixed = ('[2026-09-19 16:16:24 +0300] [150704] [INFO] Starting gunicorn\n'
                 '2026-09-19 16:16:25 [app] ERROR Unhandled\n')
        records = log_reader.parse(mixed, log_reader.ERROR)
        assert [r['logger'] for r in records] == ['150704', 'app']

    def test_an_unknown_source_is_read_as_the_application_log(self):
        records = log_reader.parse(FORMATTED, 'not-a-source')
        assert records[0]['logger'] == 'services.scep.scep_service'


class TestTheJournalIsNotProbedOnEveryRequest:
    """journalctl is a process launch, and the page asks on every request: five
    seconds apart while following, and again on each keystroke of the search
    box. On a host where the service cannot read the journal the probe fails,
    and the failure used to be logged into the log the viewer is reading."""

    @pytest.fixture
    def probes(self, monkeypatch):
        calls = []
        monkeypatch.setattr(log_reader, 'collect_journal',
                            lambda: calls.append(1) or b'ucm running\n')
        return calls

    def test_the_answer_is_remembered_between_requests(self, probes, log_file):
        log_file.write_text(FORMATTED)
        for _ in range(5):
            log_reader.read()
        assert len(probes) == 1

    def test_reading_the_journal_is_its_own_probe(self, probes):
        log_reader.read(source=log_reader.JOURNAL)
        assert len(probes) == 1

    def test_the_question_is_asked_again_once_the_answer_is_stale(self, probes, log_file,
                                                                  monkeypatch):
        log_file.write_text(FORMATTED)
        monkeypatch.setattr(log_reader, '_JOURNAL_PROBE_TTL', 0)
        log_reader.read()
        log_reader.read()
        assert len(probes) == 2

    def test_a_journal_that_starts_answering_is_offered_once_it_is_asked_again(
            self, log_file, monkeypatch):
        log_file.write_text(FORMATTED)
        monkeypatch.setattr(log_reader, 'collect_journal', lambda: None)
        assert log_reader.JOURNAL not in log_reader.read()['available_sources']

        monkeypatch.setattr(log_reader, '_JOURNAL_PROBE_TTL', 0)
        monkeypatch.setattr(log_reader, 'collect_journal', lambda: b'ucm running\n')
        assert log_reader.JOURNAL in log_reader.read()['available_sources']


