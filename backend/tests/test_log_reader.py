"""The application log reads back as records, without leaking what the bundle
redacts and without dropping the lines someone is hunting for.

A traceback carries its prefix only on the first line, so the rest has to
continue that record rather than arrive as four unparseable entries or vanish.
A line matching nothing at all is still returned: those are usually the ones
being looked for, and a level filter cannot judge a severity it never saw.
"""

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


def test_the_reader_and_the_bundle_share_one_journal_collector():
    from services import log_bundle
    assert log_reader.collect_journal is log_bundle.collect_journal


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
