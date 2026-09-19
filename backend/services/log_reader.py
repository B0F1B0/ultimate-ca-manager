"""Reading the logs back, for the log viewer.

The diagnostic bundle hands whole files to a human; this reads their tails into
records the interface can filter and colour. Redaction and journal collection
are shared with the bundle so both leave by the same gate.

Each source is read with the format it is actually written in rather than by
trying every format against every line: UCM's own for the application log,
gunicorn's two for its access and error streams, and the syslog framing
journalctl prints for the journal. A line matching nothing continues the record
above it, so a format nobody reads collapses a whole log into one record.

Only the application log carries a level of its own. The others are returned
with no level rather than being forced through a parser built for a different
shape — a level guessed from someone else's format is worse than none.

Timestamps are returned exactly as they were written. ``logging.Formatter``
renders ``asctime`` in local time with no zone and no offset, so presenting it
as an instant would attach a timezone the line never carried.
"""
from __future__ import annotations

import functools
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from services.log_bundle import LOG_DIR, collect_journal, redact
from utils.app_log import resolved_path

LEVELS = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')

# The floor the interface opens on, and the one the help describes. Applied by
# the route so that a client omitting the parameter reads the log the page
# describes rather than a noisier one.
DEFAULT_LEVEL = 'INFO'

TS_FORMAT = '%Y-%m-%d %H:%M:%S'

APP = 'app'
ACCESS = 'access'
ERROR = 'error'
JOURNAL = 'journal'
SOURCES = (APP, ACCESS, ERROR, JOURNAL)

DEFAULT_LINES = 200
MAX_LINES = 5000

# Read a bounded tail rather than the file: rotation caps it at ten megabytes,
# which is far more than any request needs and more than is worth decoding.
MAX_TAIL_BYTES = 2 * 1024 * 1024

# journalctl answers with this, on stdout and with a zero exit status, when the
# unit has no entries — which is every host where the service has never run, and
# every host whose service user cannot read the system journal. Treating it as
# content offered a Journal source whose only line said there was none.
_JOURNAL_EMPTY = re.compile(r'^\s*--\s*no entries\s*--\s*$', re.IGNORECASE)

# '%(asctime)s [%(name)s] %(levelname)s %(message)s' with a second-resolution
# asctime, as configured in app.py.
_RECORD = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[([^\]]*)\] ([A-Z]+) (.*)$'
)

# gunicorn writes its own two formats, neither of them UCM's. Without them every
# line of those files reads as the continuation of the one above and the whole
# log collapses into a single record.
_GUNICORN_ERROR = re.compile(
    r'^\[([^\]]+)\] \[(\d+)\] \[([A-Z]+)\] (.*)$'
)
_GUNICORN_ACCESS = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] (.*)$'
)

# journalctl --output=short-iso, which is what the collector asks for:
# `2026-09-19T21:30:08+02:00 host ucm[409576]: message`. The identifier is kept
# with its PID, so the worker a line came from is visible the way it is in the
# gunicorn error log.
_JOURNAL = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})) '
    r'\S+ ([^\s:]+):\s?(.*)$'
)


def _reformat(raw: str, fmt: str) -> Optional[str]:
    """A gunicorn timestamp in the shape the rest of the reader expects.

    Both carry a UTC offset the application log does not; dropping it keeps one
    timestamp format across sources, which is what the time filters compare.
    """
    try:
        return datetime.strptime(raw, fmt).strftime(TS_FORMAT)
    except ValueError:
        return None


def _tail_text(path: Path) -> tuple[str, bool]:
    """Return the tail of ``path`` and whether anything was left off the front."""
    size = path.stat().st_size
    with path.open('rb') as handle:
        if size > MAX_TAIL_BYTES:
            handle.seek(-MAX_TAIL_BYTES, 2)
            handle.readline()
            truncated = True
        else:
            truncated = False
        raw = handle.read()
    return raw.decode('utf-8', errors='replace'), truncated


def _app_record(match) -> dict:
    timestamp, name, level, message = match.groups()
    return {'ts': timestamp, 'logger': name, 'level': level, 'message': message}


def _gunicorn_error_record(match) -> dict:
    raw, pid, level, message = match.groups()
    return {'ts': _reformat(raw, '%Y-%m-%d %H:%M:%S %z'), 'logger': pid,
            'level': level, 'message': message}


def _gunicorn_access_record(match) -> dict:
    client, raw, message = match.groups()
    return {'ts': _reformat(raw, '%d/%b/%Y:%H:%M:%S %z'), 'logger': client,
            'level': None, 'message': message}


def _journal_record(match) -> dict:
    raw, identifier, message = match.groups()
    return {'ts': _reformat(raw, '%Y-%m-%dT%H:%M:%S%z'), 'logger': identifier,
            'level': None, 'message': message}


# What each source is written in. The error stream is the one source with two:
# gunicorn writes its own lines there, and an unhandled traceback reaching its
# logger arrives in UCM's format, so both belong to that file.
_READERS = {
    APP: ((_RECORD, _app_record),),
    ACCESS: ((_GUNICORN_ACCESS, _gunicorn_access_record),),
    ERROR: ((_GUNICORN_ERROR, _gunicorn_error_record), (_RECORD, _app_record)),
    JOURNAL: ((_JOURNAL, _journal_record),),
}


def parse(text: str, source: str = APP) -> list[dict]:
    """Turn one source's log text into records, oldest first.

    The formats tried are the ones that source is written in; reading a log
    with another log's parser either matches nothing, which folds the file into
    a single record, or matches by accident and reports a timestamp the line
    does not carry.

    A traceback spans many lines and only its first carries the prefix, so a
    line that matches nothing continues the record above it. A line that matches
    nothing and has no record above it is still returned, with no level: these
    are the lines someone is usually hunting for, and dropping them would hide
    exactly that.
    """
    readers = _READERS.get(source, _READERS[APP])
    records: list[dict] = []
    for line in text.splitlines():
        record = None
        for pattern, build in readers:
            match = pattern.match(line)
            if match:
                record = build(match)
                break
        if record is not None:
            records.append(record)
        elif records:
            records[-1]['message'] += '\n' + line
        elif line:
            records.append({'ts': None, 'logger': None, 'level': None, 'message': line})
    return records


def server_timezone() -> dict:
    """The zone the timestamps are written in, so a reader is not left guessing.

    ``logging.Formatter`` renders ``asctime`` in the server's local time with no
    zone and no offset. Every line in this log is therefore in whatever zone the
    server happens to be in, which is not necessarily the reader's.
    """
    local = datetime.now().astimezone()
    offset = local.strftime('%z')
    return {
        'name': local.tzname() or '',
        'offset': f'{offset[:3]}:{offset[3:]}' if offset else '',
    }


def _parse_bound(value: Optional[str]) -> Optional[datetime]:
    """Read a time bound, tolerating the forms a browser's datetime-local sends."""
    if not value:
        return None
    text = value.strip().replace('T', ' ')
    for fmt in (TS_FORMAT, '%Y-%m-%d %H:%M', '%Y-%m-%d'):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _record_time(record: dict) -> Optional[datetime]:
    try:
        return datetime.strptime(record['ts'], TS_FORMAT) if record['ts'] else None
    except ValueError:
        return None


def _at_least(level: Optional[str]) -> set[str]:
    """Levels at or above ``level``; every level when it is not one of ours."""
    if level is None or level.upper() not in LEVELS:
        return set(LEVELS)
    return set(LEVELS[LEVELS.index(level.upper()):])


def _matcher(pattern: Optional[str]):
    """A predicate over a record's message and logger, or None for no pattern.

    Deliberately a substring and not a pattern. One gevent worker answers every
    protocol this server speaks, and a caller-supplied regular expression is
    unbounded work on up to five thousand records: `(a+)+b` over a line of
    twenty-nine characters takes fifteen seconds, which is fifteen seconds in
    which ACME, SCEP and OCSP answer nothing. Searching for a pattern is worth
    having, but not before it can be run under a bound the search cannot escape.
    """
    if not pattern:
        return None
    needle = pattern.lower()
    return lambda record: (
        needle in record['message'].lower() or needle in (record['logger'] or '').lower()
    )


def filter_records(records: list[dict], level: Optional[str] = None,
                   query: Optional[str] = None,
                   logger: Optional[str] = None,
                   since: Optional[str] = None,
                   until: Optional[str] = None,
                   exclude: Optional[str] = None) -> list[dict]:
    """Apply the level floor, the component and the substring search.

    A record with no level is never filtered out by the level floor: its
    severity is unknown, and guessing it silently would hide it. The component
    filter matches a logger and everything below it, so `services.scep` covers
    `services.scep.scep_service` — the dotted names are a hierarchy and an
    operator picking a subsystem means the subtree.
    """
    wanted = _at_least(level)
    include = _matcher(query)
    omit = _matcher(exclude)
    prefix = (logger or '').strip()
    start, end = _parse_bound(since), _parse_bound(until)

    def within(record):
        # A bound asks for records between two instants, so one carrying no
        # instant cannot answer — unlike the level floor, which keeps records of
        # unknown severity rather than guess at them.
        if start is None and end is None:
            return True
        moment = _record_time(record)
        if moment is None:
            return False
        return (start is None or moment >= start) and (end is None or moment <= end)

    return [
        record for record in records
        if within(record)
        and (record['level'] is None or record['level'] in wanted)
        and (not prefix
             or record['logger'] == prefix
             or (record['logger'] or '').startswith(prefix + '.'))
        and (include is None or include(record))
        and (omit is None or not omit(record))
    ]


@functools.lru_cache(maxsize=1)
def _own_top_level() -> frozenset:
    """UCM's own top-level module names, read from the tree rather than listed.

    A hand-kept list would drift the first time a package was added.
    """
    root = Path(__file__).resolve().parent.parent
    names = {p.name for p in root.iterdir() if p.is_dir() and (p / '__init__.py').is_file()}
    names |= {p.stem for p in root.glob('*.py')}
    return frozenset(names)


def subsystems() -> list[str]:
    """The subsystems UCM can log from, whether or not they have lately.

    Built only from the lines read, the list left a quiet subsystem impossible
    to select — you could not ask for SCEP until SCEP had already said
    something. Every module creates its logger when it is imported, so the
    running process knows them all. Only the top level is offered: filtering is
    by subtree, so `services` reaches all of them, and the 319 leaf names are
    not a list anyone could use in a dropdown without a search box.
    """
    own = _own_top_level()
    return sorted({
        name.split('.')[0]
        for name, logger in logging.Logger.manager.loggerDict.items()
        if not isinstance(logger, logging.PlaceHolder) and name.split('.')[0] in own
    })


def components(records: list[dict]) -> list[str]:
    """Every subsystem, plus the specific loggers the read lines came from.

    The subsystems make a quiet one selectable; the leaves let a reader narrow
    to exactly the line they are looking at. Parents that actually branch are
    offered too: `services.scep` appears when `services.scep.scep_service` and
    `services.scep.intune_client` both do, and a parent with a single child
    would only duplicate it.
    """
    leaves = {r['logger'] for r in records if r['logger']}
    children: dict[str, set] = {}
    for name in leaves:
        parts = name.split('.')
        for depth in range(1, len(parts)):
            children.setdefault('.'.join(parts[:depth]), set()).add(
                '.'.join(parts[:depth + 1])
            )
    branching = {p for p, kids in children.items() if len(kids) > 1}
    return sorted(leaves | branching | set(subsystems()))


def source_path(source: str) -> Optional[Path]:
    """The file a source reads, or None for one that is not a file."""
    if source == APP:
        return resolved_path()
    # gunicorn takes these two from the environment, so the reader has to as
    # well: an install that moves them would otherwise read as not having them.
    if source == ACCESS:
        return Path(os.environ.get('ACCESS_LOG') or LOG_DIR / 'access.log')
    if source == ERROR:
        return Path(os.environ.get('ERROR_LOG') or LOG_DIR / 'error.log')
    return None


def journal_text() -> Optional[str]:
    """The unit journal as text, or None when it holds nothing to show."""
    raw = collect_journal()
    if raw is None:
        return None
    text = raw.decode('utf-8', errors='replace')
    if any(line.strip() and not _JOURNAL_EMPTY.match(line) for line in text.splitlines()):
        return text
    return None


# Whether the journal answers, and when that was last established. Every other
# source is a stat() away, but this one is a process launch, and the page asks
# on every request: five seconds apart while following, and again on each
# keystroke of the search box. Worse, a host whose service user cannot read the
# journal answers with a failure the collector reports, so an uncached probe
# writes a line into the very log the viewer is reading, every five seconds.
#
# The answer only changes when the service is restarted, or its groups are, so
# it is remembered for a while rather than asked again each time.
_JOURNAL_PROBE_TTL = 300.0
_journal_probe: Optional[tuple[float, bool]] = None


def _remember_journal(available: bool) -> None:
    global _journal_probe
    _journal_probe = (time.monotonic(), available)


def reset_journal_probe() -> None:
    """Forget the cached answer, so the next question is asked of journalctl."""
    global _journal_probe
    _journal_probe = None


def journal_available() -> bool:
    """Whether the journal is worth offering, asking journalctl at most rarely."""
    if _journal_probe is not None and time.monotonic() - _journal_probe[0] < _JOURNAL_PROBE_TTL:
        return _journal_probe[1]
    available = journal_text() is not None
    _remember_journal(available)
    return available


def available_sources() -> list[str]:
    """The sources this deployment can actually serve.

    Docker writes no gunicorn files and has no journal, and a native install
    that never started gunicorn has no access log yet. Offering a source that
    answers with nothing is worse than not offering it: it reads as an empty
    log rather than as one that does not exist here.
    """
    available = []
    for source in SOURCES:
        if source == JOURNAL:
            if journal_available():
                available.append(source)
            continue
        path = source_path(source)
        if path is not None and path.is_file():
            available.append(source)
    return available


def level_counts(records: list[dict]) -> dict:
    """How many records carry each level, so a summary need not re-scan."""
    counts = {level: 0 for level in LEVELS}
    counts['UNKNOWN'] = 0
    for record in records:
        counts[record['level'] if record['level'] in counts else 'UNKNOWN'] += 1
    return counts


def read(lines: int = DEFAULT_LINES, level: Optional[str] = None,
         query: Optional[str] = None, source: str = APP,
         logger: Optional[str] = None, since: Optional[str] = None,
         until: Optional[str] = None, exclude: Optional[str] = None) -> dict:
    """Read the tail of one log source as filtered records."""
    if source not in SOURCES:
        source = APP
    count = max(1, min(int(lines), MAX_LINES))

    # Reading the journal is its own answer to whether the journal is there, so
    # the source being read is fetched first and the probe told what it found.
    # Asking after the fact ran journalctl twice for one request.
    text = None
    if source == JOURNAL:
        text = journal_text()
        _remember_journal(text is not None)

    empty = {'source': source, 'path': None, 'exists': False,
             'lines': [], 'truncated': False, 'scan_truncated': False,
             'components': [], 'matched': 0, 'levels': level_counts([]),
             'timezone': server_timezone(),
             'available_sources': available_sources()}

    if source == JOURNAL:
        if text is None:
            return empty
        scan_truncated = False
        path = None
    else:
        path = source_path(source)
        if path is None or not path.is_file():
            return {**empty, 'path': str(path) if path else None}
        text, scan_truncated = _tail_text(path)

    parsed = parse(redact(text), source)
    records = filter_records(parsed, level=level, query=query, logger=logger,
                             since=since, until=until, exclude=exclude)
    # Counted before the line cap: the summary describes what the filters
    # matched, not the tail of it that fitted.
    matched, levels = len(records), level_counts(records)
    if len(records) > count:
        records = records[-count:]
    # Offered from everything read, not from what survived the filters, so
    # choosing a component never empties the list you chose it from.
    # Two different cuts, reported apart: the line cap is what the reader chose
    # and can raise, the byte cap is how far back the file was read at all.
    return {'source': source, 'path': str(path) if path else None, 'exists': True,
            'lines': records, 'truncated': matched > len(records),
            'scan_truncated': scan_truncated,
            'components': components(parsed) if source == APP else [],
            'matched': matched, 'levels': levels,
            'timezone': empty['timezone'],
            'available_sources': empty['available_sources']}
