"""Reading the logs back, for the log viewer.

The diagnostic bundle hands whole files to a human; this reads their tails into
records the interface can filter and colour. Redaction and journal collection
are shared with the bundle so both leave by the same gate.

Only the application log carries UCM's own format. The gunicorn streams and the
journal are returned as records with no level rather than being forced through
a parser built for a different shape — a level guessed from someone else's
format is worse than none.

Timestamps are returned exactly as they were written. ``logging.Formatter``
renders ``asctime`` in local time with no zone and no offset, so presenting it
as an instant would attach a timezone the line never carried.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from services.log_bundle import LOG_DIR, collect_journal, redact
from utils.app_log import resolved_path

LEVELS = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')

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


def parse(text: str) -> list[dict]:
    """Turn formatted log text into records, oldest first.

    A traceback spans many lines and only its first carries the prefix, so a
    line that does not match continues the record above it. A line that matches
    nothing and has no record above it is still returned, with no level: these
    are the lines someone is usually hunting for, and dropping them would hide
    exactly that.
    """
    records: list[dict] = []
    for line in text.splitlines():
        match = _RECORD.match(line)
        if match:
            timestamp, name, level, message = match.groups()
            records.append({
                'ts': timestamp,
                'logger': name,
                'level': level,
                'message': message,
            })
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


def filter_records(records: list[dict], level: Optional[str] = None,
                   query: Optional[str] = None,
                   logger: Optional[str] = None,
                   since: Optional[str] = None,
                   until: Optional[str] = None) -> list[dict]:
    """Apply the level floor, the component and the substring search.

    A record with no level is never filtered out by the level floor: its
    severity is unknown, and guessing it silently would hide it. The component
    filter matches a logger and everything below it, so `services.scep` covers
    `services.scep.scep_service` — the dotted names are a hierarchy and an
    operator picking a subsystem means the subtree.
    """
    wanted = _at_least(level)
    needle = (query or '').lower()
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
        and (not needle
             or needle in record['message'].lower()
             or needle in (record['logger'] or '').lower())
    ]


def components(records: list[dict]) -> list[str]:
    """The logger names present, plus every parent that groups more than one.

    A flat list of forty dotted names is not a usable dropdown, so the parents
    that actually branch are offered alongside the leaves: `services.scep`
    appears when `services.scep.scep_service` and `services.scep.intune_client`
    both do, and a parent with a single child would only duplicate it.
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
    return sorted(leaves | branching)


def source_path(source: str) -> Optional[Path]:
    """The file a source reads, or None for one that is not a file."""
    if source == APP:
        return resolved_path()
    if source == ACCESS:
        return LOG_DIR / 'access.log'
    if source == ERROR:
        return LOG_DIR / 'error.log'
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
            if journal_text() is not None:
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
         until: Optional[str] = None) -> dict:
    """Read the tail of one log source as filtered records."""
    if source not in SOURCES:
        source = APP
    count = max(1, min(int(lines), MAX_LINES))
    empty = {'source': source, 'path': None, 'exists': False,
             'lines': [], 'truncated': False, 'scan_truncated': False,
             'components': [], 'matched': 0, 'levels': level_counts([]),
             'timezone': server_timezone(),
             'available_sources': available_sources()}

    if source == JOURNAL:
        text = journal_text()
        if text is None:
            return empty
        scan_truncated = False
        path = None
    else:
        path = source_path(source)
        if path is None or not path.is_file():
            return {**empty, 'path': str(path) if path else None}
        text, scan_truncated = _tail_text(path)

    parsed = parse(redact(text))
    records = filter_records(parsed, level=level, query=query, logger=logger,
                             since=since, until=until)
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
            'components': components(parsed),
            'matched': matched, 'levels': levels,
            'timezone': empty['timezone'],
            'available_sources': empty['available_sources']}
