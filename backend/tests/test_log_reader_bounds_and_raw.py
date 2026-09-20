"""An end bound closes the minute or the day it names, and every record keeps
the line as the log wrote it."""
from services.log_reader import ACCESS, JOURNAL, filter_records, parse

APP_LINES = ("2026-09-20 01:08:00 [a] INFO first\n"
             "2026-09-20 01:08:30 [a] INFO inside the minute\n"
             "2026-09-20 01:09:00 [a] INFO next minute\n"
             "2026-09-20 02:00:00 [a] INFO later\n")


def test_until_given_to_the_minute_keeps_the_whole_minute():
    records = filter_records(parse(APP_LINES), until="2026-09-20T01:08")
    assert [r["message"] for r in records] == ["first", "inside the minute"]


def test_until_given_to_the_day_keeps_the_whole_day():
    records = filter_records(parse(APP_LINES), until="2026-09-20")
    assert len(records) == 4


def test_since_is_still_the_instant_itself():
    records = filter_records(parse(APP_LINES), since="2026-09-20T01:09")
    assert [r["message"] for r in records] == ["next minute", "later"]


def test_records_carry_the_line_as_written():
    records = parse("2026-09-20 01:08:00 [a] ERROR boom\nTraceback\n  File x\n")
    assert records[0]["raw"] == "2026-09-20 01:08:00 [a] ERROR boom\nTraceback\n  File x"
    access = parse('10.0.0.1 - - [20/Sep/2026:01:08:00 +0200] "GET / HTTP/1.1" 200 5\n', source=ACCESS)
    assert access[0]["raw"].startswith("10.0.0.1 - - [20/Sep/2026")
    journal = parse("2026-09-20T01:08:00+02:00 host ucm[1]: started\n", source=JOURNAL)
    assert journal[0]["raw"] == "2026-09-20T01:08:00+02:00 host ucm[1]: started"
    loose = parse("no format at all\n")
    assert loose[0]["raw"] == "no format at all"
