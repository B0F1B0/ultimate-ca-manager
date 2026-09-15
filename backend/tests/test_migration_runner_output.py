"""The migration report reaches the journal while it is still relevant.

Reported on an upgrade to 2.230: the service logged `Found 1 pending
migration(s) for SQLite:` and nothing more, and the `-> 087_... OK` lines
only appeared minutes later, attributed to the old process, at the next
shutdown. The progress line is written without a newline, so an unflushed
stream leaves journald holding a partial line until the process exits, and
an operator reads it as a migration that never ran.

stdout is block-buffered as soon as it is not a terminal, which is the case
under systemd, so this is checked through a real pipe rather than by reading
the source.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent

PROGRAM = (
    "import sys, time\n"
    "sys.path.insert(0, {backend!r})\n"
    "from migration_runner import say\n"
    "say('Found 1 pending migration(s) for SQLite:')\n"
    "say('  -> 087_demo...', end=' ')\n"
    "say('OK')\n"
    "time.sleep(30)\n"
)


def _run_and_read(program, timeout=10):
    """Start the program, read what arrives before it exits, then kill it."""
    env = dict(os.environ)
    env.pop('PYTHONUNBUFFERED', None)     # the whole point is block buffering
    proc = subprocess.Popen(
        [sys.executable, '-c', program], stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, env=env)
    try:
        seen = b''
        deadline = time.monotonic() + timeout
        os.set_blocking(proc.stdout.fileno(), False)
        while time.monotonic() < deadline:
            chunk = proc.stdout.read()
            if chunk:
                seen += chunk
                if b'OK' in seen:
                    break
            time.sleep(0.05)
        return seen.decode()
    finally:
        proc.kill()
        proc.wait(timeout=5)


class TestTheReportArrivesBeforeTheProcessEnds:
    def test_both_lines_are_readable_while_the_process_is_still_running(self):
        seen = _run_and_read(PROGRAM.format(backend=str(BACKEND)))
        assert 'Found 1 pending migration(s)' in seen, repr(seen)
        # The one that used to be withheld: it carries no newline of its own.
        assert '087_demo' in seen, repr(seen)
        assert 'OK' in seen, repr(seen)

    def test_a_plain_print_is_the_behaviour_being_avoided(self):
        """Without the flush, nothing arrives. This is what was happening."""
        program = (
            "import sys, time\n"
            "print('Found 1 pending migration(s) for SQLite:')\n"
            "print('  -> 087_demo...', end=' ')\n"
            "print('OK')\n"
            "time.sleep(30)\n"
        )
        seen = _run_and_read(program, timeout=3)
        assert seen == '', repr(seen)


class TestSayItself:
    def test_it_flushes_by_default(self):
        from migration_runner import say

        class Recorder:
            def __init__(self):
                self.text = ''
                self.flushes = 0

            def write(self, chunk):
                self.text += chunk
                return len(chunk)

            def flush(self):
                self.flushes += 1

        import contextlib
        rec = Recorder()
        with contextlib.redirect_stdout(rec):
            say('hello')
        assert rec.text == 'hello\n'
        assert rec.flushes >= 1

    def test_an_explicit_flush_false_is_honoured(self):
        from migration_runner import say

        class Recorder:
            def __init__(self):
                self.flushes = 0

            def write(self, chunk):
                return len(chunk)

            def flush(self):
                self.flushes += 1

        import contextlib
        rec = Recorder()
        with contextlib.redirect_stdout(rec):
            say('hello', flush=False)
        assert rec.flushes == 0
