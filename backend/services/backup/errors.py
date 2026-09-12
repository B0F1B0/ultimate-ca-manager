"""Errors raised while building a backup archive.

An archive that is missing a section, or that carries a key nobody can
decrypt, is not a backup: it is a file that will only reveal what it lost on
the day it is restored. Every such condition aborts the backup with one of
these errors instead of being downgraded to a log line.
"""


class BackupExportError(RuntimeError):
    """A requested section could not be exported.

    The message names the section (and, for key material, the object) so an
    administrator can act on it. It never carries key material, secrets or the
    underlying driver error, and is safe to return to the caller.
    """


class ScheduledBackupError(RuntimeError):
    """The scheduled backup task could not produce a usable archive.

    Raised so the scheduler records the run as failed: the task used to
    swallow every error and still report a successful run.
    """
