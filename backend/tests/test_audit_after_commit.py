"""An audit entry is written last, once the change it describes is durable.

`AuditService.log_action` commits the session it is given, and rolls all of it
back when it cannot write its own entry. Called anywhere other than last, it
is therefore the call that decides whether the business change survives, and
the caller answers the client with a success for something that has just been
undone.

The order has to hold in both directions:

* A change already staged when the audit fires rides on the audit's commit.
  The entry is what makes it durable, and an entry that cannot be written
  takes it back down with it.
* A change staged *after* the audit is described by an entry that is already
  durable. The audit says the thing happened; the commit that was supposed to
  make it happen can still fail. `services/ca/ca_crud.py` read that way: the
  files were already deleted from disk, the entry said the authority was
  deleted, and only then did the row go.

Sixteen places had it one way or the other and were corrected one at a time:
six deployment routes, two CRL configuration routes, generating a CRL and a
delta CRL, installing an externally signed one, deleting a certificate,
deleting a certificate authority, two ACME authorization paths, a webhook
refusal that recorded the very request it was refusing, and an SSO role
synchronisation that wrote the change down before making it.

Correcting them one at a time does not stop the seventeenth. This does.

The alternative was to change `log_action` so that it stops committing its
caller's session. That changes the meaning of 324 call sites at once, several
of which have no other commit and rely on it. The property is cheaper to
state here: capture what the entry needs, commit, then record.
"""
import ast
import os


SESSION_WRITES = {'add', 'delete', 'add_all', 'merge'}
AUDIT_CALLS = {'log_action', 'log_certificate', 'log_ca', 'log_csr'}
COMMITS = {'safe_commit', 'commit_or_rollback'}

# Enumerating every path through a function is exponential in the number of
# branches. Past this many the function is reported on its statement order
# alone, which is what the scan did before paths were tracked at all.
PATH_CAP = 4000

# Written down rather than silently tolerated. Each one has a reason it is the
# exception, and the reason is what stops it being copied.
DELIBERATE = {
    # The entry has to exist before the database it lives in is wiped. The
    # reset destroys it either way, so there is no ordering that saves it.
    'api/v2/system/database.py:reset_db',

    # The audit follows the commit that issues the certificate. What comes
    # after it is the SCT metadata, a separate row for a separate concern,
    # committed on its own and rolled back on its own when a log is
    # unreachable. Losing it does not unissue the certificate.
    'services/cert/mixins/lifecycle.py:create_certificate',
}


def _kind(call):
    """Classify a call as staging a change, committing, or auditing."""
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in AUDIT_CALLS:
        return 'audit'
    if isinstance(func, ast.Name) and func.id in COMMITS:
        return 'commit'
    if isinstance(func, ast.Attribute) and func.attr == 'commit':
        return 'commit'
    if isinstance(func, ast.Attribute) and func.attr in SESSION_WRITES:
        # `db.session.add(...)`, not some set's `.add(...)`. The owner has to
        # be a session: a plain Python set named `renewed_ca_ids` cost this
        # scan a false positive once, and the false positive was believed.
        owner = func.value
        if isinstance(owner, ast.Attribute) and owner.attr == 'session':
            return 'write'
        if isinstance(owner, ast.Name) and owner.id == 'session':
            return 'write'
    return None


def _events(node):
    out = [(c.lineno, _kind(c)) for c in ast.walk(node)
           if isinstance(c, ast.Call) and _kind(c)]
    return sorted(out)


def _paths(body):
    """One event list per control-flow path through `body`.

    Branch-blind scanning reads a refusal audited in one arm and a commit
    reached only in the other as a single sequence. Three quarters of what it
    reported were pairs that no single request can reach.
    """
    results = [[]]
    for stmt in body:
        if isinstance(stmt, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return [p + [(getattr(stmt, 'lineno', 0), 'stop')] for p in results]
        if isinstance(stmt, ast.If):
            branches = _paths(stmt.body) + (_paths(stmt.orelse) if stmt.orelse else [[]])
        elif isinstance(stmt, (ast.For, ast.While, ast.AsyncFor)):
            # Zero trips or one. A second trip repeats the first one's events
            # and reveals no ordering the first does not.
            branches = [[]] + _paths(stmt.body)
        elif isinstance(stmt, ast.Try):
            arms = [stmt.body] + [h.body for h in stmt.handlers]
            if stmt.orelse:
                arms.append(stmt.orelse)
            branches = [b for arm in arms for b in _paths(arm)]
            if stmt.finalbody:
                tails = _paths(stmt.finalbody)
                branches = [b + t for b in branches for t in tails][:PATH_CAP]
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            branches = _paths(stmt.body)
        else:
            branches = [_events(stmt)]
        merged = []
        for prefix in results:
            if prefix and prefix[-1][1] == 'stop':
                merged.append(prefix)
                continue
            for branch in branches:
                merged.append(prefix + branch)
                if len(merged) > PATH_CAP:
                    return merged
        results = merged
    return results


def _audit_out_of_order(fn):
    """The line of the first audit this function reaches out of order."""
    for path in _paths(fn.body):
        pending = False
        for index, (line, kind) in enumerate(path):
            if kind == 'stop':
                break
            if kind == 'write':
                pending = True
            elif kind == 'commit':
                pending = False
            elif kind == 'audit':
                if pending:
                    return line          # the entry carries the change
                staged = False
                for later_line, later_kind in path[index + 1:]:
                    if later_kind == 'stop':
                        break
                    if later_kind == 'write':
                        staged = True
                    elif later_kind == 'commit' and staged:
                        return line      # the entry ran ahead of the change
                pending = False
    return None


def _offenders():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    found = []
    for zone in ('api', 'services', 'auth', 'utils'):
        for base, _dirs, names in os.walk(os.path.join(here, zone)):
            if '__pycache__' in base:
                continue
            for name in names:
                if not name.endswith('.py'):
                    continue
                path = os.path.join(base, name)
                try:
                    tree = ast.parse(open(path).read())
                except SyntaxError:
                    continue
                for fn in ast.walk(tree):
                    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    hit = _audit_out_of_order(fn)
                    if hit:
                        rel = os.path.relpath(path, here)
                        if f'{rel}:{fn.name}' not in DELIBERATE:
                            found.append(f'{rel}:{hit} {fn.name}')
    return sorted(found)


class TestAuditLast:
    def test_no_audit_is_written_out_of_order(self):
        offenders = _offenders()
        assert offenders == [], (
            'at these places an audit entry and the change it describes are '
            'not committed in that order, so the entry decides whether the '
            f'change survives or describes one that may not: {offenders}. '
            'Capture what the entry needs, commit, then record.')

    def test_the_exceptions_still_name_something(self):
        """A reason written for a function that no longer exists is a reason
        nobody re-reads, and a hole nobody sees."""
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for entry in sorted(DELIBERATE):
            path, name = entry.rsplit(':', 1)
            full = os.path.join(here, path)
            assert os.path.exists(full), f'{path} is gone'
            tree = ast.parse(open(full).read())
            names = {fn.name for fn in ast.walk(tree)
                     if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))}
            assert name in names, f'{entry} no longer names a function'
