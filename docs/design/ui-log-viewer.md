# Surfacing UCM logs in the web UI — design note

> Internal design note for `feature/log-viewer`, not user documentation. It is
> deliberately not indexed in `docs/README.md`. Delete it or fold it into the
> admin guide if the feature lands; delete it if it does not.

## Goal

Let an administrator read UCM's own application log from the web interface,
instead of needing shell access to the host. Today the only route to those
lines is `journalctl`, a file under `/var/log/ucm/`, or `docker logs` — none of
which an operator running UCM as an appliance necessarily has.

The immediate motivation is SCEP troubleshooting. A SCEP request rejected
during validation is refused before a request record exists, so it never
appears on the SCEP Requests page, and the failure travels inside a signed PKI
message under HTTP 200 so `access.log` shows nothing unusual either. The only
record of *why* is a `logger.warning` line. That is the class of problem this
feature exists to solve.

## What already exists

Roughly two thirds of the backend is already written, for the diagnostic ZIP
bundle:

| Piece | Location | Reusable as |
|---|---|---|
| `_tail_bytes(path, max_bytes)` | `services/log_bundle.py` | Reading the tail of a log file at a line boundary |
| `_collect_journal()` | `services/log_bundle.py` | `journalctl -u ucm -n N --output=short-iso` |
| `_redact(text)` | `services/log_bundle.py` | Secret redaction, six patterns |
| `LOG_DIR` | `services/log_bundle.py` | `UCM_LOG_DIR`, default `/var/log/ucm` |
| Admin-gated endpoint + audit entry | `api/v2/system/logs.py` | The pattern to copy |
| `admin:system` scope | `auth/permissions.py` | Already admin-only, no new scope needed |

The bundle is surfaced in the UI at `AboutSection.jsx:25` as a ZIP download.
This feature is largely "make the same data readable in the browser rather than
only downloadable as an archive".

## The problem: no current log destination works everywhere

Where UCM's application log actually goes depends on the deployment, and no
single source is readable by the app on all of them:

| Deployment | Application log destination | App can read it? |
|---|---|---|
| DEB / RPM (systemd) | `RotatingFileHandler` → `/var/log/ucm/ucm.log` | Yes, when the handler opened successfully |
| DEB / RPM, handler failed | stderr → journald (unit sets `StandardError=journal`) | **No** — see below |
| Docker | stdout → `docker logs` | **No** — nothing is written to disk at all |
| Dev / source | stderr or file, depending on `UCM_LOG_FILE` | Varies |

Two specific blockers:

1. **Docker writes no log file.** `is_docker()` routes application logging to
   stdout and sets gunicorn's `accesslog`/`errorlog` to `-`. Nothing under
   `/var/log/ucm/` exists, and `_collect_journal()` returns `None` on Docker by
   design. A viewer that reads files shows an empty page to every Docker user.

2. **The service user probably cannot read the journal.** `packaging/debian/postinst`
   adds `ucm` only to the HSM group, never to `systemd-journal` or `adm`.
   Reading a *system* unit's journal requires one of those, so `journalctl -u ucm`
   run as `ucm` returns nothing. `_collect_journal()` swallows that at `info`
   level and returns `None`, which means **the existing diagnostic bundle is
   most likely already shipping without the journal it advertises.** That is a
   bug in its own right, independent of this feature.

`app.py` also falls back from the file handler to stderr on `PermissionError`
or `FileNotFoundError`, so which destination is live on a given host is not
obvious from the outside. That ambiguity is itself worth removing.

## Proposal: one canonical log file, written on every deployment

Keep every stream destination as it is, and resolve the *file* destination in
preference order so exactly one file is always written and its path is known:

```
                 ┌─ StreamHandler → stdout (Docker) / stderr (fallback only)
root logger ─────┤        unchanged — `docker logs` and journalctl keep working
                 └─ RotatingFileHandler → first path that opens:
                        native:  UCM_LOG_FILE or /var/log/ucm/ucm.log
                        then:    DATA_DIR/ucm.log      ← always writable
                        docker:  DATA_DIR/ucm.log      (no /var/log/ucm there)
```

One handler rather than two: writing the same lines to both
`/var/log/ucm/ucm.log` and `DATA_DIR/ucm.log` on a healthy native install
doubles the disk cost for nothing, and a reader that has to guess between two
paths reintroduces the ambiguity this is meant to remove. Native installs keep
their existing path, so logrotate and operator runbooks are untouched; the data
directory is the fallback that used to be stderr. `utils.app_log.resolved_path()`
reports the choice, and the diagnostic bundle and the viewer both read it.

`DATA_DIR` is the right home because it is already the one writable,
persistent location on every deployment:

| Deployment | `DATA_DIR` | Persistent? |
|---|---|---|
| DEB | `/opt/ucm/data` | Yes — in the unit's `ReadWritePaths` |
| RPM | `/var/lib/ucm` | Yes — in the unit's `ReadWritePaths` |
| Docker | `/opt/ucm/data` | Yes — the `ucm-data` named volume |
| Dev | `<repo>/data` | Yes |

Notably, `Config.LOG_FILE = DATA_DIR / "ucm.log"` **already exists** in
`config/settings.py` and nothing reads it. This design is what that setting was
evidently sketched for; it was never wired up. Wiring it up also lets us delete
the dead `Config.AUDIT_LOG_FILE` beside it, or give it the same treatment.

Consequences worth stating:

- Docker gains real log history that survives container restarts, which it does
  not have today (`docker logs` is lost when the container is recreated).
- Backups are unaffected: they are entity exports built from the database, not
  a `DATA_DIR` tarball, so a log file there is not swept in.
- Disk cost is bounded by the rotation policy, below.

### Rotation

Match the existing native handler: `maxBytes=10 MB`, `backupCount=5`, so at
most ~60 MB. Both should be settable (`UCM_LOG_MAX_BYTES`, `UCM_LOG_BACKUPS`)
so a small appliance can turn it down. The packaged `logrotate` config must not
be pointed at this file — `RotatingFileHandler` rotates it itself, and two
rotators on one file corrupt each other.

### Should this replace the `/var/log/ucm/ucm.log` handler?

No. Native installs, existing `logrotate` config, and any operator tooling
already expect that path. Adding a second handler is additive and reversible;
moving the canonical path is a breaking change for no benefit here.

## Secondary sources

Once the canonical file exists, the same endpoint can offer other sources where
they happen to be available, each degrading to "not available on this
deployment" rather than to an empty page:

| Source | Available on | Notes |
|---|---|---|
| `app` | everywhere | the resolved application log — the default |
| `access` | native only | gunicorn access log, HTTP lines only |
| `error` | native only | gunicorn worker startup, unhandled tracebacks |
| `journal` | systemd only | needs the postinst group fix, which phase 2 lands |

The response carries `available_sources`, computed per request from what is
actually there, and the interface offers only those. A source that would answer
with nothing is not offered at all: an empty pane reads as "the log is empty"
rather than as "this deployment has no such log".

Only `app` carries UCM's own format. The gunicorn streams and the journal come
back as records with no level rather than being forced through a parser built
for a different shape, and the level floor never discards a record whose
severity is unknown.

## API

```
GET /api/v2/system/logs
    ?source=app|access|error|journal     default: app
    &lines=200                           default 200, cap 2000
    &level=DEBUG|INFO|WARNING|ERROR      minimum level, default INFO
    &q=<substring>                       case-insensitive filter
    &cursor=<opaque>                     for "load older"
```

```json
{
  "source": "app",
  "available_sources": ["app", "access"],
  "lines": [
    {
      "ts": "2026-09-19T13:41:36Z",
      "level": "WARNING",
      "logger": "services.scep.scep_service",
      "message": "SCEP error response: failInfo=1, message=Invalid challenge password",
      "raw": "..."
    }
  ],
  "truncated": true,
  "next_cursor": "…"
}
```

Gate on `admin:system`, matching the bundle endpoint, and audit the read the
same way `download_log_bundle` does.

### Parsing

The formatter is `'%(asctime)s [%(name)s] %(levelname)s %(message)s'` with
`datefmt='%Y-%m-%d %H:%M:%S'`, so a line is parseable with one regex. Two
details that will otherwise bite:

- **Multi-line records.** Tracebacks span many lines and only the first carries
  the prefix. Continuation lines must be appended to the preceding record, not
  dropped and not emitted as malformed entries.
- **Unparseable lines.** Anything that does not match (gunicorn's own format,
  third-party output) should still be returned with `level: null` rather than
  discarded, or the viewer will silently hide exactly the lines someone is
  hunting for.

## Redaction and security

Reuse `_redact()` unchanged, server-side, before anything leaves the process.

It is worth being clear-eyed that this widens exposure relative to today. The
ZIP bundle is a deliberate act by an admin who then controls the file; a log
panel in the browser is persistent, searchable, and visible to anyone who can
see that screen. The six existing patterns are reasonable defence in depth but
they are pattern matching, not a guarantee — they will not catch a secret
logged in an unanticipated shape.

Mitigations:

- Keep the gate at `admin:system` (admin only). Do not extend to `operator` or
  `auditor`, even read-only.
- Audit every read, as the bundle download already does.

**Decided: no kill-switch setting.** The idea was a toggle disabling the viewer
outright, on the reasoning that a stolen admin session would otherwise gain a
searchable window over everything logged, where today that needs host shell
access. It is not worth it: an admin can already export private keys and
download full backups containing the entire database, both strictly more
dangerous than reading a log. A switch that disables the lesser capability
while the greater ones stay available buys nothing but another setting to
maintain.

## UI

**Decided: a top-level page in the sidebar's Administration group**, beside
Users, Access Control, HSM Management and Audit Logs — not a Settings section.
Something reached while troubleshooting should be one click from anywhere, and
it sits naturally next to Audit Logs, which answers the adjacent question ("who
did what" vs "what did the server do").

Concretely, a child entry in the `admin` group in `components/Sidebar.jsx`:

```js
{ id: 'logs', icon: FileText, labelKey: 'common.systemLogs',
  path: '/logs', adminOnly: true },
```

with a matching route in `App.jsx` and a `SystemLogsPage.jsx` beside
`AuditLogsPage.jsx`. `adminOnly: true` matches Users and Access Control, and
mirrors the `admin:system` gate on the endpoint — the nav entry should not
appear for anyone who would get a 403 from it.

Minimum useful set: source selector, level filter, substring search, line-count
selector, manual refresh, "load older", and copy-to-clipboard. Colour by level,
monospace, newest last.

Live tail is deliberately out of scope for a first cut. The WebSocket
infrastructure exists (`backend/websocket/`), but streaming log lines over it
needs care — a log-driven emit that itself logs is an easy feedback loop, and
per-connection authorisation has to be right. Polling on demand is enough to
validate the feature.

## The dead settings beside this one

`config/settings.py` defines two log paths that nothing reads:

```python
LOG_FILE = DATA_DIR / "ucm.log"
AUDIT_LOG_FILE = DATA_DIR / "audit.log"
```

- **`LOG_FILE` — wire it up.** It is exactly the canonical path this design
  needs, already pointing at `DATA_DIR`.
- **`AUDIT_LOG_FILE` — delete it.** Decided. The audit trail is a database
  table with a hash chain (`prev_hash` / `entry_hash`, verified by
  `/api/v2/audit/verify`), so tamper evidence already exists; and off-box
  durability — the real reason to mirror an audit trail to a second place — is
  already solved by `services/syslog_service.py`, which forwards audit events
  to a remote syslog server over UDP, TCP or TCP+TLS. A local file on the same
  host, writable by the same user, adds nothing a SIEM feed does not do better.
  It is a dead setting that reads like a feature.

## Phasing

1. **Canonical log file.** Add the `DATA_DIR/ucm.log` handler, wire up
   `Config.LOG_FILE`, delete `Config.AUDIT_LOG_FILE`, add the rotation env
   vars, keep every existing destination. Independently useful: it gives Docker
   persistent log history and makes the diagnostic bundle complete on Docker
   too.
2. **Journal group fix.** Add `ucm` to `systemd-journal` in the DEB and RPM
   post-install so `_collect_journal()` actually returns something. Folded in
   here rather than deferred: it repairs the *existing* diagnostic bundle,
   which today advertises a journal it almost certainly does not contain, and
   it is a two-line change next to the HSM group line already there. It should
   be its own commit so it can be cherry-picked if this feature stalls.
3. **Read endpoint.** `GET /api/v2/system/logs` over the canonical file, with
   parsing, filtering, redaction, admin gate, audit entry, tests.
4. **UI.** `SystemLogsPage.jsx` plus the sidebar entry, per the decision above.
5. **Secondary sources.** `access`, `error`, `journal`.

Phases 1 and 3 are the substance. Phase 1 is worth landing on its own even if
the UI is never built, and phase 2 is a bug fix that stands alone entirely.

## Open questions

None outstanding — placement, the kill switch, the journal fix and the dead
settings are all decided above.

## Risks

| Risk | Mitigation |
|---|---|
| Secrets in logs become easier to see | Server-side redaction, admin-only gate, audited reads, optional kill switch |
| Two rotators on one file | Keep the packaged `logrotate` config pointed only at the `/var/log/ucm/` files |
| Disk growth on small appliances | Bounded rotation, configurable via env |
| Large responses | Cap `lines` at 2000, cap bytes read per request |
| Log volume grows under DEBUG | Level filter applied server-side, not in the browser |
