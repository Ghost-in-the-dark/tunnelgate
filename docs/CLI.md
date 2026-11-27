# The TunnelGate command line

Reference for `app/cli.py`: every subcommand, every flag, what each one touches, and what
its exit code means. Everything here runs on the panel host, as the service user, with the
repository as the working directory (`app.cli` is imported as a module, so the cwd has to
be the checkout).

- Deploying for the first time: [docs/INSTALL_SERVER.md](INSTALL_SERVER.md)
- Something is broken right now: [docs/OPERATIONS.md](OPERATIONS.md)
- What the environment variables below do: [docs/CONFIGURATION.md](CONFIGURATION.md)

## How the command is invoked

There is no console script and no `tunnelgate` binary on `PATH`. `pyproject.toml` declares
no `[project.scripts]` entry points, so the only entry point is the module:

```bash
cd /opt/tunnelgate
.venv/bin/python -m app.cli <command> [options]
```

The parser's `prog` is `python -m app.cli` (`build_parser`), so help and usage lines name
the module. The installed layouts reach it the same way:

| Layout | Invocation |
|---|---|
| Bare metal (systemd unit, `WorkingDirectory=/opt/tunnelgate`) | `sudo -u tunnelgate /opt/tunnelgate/.venv/bin/python -m app.cli doctor` |
| Container | `docker exec -u 10001 <container> python -m app.cli doctor` |
| Installer scripts | `scripts/quick-install.sh` wraps it as `as_panel .venv/bin/python -m app.cli "$@"` |

Run every command as the same user the panel runs as. `doctor` is the one that punishes a
mismatch: it inspects file ownership from the outside, so a root-owned data directory looks
fine to root and broken to the panel (see *doctor*, below).

## Exit codes

`main()` is thin and the contract is uniform:

| Code | Meaning |
|---|---|
| `0` | Fine. Warnings do not change this. |
| `1` | A blocking problem: `doctor` found a `FAIL` check, `check-schema` found drift, `render-proxy` could not sync, `console-url` matched no router. |
| `2` | Bad usage: no subcommand (`main()` prints help and returns 2), an unknown option (`argparse`), a password that failed `password_problem`, `--password` missing on a non-tty. |
| `130` | `KeyboardInterrupt` (Ctrl-C) - "aborted" on stderr. |

The rule that matters operationally: **a failing `doctor` check exits non-zero, a warning does
not.** A deployment script can gate on the exit code, but the only way to see a warning is to
read the output.

## When to run which command

| Situation | Command |
|---|---|
| Fresh install, before the first start | `init-db`, then `seed-admin` |
| Panel came up but there is no login | `seed-admin` |
| Something is wrong and you do not know what | `doctor` |
| Before `systemctl start`, and after any change to nginx/sshd/DNS | `doctor` |
| An upgrade, or "everything 500s after upgrade" | `check-schema` |
| Routes must be republished without restarting the panel | `render-proxy` |
| A router page will not open from a browser | `console-url <router>`, then `doctor` |
| Demo data in a UI screenshot | `seed-demo`, later `seed-demo --purge` |
| Scripts, monitoring, ticket attachments | `doctor --json`, `check-schema --json`, `console-url --json` |

```bash
python -m app.cli --version      # tunnelgate 1.3.0  (argparse "version" action, exit 0)
python -m app.cli                # prints help, exit 2
```

---

## init-db

```
python -m app.cli init-db
```

`cmd_init_db`. Creates the data directories, then runs `init_db()`, which is
`Base.metadata.create_all(engine)` from `app/db.py` - it creates missing tables and indexes
and touches nothing that already exists. Idempotent: running it twice is a no-op.

It ensures `data_dir`, the parent of `TUNNELGATE_AUTHORIZED_KEYS_PATH` and the parent of
`TUNNELGATE_PROXY_ROUTES_PATH` (`_ensure_runtime_dirs`), so nginx and sshd have somewhere to
write before either has been configured.

On SQLite it prints the resolved database path, and lists the tables it can see:

```console
$ .venv/bin/python -m app.cli init-db
database ready: data/tunnelgate.db
tables: audit_logs, bootstrap_tokens, console_sessions, panel_sessions, panel_settings, router_grants, router_runtime, routers, users
```

**Exit codes:** `0` always (a failure raises and prints a traceback; there is no partial
success to report).

**What it deliberately does not do:** add a column to an existing table. That is
`check-schema`'s job - there is no migration engine.

## seed-admin

```
python -m app.cli seed-admin [--username USERNAME] [--password PASSWORD]
```

`cmd_seed_admin`. Creates the administrator, or resets the password and re-enables the account
if the username already exists. It always sets `role="admin"` and `is_active=True`, so this is
also the "I locked myself out" command.

- `--username` defaults to `TUNNELGATE_ADMIN_USERNAME` (default `admin`). The value is used
  verbatim; it is not slug-checked.
- `--password` is optional only on a terminal: omitted, it prompts twice with `getpass`
  ("password for <user>:", "repeat password:"). On a non-tty it refuses with
  `error: --password is required when stdin is not a terminal` and exits `2` - which is why
  installers always pass `--password`.

The password is run through `security.password_problem` first: fewer than
`MIN_PASSWORD_LENGTH` (8) characters, or leading/trailing whitespace, is rejected with exit
`2` and no database change. There is no default password and no `--force`.

```console
$ .venv/bin/python -m app.cli seed-admin --password 'Str0ng-Passw0rd!2026'
created user 'admin' (id=1)
log in at https://panel.example.com/login

$ .venv/bin/python -m app.cli seed-admin --username ops --password 'Str0ng-Passw0rd!2026'
created user 'ops' (id=2)

$ .venv/bin/python -m app.cli seed-admin --password 'short'
error: password must be at least 8 characters        # exit 2
```

The second "updated" run prints `updated user 'admin' (id=1)` and **no** login URL: the URL
is only printed on creation, because on an existing install the address is already known.

The login URL comes from `services.agent_endpoint.agent_url` rather than
`TUNNELGATE_PANEL_URL` - the panel URL is often loopback-only behind a TLS terminator, so it
would be unrunnable from the operator's laptop.

**Exit codes:** `0` created/updated, `2` weak password, mismatched confirmation, or no
`--password` off a tty.

**Security note:** a password on the command line is visible in `ps` and in your shell
history. Prefer the prompt on a shared host; the installers pass it because they have no
choice.

## doctor

```
python -m app.cli doctor [--json]
```

`cmd_doctor`. The centrepiece: it walks a fixed list of checks in a fixed order and prints one
line per check. Every check emits exactly one of three statuses, defined by `Check`
(`app/cli.py:49`) and produced through the `Report` helpers `ok()`, `warn()`, `fail()`:

| Status | Marker | Meaning | Affects exit code |
|---|---|---|---|
| ok | `OK  ` | The check ran and the answer is good. | no |
| warn | `WARN` | Works, but will bite later, or cannot be decided from here. | no |
| fail | `FAIL` | The deployment is broken in a way the operator must fix. | **yes** |

Each non-ok check carries a `fix` line, rendered indented under it as `-> ...`. `Report.render`
appends a tally: `29 checks: 23 ok, 5 warning(s), 1 failure(s)`.

**Exit contract:** `cmd_doctor` is `return 1 if report.failures else 0`. `--json` changes the
output format only - a report with one failure still exits `1`. A monitor can alert on the
exit code, or on `"ok": false` in the JSON.

```console
$ .venv/bin/python -m app.cli doctor
OK   python: 3.13.5 / tunnelgate 1.3.0
WARN secret key: not set (dev mode)
      -> fine for development; production refuses to start without it
OK   cookie flags: secure=False
OK   socket inventory: ss
OK   data dir: data
OK   database: data/tunnelgate.db
OK   database connect: 8 table(s)
...
FAIL launch config: the auth subrequest never forwards X-Tg-Luci-Cookie, so the gate cannot see a router cookie
      -> python -m app.cli render-proxy   # then reload nginx (the .path unit does it)

29 checks: 23 ok, 5 warning(s), 1 failure(s)
```

### --json

The machine-readable shape is `Report.render(as_json=True)`:

```json
{
  "version": "1.3.0",
  "ok": false,
  "checks": [
    {"name": "python", "status": "ok", "detail": "3.13.5 / tunnelgate 1.3.0", "fix": ""},
    {"name": "secret key", "status": "warn", "detail": "not set (dev mode)",
     "fix": "fine for development; production refuses to start without it"}
  ]
}
```

`ok` is `not failures` - the same boolean as the exit code. `name` is a stable label (not the
function name); alert on `status == "fail"` rather than on array position, and expect the set
of checks to differ by mode (path mode adds `sub_filter module` and `routes include`, and
`slug namespace` runs only in path mode).

### The checks, in execution order

The order below is the order in `cmd_doctor`; the display name is what you see, and is
often not the function name.

#### `_check_runtime` - "python", "secret key", "cookie flags"

- `_check_version` emits `OK python: 3.13.5 / tunnelgate 1.3.0` - the interpreter triplet
  plus `app.__version__`. It never fails; a wrong Python fails at import instead.
- **secret key**: `TUNNELGATE_SECRET_KEY` set is `OK`. Unset in `TUNNELGATE_ENV=production`
  is a **failure** (the app refuses to start and stored console keys cannot be decrypted);
  unset in dev is a warning.
- **cookie flags**: `TUNNELGATE_COOKIE_SECURE=true` is `OK`. In production with the flag
  unset it is only a **warning**, deliberately: the app also marks the cookie `Secure` when
  the request arrives over HTTPS from a `TUNNELGATE_TRUSTED_PROXIES` peer, and forcing the
  flag on a panel that is also reachable over plain http hands out a cookie browsers drop.

#### `_check_ss` - "socket inventory"

Is the `ss` binary installed. **This is a failure, not a warning**, and the display name
undersells it: `ss -Hltnp` is the only source of truth for "is this tunnel up". Without it
`services/tunnels.py` returns an empty map by design, every router sits at
`awaiting`/`offline` no matter how healthy it is, and `/api/v1/health` still answers `ok`.
`python:slim` and hand-rolled images ship without `iproute2`; the official image includes it.

Fix: `apt-get install -y iproute2`.

#### `_check_storage` - "data dir", "database", "database connect", "database schema", "authorized_keys dir", "authorized_keys mode", "authorized_keys"

- **data dir**: writes and unlinks a probe file (`_writable_dir`) - it does not trust the mode
  bits. Failure suggests `install -d -o tunnelgate -g tunnelgate -m 0750 <dir>` and, in the
  same `fix`, the container form `-o 10001 -g 10001` (`_dir_fix`: the container runs as a
  fixed uid 10001, so the bare-metal ownership line silently does the wrong thing there).
- **database**: on SQLite, a missing file is a warning pointing at `init-db`; present is `OK`.
- **database connect**: `SELECT 1` plus a table count. Any exception is a **failure**, and
  `_db_access_hint` picks the fix: a `PermissionError` means the documented uid mismatch
  (saying "run init-db" there would send you the wrong way), anything else means fix the
  schema.
- **database schema**: zero tables is a warning, not a failure - `init-db` has not run.
- **authorized_keys dir / mode**: the file must not be group- or world-readable; `sshd`
  ignores a loose file under `StrictModes`, so an `0604` copy is a warning with
  `chmod 600`. An absent file is `OK`: it is written when the first router is created.

#### `_check_ssh` - "sshd reachable", "sshd drop-in", "ssh user", then "authorized_keys"

- **sshd reachable**: a real TCP connect to `TUNNELGATE_SSH_HOST`:`TUNNELGATE_SSH_PORT`.
  Failure: nothing can be installed, because the routers tunnel in here.
- **sshd drop-in**: `/etc/ssh/sshd_config.d/tunnelgate.conf` must contain both
  `AllowTcpForwarding remote` and `GatewayPorts no`. Present but wrong is a **failure**;
  absent is a warning. The fix line is the `install -m 0644 deploy/sshd/tunnelgate.conf ...
  && sshd -t && systemctl reload ssh` sequence.
- **ssh user**: the `TUNNELGATE_SSH_USER` account must exist (`pwd.getpwnam`). Missing is a
  warning with the `useradd --system` line, because the panel can still serve the UI.

#### `_check_authorized_keys_readable` - "authorized_keys"

The check whose name is least self-explanatory and whose failure is most confusing:
**can the SSH account read the file?** `sshd` switches to that account before opening
`authorized_keys`, so a root-owned `0600` file - exactly what a panel started as root writes -
makes every router fail with `Permission denied (publickey)` while the log only says
`Could not open user '...' authorized keys: Permission denied`. Nothing else in the report
would notice.

It judges from mode bits (`_readable_by`), **not** `os.access()`: `doctor` usually runs as
root, and root passes every check, which is precisely the wrong answer. A directory needs the
execute bit as well as read, since `sshd` has to walk into it. Failure prints the
`chown tunnelgate:tunnelgate ...; chmod 0700 <dir>; chmod 0600 <file>` sequence.

#### `_check_slug_namespace` - "slug namespace" (path mode only)

Do existing router slugs collide with the panel's own first path segments
(`config.RESERVED_SLUGS`: `__tg`, `access`, `api`, `assets`, `audit`, `automations`,
`hosts`, `login`, `routers`, `settings`)? Creation refuses these, but a panel upgraded from
an older build can already own one.

Two behaviours worth knowing:

- **In subdomain mode the check does not run and prints nothing** - no line, not even a
  skipped one. A report with fewer checks than usual may just mean `TUNNELGATE_ROUTE_MODE`
  is `subdomain`.
- A clash is a **failure even when it does not break nginx**. `api`/`assets` produce a
  duplicate `location`, so `nginx -t` rejects the whole config and no route update can be
  published; `login` and friends shadow a panel page, and `/login` becomes an unbreakable
  308 -> 401 -> 302 loop that locks the operator out. Slugs are immutable and follow the
  router name at creation, so the fix is to re-create the router under another name.

#### `_check_ports` - "tunnel ports", "console ports", "tunnel bind address"

- **tunnel ports**: free ports out of `TUNNELGATE_PORT_MIN..MAX`. Zero free is a **failure**
  ("delete stale routers, or widen the range"); under 10% free is a warning.
- **console ports**: the console pool must not overlap the tunnel pool at all - an overlap
  hands one port to two listeners, so it is a failure, not a warning.
- **tunnel bind address**: `TUNNELGATE_BIND_ADDRESS` must be `127.0.0.1`; anything else is a
  warning. The tunnel listeners stay on loopback and nginx is the only public listener.

#### `_check_proxy` - "proxy driver", "routes dir", "nginx", "reload command" (+ path-mode extras)

- **proxy driver**: `none` is a warning ("no router vhosts are generated", fine for dev).
  Anything outside `nginx|caddy|none` is a failure. **`caddy` combined with
  `TUNNELGATE_ROUTE_MODE=path` is a failure**: only the nginx renderer rewrites LuCI's HTML
  and scopes cookies per prefix, so every reconcile would raise and every route would silently
  stay unpublished.
- **routes dir**: the same probe/writability rule as the data dir.
- **nginx**: `shutil.which("nginx")` or `/usr/sbin/nginx`. Missing is only a **warning** - in
  the supported container deployment nginx is a separate service, and on bare metal the panel
  only writes config, it never serves it.
- **reload command**: the first token of `TUNNELGATE_PROXY_RELOAD_COMMAND` must be executable
  (failure otherwise). Empty is a warning: the panel writes `routes.conf` but never reloads
  nginx, which is correct with the `tunnelgate-nginx-reload.path` unit and wrong without it.
- **caddy admin** (caddy driver only, in place of the nginx checks): reports
  `TUNNELGATE_CADDY_ADMIN_URL` and warns when it is **not on loopback** - Caddy's admin API
  is unauthenticated by design, so the only thing standing between it and the network is the
  bind address. Keep it on `127.0.0.1`; a remote admin URL is a warning, not a failure,
  because the panel still works while that door is open.
- In path mode with nginx present, two more checks run: `_check_sub_filter` and
  `_check_routes_include`.

##### `_check_sub_filter` - "sub_filter module"

Path mode is the only mode that rewrites LuCI's root-absolute URLs under `/<slug>/`, and it
needs nginx built `--with-http_sub_module`. A stock distro `nginx` package has it; a slim
build may not, and the breakage is invisible until a router page loads with broken CSS and
dead links. A missing module is a **failure** whose fix is either the distro package or
switching to `TUNNELGATE_ROUTE_MODE=subdomain`. If `nginx -V` cannot be read the check is
only a warning - an unreadable module list is not evidence of a missing module.

##### `_check_routes_include` - "routes include"

Does nginx accept the rendered config *where it is included*? Rather than infer the layout,
this runs `nginx -t` and lets nginx answer. That covers both directions: a separate-layout
file (its own `server{}`) included inside a server block is illegal, and a merged-layout file
(locations only) included in the `http` context is illegal.

Two subtleties, both encoded in the code:

- `nginx -t` is a full start-up. Run unprivileged it can die on `/run/nginx.pid` **after**
  printing "syntax is ok" - `_nginx_test_did_not_reach_the_config` detects exactly that and
  downgrades the result to a **warning** ("the config parses, but nginx -t could not finish"),
  telling you to re-run as root. Blaming the include there would send you to move a correct
  include.
- With `settings.gateway_merged` (routers published under the panel's own name) the fix text
  says "include it INSIDE the panel server block"; on a plain-HTTP hop it says to include it in
  the gateway vhost and to remove it from the panel vhost (leaving it there puts every
  `/<slug>/` back on the panel's origin and silently undoes the separation); otherwise it
  points at the `http` context.

This check only runs in path mode with nginx present, and returns silently if `routes.conf`
does not exist yet - `_check_launch` reports a missing render.

#### `_check_launch` - "route mode", "router hostnames", "gateway host", "cookie scope", "public origin", "launch config"

Can a browser actually get from the panel into a router's LuCI? "Public route" is a host the
browser holds no panel cookie for, so the way in is a one-time ticket redeemed at
`/__tg/enter`, which installs a cookie scoped to that router host. Both usual breakages look
identical from the UI: an endless bounce through `/login`.

- **route mode**: an unrecognised `TUNNELGATE_ROUTE_MODE` is a **warning** - the panel falls
  back to `subdomain`, so it works, but not as written. This is the one place an invalid value
  does not fail, because a typo must not stop the panel from booting.
- **router hostnames**: subdomain mode checks `<slug>.<TUNNELGATE_SUBDOMAIN_SUFFIX or
  panel_host>` is a usable host (`_hostname_problem`: not empty, no whitespace, not an IP, has
  a dot, valid DNS labels); path mode checks the gateway host instead
  (`_gateway_problem`, stricter: a bare IP has no obtainable certificate). A bad suffix is a
  **failure**; the fix names `TUNNELGATE_ROUTE_MODE=path` as the way out when no usable domain
  exists at all.
- **gateway host**: in merged layout (gateway == panel host) this is a warning - routers then
  share the panel's origin, so a hostile router page runs in the panel's origin. It works, it
  costs origin isolation, and [docs/SECURITY.md](SECURITY.md) explains the trade. A gateway on
  its own name over a plain-HTTP hop (`TUNNELGATE_PROXY_PLAIN_HTTP=true`, what
  `scripts/quick-install.sh --gateway-host` installs) is **OK**: the renderer emits locations
  only, so the one thing to get right there is the include, which is the "routes include"
  check's job.
- **cookie scope**: `TUNNELGATE_COOKIE_DOMAIN` set is a warning; per-router cookies supersede
  the domain-wide session cookie.
- **public origin**: `TUNNELGATE_PANEL_URL` loopback **and** `TUNNELGATE_PUBLIC_URL` unset is a
  warning, because every redirect would name `127.0.0.1`, which no browser can reach.
- **launch config**: the real check. Missing `routes.conf`/`*.auth.conf` is a warning
  ("start the panel once, or run: render-proxy"). Otherwise it reads the rendered files: no
  `/__tg/enter`, or an auth location that never forwards the router cookie header
  (`X-Tg-Luci-Cookie` by default), is a **failure** with the fix `render-proxy` then reload.
  This is the common upgrade mistake and it is only visible in the generated files.
  - An **empty fleet is not a failure**: the renderer states "No routers currently have an
    allocated tunnel port." and the check reports `OK ... no routers yet`. Treating that as
    stale config used to fail `doctor` on every fresh install, which is the one moment an
    operator is guaranteed to run it.
  - Caddy returns early with a warning: its routes live in memory and cannot be inspected
    from here, so `render-proxy` is the recommended re-push after an upgrade.

#### `_check_agent_endpoint` - "agent endpoint"

The one value an install cannot recover from: the address a router is told to dial. A router
on a customer network has no route to the panel host's loopback, so a loopback endpoint makes
every rendered install command unrunnable and the router simply never appears - with nothing
in the panel's own logs to say so. Loopback is a **warning** (tunnels that already exist keep
working), with the fix `TUNNELGATE_PUBLIC_URL` or the endpoint in *Settings -> Panel*. A good
value reports the URL and its source, for example `https://panel.example.com (public_url)`.

#### `_check_console` - "console", "console ssh client", "console port range", "console key storage"

- **console**: `TUNNELGATE_CONSOLE_ENABLED=false` is a plain `OK console: disabled`. Enabled
  reports the range and the reminder that the ports are loopback-only and must **not** be
  opened in the firewall.
- **console ssh client**: `paramiko` must import. Missing is a **failure** - console sessions
  cannot start (tunnels are unaffected).
- **console port range**: min > max is a failure; otherwise it reports the pool size.
- **console key storage**: no `TUNNELGATE_SECRET_KEY` is a warning - console private keys
  cannot be sealed, and provisioning fails without it in production.

#### `_check_frontend` - "web UI"

`<web_dist>/index.html` exists. Missing is a **warning**: `/api` and `/health` still work, the
SPA is just not built (`cd web && npm ci && npm run build`).

### Reading a doctor report

1. Fix every `FAIL` first; those are the ones that change the exit code.
2. `WARN` lines are judgement calls with the reasoning in the `fix` text - read it before
   "fixing" one. Several are warnings *on purpose*: nginx absent in the container layout, a
   loopback `panel_url` behind a TLS terminator, an unset cookie flag on a dual-scheme panel.
3. If `doctor` itself dies with `PermissionError` or reports "not writable" for files it
   should own, you are running it as the wrong uid - the check is describing you, not the
   install. See [docs/OPERATIONS.md](OPERATIONS.md) section 4.

## check-schema

```
python -m app.cli check-schema [--json]
```

`cmd_check_schema`. Compares the ORM metadata (`_model_columns`, from
`Base.metadata.sorted_tables`) with the live database (`sqlalchemy.inspect`) and prints the
DDL needed to reconcile them. **There is no migration engine by design**: the schema only
ever grows, and a missing column needs an `ALTER TABLE` that `create_all` cannot generate.

Three findings, three different answers:

| Finding | Reported as | Exit |
|---|---|---|
| Nothing missing | `schema up to date (9 tables)` | 0 |
| Extra columns (in DB, not models) | a note; "harmless, but usually means a rollback or a hand edit" | 0 |
| Missing columns | `ALTER TABLE` statements to apply | 1 |
| Missing tables | **not fixable with ALTER TABLE** - restore a backup or start fresh | 1 |

```console
$ .venv/bin/python -m app.cli check-schema
schema drift detected in data/tunnelgate.db

Apply these statements, then restart the panel:

  ALTER TABLE routers ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0;

Back up the database first: sqlite3 <db> '.backup <db>.bak'
Add NOT NULL only after you have values to backfill; SQLite cannot add a
NOT NULL column without a default.
```

### Why the printed DDL carries a DEFAULT

`_column_default` exists because **SQLite refuses `ADD COLUMN` with `NOT NULL` and no
default**. For a column that is non-nullable and has a scalar default in the model, it emits
`NOT NULL DEFAULT <value>` with the right literal (bools become `1`/`0`, strings are
quote-escaped); otherwise it emits neither and leaves the backfill to you. That is why the
closing advice says to add `NOT NULL` only after backfilling - the tool will not invent a
default for a column that has none.

The reported DDL is a suggestion, not an executed migration: the command never writes to the
database. Back up first (`sqlite3 <db> '.backup <db>.bak'`), apply by hand, restart the panel.

### --json

```json
{
  "ok": true,
  "db_url": "sqlite:///./data/tunnelgate.db",
  "missing_tables": [],
  "missing_columns": [],
  "extra_columns": [{"table": "routers", "column": "old_flag"}]
}
```

`ok` ignores `extra_columns` - extra columns do not break the panel. The exit code matches
`ok`, so an upgrade script can run `check-schema --json` and parse the body or just check the
code. `scripts/update.sh` does exactly that before it finishes an upgrade.

**Exit codes:** `0` in sync, `1` drift.

## seed-demo

```
python -m app.cli seed-demo [--no-ports] [--purge]
```

`cmd_seed_demo`. Inserts three fake routers (`DEMO_ROUTERS`) so a fresh UI is not an empty
shell:

| Slug | Name | Status | Group |
|---|---|---|---|
| `demo-office` | Office AP (demo) | `online` | Office |
| `demo-lab` | Lab router (demo) | `offline` | Lab |
| `demo-garage` | Garage repeater (demo) | `pending` | Home |

`online` and `offline` routers get an allocated tunnel port and a `RouterRuntime` row, because
a router without a port gives the proxy renderer nothing to point at. `pending` gets neither -
it was never installed.

- `--no-ports` skips port allocation (`router.remote_port = None`), for a screenshot on a host
  where the pool matters or where `doctor` should not report consumption.
- `--purge` is intercepted in `main()` and calls `cmd_seed_demo_purge`, which deletes every
  router whose slug starts with `demo-`. It is not a seeding mode and ignores the other flags.

Idempotent: an existing slug is skipped, not overwritten.

```console
$ .venv/bin/python -m app.cli seed-demo
created demo router demo-office (online)
created demo router demo-lab (offline)
created demo router demo-garage (pending)

These are fake. Remove them before going live:
  python -m app.cli seed-demo --purge

$ .venv/bin/python -m app.cli seed-demo --purge
deleted 3 demo router(s)
```

Running it again prints `skipped existing router ...` for each and then "nothing to do".

**Exit codes:** `0` in all cases, including "nothing to do". **Remove the demo data before an
install is customer-facing** - it is real rows in the real tables, and the go-live checklist in
[docs/SECURITY.md](SECURITY.md) includes it.

## render-proxy

```
python -m app.cli render-proxy
```

`cmd_render_proxy`. Writes the reverse-proxy config from the database without going through
the running panel - the out-of-band repair path, and the documented fix after an upgrade
changed the rendered vhosts.

It builds a `ProxyManager` and runs the same two steps the panel runs at start-up:

1. `manager.startup()` creates the routes directory and **seeds placeholder files**
   (`routes.conf` and the `*.auth.conf` snippet) with a "generated - do not edit" marker.
   nginx refuses to start if an include target is missing.
2. `manager.sync_routes()` renders from `load_routes` and writes atomically, snippet first - a
   vhost must never be published before the snippet it includes exists, or nginx keeps serving
   the previous fleet config after a failed reload. It then runs
   `TUNNELGATE_PROXY_RELOAD_COMMAND` itself if anything changed; unlike the long-running panel,
   this command is a one-shot, so it reloads in the same process.

If the manager records a `last_error`, the command turns it into
`proxy sync failed: ...` and exits non-zero rather than reporting a happy no-op.

```console
$ .venv/bin/python -m app.cli render-proxy
nginx driver: 12 route(s) -> data/tunnelgate.routes.conf
changed: yes (nginx must be reloaded)

$ TUNNELGATE_PROXY_DRIVER=none .venv/bin/python -m app.cli render-proxy
none driver: 0 route(s) -> data/tunnelgate.routes.conf
changed: no (no reload needed)
```

What gates it: `TUNNELGATE_PROXY_DRIVER` (`nginx`/`caddy`/`none`), `TUNNELGATE_PROXY_ROUTES_PATH`,
`TUNNELGATE_ROUTE_MODE` and `TUNNELGATE_GATEWAY_HOST` (path mode), and
`TUNNELGATE_PROXY_RELOAD_COMMAND`. With `driver=none` it renders nothing and exits `0`.

**Exit codes:** `0` successful sync, even when nothing changed; `1` when the sync failed,
printed as `error: ProxyError: ...` on stderr. Two failures worth recognising: an unknown
driver value, and the reload command exiting non-zero (a common one is `nginx -s reload` with
an empty or missing `/run/nginx.pid`, which happens when nginx is not running yet).

After a successful render on bare metal, `doctor` should show `routes include: OK` and
`launch config: /__tg/enter is served ...`. With the `tunnelgate-nginx-reload.path` unit the
reload is handled for you; for caddy, `render-proxy` is how you re-push every route, because
caddy holds them in memory.

## console-url

```
python -m app.cli console-url [router] [--json]
```

`cmd_console_url`. Prints the URLs an operator actually needs for one router, or for all of
them (`order_by(Router.slug)`) when the positional argument is omitted.

`router` is matched against **slug, id, or name** in one query
(`Router.slug == x | Router.id == x | Router.name == x`). Two routers with the same name make
`scalar_one_or_none` raise rather than guess, so prefer the slug in scripts.

```console
$ .venv/bin/python -m app.cli console-url demo-lab
Lab router (demo) (demo-lab)
  id:          f91ac9569197403a87af8f6310e49c77
  status:      offline
  LuCI:        https://demo-lab.panel.example.com
  open:        https://demo-lab.panel.example.com/__tg/enter
  console:     https://console.panel.example.com/#/routers/f91ac9569197403a87af8f6310e49c77
  direct ssh:  (no console port allocated yet)

Console ports bind 127.0.0.1 on the panel host and are never opened in the firewall.
```

The two LuCI-ish lines are different on purpose, and mixing them up is the usual support
ticket: `LuCI` is the plain router URL (`settings.router_url`), which only authenticates a
browser that already holds that router's cookie; `open` is the `/__tg/enter` launch URL
(`services.launch.launch_url`) that installs the cookie through a one-time ticket. Give
operators `open`, not `LuCI`.

`direct ssh` prints only when a console port is allocated:
`ssh -p <port> <user>@127.0.0.1`, and is explicitly marked "from the panel host only".

### --json

A list, even for one router:

```json
[
  {
    "id": "f91ac9569197403a87af8f6310e49c77",
    "slug": "demo-lab",
    "name": "Lab router (demo)",
    "status": "offline",
    "console_host": "console.panel.example.com",
    "console_port": null,
    "luci_url": "https://demo-lab.panel.example.com",
    "launch_url": "https://demo-lab.panel.example.com/__tg/enter",
    "console_url": "https://console.panel.example.com/#/routers/f91ac9569197403a87af8f6310e49c77"
  }
]
```

`console_host` is `"console." + settings.host_suffix`, not a separately configured value;
`console_port` is `null` until one is allocated.

**Exit codes:** `0` printed; `1` when the argument matched no router
(`error: no router matching 'nope'`) or when there are no routers at all
(`error: no routers yet`). Both messages go to stderr.

---

## Appendix: subcommand matrix

| Subcommand | Flags | Reads | Writes | Exit 0 / non-zero |
|---|---|---|---|---|
| `init-db` | - | settings | DB schema, runtime dirs | 0 / raises |
| `seed-admin` | `--username`, `--password` | settings, users | users row | 0 / 2 |
| `doctor` | `--json` | everything | nothing (probe files only) | 0 / 1 (a FAIL), 2 (usage) |
| `check-schema` | `--json` | models, live DB | nothing | 0 / 1 (drift) |
| `seed-demo` | `--no-ports`, `--purge` | routers | routers, runtime, ports | 0 |
| `render-proxy` | - | routers, settings | `routes.conf`, auth snippet | 0 / 1 |
| `console-url` | `[router]`, `--json` | routers | nothing | 0 / 1 |
| `--version` | - | `app.__version__` | nothing | 0 |

Every command calls `init_db()` (or an equivalent) first, so all of them are safe to run
before the panel has ever started.
