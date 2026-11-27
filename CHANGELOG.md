# Changelog

All notable changes to TunnelGate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Panel and router are versioned separately: `agent/install.sh` carries its own
`CLIENT_VERSION` (the bootstrap protocol the panel records per router), so a panel patch release
does not require reinstalling every router.

## [1.3.0] - 2026-11-27

A security release. Two of the three findings below were not theorised: they were reproduced in a
real browser against a copy of the shipped configuration before anything was changed, and the
browser transcript - a router page creating a second admin account, then reading a *neighbour*
router's LuCI - is why this is a minor bump with a breaking edge for API clients rather than a
patch.

The theme is one sentence: **a path is not an origin boundary**. The panel's merged path layout
(router pages served on the panel's own hostname) turned a compromised router into a working
panel session, and turned each router into a reader of every other router. It remains supported -
one public name is all some deployments have - but it is no longer what the installer chooses for
you silently, and the docs now say exactly what it costs.

### Security

- **Per-router authorization (`RouterGrant`).** The proxy gate authenticated callers and stopped
  there: any signed-in account, a `viewer` included, could open every router's LuCI and read every
  router row, because nothing answered "may *this* user reach *this* router". A new
  `router_grants` table and one predicate (`app/services/access.py`) now answer that question for
  the gate, the router API, the launch hand-off and the console. `admin` and `operator` reach
  every router - they can rotate a key and take one anyway, so a grant would be theatre - and a
  `viewer` reaches only what an admin granted. Admin routes: `GET`/`PUT
  `/api/v1/users/{id}/routers` (PUT replaces the whole set; an unknown id is a 400 naming it) and
  `DELETE /api/v1/users/{id}/routers/{router_id}`. **Upgrade note:** this is a new *table*, which
  `init-db` creates automatically, so no `ALTER TABLE` is needed. Existing `viewer` accounts start
  with no grants and therefore see no routers until an admin grants them - by design, but say so
  before upgrading if anyone signs in as a viewer today.
- **The console verifies the router's SSH host key.** `ConsoleHostKeyPolicy` was supposed to pin
  it and never could: `_pinned_host_key_fingerprint()` probed attribute names the model did not
  have, so the pin was always `None`, every handshake logged "unpinned" and accepted anything.
  A router - or anything that had taken one - could terminate the panel's SSH session with a host
  key of its choosing and read the operator's keystrokes. The key is now pinned on first use
  (`Router.console_host_key_fingerprint`, `console_host_key_seen_at`) and every later handshake
  must match it or the console refuses with `console_auth_failed` and a message naming the
  remedy. `GET /api/v1/routers/{id}/console` reports the pin; `DELETE .../console/host-key`
  clears it for a device an admin has verified out of band. **Upgrade note:** two new *columns* on
  `routers`; `init-db` will not add them, so run `python -m app.cli check-schema` and apply the
  printed `ALTER TABLE routers ADD COLUMN ...` statements with a backup taken first. Until you do,
  the console cannot persist a pin - it still refuses a changed key within one session, but
  relearns on the next open, and `doctor` shows the drift.
- **The CSRF token is no longer in any response body.** It lived in the JSON of
  `POST /api/auth/login` and `GET /api/auth/me`, which was safe exactly while `/api/` was a
  different origin from anything able to run script - untrue in the merged layout, where one
  `fetch` of `/api/auth/me` was enough to lift it. It is now delivered in its own cookie
  (`TUNNELGATE_CSRF_COOKIE_NAME`, default `tg_csrf`) and every mutating request must present the
  header *and* the cookie, agreeing with each other and with the session row
  (`app/deps.py:csrf_protect`, constant-time). **Breaking for hand-written API clients** that read
  `csrf_token` from the JSON: read the cookie instead. The SPA does so automatically, so a browser
  user needs only a reload. Be clear about the limit: a script that already runs in the panel
  origin can read a non-`HttpOnly` cookie just as it read the body, so this narrows the
  merged-layout exposure rather than closing it.

### Added

- **`scripts/quick-install.sh` stops choosing the shared origin for you.** It now asks, and with
  no terminal it refuses: the refusal names both ways forward instead of installing the risky
  layout silently. `--gateway-host NAME` publishes routers on their own name over the same plain
  HTTP listener (new `deploy/nginx/tunnelgate-gateway-behind-proxy.conf`, and the panel vhost's
  `routes.conf` include is *removed* in that layout so router paths do not exist on the panel
  origin at all), and `--allow-shared-origin` is the explicit consent for the one-name case. The
  new setting `TUNNELGATE_PROXY_PLAIN_HTTP` (default `false`, so every existing rendering is
  byte-identical) tells the renderer that nginx serves plain HTTP and TLS terminates in front.
- **Router grants in the UI.** Settings -> Users gains a "Routers" action for `viewer` rows: a
  dialog listing every router as a checkbox, the current grants pre-checked, one Save sending the
  complete set. The action is hidden for `admin`/`operator`, and the row explains which of the two
  rules applies rather than offering checkboxes that would imply a restriction that does not
  exist.
- **`docs/SECURITY.md` §6.2, "Router-to-router visibility".** The merged layout's second
  consequence had no home: A11 covered "a router can become the panel", not "a router can read its
  neighbours". §6.2 states it, names what does and does not reduce it, and limitation 11 now
  carries both halves.

### Fixed

- `GET /api/v1/stats` and `GET /__tg/launch` enforced less than the routes around them: the
  counters counted every router for every role (telling a `viewer` the fleet's size and health for
  devices they cannot open), and the launch hand-off minted a router credential for a `viewer`
  with no grant - a ticket born dead, plus a misleading `luci.launch` audit row. Both now use the
  same per-router predicate as everything else.

### Changed

- `docs/SECURITY.md` limitation 4 is no longer "no per-router ACL" but the grant rule that exists,
  with the merged-layout caveat attached; `README.md` carries the same correction.
- `docs/API.md`, `docs/CLI.md`, `docs/CONFIGURATION.md`, `docs/INSTALL_SERVER.md`, `docs/INDEX.md`
  and `deploy/env/tunnelgate.env.example` follow the new routes, the two new settings and the
  revised contracts.

## [1.1.2] - 2026-11-19

The release that makes the router install work on a stock router, and makes the panel reachable
from one that does not trust its certificate. Both were measured on real OpenWrt images of every
generation rather than reasoned about, and both changed the design.

Numbered as a patch release at the maintainer's request. It carries two feature-level changes
(the fetcher-probing installer and the TLS-trust toggle), which would normally be a minor bump,
and it supersedes the never-published 1.2.0: that tag was cut, found to contain the defects
listed under Security below, and withdrawn before anyone could install from it. There is no
1.2.0 to upgrade from and no 1.1.1.

### Added

- **An install command that works with no curl.** No official OpenWrt image ships curl, and
  `/usr/bin/wget` there is a symlink to `uclient-fetch` — which only gained `--header` in 24.10
  and does not retry a POST after a 401, so the old `curl -fsSL -H 'X-Bootstrap-Token' …` one-liner
  could not work on the devices it was written for. The panel now emits one command that probes
  for curl or wget itself, fetches the installer to `/tmp/tg-install.$$.sh`, greps it for the
  installer's sentinel and only then runs it — because a 401 answers an empty body, and `| sh` on
  an empty body is a silent success. The token rides as the **basic-auth username** with a
  placeholder password: measured through a logging proxy, `uclient-fetch` sends
  `base64(TOKEN:x)` and the panel answers 200, while an empty password sends `base64(TOKEN)` with
  no colon and the panel answers 401. URL userinfo is gone: GNU wget 1.25 rejects it outright.
- **Three token channels, and a challenge.** `X-Bootstrap-Token`, the HTTP Basic username, and a
  `bootstrap_token` body field authenticate the exchange; `X-Api-Token`, the Basic username and an
  `api_token` body field authenticate the heartbeat. Every 401 now carries
  `WWW-Authenticate: Basic realm="tunnelgate"`, which is what makes a challenge-response client
  retry at all. Bodies are parsed by hand rather than declared as pydantic models, because
  `uclient-fetch` always posts `application/x-www-form-urlencoded` and a declared model answered
  422 before the handler ran.
- **"Ignore SSL self-signed certificates"** on the Agent endpoint card (Settings → Panel), stored
  as `verify_tls` next to the endpoint. Off, the install command gains `curl -k` /
  `wget --no-check-certificate` and one comment line saying so, the installer injects
  `TG_TLS_VERIFY=0`, the agent writes `tunnelgate.main.tls_verify` and the heartbeat stops
  verifying. On, every command is byte-identical to what it was. The setting is normalised rather
  than rejected: `http` forces it true (there is no certificate to check), and an unreadable
  stored value falls back to verifying — never the other way round.
- **`tests/test_install_contract.py`** — the rendered installer, which nothing had ever tested.
  It renders through `bootstrap.render_install_script`, runs the result, and asserts it gets past
  its own self-check; it also proves a damaged body is still refused. Two of its tests failed when
  first written, and the reason was a real defect (see Fixed).
- **`tests/test_docs_config.py`**, **`tests/test_security.py`**, **`tests/test_heartbeat.py`** —
  the documented setting count, the documented install command, the basic-auth parser, and the
  heartbeat's TLS policy, each asserted instead of promised.
- **`docs/CLI.md`**, **`docs/CONFIGURATION.md`** (all 61 settings, their defaults and the failure
  each one prevents), **`docs/INDEX.md`** (a routed map of every document) and
  **`CONTRIBUTING.md`**.
- The router agent installs the OpenSSH client itself when the router has only dropbear, including
  on images that use `apk`.
- **The installer refuses to hand a private key over an unverifiable channel.** On a 19.07-generation
  image the fetcher accepts a self-signed certificate (measured), so a warning in `logread` is not
  consent - and the host key fingerprint arrives in the *same response* as the private key, so a
  machine on the path can substitute the key, the fingerprint and the pin together;
  `pin_host_key` cannot detect that, because its input is attacker-controlled from the start. When
  the panel URL is https and `tls_verify=1`, the install now stops **before the POST**. The two
  ways forward are an upgrade to 21.02 or newer, or turning the check off in the panel - which puts
  the acknowledgement in an audited setting rather than an environment variable. There is
  deliberately no `TG_FORCE` bypass: mixing "not OpenWrt" and "I accept an unauthenticated panel"
  into one switch is how both get used by accident. The same capability warning now also appears in
  the heartbeat (once per boot, on `tmpfs`, so it cannot accumulate) and in `--status`, so an
  operator who never re-reads the install log still sees it.

### Fixed

- **The installer never installed OpenSSH.** `ensure_openssh()` began with `command -v ssh`, which
  on every stock image is a symlink to `/usr/sbin/dropbear` — so it logged "openssh-client
  present" and installed nothing, the exact state its own comment said it could not tolerate
  (`permitlisten` cannot be enforced per key by dropbear). Detection is now functional: `ssh -V`
  must mention `OpenSSH_`, `ssh-keygen` must *generate* an OpenSSH-format key and read it back
  (dropbear's cannot, and prints `Exited: String too long` while exiting 0), and `ssh-keyscan`
  must exist. Each failed probe names the package that fixes it: `openssh-client` alone is not
  enough, since `ssh-keygen` lives in `openssh-keygen` and `ssh-keyscan` in
  `openssh-client-utils`.
- **The served script was not executable.** The panel prepended its header *above* the installer's
  `#!/bin/sh`, so line 1 was a comment: running the file directly got it interpreted by whatever
  shell was current, silently, and `sh -n` passed. The served file is now shebang first, sentinel
  second, injected assignments third.
- **The installer's self-check rejected every real install.** It looked for its sentinel in the
  first two lines, which the injected header had pushed to line 8 — so a correct download failed
  with "does not look like the TunnelGate installer". The window is now 40 lines from the top
  (not "anywhere in the file", which would let a captive-portal page vouch for itself).
- **19.07 could not fetch the installer at all.** Its `uclient-fetch` is built without a TLS
  library, so the first https request dies with `wget: SSL support not available`. The installer
  detects a missing `libustream` and installs it for the requests it makes — but it cannot rescue
  the download that fetches it, so the docs now say to install `libustream-wolfssl` first.
- **`--purge` left two of the three OpenSSH packages behind**, and on 24.10 a leftover
  `openssh-keygen` shadows dropbear's. The uninstaller removes exactly what the installer adds.
- The development mock server emitted a six-month-old install command; it now emits the real one.
- `doctor` no longer reports a warning as a failure when it cannot open nginx's pid file as an
  unprivileged user.

### Security

The router agent writes credentials to disk and runs as root on every boot, so its temporary
files and command lines were audited the way the panel's were. Every item below was reproduced
before it was fixed, and has a regression test that fails on the old code.

- **`write_heartbeat_bin` was never closed.** The heredoc that embeds the heartbeat ended without
  a closing brace, so `write_uninstall_bin` was defined *inside* it: a `--dry-run` printed
  `write_uninstall_bin: not found` and then carried on, because the script does not set `-e`. A
  nested function is invisible until the outer one runs, which is why no test noticed.
- **Credentials in world-readable `/tmp`.** The exchange body, the heartbeat body and the
  fetchers' error files were fixed, pid-derived names (`/tmp/tunnelgate-report.$$`), created 0644
  and containing the bootstrap token and the API token. A local user could pre-create the name as
  a symlink and have root write through it. Each of the three processes (installer, heartbeat,
  reconnect loop) now creates a private `mktemp -d` directory under `umask 077` with mode 0700,
  lazily on first use, and removes it on `EXIT` and on `INT`/`TERM` - a trap handler that only
  cleans up *returns* to the interrupted code, so the signal handler exits explicitly.
- **The token was on every command line.** The exchange and the heartbeat passed the credential
  as `-H "X-Api-Token: ..."` and as basic auth, which puts it in `/proc/PID/cmdline` for anyone
  to read - every 60 seconds, forever. Both are gone; the JSON body carries the token and the
  panel accepts it there, which is also the only channel a pre-24.10 `uclient-fetch` has.
- **`--dry-run` wrote the real token to disk** before checking that it was a dry run, then tried
  to redact it with `sed "s/$TOKEN/***/g"` - which dies with `unknown option to 's'` whenever the
  base64 token contains a `/`, so the preview vanished and the file stayed. The report is now
  built with the marker already in place; the token is never written on that path at all.
- **`pin_host_key` pinned every key of the matching type.** If the panel host published two
  ed25519 keys, both were pinned, and the second kept being accepted after the first was revoked.
  Each candidate is now fingerprinted in isolation and only the one the panel named is pinned.
  "The host answered with different keys" and "`ssh-keyscan` got no answer" are also now
  different errors: the second is a firewall, not a MITM.
- **A console account that cannot log in, silently.** `adduser -D -H` creates a non-root account
  with no home, and the console key was then written to root's `/etc/dropbear/authorized_keys`,
  which dropbear does not read for non-root users. When `adduser` failed the log said "the console
  will connect as root" while the config still named the missing user. The installer now decides
  the effective account and key path once, writes both to UCI so panel and router cannot disagree,
  puts a non-root key in `$HOME/.ssh/authorized_keys`, records `console_user_created` so
  `--purge` deletes only an account it created, and falls back to root *in the config* when the
  account cannot be created.
- **`cfg_set`'s fallback injected into a `sed` replacement.** A value containing `&` (any URL
  with a query string), `|` or a backslash corrupted the config - on the one path that exists for
  hosts where nothing else works. Replaced with an `awk` rewrite that takes the value as data.
- **The TLS capability gate failed open.** `[0-9]*` matches `19x`, then the numeric comparison
  returned 2, which read as "safe". A release string that is not all digits now counts as
  unverifiable, which is the conservative direction.
- **`--status` on the installer itself was broken.** `cfg_get` existed only inside the embedded
  heredocs, so `--status` printed `cfg_get: not found` and then reported every option at its
  default - a https panel shown as plain http.
- Heredoc writes now fail loudly (`|| err cannot write ...`) instead of silently producing a
  truncated agent on a full filesystem, and the dead `tunnel_pid` option (written by nobody,
  read by two scripts) is gone.

### Documentation

- docs/INSTALL_ROUTER.md gains the sentinel check, the three-package OpenSSH table, the 19.07
  libustream trap, "TLS verification, and how to turn it off for one panel", and a troubleshooting
  row for the fetch that fails before any TunnelGate code runs.
- docs/SECURITY.md, docs/API.md, docs/OPERATIONS.md, docs/ARCHITECTURE.md, docs/UI.md, README.md
  and CONTRACT.md are brought in step with the token channels, `verify_tls` and the new command
  shape. Every document that shows an install command now shows the real one, enforced by a test.

### Testing

879 tests. `ruff check` and `ruff format --check` clean, shellcheck plus `busybox sh -n` on the
installer, uninstaller, heartbeat and both server scripts, and the five embedded heredocs asserted
byte-identical to their standalone sources. Every security fix above has a test that was shown to
fail on the old code before the fix was accepted.

The whole path was exercised against real stock images of **19.07.10, 22.03.7, 23.05.5 and
24.10.1** in containers, against a disposable panel with a real sshd — including a bare 23.05.5
with no curl, no `ssh-keygen` and no `ssh-keyscan`, which now installs itself and finishes with
`OpenSSH 9.8`. The heartbeat's TLS policy was proven both ways in a 24.10.1 container, and the
endpoint API's normalisation matrix was verified against the live panel.

### Known limits

- On **19.07** with `libustream`, `uclient-fetch` accepts a self-signed certificate outright, so
  `tls_verify=1` there records a promise the fetcher cannot keep (a hostname mismatch is still
  caught). The installer detects this and says so; 21.02 is the floor for real chain verification.
- The token is visible on the router: as an argument in the shell history of the shell that ran
  the install command, and in `ps` for the few milliseconds that command runs. It is single-use
  and expires in 15 minutes. The agent itself never puts a credential on a command line; only the
  one-liner the operator pastes does.
- `apk` package resolution (the SNAPSHOT/SDK images) is verified with `apk add --simulate`, not
  with a full install; the `opkg` path is exercised end to end on 19.07.10, 22.03.7, 23.05.5 and
  24.10.1.
- A non-root console account is created, pointed at its own key file and recorded for `--purge`,
  but no test creates a real Unix account: the tests stub `id`/`adduser` and assert the
  decision. The account creation and dropbear's read of that file are the operator's step.

## [1.1.0] - 2026-11-18

The release that makes the documented install command work. 1.0.0's quick-install URL pointed at
its own tag, where `scripts/quick-install.sh` did not exist, so the command in the install docs
returned 404 for the whole life of that release. A test now pins the documentation to the version
in the tree, and the tag is built by CI rather than trusted.

### Added

- **`scripts/quick-install.sh`** — one-command install for the shape most small fleets actually
  have: TLS terminated on somebody else's reverse proxy, one ordinary public name, no certificate
  and no DNS record on this host. Renders `deploy/nginx/tunnelgate-behind-proxy.conf` (plain HTTP,
  path routing, merged layout) and tells you which `proxy_set_header` lines your edge has to
  replicate. Runs from the network (`curl -fsSL …/quick-install.sh | sudo sh -s -- --host
  panel.example.com`): it detects the pipe, fetches its own sources into a temporary directory and
  removes them on exit. Asks which account the service should run as, and reads every answer from
  `/dev/tty` so a piped answer cannot be swallowed and a run redirected to a log never blocks on
  an invisible question. `--dry-run` changes nothing and does not require root.
- **`scripts/update.sh`** — in-place upgrade with a real safety order: backup first (database via
  `sqlite3 .backup`, env file, `authorized_keys`, routes files, `pip freeze`, `code.tar.gz`),
  then dependencies, then `check-schema` run with the **new** code against a **snapshot** of the
  database, then the SPA build, then the swap, then a restart verified over `/api/v1/health`;
  it rolls the code and the freeze back if the new build never answers. Discovers the installation
  from systemd, so it covers the quick-install, setup-server and manual layouts, and never rewrites
  a unit file an operator may have hardened.
- **Console termination** — `DELETE /api/v1/console/sessions/{id}` closes a live shell, audited as
  `console.terminate`, and the console screen grows a Kill action on open rows. Deleting a router
  now ends its shells with `router_disconnected` instead of leaving a root prompt on a device the
  panel no longer knows about.
- `deploy/nginx/tunnelgate-behind-proxy.conf` — plain-HTTP, path-routing vhost for the
  behind-someone-else's-proxy layout, mutually exclusive with the TLS vhost.
- `tests/test_api_docs.py` — docs/API.md and the served routes are compared in both directions, so
  a route can be neither undocumented nor documented-but-absent. It immediately found
  `GET /api/v1/routers/{id}/console/sessions`, which the UI calls and no document mentioned.
- `tests/test_version.py` — the four version strings, the changelog and every tag pinned in the
  docs must agree.
- CI builds release tags (`v*`), so the run a release links to is the one that tested the bytes it
  ships.

### Fixed

- **sshd does not open `authorized_keys` as root.** It switches to the target account first, so a
  root-owned `0700 .ssh` or `0600` key file makes every router fail with
  `Permission denied (publickey)` while the panel looks perfectly healthy. The panel now chooses
  the file's owner from what sshd needs rather than from who is writing — a file it can read keeps
  its owner, one it cannot read (including a root-owned leftover from an older release) is handed to
  the SSH account, along with the directory when that is what blocks the traversal. `doctor` grows
  the matching check, judged from mode bits because doctor usually runs as root and root passes
  everything. The installer leaves `.ssh` and `authorized_keys` with the tunnel account in both
  `--run-as` modes.
- **An empty router fleet** produced a `routes.conf` that nginx refused with
  `unknown "tg_router" variable`, so the first install of a fresh panel could not reload nginx at
  all. Both variables are now declared in an internal location nobody calls. (A server-level `set`
  also parses but resets them on the internal redirect to `@tg_login`, losing the slug from the
  login bounce; a `map` is illegal inside a server block. Measured against nginx 1.26.3.)
- **Router and launch URLs were hardcoded `https`**, so a plain-HTTP install advertised links
  nothing listened on. The scheme now follows an explicitly `http` `TUNNELGATE_PUBLIC_URL` and
  stays `https` when it is unset, so a TLS-terminating deployment that forgot the variable cannot
  downgrade itself. `Settings.router_url` delegates instead of duplicating the decision.
- **Routers were told to dial the loopback `PANEL_URL`** — an install command that cannot work off
  the panel host. The agent endpoint now falls through to `TUNNELGATE_PUBLIC_URL` while
  `PANEL_URL` is loopback, and `doctor` warns when the result is still loopback.
- **`doctor` failed every fresh install** with "the router vhosts have no /__tg/enter, so Public
  route loops via /login" — the hand-off is rendered once per router, so an empty fleet
  legitimately has none. It now distinguishes an empty fleet from a stale config.
- **The installer claimed success while the panel was dying** on a port already in use, because
  `systemctl restart` returns before the bind fails. It now polls `/api/v1/health` and stops with
  the unit's journal. The sshd step proves `:22` still listens after the reload and only escalates
  to a restart when the listener is gone.
- Tests and the dry run work as an ordinary user, as CI runs them: `nginx -t` keeps its pid and
  logs inside the test's temp prefix and rebinds the privileged listeners, and three
  `authorized_keys` ownership tests no longer reach for "any account that is not mine" (which on a
  developer box is root and passes every check, so they asserted the opposite of their names).

### Documentation

- **The router that dials its own WAN address.** The panel's name resolves to an address the
  device itself owns, the kernel delivers the packet to local port 443, and uhttpd answers with its
  self-signed `CN=OpenWrt` certificate — so mbedTLS reports a CN mismatch *and* an untrusted
  certificate in the same breath, and `curl -k` would hide the wrong thing. NAT loopback cannot
  help: a packet addressed to the device's own IP never enters the nat tables. The three fixes that
  do work (dnsmasq domain override, install from another LAN host, LAN-reachable agent endpoint)
  and the two probes that identify the case are written down.
- docs/INSTALL_SERVER.md §9 Upgrades rewritten around `scripts/update.sh`, keeping the manual
  recipe for hosts where it cannot be used; docs/OPERATIONS.md points at it too.
- docs/API.md, docs/UI.md, README.md and CONTRACT.md brought in step with the console, upgrade and
  proxy changes; the repository layout lists the new scripts.

### Testing

690 tests, `ruff check` and `ruff format --check` clean, shellcheck on the router installer,
quick-install and updater, and the CI jobs for the SPA typecheck/build/test, `docker compose
config`, `nginx -t` in a container and `systemd-analyze verify` on the shipped units.

The quick-install and update scripts were also run for real: against a live panel, a real sshd and
a real router agent, and the updater against four systemd instances (source, git and archive
modes), including a release that fails on import and rolls itself back.

## [1.0.0] - 2026-11-18

First release. Panel (FastAPI + SQLite/PostgreSQL, Argon2id, CSRF, login rate limiting, audit log),
nginx `auth_request` gateway with per-router hostname or path prefix, one-line router installer
(POSIX shell, procd, Ed25519 keys minted and revoked by the panel, private half never stored),
in-browser console over WebSocket and xterm.js, React SPA, Docker and systemd deployment.

Three defects found by running the whole stack before release, each of which a green test suite had
missed:

- **`permitopen="none"` silently disarmed every router.** `none` is valid as an `sshd_config`
  directive but invalid as an `authorized_keys` key option, and sshd discards the **entire line**:
  every router fails with `Permission denied (publickey)` and the panel logs say nothing. Now
  `permitopen="127.0.0.1:1"`, with regression tests that drive a real sshd. Recorded in
  docs/SECURITY.md.
- **The console dialled the wrong account** — `Router.ssh_user` is the panel-side tunnel login,
  which does not exist on OpenWrt — while `console_state()` still reported `ready`. Every real
  deployment failed with `console_auth_failed`. Now one source of truth, configurable through
  `TUNNELGATE_CONSOLE_SSH_USER`.
- **Phantom console sessions**: a panel restart stranded rows with `closed_at IS NULL` forever and
  `/api/v1/stats` counted them as live shells. Now swept at startup with an audit row.

Plus, before shipping: the container image had no `ss` (every router would have stayed offline
while health said `ok`), `web/dist` was claimed but gitignored (a fresh clone broke the image
`COPY`), and `doctor` tracebacked on any uid mismatch.
