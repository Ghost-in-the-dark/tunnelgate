# Changelog

All notable changes to TunnelGate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Panel and router are versioned separately: `agent/install.sh` carries its own
`CLIENT_VERSION` (the bootstrap protocol the panel records per router), so a panel patch release
does not require reinstalling every router.

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
