# TunnelGate

**Centralised, authenticated access to the web UIs (LuCI) of an OpenWrt router fleet over SSH
reverse tunnels - plus an in-browser console.**

```
    router (behind NAT, no public IP)                        VPS (public IP)
  ┌────────────────────────────────────┐       ┌──────────────────────────────────────────┐
  │ ssh -R 127.0.0.1:20001:localhost:80│──────▶│ sshd  ──▶ 127.0.0.1:20001  (LuCI)        │
  │ ssh -R 127.0.0.1:25001:localhost:22│──────▶│        ──▶ 127.0.0.1:25001  (console)    │
  │ procd keeps it alive, retries      │       │ nginx ──▶ auth_request ──▶ proxy_pass    │
  └────────────────────────────────────┘       │ panel ──▶ FastAPI + SQLite + React SPA   │
                                               └──────────────────────────────────────────┘
```

Routers dial **out**, so no port forwarding, no public IP and no VPN client is needed on the
router side; the panel dials **in** through the console listener for its shell.

## What you get

* `https://<slug>.<domain>` for every router, TLS, gated by `auth_request` against the panel
  (subdomain, not a path prefix, so LuCI's absolute URLs and WebSockets work unmodified). The
  **Open LuCI** link hands the browser off through a single-use ticket and lands it on that
  router's hostname with a short-lived cookie scoped to that host alone - the panel session
  never leaves the panel origin, and `TUNNELGATE_COOKIE_DOMAIN` is never needed.
* **One host, many paths, if you have no wildcard certificate.**
  `TUNNELGATE_ROUTE_MODE=path` publishes every router as `https://<gateway>/<slug>/` instead:
  one ordinary certificate for `TUNNELGATE_GATEWAY_HOST` (a free dynamic-DNS name is enough), no
  wildcard DNS, no per-router records. nginx then rewrites LuCI's absolute links and redirects
  into the prefix and scopes each router's cookie to `/<slug>/`. The console keeps its own
  hostname. The gateway has two layouts: by default it is a name of its own, and router content
  stays a separate origin from the panel; if you point `TUNNELGATE_GATEWAY_HOST` at
  `TUNNELGATE_PANEL_HOST` the panel and the routers share one origin under one name (the
  "merged" layout - `routes.conf` then goes *inside* the panel `server` block, not the http
  context), which is convenient but lets a compromised router script the panel origin with the
  operator's session. `app.cli doctor` warns under `gateway host` when your configuration is
  merged, and stays quiet otherwise; docs/SECURITY.md §6.1 explains the trade. Subdomain mode
  stays the default: it needs no rewriting, so nothing in a LuCI app can escape its own host.
* A one-line, single-use, 15-minute install command per router - no key, no port and no secret
  in it; the key is minted when the router exchanges the token.
* A live status model (`pending → awaiting → online → offline`) backed by observed sockets **and**
  a LuCI health check, not by a database flag.
* Key rotation and deletion that revoke server-side immediately.
* An interactive **browser console** into each router (xterm.js over a WebSocket to a panel-side
  SSH client that travels down the same reverse tunnel).
* Roles (`admin`/`operator`/`viewer`), per-request CSRF, login throttling and an append-only audit
  of every access and mutation.
* An admin-editable **agent endpoint** (Settings → Panel): the protocol, host and port routers dial
  can be changed from the UI, so moving the panel behind a new name needs no re-install - new
  install commands use it immediately and already-installed routers are re-pointed over the
  heartbeat.
* Runs **behind a reverse proxy or load balancer** with a real trust boundary: `X-Forwarded-For`
  is only believed from `TUNNELGATE_TRUSTED_PROXIES` and read from the right, so rate limits and
  audit addresses cannot be forged by a header.
* nginx **or** Caddy as the proxy driver, SQLite **or** PostgreSQL, Docker Compose **or** systemd.

## Quick start (development)

```bash
git clone https://github.com/Ghost-in-the-dark/tunnelgate.git && cd tunnelgate
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
(cd web && npm ci && npm run build)     # or: npm run dev (see below)
./scripts/dev.sh                        # init db, seed admin, run on :8080
```

Open <http://127.0.0.1:8080> and log in as `admin` / `admin-t3st-pass` (development default;
override with `TUNNELGATE_ADMIN_PASSWORD`). The default `proxy_driver` is `none` in development,
so routers are reachable at `http://127.0.0.1:<tunnel_port>` directly - no nginx needed to try the
whole flow.

```bash
pytest -q                     # backend + installer tests
ruff check app tests && ruff format --check app tests
cd web && npm run typecheck && npm run build
```

## Production deployment

If your TLS is terminated by **your own reverse proxy** (nginx, Caddy, Traefik, a load
balancer), one command installs everything up to that point - no certificate, no DNS record, no
ACME client:

```bash
curl -fsSL https://raw.githubusercontent.com/Ghost-in-the-dark/tunnelgate/main/scripts/quick-install.sh \
  | sudo sh -s -- --host gate.example.com
```

It downloads the sources into a temporary directory (removed when it finishes), asks one
question - which account the panel service runs as: a dedicated `tunnelgate` account
(recommended, the default) or `root` (not recommended) - and serves plain HTTP on one port.
Path routing in the merged layout means every router is `<your-public-url>/<slug>/` on the
panel's own name - one ordinary name (a free dynamic-DNS one included) and no wildcard
certificate are enough. It then prints the `proxy_set_header` lines your edge has to
replicate. Run with `--help` for the flags, `--dry-run` to see the plan, and
read [docs/INSTALL_SERVER.md](docs/INSTALL_SERVER.md#quick-install-tls-terminated-by-your-own-proxy)
for what it does and the traps it handles. Merged layout shares the panel's origin with every
router - read [docs/SECURITY.md §6.1](docs/SECURITY.md) before adding routers you do not control.

### Upgrading an installed panel

```bash
curl -fsSL https://raw.githubusercontent.com/Ghost-in-the-dark/tunnelgate/main/scripts/update.sh \
  | sudo sh -s -- --ref v1.1.0
```

Omit `--ref` for the latest release; `--check-only` prints installed vs available and changes
nothing. It backs up the database, the env file, `authorized_keys`, the routes files and the
code first, checks the schema with the new build against a *snapshot* (never the live file),
rebuilds the SPA, swaps the code only after all three pass, then verifies the version over
`/api/v1/health` - and rolls back by itself if the new build does not come up. Live tunnels
stay up throughout: their forwards belong to sshd, not to the panel. Details in
[docs/INSTALL_SERVER.md §9](docs/INSTALL_SERVER.md).

Manual install, for a host that terminates TLS itself:

```bash
# VPS, Ubuntu/Debian - full walkthrough in docs/INSTALL_SERVER.md
install -m 0600 /dev/null /etc/tunnelgate.env && $EDITOR /etc/tunnelgate.env
.venv/bin/python -m app.cli init-db
.venv/bin/python -m app.cli seed-admin --password "$TUNNELGATE_ADMIN_PASSWORD"
.venv/bin/python -m app.cli doctor
systemctl enable --now tunnelgate
```

Docker alternative:

```bash
docker compose up -d          # panel + nginx, see docker-compose.yml
```

## Onboarding a router in four steps

1. **Choose OS** - the wizard produces `sh` (OpenWrt/Linux), a FreeBSD variant, or a PowerShell
   equivalent.
2. **Details** - friendly name (required), group, integrations.
3. **Copy the command** - one line, no secrets beyond a single-use token:
   ```sh
   curl -fsSL -H 'X-Bootstrap-Token: <token>' 'https://panel.example.com/api/v1/routers/install?os=linux' | sh
   ```
4. **Watch it connect** - the wizard polls `/api/v1/routers/{id}/status` every 2 s through
   `Waiting for connection → Connected → Receiving initial report → Done`.

Then **Open LuCI** or **Console** from the router list.

## Documentation

| Document | Read it when |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | you want the design, the sequence diagrams and why nginx gates per vhost |
| [docs/SECURITY.md](docs/SECURITY.md) | you are reviewing the threat model, `authorized_keys`, or the console key |
| [docs/API.md](docs/API.md) | you are integrating with the REST API |
| [docs/INSTALL_SERVER.md](docs/INSTALL_SERVER.md) | you deploy the VPS side |
| [docs/INSTALL_ROUTER.md](docs/INSTALL_ROUTER.md) | you install/upgrade/remove the router agent |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | something is broken, or it is 3 a.m. |
| [docs/UI.md](docs/UI.md) | you are working on the SPA |
| [CONTRACT.md](CONTRACT.md) | you are adding a module and need the frozen interfaces |

## Repository layout

```
app/                  FastAPI application
  api/                routers grouped by resource (auth, routers, bootstrap, heartbeat, audit,
                      users, meta, gate, console, console_ws)
  services/           ports, keys, bootstrap, tunnels, monitor, proxy, console, audit
  config.py db.py models.py schemas.py security.py deps.py errors.py main.py cli.py
agent/                OpenWrt installer, procd init script, uninstaller (POSIX sh / dropbear)
deploy/               nginx + Caddy configs, sshd drop-in, systemd units, docker-compose
scripts/              quick-install.sh (behind your own proxy), setup-server.sh (full TLS host),
                      update.sh (in-place upgrade with backup and rollback), dev.sh
web/                  React + TypeScript + Vite SPA (list, wizard, router page, console)
tests/                pytest suite
docs/                 the documents above
```

## How the pieces fit

* **Two-level credentials.** A single-use, 15-minute bootstrap token (sha256 at rest) is
  exchanged for an ed25519 key that exists only inside the exchange response. Only the public
  half is ever stored server-side.
* **The key can do one thing.** `permitlisten="127.0.0.1:<tunnel_port>",permitlisten="127.0.0.1:<console_port>"`
  plus `no-pty,command="/bin/false",permitopen="127.0.0.1:1"` (`none` is an sshd_config-only
  keyword and sshd rejects the whole key line over it) - rendered by
  `app/services/keys.py`, with an sshd `Match` block as the second layer. (Note: the obvious
  `restrict` prefix **breaks** `permitlisten`; see docs/SECURITY.md §3.)
* **Auth at the edge.** Each router is its own nginx `server` block with
  `auth_request /__tg/auth`; the router id is injected by nginx, never taken from the request
  URL, so a user cannot point their session at a different router.
* **Online means reachable.** A listener alone is not enough - the monitor also fetches LuCI.
* **Console inverts the direction.** The panel holds a sealed ed25519 key and logs into the
  router's dropbear over the second reverse forward; the router only ever holds the public half,
  delivered by heartbeat and revocable by rotation.

## Assumptions and deliberate limits

* **A calm TTL, not a long-lived secret, protects onboarding.** If your operators paste install
  commands into chat, the 15-minute window is the mitigation; lower it if you need more.
* **One panel instance.** `authorized_keys` and the nginx route file are files, not a leased
  resource. Run one instance (PostgreSQL does not change this).
* **No migration engine.** SQLite + additive schema changes; `app.cli check-schema` prints the
  `ALTER TABLE` statements to apply.
* **The console grants root on the router by default** - it is an operator tool, gated by role and
  audited, not a sandbox. A dedicated router user is supported and documented.
* **TLS, DNS and a wildcard certificate are prerequisites** for subdomain mode (`path` mode
  needs one ordinary certificate, not a wildcard), and TLS is not built in; the panel assumes it
  is reached over HTTPS and sets `Secure` cookies accordingly.
* LuCI keeps its own users; TunnelGate does not manage them.
* **The trust boundary is a setting, not a guess.** Behind a proxy, forwarded headers are believed
  only from `TUNNELGATE_TRUSTED_PROXIES` (default `127.0.0.1,::1`); `TUNNELGATE_FORWARDED_ALLOW_HOPS`
  says how many proxies of your own are in the path. Leave both alone for a direct-to-nginx setup.

## Known limitations (not implemented, on purpose or by scope)

1. **A panel RCE can decrypt console keys** (they must be unsealed per handshake). Tunnel keys are
   never stored. Mitigate by keeping the panel minimal and ringing it with a network policy.
2. **scrypt parameters** (`n=2^14`) are tuned for login latency, not for offline resistance.
3. **No MFA/TOTP** on panel login (the design allows adding it in front of `/api/auth/login`).
4. **No per-router ACL** - groups are labels; every operator may reach every router.
5. **Windows/MacOS router-side script is experimental** - only the POSIX path is tested in CI.
6. **FreeBSD client support is best-effort** (`pkg` + `autossh`) and not covered by tests.
7. **No graceful handing-off of live SSH sessions on panel restart** - consoles drop and the user
   reconnects; tunnels are unaffected (sshd owns them).
8. **`luci.open` audit is throttled** to one row per user/router/minute.
9. **A router grant is per-router, not per-request.** `tg_luci` is a signed, Host-scoped
   cookie (default 1 h, `TUNNELGATE_ROUTER_SESSION_TTL_MINUTES`) and is stateless, so it cannot
   be revoked individually: delete the router or rotate `TUNNELGATE_SECRET_KEY` to invalidate
   every one of them. Panel sign-out does not clear it.
10. **In-flight launch tickets live in process memory** (like console tickets). A panel restart
    mid-hand-off drops them - the operator clicks the link again - and one process per
    deployment is assumed, as everywhere else.
11. **No built-in metrics endpoint** (Prometheus); `/api/v1/stats` is what exists.
12. **The wizard's connection check is polling, not WebSocket** - simpler, and 2 s latency is
    invisible next to a firmware install.

## License

MIT - see `LICENSE`.
