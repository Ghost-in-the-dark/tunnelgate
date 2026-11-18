# TunnelGate - module contract (read this before writing code)

Everything below is FROZEN. Do not rename modules, routers, endpoints or response fields:
other teammates generate against it. If something is genuinely missing, add it inside your
own files and tell the Lead - never edit shared files.

## Shared files owned by the Lead (do NOT edit)
| File | Contents |
|---|---|
| `app/config.py` | `Settings` (env prefix `TUNNELGATE_`), `get_settings()`, `utcnow()`, `SLUG_RE` |
| `app/db.py` | `Base`, `init_db()`, `init_engine()`, `get_db()`, `session_scope()`, `reset_for_tests()` |
| `app/models.py` | `User`, `PanelSession`, `Router`, `BootstrapToken`, `AuditLog`, `STATUS_*` |
| `app/security.py` | `hash_password/verify_password`, `new_token/hash_token`, `generate_ed25519_keypair`, `authorized_key_line`, `key_fingerprint`, `RateLimiter` |
| `app/errors.py` | `ApiError(status, code, message, details?, headers?)`, `install_error_handlers(app)` |
| `app/schemas.py` | every request/response model + `iso(dt)` |
| `app/deps.py` | `DbSession`, `CurrentUser`, `CurrentSession`, `OptionalSession`, `AdminUser`, `OperatorUser`, `CsrfGuard`, `client_ip()` |
| `app/main.py` | `create_app()` - imports your routers |

Import style:

```python
from app.deps import DbSession, CurrentUser, AdminUser, OperatorUser, CsrfGuard, client_ip
from app.errors import ApiError
from app.schemas import RouterOut, iso
```

## Modules the API owner must create (exact names)
Each module exposes `router = APIRouter(...)`. `app/main.py` already imports them:

| Module | Prefix | Endpoints |
|---|---|---|
| `app/api/auth.py` | `/api/auth` | `POST /login`, `POST /logout`, `GET /me`, `POST /password` |
| `app/api/routers.py` | `/api/v1/routers` | `POST /`, `GET /`, `GET /{router_id}`, `PATCH /{router_id}`, `DELETE /{router_id}`, `POST /{router_id}/rotate-key`, `GET /{router_id}/status`, `GET /{router_id}/script` |
| `app/api/bootstrap.py` | `/api/v1/routers` | `POST /bootstrap/exchange` (header `X-Bootstrap-Token`), `GET /install` (header `X-Bootstrap-Token`, query `os=linux`) |
| `app/api/heartbeat.py` | `/api/v1/routers` | `POST /{router_id}/heartbeat` (header `X-Api-Token`) |
| `app/api/audit.py` | `/api/v1/audit` | `GET /` (filters router_id, actor, action, limit, offset) |
| `app/api/users.py` | `/api/v1/users` | `GET /`, `POST /`, `PATCH /{user_id}`, `DELETE /{user_id}` (admin only) |
| `app/api/meta.py` | `/api/v1` | `GET /health` (no auth), `GET /config` (auth), `GET /stats` |
| `app/api/gate.py` | `/__tg` | `GET /auth` - nginx `auth_request` subrequest: 200 + `X-Tg-User` header, or 401 |
| `app/api/console.py` | `/api/v1` | `POST /routers/{id}/console/start`, `GET /routers/{id}/console`, `GET /console/sessions` |
| `app/api/console_ws.py` | `/api/v1` | `WS /routers/{id}/console/ws?ticket=...` - the interactive shell |

## Service modules
| Module | Responsibility |
|---|---|
| `app/services/ports.py` | `allocate_port(db)`, `release_port(db, port)`, `port_free_in_os(port)` |
| `app/services/keys.py` | `issue_key(db, router)` -> `KeyPair`, `render_authorized_keys(db)`, `write_authorized_keys()`, `revoke_router_key(db, router)`, `issue_console_key(db, router)` (ed25519, sealed at rest), `console_key_registration(router)`, `install_console_key_on_router(...)` (dropbear helper for the script) |
| `app/services/bootstrap.py` | `issue_bootstrap_token(db, router, purpose, actor)`, `exchange_token(db, token, report, ip)`, `build_install_command()`, `load_install_script()` |
| `app/services/tunnels.py` | `list_listening_tunnels()`, `is_tunnel_up(port)`, `health_check(port)` |
| `app/services/monitor.py` | async `run_monitor(stop_event, proxy)` updating status every `tunnel_poll_seconds` |
| `app/services/console.py` | `ConsoleError`, `open_ssh(router)` (async, paramiko), `ConsoleTicketStore`, `ticket()`/`consume()` |
| `app/services/console_ws.py` | `ConsoleWebSocketHandler` - pipes an async SSH channel to a WebSocket with resize, idle/max-duration limits and audit |
| `app/services/proxy.py` | `ProxyManager` with drivers `nginx` / `caddy` / `none`, `sync_routes()` |
| `app/services/audit.py` | DONE (Lead): `record(db, action, actor=..., router=..., ip=..., detail=...)` |

## Decisions already made - do not revisit
* Router lifecycle: `pending` -> (key exchanged) `awaiting` -> (tunnel observed + LuCI health ok) `online` -> (tunnel gone) `offline`.
  Wizard phase mapping: `waiting` (no key yet), `connected` (tunnel up, heartbeat not yet seen),
  `reporting` (heartbeat received, metadata arriving), `done` (heartbeat + health ok), `offline`.
* Only the PUBLIC key is stored: `Router.public_key` / `Router.key_fingerprint`.
* Bootstrap token: `new_token()` plaintext shown once; DB stores `hash_token()`; single use, TTL
  `settings.bootstrap_ttl_minutes` (default 15).
* Every router gets a fresh ed25519 key; the private half appears ONLY in the exchange response
  and must never be logged, cached or written to a server file.
* authorized_keys lines come from `security.authorized_key_line(...)`: `restrict,...,permitlisten="bind:port"`.
* The install script is POSIX sh (busybox ash compatible), served *with* the token substituted into
  it by the server, so the token never appears in a URL or in shell history of the router.
* The reverse proxy gates visitors with `auth_request GET /__tg/auth` and injects `X-Tg-User`.
* All timestamps are naive UTC in the DB; API serialises through `schemas.iso()`.
* Errors always use the envelope: `{"error": {"code", "message", "details"?}}` - raise `ApiError`.

## Testing contract
Tests live in `tests/`, run with `.venv/bin/pytest`. Use `tests/conftest.py` fixtures:
`client` (httpx TestClient, fresh temp SQLite per test), `admin_client` (logged in as admin,
CSRF header set), `db`, `settings_override`.

## File ownership (write scopes - do not cross them)

| Owner | Files |
|---|---|
| **Lead** | `app/config.py`, `app/db.py`, `app/models.py`, `app/security.py`, `app/errors.py`, `app/schemas.py`, `app/deps.py`, `app/main.py`, `app/services/audit.py`, `tests/conftest.py`, `README.md`, `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/SECURITY.md`, `docs/OPERATIONS.md`, `docs/INSTALL_SERVER.md`, `.github/` |
| **api-core** | `app/api/{auth,routers,bootstrap,heartbeat,audit,users,meta,gate}.py`, `app/services/{ports,keys,bootstrap,tunnels}.py`, `tests/test_{auth,routers,bootstrap,ports,keys,gate,audit}.py` |
| **runtime** | `app/services/{monitor,proxy}.py`, `app/cli.py`, `deploy/`, `scripts/`, `tests/test_{monitor,proxy}.py` |
| **router-agent** | `agent/`, `tests/test_installer.py`, `docs/INSTALL_ROUTER.md` |
| **frontend** | `web/`, `docs/UI.md` |

Never edit a file outside your scope. Need a change in a shared file? Message the Lead.

## Runtime facts
* Repo: `/root/openwisp/tunnelgate`, Python venv at `.venv` (activate with `. .venv/bin/activate`).
* Run tests: `.venv/bin/python -m pytest -q`. Run one file: `.venv/bin/python -m pytest tests/test_x.py -q`.
* Lint: `.venv/bin/ruff check app tests` (config in `pyproject.toml`).
* Node 24 + npm 11 are available; npm registry reachable.
* Debian 13 host, root, docker available, no nginx installed yet (may install via apt).
* The app must stay importable at all times: `python -c "from app.main import app"` must work.

---

# ADDENDUM 1 - web console (interactive shell), added after the initial freeze

The panel now also gives operators an interactive shell on the router (browser terminal).
The tunnel-only design is unchanged; the console is a second, independently gated channel.

## Why a second reverse forward instead of a second SSH key
The router side runs **dropbear**, which cannot enforce `permitlisten`-style restrictions and
whose `-R` handling is unreliable. So the direction is inverted: the panel authenticates
**to the router**, not the other way round.

* The panel holds an ed25519 **console key pair** whose *private* half is sealed with
  AES-256-GCM (`security.encrypt_secret`) and stored in `routers.console_key_sealed`.
  It is unsealed only for the duration of one SSH handshake.
* The router receives only the **public** half, installed into its own
  `/etc/dropbear/authorized_keys` (plus an optional dedicated `tunnelgate` user whose login
  shell is `/bin/ash`; see `docs/SECURITY.md` for the trade-off and the UCI switch that
  requires root instead).
* A **second reverse listener** on the panel host loopback (`routers.console_port`, from the
  `console_port_min..console_port_max` pool) is forwarded by the router's ssh client to
  `127.0.0.1:22` **on the router**. The panel simply dials `127.0.0.1:console_port` and gets
  the router's dropbear.
* Both ports live in the **same** authorized_keys line: one key, one connection, two
  `permitlisten` entries. Adding a second key with a second connection was designed and
  rejected - it doubles the procd supervision surface and the failure modes for no gain.

## frozen additions to shared files
| File | Addition |
|---|---|
| `app/models.py` | `Router.console_port`, `Router.console_ssh_port`, `Router.console_public_key`, `Router.console_key_sealed`, `Router.console_key_fingerprint`, `Router.console_key_serial`, `Router.console_installed_at`, `RouterRuntime`, `ConsoleSession` |
| `app/schemas.py` | `ConsoleSpec`, `ConsoleRegistration`, `ConsoleStartOut`, `ConsoleSessionOut`, `ConsoleSessionListOut`; `BootstrapExchangeOut.console`, `HeartbeatOut.console`, `RouterOut.console_port/console_ready`, `StatsOut.console_sessions_active` |
| `app/security.py` | `authorized_key_line(public_line, bind_address=, ports=, ...)` (**signature changed**: `port` -> `ports`, a list or an int), `console_authorized_key_line()`, `master_key()`, `encrypt_secret()`, `decrypt_secret()` |
| `app/config.py` | `console_enabled`, `console_port_min/max`, `console_idle_timeout_seconds`, `console_max_sessions_per_user`, `console_max_session_seconds`, `console_connect_timeout_seconds`, `console_term`, `secret_key`, `console_bind_address`, `console_ttl_seconds` |
| `app/main.py` | imports `app.api.console` and `app.api.console_ws` |

## THE authorized_keys bug this addendum fixes
The original line started with `restrict`. OpenSSH expands `restrict` to
`no-port-forwarding,no-agent-forwarding,...,no-pty,no-user-rc`, and `permitlisten` is checked
**after** that blanket denial, so a line with both `restrict` and `permitlisten` refuses every
forward: `ssh -R` fails with "remote port forwarding failed for listen port N". Reproduced
against OpenSSH 10.2 with a throwaway sshd before this contract was amended. The line now
spells the restrictions out and keeps `permitlisten` effective:

```
no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc,command="/bin/false",permitopen="127.0.0.1:1",permitlisten="127.0.0.1:20001",permitlisten="127.0.0.1:25001" ssh-ed25519 AAAA... tunnelgate:<slug>:1
```

Local forwarding is pinned to `permitopen="127.0.0.1:1"`, not to `none`: `PermitOpen none`
is an `sshd_config` keyword, and as a key option sshd rejects it and discards the whole line
("bad key options: invalid permission port"), locking every router out with nothing but
"Permission denied (publickey)". Frozen by `tests/test_keys.py` against a real sshd.

## Console lifecycle (what every owner must implement against)
1. `status=online` and `console_port` allocated. Keys are created **lazily** the first time
   somebody opens a console (`issue_console_key`), so the panel carries no key material for
   routers nobody shells into.
2. The router's heartbeat receives `console` in the response while its stored
   `console_key_serial` is behind (or the user/authorized_keys file is missing). It installs
   the public key and reports `console_installed: true` on the next heartbeat, which sets
   `Router.console_installed_at`. `console_ready` in `RouterOut` = key exists + installed.
3. `POST /api/v1/routers/{id}/console/start` opens the SSH connection (paramiko,
   `connect_timeout=console_connect_timeout_seconds`, `allow_agent=False`,
   `look_for_keys=False`, reject-unknown-host-key policy using the stored router host key when
   present) and returns a **one-time ticket** (30 s TTL, in-memory, bound to router+user).
4. The browser connects to `WS /api/v1/routers/{id}/console/ws?ticket=...`. The ticket is
   consumed exactly once. The socket carries raw bytes both ways plus JSON control frames
   `{"type":"resize","cols":N,"rows":N}` client -> server and
   `{"type":"status"|"exit",...}` server -> client.
5. Every session gets a `ConsoleSession` row (who, from where, when, byte counts, close
   reason) **and** an `AuditLog` entry `console.open` / `console.close`. Idle timeout and
   max-duration come from settings; `viewer` may not open one, `operator` and `admin` may.

## Nginx: the console hostname
The console WebSocket is served by the panel vhost, **not** by a per-router vhost, because the
`/__tg/auth` subrequest is the only place that can validate the panel session and the router
binding. `deploy/nginx/tunnelgate.conf` therefore adds a second server block for
`console.<host_suffix>` that proxies `/api/` to the panel and serves the SPA; browsers open
`wss://console.<host_suffix>/api/v1/routers/<id>/console/ws?ticket=...`.

## Ownership additions
| Owner | Files |
|---|---|
| **console-core** | `app/services/{console,console_ws}.py`, `app/api/{console,console_ws}.py`, `tests/test_{console,console_ws}.py` |
| **api-core** | additionally `issue_console_key` / `console_key_registration` in `app/services/keys.py`, console port allocation in `app/services/ports.py`, console fields in `app/api/{routers,bootstrap,heartbeat,meta}.py` |
| **runtime** | additionally the `console.<host_suffix>` nginx block and the `console_port_min/max` range in `deploy/` |
| **router-agent** | additionally the console block in `agent/install.sh` (create user if requested, install the public key, honour the heartbeat-delivered registration) |
| **frontend** | additionally `/routers/:id/console` with xterm.js |
