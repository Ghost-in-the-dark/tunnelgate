# Configuring TunnelGate

Every knob the panel reads is an environment variable with the prefix `TUNNELGATE_`, and every
one of them has a default that is safe to leave alone. This page is the reference: what each
variable means, what the default costs you, and what breaks when it is wrong. The operator
skeleton you will actually copy is [`deploy/env/tunnelgate.env.example`](../deploy/env/tunnelgate.env.example);
the install walk-through is [`INSTALL_SERVER.md`](INSTALL_SERVER.md); day-2 behaviour is
[`OPERATIONS.md`](OPERATIONS.md); the security reasoning behind the cookie, proxy-trust and
path-mode settings is [`SECURITY.md`](SECURITY.md).

This document is authoritative. The appendix at the end of `INSTALL_SERVER.md` predates the
current `app/config.py` and is known to be incomplete and, for `TUNNELGATE_TRUST_FORWARDED_PROTO`,
wrong - see [Trap 1](#trap-1-x-forwarded-proto-is-used-by-the-panel-not-just-uvicorn).

## How settings are loaded

`app/config.py` defines one `pydantic_settings.BaseSettings` subclass, `Settings`, with 61
fields (the count is checked by the tests). Its `model_config` says how they are read:

| Config | Value | Consequence |
|---|---|---|
| `env_prefix` | `TUNNELGATE_` | The variable for field `panel_host` is `TUNNELGATE_PANEL_HOST`. No field is readable under its bare name. |
| `env_file` | `os.environ.get("TUNNELGATE_ENV_FILE", ".env")` | A `.env` file in the process working directory is read automatically. `TUNNELGATE_ENV_FILE` points somewhere else instead. |
| `env_file_encoding` | `utf-8` | A non-UTF-8 env file is a startup error, not a warning. |
| `extra` | `ignore` | Unknown `TUNNELGATE_*` variables are ignored, and so are the other variables in the env file - which matters because the same file carries `TUNNELGATE_PORT` (see below) and is often shared with the shell. |
| `case_sensitive` | `False` | `tunnelgate_panel_host` and `TUNNELGATE_PANEL_HOST` are the same variable. |

**Precedence**, highest first:

1. **Real process environment** (what systemd's `EnvironmentFile=`, `docker compose`'s `env_file:`,
   your shell, or `sudo -E` puts there).
2. **The env file** named by `TUNNELGATE_ENV_FILE`, else `.env` in the working directory.
3. **Field defaults in `app/config.py`.**

That order is the one operators expect and the one pydantic-settings implements: putting a key in
`/etc/tunnelgate.env` cannot override an environment variable that is already exported, so a
systemd drop-in with `Environment=TUNNELGATE_ROUTE_MODE=path` beats the env file silently.

Two consequences of how the file is wired, both verified against `app/config.py:59`:

* The env-file **path** is resolved when `app/config.py` is imported, not each time settings are
  built. `TUNNELGATE_ENV_FILE` has to be set before the process imports the app - i.e. in the
  unit's environment or on the command line - and setting it at runtime does nothing.
* Switching the env file does not restart anything. The panel reads its settings once at startup
  (see the cache below); a change needs a restart of the panel process, not a reload of the file.

### Read once, then cached

`get_settings()` is `lru_cache`d and returns one `Settings` object per process. Every module calls
it rather than re-reading the environment, so the whole panel sees a single consistent snapshot.
Changing an environment variable while the panel runs changes nothing; restart it.

The four module helpers in `app/config.py` are the whole lifecycle:

| Function | What it does | Who uses it |
|---|---|---|
| `get_settings()` | Returns the cached `Settings` - or the installed override, if one is set. | Every module. |
| `set_settings_override(settings)` | Installs an explicit `Settings` object and clears the cache. `None` removes the override. | `create_app(settings=...)` and the test suite. |
| `clear_settings_cache()` | Drops both the override and the cache, so the next call rebuilds from the environment. | Tests. |
| `reload_settings()` | Clears the cache and returns a freshly built `Settings`, leaving any override in place. | `app.cli` before it validates a deployment. |

`Settings.ensure_dirs()` is called from the app lifespan: it creates `data_dir`, the parent of
`authorized_keys_path` and the parent of `proxy_routes_path`. A path whose parent cannot be created
fails the panel at startup, which is deliberate - a panel that cannot write its own
`authorized_keys` is a panel that silently never activates a tunnel.

### Settings an operator changes from the UI

Not everything lives in the environment. Exactly one setting has a database override today: the
**agent endpoint** (the base URL routers are told to dial). It is stored in the `panel_settings`
table by `app/services/agent_endpoint.py`, edited at **Settings -> Agent endpoint**, and it
**wins over** `TUNNELGATE_PANEL_URL`. The env var stays the fallback, so a fresh install behaves
exactly as its env file says and an operator who moves the panel can re-point already-installed
routers without touching the file or restarting. See [`OPERATIONS.md`](OPERATIONS.md) "Move the
panel to a new address" and [`API.md`](API.md) for the routes.

That row holds four values, not three: scheme, host, port and **`verify_tls`**, the TLS policy a
router is told to apply to the panel's certificate (`true` by default; `false` accepts a
self-signed one). It is a column of that stored row and **not an environment variable**: there is
no `TUNNELGATE_*` setting for it, and adding one would be wrong, because the policy has to move
with the address it belongs to. The env file therefore stays silent about it, the setting count
does not change, and the only ways to read or write it are
`GET`/`PUT /api/v1/settings/agent-endpoint` and the checkbox under **Settings -> Agent
endpoint**. What it costs to turn off is in [`SECURITY.md`](SECURITY.md), "When to turn
certificate verification off".

`TUNNELGATE_PANEL_URL` and `TUNNELGATE_PUBLIC_URL` are **not** that override. The first is the
panel's internal address (what nginx `proxy_pass`es to); the second is the origin a browser sees.
Confusing them is what makes a router visitor get redirected to `http://127.0.0.1:8080`.

## The one variable that is not a setting: `TUNNELGATE_PORT`

`TUNNELGATE_PORT` is read by the **installer and the launcher**, never by the application. There is
no `port` field in `Settings`, so setting it in the env file does not change what the panel
listens on unless the thing that starts uvicorn also honours it:

| Where | Line | What it does |
|---|---|---|
| `deploy/docker/entrypoint.sh` | 33, 36 | `--port "${TUNNELGATE_PORT:-8080}"` - the container entrypoint passes it to uvicorn. |
| `docker-compose.yml` | 52 | `TUNNELGATE_PORT: "8080"` - the compose default for the panel service. |
| `scripts/quick-install.sh` | 643 | Writes `TUNNELGATE_PORT=$PANEL_PORT` into the generated env file. |
| `scripts/update.sh` | 738 | Falls back to `http://127.0.0.1:${TUNNELGATE_PORT:-8080}` for the health probe when `PANEL_URL` is not an absolute URL. |

The bare-metal unit hard-codes it instead: `deploy/systemd/tunnelgate.service:13` runs uvicorn with
`--port 8080`. If you change the panel port there, change the `ExecStart` line, and keep
`TUNNELGATE_PANEL_URL` pointing at the same port - `PUBLIC_URL`, the agent endpoint and the
generated nginx `proxy_pass` are derived from it.

The rule: `TUNNELGATE_PORT` describes **how the panel is started**, not **what the panel is**. The
env example carries it because the container needs it; a systemd install carries the port in the
unit.

## Reference

Defaults below are the literals in `app/config.py`. Types matter: a `list[str]` field is JSON in
the environment, an `int` is decimal digits, a `Path` is a filesystem path.

### Runtime

| Variable | Default | Meaning |
|---|---|---|
| `TUNNELGATE_ENV` | `dev` | Deployment mode. `production` (or `prod`) makes `TUNNELGATE_SECRET_KEY` mandatory, hides the API docs, and is what doctor checks against. |
| `TUNNELGATE_LOG_LEVEL` | `info` | Level for the `tunnelgate` logger tree: proxy rendering, monitor state changes, console lifecycle, auth events. `critical`/`error`/`warning`/`info`/`debug`. |
| `TUNNELGATE_DB_URL` | `sqlite:///./data/tunnelgate.db` | SQLAlchemy URL. Only SQLite is tested; `is_sqlite` keys off the `sqlite` prefix. Four slashes for an absolute path: `sqlite:////var/lib/tunnelgate/tunnelgate.db`. |
| `TUNNELGATE_DATA_DIR` | `./data` | Directory for the dev secret key, the default `authorized_keys` and the default routes file. Created at startup. |

`debug` logs one line per proxy decision. It is for a troubleshooting window, not a steady state -
at fleet size the journal becomes unreadable.

### Panel and HTTP

| Variable | Default | Meaning |
|---|---|---|
| `TUNNELGATE_PANEL_URL` | `http://127.0.0.1:8080` | The panel's **internal** address: what the reverse proxy forwards to. Not what routers dial (that is the agent endpoint, below) and not what browsers are redirected to. |
| `TUNNELGATE_PANEL_HOST` | `panel.example.com` | The panel's own host name. Used as nginx `server_name`, as the fallback router suffix, and as the comparison for the merged path layout. |
| `TUNNELGATE_PUBLIC_URL` | unset | The **browser-facing** origin. Every redirect the panel writes names it (the login bounce from a router vhost, the launch hand-off), and it decides the scheme of advertised router URLs and the agent endpoint when `PANEL_URL` is loopback. Unset, it is derived from `PANEL_URL`'s scheme plus `PANEL_HOST`. |
| `TUNNELGATE_COOKIE_NAME` | `tg_session` | Panel session cookie name. Deliberately different from the router cookie so the two can never be confused. |
| `TUNNELGATE_COOKIE_DOMAIN` | unset | Domain scope of the session cookie. Unset means host-only. Read [Trap 5](#trap-5-cookie_domain-hands-the-session-to-every-router) before touching it. |
| `TUNNELGATE_COOKIE_SECURE` | `false` | Force the `Secure` flag. The cookie is already marked `Secure` whenever the request arrives over HTTPS from a trusted proxy, so a normal TLS deployment needs nothing here. Read [Trap 4](#trap-4-cookie_secure_forcing-it-on-breaks-plain-http-deployments). |
| `TUNNELGATE_SESSION_TTL_MINUTES` | `720` | Panel session lifetime: both the cookie `max-age` and the stored session expiry. |
| `TUNNELGATE_CSRF_HEADER` | `X-CSRF-Token` | Header every state-changing API call must carry. |
| `TUNNELGATE_ADMIN_USERNAME` | `admin` | Username of the account seeded on first start. |
| `TUNNELGATE_ADMIN_PASSWORD` | unset | Password for that first admin. Read only when the users table is empty. Generate it, do not invent it: `openssl rand -base64 24`. With no users and no password the panel starts with **no login at all** and logs a warning. |
| `TUNNELGATE_LOGIN_RATE_LIMIT` | `10` | Failed logins allowed per window, per client address. |
| `TUNNELGATE_LOGIN_RATE_WINDOW_SECONDS` | `900` | The window for the limiter above. |
| `TUNNELGATE_CORS_ORIGINS` | `[]` | Extra origins allowed to make credentialed requests. JSON list. Empty means same-origin only, which is the normal deployment. A `*` entry is refused at startup, because credentialed CORS with a wildcard lets any site read authenticated responses. |

`PUBLIC_URL` has one failure mode worth repeating: behind a TLS terminator `PANEL_URL` is loopback,
and every redirect derived from it names `127.0.0.1` - a name the operator's browser cannot reach.
`app.cli doctor` warns under "public origin" when it sees exactly that combination.

### How routers are published

These are the settings that decide where a router's LuCI answers. `ROUTE_MODE` picks the shape,
`SUBDOMAIN_SUFFIX` and `GATEWAY_HOST` name the hosts.

| Variable | Default | Meaning |
|---|---|---|
| `TUNNELGATE_ROUTE_MODE` | `subdomain` | `subdomain`: `https://<slug>.<host_suffix>`, one vhost per router, needs a wildcard certificate. `path`: `https://<gateway>/<slug>/`, one vhost for the fleet, needs one ordinary certificate and nginx. Unknown values fall back to `subdomain`; doctor reports them. |
| `TUNNELGATE_SUBDOMAIN_SUFFIX` | unset (= `PANEL_HOST`) | Suffix of router vhosts in subdomain mode: a router with slug `lab` is `lab.<suffix>`. |
| `TUNNELGATE_GATEWAY_HOST` | unset (= `gate.<host_suffix>`) | The one host serving every router in path mode. Must be a real DNS name, not an IP. Equal to `PANEL_HOST` selects the merged layout. |
| `TUNNELGATE_PROXY_DRIVER` | `nginx` | `nginx`, `caddy` or `none`. `none` renders no router vhosts at all (dev only). Path mode requires `nginx`: it needs HTML rewriting and per-prefix cookie scoping, which the caddy driver does not do. |
| `TUNNELGATE_PROXY_ROUTES_PATH` | `./data/tunnelgate.routes.conf` | The generated include the proxy reads. Its sibling `*.auth.conf` carries the shared `auth_request` snippet. |
| `TUNNELGATE_PROXY_RELOAD_COMMAND` | `nginx -s reload` | Shell command run after a route change. **Leave empty under systemd and compose**: the unit sets `NoNewPrivileges=yes`, so the panel cannot signal root's nginx; the `tunnelgate-nginx-reload.path` unit does it instead. |
| `TUNNELGATE_CADDY_ADMIN_URL` | `http://127.0.0.1:2019` | Caddy admin API, used only when the driver is `caddy`. Must be loopback - doctor fails a remote admin API. |
| `TUNNELGATE_CADDY_SERVER` | `srv0` | The Caddy server name routes are pushed into. |

Subdomain mode needs a **wildcard** certificate (`*.<suffix>`), because `<slug>` is not known before
the router is registered; that needs DNS-01. If you have no wildcard and no DNS control, path mode
exists for you - see [`INSTALL_SERVER.md`](INSTALL_SERVER.md) "Decide the DNS layout first".

### Router launch hand-off

Opening a router does not widen the panel cookie. The panel mints a single-use ticket; the router
vhost redeems it at `/__tg/enter`, sets a cookie scoped to **that** router host, and the gate
accepts either credential. These four settings tune that window; the defaults are correct for
almost everyone.

| Variable | Default | Meaning |
|---|---|---|
| `TUNNELGATE_ROUTER_COOKIE_NAME` | `tg_luci` | Name of the per-router cookie. The `X-...-Cookie` header the vhost uses for the auth subrequest is derived from it, so renaming it keeps snippet, gate and launcher in step - but every operator has to open their router once more. |
| `TUNNELGATE_LAUNCH_TICKET_TTL_SECONDS` | `120` | How long a launch ticket stays redeemable. It is created by a click and consumed by the redirect that follows, so a longer window buys an interrupted redirect, not convenience. |
| `TUNNELGATE_ROUTER_SESSION_TTL_MINUTES` | `60` | Lifetime of the router-host cookie. LuCI has no session of its own here, so this is the whole authorization lifetime for that one device. There is no per-cookie revocation - lower it if a shared browser reaching a router's LuCI is a concern. |
| `TUNNELGATE_TRUST_PROXY_HEADERS` | `true` | Master switch for believing forwarded headers. Off means the client address is always the socket peer. |
| `TUNNELGATE_TRUSTED_PROXIES` | `["127.0.0.1", "::1"]` | Peers or CIDRs whose `X-Forwarded-For` / `X-Real-IP` is believed. **JSON list syntax**, see [Trap 2](#trap-2-trusted_proxies-is-json-and-the-comma-form-refuses-to-boot). |
| `TUNNELGATE_FORWARDED_ALLOW_HOPS` | `1` | How many of **our own** proxies sit in front of the panel, i.e. how many entries to skip from the right of `X-Forwarded-For`. 1 for nginx/Caddy; 2 for e.g. Cloudflare in front of nginx. Higher values move the answer left, never right. |
| `TUNNELGATE_TRUST_FORWARDED_PROTO` | `true` | Believe `X-Forwarded-Proto` from a trusted peer. This makes a panel behind a TLS terminator mark its session cookie `Secure` without also setting `COOKIE_SECURE`. It is consumed by the panel - see [Trap 1](#trap-1-x-forwarded-proto-is-used-by-the-panel-not-just-uvicorn). |

Two properties of this trust boundary are worth stating because they are the whole reason it
exists: the headers are only read when the **socket peer** is in `TRUSTED_PROXIES`, and if the
configured hop count exceeds the entries actually present, the panel falls back to the socket peer
rather than reading an entry the client could have typed. Both fail closed.

### SSH

The panel never opens a tunnel itself. It renders `authorized_keys` and lets the host sshd own the
listeners; these settings tell it where that file is and how to reach sshd.

| Variable | Default | Meaning |
|---|---|---|
| `TUNNELGATE_SSH_HOST` | `127.0.0.1` | Where sshd is, for doctor's reachability probe. The panel does not dial it to run tunnels. |
| `TUNNELGATE_SSH_PORT` | `22` | sshd port for the same probe. |
| `TUNNELGATE_SSH_USER` | `tunnelgate` | The system account that holds the forwards. Every key line is constrained to it. |
| `TUNNELGATE_SSH_HOST_KEY_PATH` | `/etc/ssh/ssh_host_ed25519_key.pub` | Host key whose fingerprint the installer pins for the router. |
| `TUNNELGATE_AUTHORIZED_KEYS_PATH` | `./data/authorized_keys` | The rendered key file sshd reads. Must be writable by the panel and readable **as** the tunnel user, and must not live somewhere world-writable. |
| `TUNNELGATE_AUTHORIZED_KEYS_MODE` | `384` (`0o600`) | File mode applied to `authorized_keys`. **Decimal integer** - see [Trap 6](#trap-6-authorized_keys_mode-is-a-decimal-int-holding-an-octal-value). |
| `TUNNELGATE_SSHD_RELOAD_COMMAND` | empty | Shell command to reload sshd after a rewrite. Empty is correct: sshd re-reads `authorized_keys` on the next authentication, so a new key works without a reload. |

The file is written atomically - temp file, `chmod`, `fsync`, `rename` - because sshd may read it at
any moment and a half-written file locks operators out of their own routers. The security model of
the key lines themselves (the `restrict` and `permitopen` traps) is [`SECURITY.md`](SECURITY.md) §3,
not configuration.

### Storage, port pools and health

Reverse listeners are sshd's, on loopback. **Never open either pool in the firewall**; nginx is the
only public listener.

| Variable | Default | Meaning |
|---|---|---|
| `TUNNELGATE_BIND_ADDRESS` | `127.0.0.1` | Address the tunnel listeners bind to. Doctor warns on anything but loopback, correctly. |
| `TUNNELGATE_PORT_MIN` | `20000` | Low end of the tunnel (LuCI) port pool. |
| `TUNNELGATE_PORT_MAX` | `25000` | High end of the tunnel pool. |
| `TUNNELGATE_CONSOLE_PORT_MIN` | `25001` | Low end of the console pool. Keep it disjoint from the tunnel pool. |
| `TUNNELGATE_CONSOLE_PORT_MAX` | `30000` | High end of the console pool. |
| `TUNNELGATE_ROUTER_HTTP_PORT` | `80` | LuCI's port **on the router**, the local target of a forward. Per-router override wins. |
| `TUNNELGATE_BOOTSTRAP_TTL_MINUTES` | `15` | How long an install or rotate token stays valid. It is baked into the install command, so it must outlive "paste this into a router" - the quick-install script raises it to 30. |
| `TUNNELGATE_TUNNEL_POLL_SECONDS` | `5` | Monitor loop interval. Minimum 1. |
| `TUNNELGATE_HEALTH_TIMEOUT_SECONDS` | `3.0` | HTTP timeout for the router health probe. |
| `TUNNELGATE_HEALTH_PATH` | `/` | Path probed on the router for health. |
| `TUNNELGATE_STALE_OFFLINE_SECONDS` | `90` | A router silent longer than this is declared offline. `0` disables the staleness rule. |
| `TUNNELGATE_REQUIRE_HEALTH_FOR_ONLINE` | `true` | With this on, a listener alone is not enough: the router must also answer its health probe before it is shown online. Turn it off only if your devices legitimately cannot answer. |

A port pool is sized in the hundreds for a reason: entries are not reclaimed while a router row
holds a port, so shrinking `PORT_MAX` below an already-allocated port makes that router
unrepairable through the UI until the row is fixed. Size up, not down.

Online means "listener present **and** healthy" by default, which is the only definition that
distinguishes a working LuCI from a forwarded port whose target is dead. `REQUIRE_HEALTH_FOR_ONLINE=false`
makes the status cheaper and less useful.

### Console (web terminal)

| Variable | Default | Meaning |
|---|---|---|
| `TUNNELGATE_CONSOLE_ENABLED` | `true` | Master switch. Off, no console ports are allocated and no console key is installed on routers. |
| `TUNNELGATE_CONSOLE_IDLE_TIMEOUT_SECONDS` | `900` | Idle timeout for a shell. |
| `TUNNELGATE_CONSOLE_MAX_SESSIONS_PER_USER` | `3` | Concurrent shells per panel user. |
| `TUNNELGATE_CONSOLE_MAX_SESSION_SECONDS` | `7200` | Hard cap on one shell's lifetime, idle or not. |
| `TUNNELGATE_CONSOLE_TERM` | `xterm-256color` | `TERM` handed to the shell. |
| `TUNNELGATE_CONSOLE_SSH_USER` | `root` | Account the panel logs in as **on the router**. It is also the account the console key is installed for, so the dial and the key cannot drift - but it means changing it re-issues every console key. `root` is the dropbear default and the only account guaranteed on OpenWrt; [`SECURITY.md`](SECURITY.md) §5 explains the dedicated-user alternative. |
| `TUNNELGATE_CONSOLE_CONNECT_TIMEOUT_SECONDS` | `10.0` | Timeout for opening the SSH session to the router. |

The console binds loopback only. It is not configurable on purpose: the listener is dialled from
the same host, and exposing it would add a second public surface for no benefit.

### Secrets and frontend

| Variable | Default | Meaning |
|---|---|---|
| `TUNNELGATE_SECRET_KEY` | unset | Master key for secrets at rest - today the console private keys, sealed with AES-256-GCM. Any passphrase is stretched with SHA-256, but generate one: `openssl rand -base64 48`. **Required when `ENV=production`**: without it the app refuses to start, and losing it invalidates every console key (tunnels and LuCI keep working). In dev a key is generated once into `<data_dir>/secret.key`, and that fallback is refused in production. |
| `TUNNELGATE_STATIC_DIR` | unset (= `<repo>/web/dist`) | Where the built SPA lives. Without it the panel serves the API only and every page returns the API's 404. |
| `TUNNELGATE_DOCS_ENABLED` | unset | Serve `/api/docs` and `/api/openapi.json`. Unset means **on unless `ENV` is `prod` or `production`** - see [Trap 8](#trap-8-docs_enabled-defaults-off-in-production-but-not-in-staging). |

The env example sets `TUNNELGATE_ENV=production`, so on a normal install the Swagger UI and the
OpenAPI document return 404 to unauthenticated callers. That is the intent: they advertise every
route and every schema.

## Derived values

`Settings` also exposes properties. They are **read-only derivations**, not knobs - there is no
environment variable for any of them, and setting one is impossible. They exist so that the
renderers, the API and the launch hand-off cannot drift apart about the same decision.

| Property | Value | Why it exists |
|---|---|---|
| `is_sqlite` | `db_url` starts with `sqlite` | Gates SQLite-only handling, e.g. skipping the in-memory database in maintenance commands. |
| `docs_visible` | `docs_enabled` if set, else `env` not in `prod`/`production` | One place decides the docs question; `create_app` reads only this. |
| `host_suffix` | `subdomain_suffix` or `panel_host` | A deployment only has to name the panel host once; router hosts and the console host derive from it. |
| `route_mode_normalized` | `path` or `subdomain` | Reduces `route_mode` to the two values the renderers understand: trimmed, lowercased, unknown falls back to `subdomain`. |
| `path_routing` | `route_mode_normalized == "path"` | The boolean every renderer branches on. |
| `gateway` | `gateway_host`, else `gate.<host_suffix>` | The host routers are published on in path mode. Defaults to a `gate.` subdomain so one DNS name suffices. |
| `gateway_merged` | path mode **and** `gateway` equals `panel_host` (case- and dot-insensitive on both sides) | Selects between the two path layouts, which are structurally different files - see [Trap 7](#trap-7-gateway_host--panel_host-silently-selects-the-merged-layout). |
| `web_dist` | `static_dir` or `<repo>/web/dist` | Where the SPA is, so the static mount and doctor agree. |
| `router_prefix(slug)` | `/<slug>` | The path a router owns in path mode. A static method, so a router location is computed one way only. |
| `router_url(slug)` | the router's public URL | Delegated to `app/services/proxy.py`, because the scheme depends on `PUBLIC_URL` and the merged layout's port; two copies of that decision is how a panel ends up advertising `https` on an install that answers `http`. |
| `console_bind_address` | `127.0.0.1` | Always loopback; fixed rather than configurable. |
| `console_ttl_seconds` | `900` | TTL for the router-side single-use console registration, deliberately independent of the install-token TTL. |

`router_prefix` and `router_url` take a slug, so they are methods rather than properties. Everything
else in the table is a `@property`.

## Router slugs: `SLUG_RE` and `RESERVED_SLUGS`

A slug is the router's identity in DNS and in the path namespace, so it is constrained in one place
(`app/config.py`) and validated in one place (`app/schemas.py`, plus a check on create in
`app/api/routers.py`).

```python
SLUG_RE = r"^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$"
```

In words: 1 to 40 characters, lower-case ASCII letters, digits and single internal hyphens; it
starts and ends alphanumeric, so no leading or trailing hyphen and no leading digit hyphen
confusion. No dots (it is a DNS label), no underscores, no upper case, no spaces. Input is stripped
and lower-cased before it is checked, so `Lab-Router` is accepted as `lab-router`.

`RESERVED_SLUGS` is a frozen set of ten names that may never be handed to a router:

```
__tg  access  api  assets  audit  automations  hosts  login  routers  settings
```

The reason is path routing. In **subdomain** mode a slug is a DNS label and any valid label works -
nothing collides. In **path** mode, and especially in the merged layout where the gateway is the
panel's own host, a slug is also the **first path segment on the panel host**, and the panel
already owns several of those. The collision is not cosmetic, and what happens depends on the
name:

* **`api` and `assets`** - the panel vhost already declares `location /api/` and `location /assets/`.
  A router published there produces a duplicate location and `nginx -t` rejects the **whole**
  config: the panel can no longer render routes at all until the router is renamed, which in path
  mode may be unfixable from the UI.
* **`login`, `hosts`, `routers`, `audit`, `settings`, `automations`, `access`** - the config parses
  and the router silently **shadows** the panel page. `login` is the expensive one: `/login` 308s to
  `/login/`, the router location answers 401, and the bounce returns to `/login?router=login` - an
  unbreakable loop that locks the operator out of the panel entirely, so the router cannot even be
  renamed through the UI.
* **`__tg`** - the internal gate namespace (`/__tg/enter`, `/__tg/auth`). A router there would
  collide with the hand-off itself.

Refusing these costs an operator a different name; the alternative is a locked-out panel. They are
rejected **at creation in both modes** on purpose: a deployment can switch to path mode later, and
a slug never changes once it is baked into DNS and into an installed agent's configuration.

**Picking a safe slug:** use lower-case letters, digits and hyphens, describe the site
(`lab-router`, `branch-berlin-1`), do not use a name from the list above, and remember that it
becomes a DNS label in subdomain mode and a URL path in path mode - so it should read acceptably
in both. A panel upgraded from an older build may already own a reserved slug; `app.cli doctor`
reports that under "slug namespace" in path mode, because only path mode renders the colliding
locations.

## Traps

Each of these has cost someone a deployment. They are ordered roughly by how long the symptom
takes to diagnose.

### Trap 1: `X-Forwarded-Proto` is used by the panel, not just uvicorn

Some older documentation says `TUNNELGATE_TRUST_FORWARDED_PROTO` is "declared for symmetry and
unused by the app". That is false. `app/forwarded.py:132` defines `request_scheme()`, which reads
`settings.trust_forwarded_proto` and, when the peer is a trusted proxy, returns the scheme from
`X-Forwarded-Proto`. `tests/test_forwarded.py:177` covers the flag-off path. Its consumer is the
`Secure` flag on the session cookie: a panel behind a TLS terminator marks the cookie `Secure`
because the request says so, not because the operator remembered `TUNNELGATE_COOKIE_SECURE`.

The transport-level part is separate: uvicorn runs with `--proxy-headers --forwarded-allow-ips
127.0.0.1` (`deploy/systemd/tunnelgate.service:13`, `deploy/docker/entrypoint.sh:37-38`), which is
what makes the *scheme uvicorn saw* correct in the first place. The two are independent, and the
panel-side flag also applies to untrusted peers only by refusing to believe them: an untrusted
client cannot upgrade its own request.

### Trap 2: `TRUSTED_PROXIES` is JSON, and the comma form refuses to boot

The field is `list[str]`, so pydantic-settings parses it as **JSON**:

```bash
TUNNELGATE_TRUSTED_PROXIES='["127.0.0.1", "::1"]'   # correct
TUNNELGATE_TRUSTED_PROXIES='["10.0.0.0/8"]'         # CIDRs work too
TUNNELGATE_TRUSTED_PROXIES=127.0.0.1,::1            # SettingsError, panel does not start
```

The failure is at startup with a message about "error parsing value for field
trusted_proxies", so it is at least loud. Note the quoting: in a shell assignment the outer
single quotes are required; in an `EnvironmentFile=` they are not needed, which is why the env
example writes the value bare.

The default is loopback, which means "a proxy on this host works out of the box, a proxy anywhere
else must be named". A proxy on another host that is not listed has its `X-Forwarded-For` ignored,
so every client address in the audit log is the proxy's. That is a correctness problem, not a
security one - the direction of the failure is safe.

### Trap 3: a `route_mode` typo silently falls back to subdomain

`route_mode_normalized` accepts only `subdomain` (case-insensitively, trimmed) and `path`; anything
else, including an empty string, becomes `subdomain`. This is deliberate - a typo must not stop the
panel from booting - but the panel therefore renders subdomain vhosts while the operator believes
path mode is on, and the symptom is every router 404ing on a host that does not resolve.

`app.cli doctor` catches it: it compares the raw `route_mode` against the two accepted values and
warns "TUNNELGATE_ROUTE_MODE=... is not 'subdomain' or 'path'". If routers are unreachable after a
configuration change, run doctor before debugging DNS.

### Trap 4: `COOKIE_SECURE` forcing it on breaks plain-HTTP deployments

`true` forces the `Secure` flag unconditionally. `true` on a LAN deployment reached over
`http://` makes browsers drop the cookie, and the symptom is that login appears to succeed and
then bounces straight back to the login page - with no error anywhere, because from the server's
point of view it did answer correctly.

Leave it `false` and let the request scheme decide: the cookie is marked `Secure` whenever the
request arrived over HTTPS from a trusted proxy. Set it `true` only when the panel is **never**
reachable over plain HTTP. Doctor warns when it is `false` in production, which is informative
rather than a demand.

### Trap 5: `COOKIE_DOMAIN` hands the session to every router

Unset, the session cookie is **host-only**: `panel.example.com` sets it and the browser never sends
it to `lab.panel.example.com` or `console.panel.example.com`. That is the posture everything else
assumes.

Setting a domain sends `tg_session` to **every name under the domain**, including every router's LuCI.
The blast radius inverts: the operator's panel session travels to a device whose only job is to be a
cheap, internet-exposed router, and anyone who compromises one router gets a live panel session, not
just that router. The panel does strip `Cookie` on the router hop in both drivers
(`app/services/proxy.py:440`, `:661`), which keeps the cookie off the router's *server* - but the
browser has still attached it to the router's origin, and that is the part a generated vhost cannot
fix.

Router access does not need it: the launch ticket and the per-router cookie exist precisely so the
session cookie does not have to travel. Doctor warns on any value under "cookie scope".

### Trap 6: `AUTHORIZED_KEYS_MODE` is a decimal int holding an octal value

The field is an `int` with default `0o600` = **384 decimal**. The environment only ever gives
pydantic a decimal string, and `0o600` is not accepted:

```bash
TUNNELGATE_AUTHORIZED_KEYS_MODE=384   # correct: 384 decimal == 0o600
TUNNELGATE_AUTHORIZED_KEYS_MODE=0o600 # ValidationError: not a valid integer
TUNNELGATE_AUTHORIZED_KEYS_MODE=600   # accepted, and means 0o1130 - wrong file mode
```

The dangerous case is the last one: `600` parses fine and `chmod` sets an odd mode that sshd may
reject under `StrictModes`, after which no router can authenticate. If you must set this, compute
the decimal value (`printf '%d' 0o600`) rather than typing the octal digits.

### Trap 7: `GATEWAY_HOST == PANEL_HOST` silently selects the merged layout

There is no flag for the path-mode layout; it is decided by comparing the two names, case- and
trailing-dot-insensitively. Equal selects the **merged** layout, which is a structurally different
file: locations only, included *inside* the panel `server` block, sharing the panel's origin. Not
equal keeps the **separate** layout: a complete `server{}` block plus the upgrade map, included
from the nginx *http* context.

Two consequences. Getting the include context wrong is caught loudly - nginx refuses the config
outright rather than serving something wrong, and doctor's "routes include" check runs `nginx -t`
and names the context the current layout wants. The security consequence is quiet: in merged mode a
path is not an origin boundary, so a hostile router page runs JavaScript in the panel's origin and
can act as the signed-in operator. It is supported, but it is a trade - see [`SECURITY.md`](SECURITY.md) §6.1.
Keep the gateway on its own name whenever DNS and certificates allow it.

Also remember that `gateway_host` must be a **DNS name**, not an IP: a public CA cannot issue a
certificate for a bare address. Doctor fails an IP, an empty value and a dotless name under "router
hostnames".

### Trap 8: `docs_enabled` defaults off in production, but not in staging

`docs_visible` is `false` only when `ENV` is exactly `prod` or `production` (trimmed and
lower-cased). `staging`, `prod-eu` and an unset value all leave the Swagger UI and the OpenAPI
document **on**. If a deployment is internet-facing but does not call itself production, set
`TUNNELGATE_DOCS_ENABLED=false` explicitly.

### Trap 9: `TRUSTED_PROXIES` and `FORWARDED_ALLOW_HOPS` disagree

These two must describe the same topology. `TRUSTED_PROXIES` says *who* may assert a client
address; `FORWARDED_ALLOW_HOPS` says *how far from the right* to read in the chain. Trust loopback
but have Cloudflare in front of nginx, and with the default `1` you will read Cloudflare's address
instead of the client's. Trust a proxy you do not actually run, and a client can forge its own
address. Set hops to the number of proxies **you** operate.

### Trap 10: `PROXY_RELOAD_COMMAND` under a hardened unit fails forever

The systemd unit runs with `NoNewPrivileges=yes`, so the panel cannot `sudo` to reload a root-owned
nginx. A reload command there fails on every route change, silently from the UI's point of view
except for `reload_pending` in `/api/v1/stats`. Leave it empty and use the
`tunnelgate-nginx-reload.path` unit, which runs as root and validates with `nginx -t` first. The
same applies to compose, where the nginx service watches the file.

## Checking a deployment

`app.cli doctor` validates this whole surface - data dir, database, `authorized_keys` path and
mode, sshd reachability, both port pools, nginx and its modules, the route include and its context,
the reload command, the cookie flags, the public origin, the slug namespace, the version and the
secret key. It exits non-zero on a blocking problem and prints the fix. Run it after any change to
this file, before looking anywhere else.

```bash
sudo -u tunnelgate /opt/tunnelgate/.venv/bin/python -m app.cli doctor
```

The CLI's other configuration-aware commands are covered in `CLI.md`.

## Related documents

* [`INSTALL_SERVER.md`](INSTALL_SERVER.md) - the install walk-through and the env-file skeleton.
* [`INSTALL_ROUTER.md`](INSTALL_ROUTER.md) - what the router side reads.
* [`OPERATIONS.md`](OPERATIONS.md) - day-2 behaviour, moving the panel, backups, diagnosis.
* [`SECURITY.md`](SECURITY.md) - cookie scope, proxy trust, path-mode origins, console key handling.
* [`ARCHITECTURE.md`](ARCHITECTURE.md) - how the pieces fit together.
* [`API.md`](API.md) - the agent-endpoint settings routes and their audit events.
* [`deploy/env/tunnelgate.env.example`](../deploy/env/tunnelgate.env.example) - the annotated skeleton.
