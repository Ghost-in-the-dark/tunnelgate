# TunnelGate HTTP API

Base URL: `https://panel.example.com`. Everything is JSON (`application/json`) except
`GET /api/v1/routers/install`, which returns `text/x-shellscript`.

Interactive documentation is generated from the same code at `/api/docs` (OpenAPI at
`/api/openapi.json`) - **that** is the authoritative field list; this document is the contract
and the reasoning behind it.

## Conventions

### Authentication

Two completely separate mechanisms:

| Caller | Credential | Where |
|---|---|---|
| Operator (browser) | `tg_session` cookie (HttpOnly, SameSite=Lax, Secure in production) | `POST /api/auth/login` |
| Router, during onboarding | `X-Bootstrap-Token` header | single-use, 15 min |
| Router, afterwards | `X-Api-Token` header | derived from its public key, see below |

State-changing operator requests **must** carry `X-CSRF-Token` with the value returned by
login (double-submit; the token is bound to the server-side session row, not to a cookie).
Missing or wrong CSRF on a mutating request → `403 csrf_failed`.

The `X-Api-Token` a router sends on heartbeats is `"tg_" + sha256(public_key)[:40]`, the same
value handed to it at exchange time. It is deliberately **not** a stored secret: it can be
recomputed from the router's public key, so it needs no column and no rotation ceremony, and by
itself it can do only one thing - report that router's own metadata.

### Errors

Every error, including install-script errors, uses one envelope:

```json
{"error": {"code": "invalid_token", "message": "Bootstrap token is invalid or expired", "details": null}}
```

| HTTP | `code` | Meaning |
|---|---|---|
| 400 | `validation_error` | Pydantic rejected the body (`details` lists the fields) |
| 401 | `unauthorized` | No/expired session cookie, or a disabled account |
| 401 | `invalid_credentials` | Wrong username or password |
| 401 | `invalid_token` | Bootstrap token unknown, used, or expired (**all three share one code**) |
| 401 | `invalid_api_token` | Heartbeat token does not match the router |
| 403 | `forbidden` | Authenticated but the role is too low |
| 403 | `csrf_failed` | Missing/incorrect `X-CSRF-Token` |
| 404 | `not_found` | Unknown router/user |
| 409 | `already_installed` | Re-issuing a script for a router that already has a key |
| 409 | `console_not_ready` | Console key not installed yet, or router offline |
| 422 | `slug_taken` | Slug collision that could not be resolved |
| 429 | `rate_limited` | Login or exchange throttled (`Retry-After` header set) |
| 503 | `no_free_port` | Port pool exhausted |

### Timestamps

All timestamps are UTC, serialised as ISO-8601 with a trailing `Z` (`2026-11-17T21:42:34Z`).
Two timestamps in the same second are indistinguishable by design.

### Roles

| Role | May |
|---|---|
| `viewer` | read routers, read audit, open **LuCI** |
| `operator` | + create/rotate/delete routers, read install scripts, open a **console** |
| `admin` | + manage users, terminate console sessions, reissue scripts for installed routers |

---

## Auth

### `POST /api/auth/login`

```json
{"username": "admin", "password": "..."}
```

→ `200`

```json
{
  "user": {"id": 1, "username": "admin", "display_name": "Administrator",
           "role": "admin", "is_active": true, "created_at": "...", "last_login_at": "..."},
  "csrf_token": "b7c1...",
  "expires_at": "2026-11-18T09:42:34Z"
}
```

Sets `Set-Cookie: tg_session=<opaque>; HttpOnly; SameSite=Lax; Path=/; Max-Age=...`
(`Secure` when `TUNNELGATE_COOKIE_SECURE=true`).

Rate limited per client IP and per IP+username: `TUNNELGATE_LOGIN_RATE_LIMIT` (10) attempts per
`TUNNELGATE_LOGIN_RATE_WINDOW_SECONDS` (900). Exceeding it → `429` with `Retry-After`.

### `POST /api/auth/logout`

Revokes the session row and clears the cookie. → `204`.

### `GET /api/auth/me`

→ `200` `UserOut` (no CSRF token; the SPA keeps the one it got at login).

### `POST /api/auth/password`

```json
{"current_password": "...", "new_password": "..."}
```

Rehashes and revokes **every other** session of that user. → `204`.

---

## Routers

### `POST /api/v1/routers`  *(operator)*

```json
{
  "name": "Office AP",
  "slug": "office-ap",
  "group_name": "warehouse",
  "integrations": ["prometheus", "netbox"],
  "os_type": "linux",
  "notes": "second floor",
  "http_port": 80
}
```

Only `name` is required. `slug` is derived from the name (`Office AP` → `office-ap`) and
collisions get `-2`, `-3`…; the slug is the DNS label of the router's vhost, so it must be a
valid label (1-40 chars of `a-z0-9-`).

→ `201` `RouterCreatedOut` = `RouterOut` **plus**

```json
{
  "bootstrap_token": "Q1r...43-chars",
  "bootstrap_expires_at": "2026-11-17T21:57:34Z",
  "install_command": "curl -fsSL -H 'X-Bootstrap-Token: Q1r...' 'https://panel.example.com/api/v1/routers/install?os=linux' | sh",
  "install_script_url": "https://panel.example.com/api/v1/routers/install?os=linux"
}
```

> This is the **only** time the plaintext token is ever returned. The database keeps
> `sha256(token)`. If the operator loses it, rotate the key.

### `GET /api/v1/routers`

Query: `status` (`pending|awaiting|online|offline|revoked`), `q` (name/slug/hostname/MAC/IP
substring), `limit`, `offset`.

→ `200`

```json
{"items": [RouterOut, ...], "total": 12, "online": 9, "offline": 2, "pending": 1}
```

### `GET /api/v1/routers/{id}` → `RouterOut`

### `PATCH /api/v1/routers/{id}` *(operator)*

`name`, `group_name`, `notes`, `http_port`. The slug never changes after creation (it is baked
into DNS and into already-installed routers).

### `DELETE /api/v1/routers/{id}` *(operator)*

Revokes the key (rewrites `authorized_keys` + no-op if the tunnel user is absent), frees **both**
ports, deletes the row (cascade: tokens, runtime, console sessions) and returns `204`.
The router's ssh then dies on its next reconnect attempt ("Permission denied") and procd
retries forever; run the uninstaller on the router to stop that.

### `POST /api/v1/routers/{id}/rotate-key` *(operator)*

→ `200` `RotateKeyOut`:

```json
{
  "bootstrap_token": "...",
  "bootstrap_expires_at": "...",
  "install_command": "...",
  "install_script_url": "...",
  "note": "The previous key is revoked immediately; the router re-registers itself."
}
```

The old key is revoked **at once** and the ports are retained, so a re-install lands on the same
vhost and listener. Status returns to `pending` until the router exchanges the new token.

### `GET /api/v1/routers/{id}/script` *(operator)*

For "Show install script" on a router that has **not** been installed yet. Returns a fresh token
+ command (the old one is invalidated). For an installed router: `409 already_installed` unless
`?reissue=true` and the caller is an admin, which is equivalent to rotate-key.

### `GET /api/v1/routers/{id}/status`

Cheap endpoint for the wizard's 2-second poll.

```json
{
  "id": "9f3c...", "status": "online", "phase": "done", "online": true,
  "tunnel_present": true, "health_ok": true,
  "last_seen_at": "2026-11-17T21:43:02Z", "last_heartbeat_at": "2026-11-17T21:42:58Z",
  "message": "LuCI responded"
}
```

`phase` is derived, not stored:

| phase | Condition | Wizard shows |
|---|---|---|
| `waiting` | no key yet | "Waiting for connection" |
| `connected` | tunnel up, no heartbeat yet | "Connected" |
| `reporting` | tunnel up + heartbeat, health not yet ok | "Receiving initial report" |
| `done` | tunnel up + heartbeat + health ok | "Done" |
| `offline` | had a key, nothing observed | "Router is offline" |

---

## Bootstrap (router-facing, unauthenticated)

### `GET /api/v1/routers/install?os=linux|freebsd|windows`

Header: `X-Bootstrap-Token`.

→ `200 text/x-shellscript`, `Cache-Control: no-store`, with `TG_PANEL_URL` and
`TG_BOOTSTRAP_TOKEN` substituted into the script body. The token is **never** echoed in a URL,
a log line or a response header.

The `os` parameter only selects the shell dialect of the generated script (`linux` → POSIX sh,
`freebsd` → sh with `pkg` notes, `windows` → a PowerShell equivalent that is documented but
marked experimental).

### `POST /api/v1/routers/bootstrap/exchange`

Headers: `X-Bootstrap-Token`. Body (`BootstrapReport`, all optional):

```json
{"hostname": "OpenWrt", "model": "Xiaomi AX3200", "openwrt_version": "23.05.5",
 "mac": "aa:bb:cc:dd:ee:ff", "uptime_seconds": 84213, "client_version": "1.0.0"}
```

→ `200` `BootstrapExchangeOut`

```json
{
  "router_id": "9f3c...",
  "router_name": "Office AP",
  "slug": "office-ap",
  "ssh": {"host": "203.0.113.10", "port": 22, "username": "tunnelgate",
          "host_key_fingerprint": "SHA256:...", "host_key_type": "ssh-ed25519"},
  "tunnel": {"remote_port": 20001, "bind_address": "127.0.0.1",
             "router_http_port": 80, "local_target": "127.0.0.1:80",
             "url": "https://office-ap.panel.example.com"},
  "console": {"enabled": true, "ssh_user": "root", "allowed_from": "127.0.0.1",
              "console_port": 25001, "target_port": 22,
              "authorized_keys_path": "/etc/dropbear/authorized_keys", "shell": "/bin/ash"},
  "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "private_key_path_hint": "/root/.ssh/tunnelgate_ed25519",
  "api_token": "tg_9f1c...",
  "heartbeat_url": "https://panel.example.com/api/v1/routers/9f3c.../heartbeat",
  "key_fingerprint": "SHA256:...",
  "server_time": "2026-11-17T21:42:34Z"
}
```

The token is consumed **before** the key is generated, inside one transaction, so two
simultaneous exchanges cannot both succeed. The private key exists only in this response body:
it is not logged, not cached, not written to a server file, and not recoverable afterwards.

---

## Heartbeat (router-facing)

### `POST /api/v1/routers/{id}/heartbeat`

Header: `X-Api-Token`. Body: `HeartbeatIn` (hostname, model, openwrt_version, uptime_seconds,
mac, tunnel_pid, client_version).

→ `200` `HeartbeatOut`

```json
{"ok": true, "status": "online", "server_time": "...", "tunnel_present": true,
 "desired": null,
 "console": {"serial": 1, "user": "root",
             "public_key": "ssh-ed25519 AAAA... tunnelgate-console",
             "fingerprint": "SHA256:...",
             "authorized_keys_path": "/etc/dropbear/authorized_keys", "shell": "/bin/ash"}}
```

`console` is present only while the router's stored key serial is behind the server's, so a
router rewrites its `authorized_keys` exactly once per rotation. A heartbeat can refresh
metadata and deliver the console key; it can **never** mark a router online (that requires an
observed tunnel - see ARCHITECTURE.md §7).

---

## Console (web shell)

### `GET /api/v1/routers/{id}/console`

→ `200`

```json
{"state": "ready", "console_port": 25001, "installed_at": "...",
 "fingerprint": "SHA256:...", "active_sessions": 0,
 "idle_timeout_seconds": 900, "max_session_seconds": 7200}
```

`state`: `disabled` (feature off for this router) · `no_key` (never opened yet) ·
`not_installed` (key created, router has not picked it up) · `ready` · `offline`.

### `POST /api/v1/routers/{id}/console/start` *(operator, CSRF)*

Opens the SSH connection (this is the reachability check) and mints a one-time ticket.

→ `200` `ConsoleStartOut`

```json
{"router_id": "9f3c...", "ticket": "t_8f2...", "ws_path": "/api/v1/routers/9f3c.../console/ws?ticket=t_8f2...",
 "expires_at": "2026-11-17T21:43:04Z", "console_port": 25001}
```

Ticket: 30 s TTL, single use, bound to (router_id, user_id, client IP). Rate limited to
10 starts/minute per user. `403` for `viewer`.

### `WS /api/v1/routers/{id}/console/ws?ticket=...`

Cookie-authenticated (browsers cannot set headers on a WebSocket upgrade; the ticket is the
CSRF-equivalent proof). Frame protocol:

| Direction | Frame | Meaning |
|---|---|---|
| client → server | text | raw keystrokes typed into the terminal |
| client → server | text JSON `{"type":"resize","cols":120,"rows":32}` | terminal resized |
| client → server | text JSON `{"type":"ping"}` | keepalive |
| server → client | text | raw shell output (ANSI included) |
| server → client | text JSON `{"type":"status","state":"connected"}` | lifecycle |
| server → client | text JSON `{"type":"exit","reason":"idle_timeout"}` | session ended |

Close reasons: `idle_timeout`, `max_duration`, `client_closed`, `router_disconnected`,
`admin_terminated`, `server_shutdown`.

### `GET /api/v1/console/sessions`

Recent `ConsoleSession` rows. Operators see their own; admins see all. Filters: `router_id`,
`limit`, `offset`.

```json
{"items": [{"id": "...", "router_id": "...", "router_name": "Office AP", "username": "alice",
            "client_ip": "198.51.100.7", "started_at": "...", "closed_at": "...",
            "close_reason": "client_closed", "bytes_in": 8123, "bytes_out": 40211}],
 "total": 1}
```

---

## Audit

### `GET /api/v1/audit`

Filters: `router_id`, `actor`, `action`, `outcome`, `limit` (default 100, max 1000), `offset`.

```json
{"items": [{"id": 41, "ts": "...", "actor_username": "alice", "action": "router.create",
            "outcome": "ok", "router_id": "...", "router_name": "Office AP",
            "ip": "198.51.100.7", "detail": null}], "total": 41}
```

Actions: `auth.login`, `auth.login_failed`, `auth.logout`, `auth.password`, `router.create`,
`router.update`, `router.delete`, `router.rotate`, `router.script`, `router.exchange`,
`luci.open`, `console.start`, `console.open`, `console.close`, `console.terminate_cmd_failed`,
`user.create`, `user.update`, `user.delete`.

`luci.open` is throttled to at most one row per (user, router, minute) so a LuCI page with 40
subresources does not create 40 rows.

---

## Users *(admin only)*

`GET /api/v1/users` · `POST /api/v1/users` · `PATCH /api/v1/users/{id}` ·
`DELETE /api/v1/users/{id}`

```json
{"username": "bob", "password": "at-least-8-chars", "display_name": "Bob", "role": "operator"}
```

The last active admin cannot be deleted or demoted (`409 last_admin`).

---

## Meta

### `GET /api/v1/health` (no auth)

```json
{"status": "ok", "version": "1.0.0", "time": "2026-11-17T21:42:34Z"}
```

### `GET /api/v1/config`

```json
{"panel_url": "https://panel.example.com", "subdomain_suffix": "panel.example.com",
 "bootstrap_ttl_minutes": 15, "poll_interval_seconds": 2, "proxy_driver": "nginx",
 "version": "1.0.0"}
```

### `GET /api/v1/stats`

```json
{"routers_total": 12, "routers_online": 9, "routers_offline": 2, "routers_pending": 1,
 "ports_free": 456, "users_total": 3, "console_sessions_active": 1}
```

---

## Internal: the nginx auth subrequest

Not part of the public API but worth documenting because it *is* the authorisation boundary.

### `GET /__tg/auth?router_id=<id>&uri=<original-uri>`

Called by nginx `auth_request` for every request to `https://<slug>.<domain>`.

* `200` + `X-Tg-User`, `X-Tg-Role`, `X-Tg-Router` headers → nginx proxies the request.
* `401` → nginx redirects to the panel login.
* Anything else, including a panel crash → nginx denies (fail closed).

It audits `luci.open` (throttled) so the audit log can answer "who looked at which router".
