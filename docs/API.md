# TunnelGate HTTP API

Base URL: `https://panel.example.com`. Everything is JSON (`application/json`) except
`GET /api/v1/routers/install`, which returns `text/x-shellscript`.

Interactive documentation (`/api/docs`, `/api/openapi.json`) is **disabled in production** -
both return `404`, because an unauthenticated schema dump is free reconnaissance. The switch is
`TUNNELGATE_DOCS_ENABLED`; unset, it is on for every `TUNNELGATE_ENV` except `prod`/`production`.
Both the shipped env file and `scripts/setup-server.sh` set `TUNNELGATE_ENV=production`, so a
normal install has no `/api/docs`. This document is the field list you have in production, plus
the contract and the reasoning behind it.

## Conventions

### Authentication

Two completely separate mechanisms:

| Caller | Credential | Where |
|---|---|---|
| Operator (browser) | `tg_session` cookie (HttpOnly, SameSite=Lax, Secure in production) | `POST /api/auth/login` |
| Router, during onboarding | `X-Bootstrap-Token` header | single-use, 15 min |
| Router, afterwards | `X-Api-Token` header | derived from its public key, see below |

State-changing operator requests **must** carry `X-CSRF-Token`, and the value must match the
`tg_csrf` cookie that login sets beside the session cookie (name from
`TUNNELGATE_CSRF_COOKIE_NAME`, default `tg_csrf`). The client reads that cookie and echoes it in
the header; the server then checks three things - the header is present, it equals the cookie,
and the cookie equals the server-side `PanelSession.csrf_token`. Sending only one of the two, or
sending two different values, is `403 csrf_failed`.

Neither `POST /api/auth/login` nor `GET /api/auth/me` puts the token in the response body any
more. That was the bug: in the merged path layout a router page is same-origin with the panel,
so a compromised router could fetch `/api/auth/me` with the operator's cookie and read the token
straight out of the JSON. No response body carries it now; see docs/SECURITY.md.

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
| 409 | `agent_endpoint_unusable` | `TUNNELGATE_PANEL_URL` does not parse as http(s) and no override is stored (settings routes) |
| 409 | `console_not_ready` | Console key not installed yet, or router offline |
| 422 | `slug_taken` | Slug collision that could not be resolved |
| 422 | `validation_error` | A field failed a business rule; `details.fields` says which (settings routes) |
| 429 | `rate_limited` | Login or exchange throttled (`Retry-After` header set) |
| 503 | `no_free_port` | Port pool exhausted |

### Timestamps

All timestamps are UTC, serialised as ISO-8601 with a trailing `Z` (`2026-11-17T21:42:34Z`).
Two timestamps in the same second are indistinguishable by design.

### Roles

| Role | May |
|---|---|
| `viewer` | read **the routers granted to them**, read audit, open **LuCI** on a granted router |
| `operator` | + **every** router, create/rotate/delete routers, read install scripts, open a **console** |
| `admin` | + manage users and grants, terminate console sessions, reissue scripts for installed routers, set the agent endpoint |

`admin` and `operator` are allowed on every router without a grant row: they rotate keys and
read install scripts, which already means a working credential for any device, so asking for a
grant on top would be theatre. `viewer` is the role grants exist for - see
[Per-router access](#per-router-access-grants).

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
  "expires_at": "2026-11-18T09:42:34Z"
}
```

Sets **two** cookies:

```
Set-Cookie: tg_session=<opaque>; HttpOnly; SameSite=Lax; Path=/; Max-Age=<session ttl>
Set-Cookie: tg_csrf=<the session row's csrf token>; SameSite=Lax; Path=/; Max-Age=<same ttl>
```

(`Secure` on both when `TUNNELGATE_COOKIE_SECURE=true`.) The second one is deliberately **not**
HttpOnly: the SPA has to read it to build the `X-CSRF-Token` header, and a token only the browser
can send is a token the browser must be able to show to script. The session cookie is the
credential; this cookie is only the second half of a same-origin proof. The response body carries
no token at all - that is what makes a fetched-and-read attack impossible.

No `Domain` attribute is emitted unless `TUNNELGATE_COOKIE_DOMAIN` is set, so the cookie is
**host-only** and a browser sends it only to the panel hostname - never to a router vhost. Setting
that variable makes the session cookie travel to every `<slug>.<suffix>`, which turns one
compromised router into a panel session; see docs/SECURITY.md §6.

Rate limited per client IP and per IP+username: `TUNNELGATE_LOGIN_RATE_LIMIT` (10) attempts per
`TUNNELGATE_LOGIN_RATE_WINDOW_SECONDS` (900). Exceeding it → `429` with `Retry-After`.

### `POST /api/auth/logout`

Revokes the session row and clears **both** cookies - `tg_session` and `tg_csrf`, each with
`Max-Age=0`. → `204`.

Leaving the CSRF cookie behind would keep a live-looking token in the browser past the session
it belongs to.

### `GET /api/auth/me`

→ `200` `SessionOut` = `{"user": UserOut, "expires_at": "..."}`. No CSRF token in the body:
it lives in the `tg_csrf` cookie, which login set and logout deletes.

A reloaded SPA boots from this call and reads the cookie. The route does not set it: only login
writes `tg_csrf` and only logout deletes it, so a browser that lost the cookie has no token
until it signs in again - the next mutating request fails `403 csrf_failed` rather than
guessing.

### `POST /api/auth/password`

```json
{"current_password": "...", "new_password": "..."}
```

Rehashes and revokes **every other** session of that user. → `204`.

---

## Per-router access (grants)

Every router endpoint, the LuCI gate and the console check the same rule, implemented once in
`app/services/access.py`:

```
admin, operator             -> every router
viewer                      -> only the routers in router_grants for that user
```

A viewer with no grant therefore sees an empty router list and a plain `401 not_authenticated`
from the gate - the same body an unauthenticated caller gets, so a viewer cannot use the panel
to find out which router ids exist. The REST endpoints answer `403 forbidden` for a router the
caller may not see, and for a router id that does not exist the answer is the same `403`: a
`404` exists only for callers who are allowed on every router (`admin`/`operator`), where
telling "missing" from "forbidden" leaks nothing.

Grants are managed by an admin (see [Users](#users-admin-only)); a viewer who creates a router is
granted it automatically, otherwise the router would appear in the create response and vanish
from their list forever.

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
  "install_command": "TK='Q1r...'; U='https://panel.example.com/api/v1/routers/install?os=linux'; F=/tmp/tg-install.$$.sh\nif command -v curl >/dev/null 2>&1; then curl -fsSL -o \"$F\" -u \"$TK:\" \"$U\"\nelif command -v wget >/dev/null 2>&1; then wget -q -O \"$F\" --user=\"$TK\" --password=x \"$U\"\nelse echo 'TunnelGate: neither curl nor wget is installed on this router' >&2; exit 1; fi\ngrep -q 'TunnelGate router agent installer' \"$F\" 2>/dev/null || { ...; rm -f \"$F\"; exit 1; }\nsh \"$F\"",
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

A viewer gets only the routers granted to them, and the counters describe that filtered set:
`total` is the number of routers they can see, not the number in the panel. Returning the
unfiltered totals would turn the list into a census of devices the caller may not touch.

### `GET /api/v1/routers/{id}` → `RouterOut`

Two URL fields, and they are not interchangeable:

| field | value | use |
|---|---|---|
| `url` | `https://<slug>.<suffix>` | the router's real public address - display it, copy it, poll it |
| `launch_url` | `https://<slug>.<suffix>/__tg/enter` | what a click must follow: it installs a cookie scoped to that router host |

The scheme is `https` unless `TUNNELGATE_PUBLIC_URL` is explicitly an `http` origin, in which
case both fields use `http` - an install that only answers plain HTTP must not advertise links
nothing listens on. In path mode on the panel's own host (the merged layout) the URLs also carry
`TUNNELGATE_PUBLIC_URL`'s port. See `docs/INSTALL_SERVER.md` §7.

`null` for both while the router has no proxy route yet. Opening `url` in a browser that has
never been through the hand-off bounces through `/login`; see
[the launch hand-off](#internal-the-router-launch-hand-off).

### `PATCH /api/v1/routers/{id}` *(operator)*

`name`, `group_name`, `notes`, `http_port`. The slug never changes after creation (it is baked
into DNS and into already-installed routers).

### `DELETE /api/v1/routers/{id}` *(operator)*

Revokes the key (rewrites `authorized_keys` + no-op if the tunnel user is absent), kills its
live console shells (each closes with `router_disconnected`; the count lands in the audit
detail), frees **both** ports, deletes the row (cascade: tokens, runtime, console sessions) and
returns `204`. The shells are signalled first because the session rows vanish with the router:
a shell left running would be a root prompt on a device with no row and no way to reach it.
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

→ `200 text/x-shellscript`, `Cache-Control: no-store`, with `TG_PANEL_URL`,
`TG_BOOTSTRAP_TOKEN` and `TG_TLS_VERIFY` (`1` or `0`, from the agent endpoint's `verify_tls`)
substituted into the script body. The token is **never** echoed in a URL, a log line or a response
header.

The `os` parameter only selects the shell dialect of the generated script (`linux` → POSIX sh,
`freebsd` → sh with `pkg` notes, `windows` → a PowerShell equivalent that is documented but
marked experimental).

`TG_TLS_VERIFY=0` makes the body fetch with `-k` (curl) or `--no-check-certificate`
(wget/uclient-fetch) and prefixed with a comment saying so; with `1` the body is byte-for-byte what
it was before the flag existed. The installer writes the value into `tunnelgate.main.tls_verify`,
which is what the agent (and the heartbeat) read from then on.

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

`heartbeat_url` is built from the **agent endpoint**, not from `TUNNELGATE_PANEL_URL`: it is the
address this router will actually dial from its own network. If you are moving the panel later,
change the agent endpoint (`PUT /api/v1/settings/agent-endpoint`) and re-issue the script;
already installed routers are re-pointed by their heartbeat instead (see
[Heartbeat](#heartbeat-router-facing)).

Rate limits, all of which answer `429 rate_limited` with `Retry-After`:

| Limit | Value | Scope |
|---|---|---|
| `EXCHANGE_LIMIT` | 60 per 60 s | per client IP, counted **separately** for `/install` and `/bootstrap/exchange` |
| `SCRIPT_LIMIT` | 5 per 15 min | per **token**, on `/install` only - independent of the caller's address |

The per-IP window is generous because a router may retry the installer while the operator watches
its console. The per-token cap is the tighter of the two on purpose: every `/install` render
echoes the live single-use credential into the response body, so a caller who rotates source
addresses could otherwise keep pulling the same token for its whole TTL. Hitting it means
"mint a new token", not "wait" - the token is telling you it has been handled enough.

---

## Heartbeat (router-facing)

### `POST /api/v1/routers/{id}/heartbeat`

Header: `X-Api-Token`. Body: `HeartbeatIn` (hostname, model, openwrt_version, uptime_seconds,
mac, tunnel_pid, client_version, console_serial, console_installed).

→ `200` `HeartbeatOut`

```json
{"ok": true, "status": "online", "server_time": "...", "tunnel_present": true,
 "desired": {"heartbeat_url": "https://panel.example.com/api/v1/routers/9f3c.../heartbeat"},
 "console": {"serial": 1, "user": "root",
             "public_key": "ssh-ed25519 AAAA... tunnelgate-console",
             "fingerprint": "SHA256:...",
             "authorized_keys_path": "/etc/dropbear/authorized_keys", "shell": "/bin/ash"}}
```

`desired` is the **only** channel that re-points a router which is already installed. It carries
the address the router should use from now on, built from the agent endpoint (Settings →
Agent endpoint, falling back to `TUNNELGATE_PANEL_URL`; see [Settings](#settings-admin-only-csrf)),
**not** from the panel's internal address. The agent compares it with the `heartbeat_url` it has
stored, and when the two differ and the new value starts with `http://` or `https://` it rewrites
`tunnelgate.main.heartbeat_url` in UCI and logs `panel moved: heartbeat_url updated to ...`. It is
repeated on every heartbeat, so a router that missed a beat still converges, and a value that is
not an http(s) URL is ignored with a log line rather than written. See
`docs/INSTALL_SERVER.md`, "Moving the panel without re-installing routers".

`desired` carries the address and **only** the address: the endpoint's `verify_tls` is not part
of it, so changing the flag never reaches a router that is already installed. That router's policy
is the `tunnelgate.main.tls_verify` option the installer wrote for it - see
`docs/SECURITY.md`, "When to turn certificate verification off".

`console` is present only while the router's stored key serial is behind the server's, so a
router rewrites its `authorized_keys` exactly once per rotation. A heartbeat can refresh
metadata and deliver the console key; it can **never** mark a router online (that requires an
observed tunnel - see ARCHITECTURE.md §7). It also records the router's observed source address
in `client_ip`, which is why the reverse-proxy trust rules in `docs/SECURITY.md` §7 matter for
the audit trail.

---

## Console (web shell)

### `GET /api/v1/routers/{id}/console`

→ `200`

```json
{"state": "ready", "console_port": 25001, "console_ssh_port": 22, "ssh_user": "root",
 "installed_at": "...", "fingerprint": "SHA256:...",
 "host_key_fingerprint": "SHA256:...", "host_key_pinned_at": "...",
 "active_sessions": 0, "idle_timeout_seconds": 900, "max_session_seconds": 7200,
 "max_sessions_per_user": 3}
```

`state`: `disabled` (feature off for this router) · `no_key` (never opened yet) ·
`not_installed` (key created, router has not picked it up) · `ready` · `offline`.

Two fingerprints, deliberately separate:

| Field | What it fingerprints |
|---|---|
| `fingerprint` | the **console key** the panel presents to the router (the panel's identity) |
| `host_key_fingerprint` | the **router's own SSH host key**, pinned on the first console open and required never to change; `null` until that first open |

`host_key_pinned_at` is when that key was learned; while the pin is `null` the console has not
verified the device yet, which the UI should say in those words rather than showing an empty
string that reads like "nothing to check". Compare `host_key_fingerprint` with
`ssh-keygen -lf` on the device; comparing the *other* one proves nothing about the router.

Readable by every authenticated user for a router they may access - console state is per-router
data (ports, fingerprints, live session count), so a viewer without a grant gets `403` here
just as on the router row itself.

### `POST /api/v1/routers/{id}/console/start` *(operator, CSRF)*

Opens the SSH connection (this is the reachability check) and mints a one-time ticket.

→ `200` `ConsoleStartOut`

```json
{"router_id": "9f3c...", "ticket": "t_8f2...", "ws_path": "/api/v1/routers/9f3c.../console/ws?ticket=t_8f2...",
 "expires_at": "2026-11-17T21:43:04Z", "console_port": 25001}
```

Ticket: 30 s TTL, single use, bound to (router_id, user_id, client IP). Rate limited to
10 starts/minute per user. `403` for `viewer`.

The dial performs the host key check, so the failures below are the ones an operator will
actually see:

| Status | `code` | Meaning |
|---|---|---|
| `502` | `console_auth_failed` | the router presented a host key that does not match its pin, or rejected the console key (see the message: it names which) |
| `502` | `console_unreachable` | the loopback listener did not answer; the router is offline or its forward is down |
| `409` | `console_no_key` | no console key, or no console port allocated |

The first successful open **pins** the router's host key (`host_key_fingerprint` on the read
endpoint). Every later open must present the same key. A different one is refused before a
session exists - a reflash, a swapped device, or an impostor inside the tunnel all look the
same from here, and the recovery is the same: verify the device out of band, then clear the
pin with the `DELETE .../console/host-key` route below.

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

### `DELETE /api/v1/routers/{id}/console/host-key` *(admin, CSRF)*

Forget the router's pinned SSH host key, so the next console open learns it again. → `204`

This is the only way out of the trust-on-first-use pin, and it exists because the pin cannot be
allowed to relearn itself: a router that has been taken over would present its own host key and
every console would silently talk to the attacker. A router that was legitimately reflashed or
physically replaced genuinely does come back with a new host key, so an admin with out-of-band
proof of the device - console cable, physical access, a trusted second path - clears the pin
here and the next `start` re-pins it.

Verify the device **before** calling this. Calling it because a console opening felt wrong is
the exact move someone who took the router needs, which is why it is admin-only and audited as
`console.host_key.cleared` with the discarded fingerprint, who discarded it and from where.

| Status | `code` | Meaning |
|---|---|---|
| `204` | - | pin cleared (also when there was no pin) |
| `404` | `router_not_found` | no such router |
| `403` | `forbidden` | caller is not an admin |
| `403` | `csrf_failed` | missing or stale CSRF token |

It terminates nothing: live shells were verified when they opened and keep running.

### `DELETE /api/v1/console/sessions/{id}` *(admin, CSRF)*

Force-close one live console session. → `204`

The panel does not write `closed_at` here: it signals the handler that owns the shell and that
handler's teardown stamps the row, the byte counters and the `console.close` audit entry. One
writer per row is why a kill cannot leave a finished-looking row in front of a shell that is
still running.

| Status | `code` | Meaning |
|---|---|---|
| `404` | `console_session_not_found` | no such `ConsoleSession` row |
| `409` | `console_session_closed` | the session already ended; `details.close_reason` says how |
| `409` | `console_session_not_live` | the row is open but no handler in this process owns it (still starting, or left over from a previous run) |
| `403` | `forbidden` | caller is not an admin |
| `403` | `csrf_failed` | missing or stale CSRF token |

The kill is audited as `console.terminate` with the target username and address, and the session
itself closes with reason `admin_terminated`.

### `GET /api/v1/console/sessions`

Recent `ConsoleSession` rows. Operators see their own; admins see all. Filters: `router_id`,
`limit`, `offset`.

```json
{"items": [{"id": "...", "router_id": "...", "router_name": "Office AP", "username": "alice",
            "client_ip": "198.51.100.7", "started_at": "...", "closed_at": "...",
            "close_reason": "client_closed", "bytes_in": 8123, "bytes_out": 40211}],
 "total": 1}
```

### `GET /api/v1/routers/{id}/console/sessions`

The same rows scoped to one router, same filters and shape. It is what the router detail page
asks for; `404 router_not_found` if the router does not exist.

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
`luci.open`, `console.start`, `console.open`, `console.close`, `console.terminate`,
`console.host_key.cleared`, `user.create`, `user.update`, `user.delete`,
`user.grants.update`, `user.grants.revoke`,
`settings.agent_endpoint.save`,
`settings.agent_endpoint.reset`, `settings.agent_endpoint.test`.

`settings.agent_endpoint.test` is written with `outcome: "error"` when the probe failed even
though the request itself was allowed (the same convention `console.start` uses when the SSH
dial fails): the row records what the panel found, not whether it was permitted to look.

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

The grant routes below decide which routers a `viewer` may reach; see
[Per-router access](#per-router-access-grants) for the rule they feed.

### `GET /api/v1/users/{id}/routers` *(admin)*

The routers granted to one user, in the router list shape the rest of the panel uses. Only
meaningful for a `viewer`: `admin` and `operator` are allowed on every router without a row
here, so an empty list for them is not a lack of access.

→ `200` `{"items": [RouterOut, ...], "total": 2}`

### `PUT /api/v1/users/{id}/routers` *(admin, CSRF)*

```json
{"router_ids": ["a1b2...", "c3d4..."]}
```

**Replaces** the whole set for that user - it is not a merge. A set operation is idempotent, so
a retry after a timeout cannot double-grant, and the audit row records the state that resulted
instead of a delta nobody can replay against an unknown starting point. Send
`{"router_ids": []}` to revoke everything.

→ `200` with the same envelope as `GET`, now describing the new set.

| Status | `code` | Meaning |
|---|---|---|
| `400` | `validation_error` | an id in `router_ids` does not exist; the message and `details.fields` name it |
| `403` | `forbidden` | caller is not an admin - an operator who could grant themselves routers would make the whole access check pointless |
| `403` | `csrf_failed` | missing or stale CSRF token |
| `404` | `not_found` | no such user |

An unknown id is refused rather than skipped: silently dropping it would tell the caller a grant
exists when no row was written, and nobody would find out until that person cannot open the
router. Router ids are validated by a single `SELECT ... WHERE id IN (...)`, so the whole body
is rejected or none of it is.

Grants and roles are independent on purpose. Promoting a user to `admin` or `operator` leaves
their rows in place - redundant, harmless, and the whole permission again if the role ever falls
back to `viewer`. Demoting to `viewer` does **not** create grants and does not copy anything
from the old role: until an admin grants routers, that user reaches none. Nothing deletes rows
behind the caller's back here; deleting the user or the router does, by `ON DELETE CASCADE`.

Audited as `user.grants.update` with `detail` = `{"username", "router_ids", "added",
"removed"}`.

### `DELETE /api/v1/users/{id}/routers/{router_id}` *(admin, CSRF)*

→ `204`. Removes exactly one grant and audits `user.grants.revoke` with
`detail: {"username": "...", "router_ids": ["<router_id>"]}`.

`404 not_found` when that user has no grant for that router: a delete that reports success while
doing nothing teaches the caller the router was protected when it was not.

---

## Settings *(admin only, CSRF)*

One thing is editable from the panel: the **agent endpoint**, i.e. the scheme, host and port a
router dials. It is deliberately not the same value as `TUNNELGATE_PANEL_URL`.

| Value | Answers | Used by |
|---|---|---|
| `panel_url` (`TUNNELGATE_PANEL_URL`) | where the panel listens for **its own** proxy - the `proxy_pass` target, usually `http://127.0.0.1:8080` | the nginx/Caddy route renderer, login redirects |
| agent endpoint | where a **router** dials the panel - `https://panel.example.com` | install command, script body, bootstrap exchange `heartbeat_url`, heartbeat `desired.heartbeat_url` |

On a flat install they are the same string and nothing needs to be set. They must differ as soon
as a TLS terminator, a cloud load balancer or a non-default port sits in front of the panel: the
panel still binds loopback, while routers dial the public address. Pointing `panel_url` at the
public name to fix that would break the panel's own routing, which is why the override lives in
the database and not in the env file.

The endpoint also carries one bit of TLS policy, `verify_tls` (default `true`). It is
deliberately **not** part of `agent_url`: the URL stays a plain address that can be pasted into a
shell or printed in a log line, while the policy travels beside it - `false` makes the install
command fetch with `-k` / `--no-check-certificate` and makes the agent accept a certificate it
cannot verify. An `http` endpoint is always `true`, because there is no certificate to verify.

Source is reported honestly in every response: `environment` (from `TUNNELGATE_PANEL_URL`, or
from `TUNNELGATE_PUBLIC_URL` when the former is loopback and therefore unreachable from a router)
or `database` (the admin stored an override).

### `GET /api/v1/settings/agent-endpoint`

→ `200`

```json
{
  "agent_url": "https://panel.example.com",
  "agent_endpoint": {"scheme": "https", "host": "panel.example.com", "port": null,
                     "source": "environment", "verify_tls": true}
}
```

`port: null` means "the scheme default" (80/443); a port equal to that default is normalised
away, so `https` + `443` and `https` + `null` produce the same `agent_url`. IPv6 hosts are
stored unbracketed and rendered bracketed.

`verify_tls` is what the router is told to do with the panel's certificate: `true` (the default)
verifies it, `false` accepts a self-signed or otherwise unverifiable one. Rows written before this
field existed read as `true`.

→ `409 agent_endpoint_unusable` when `TUNNELGATE_PANEL_URL` cannot be parsed as an http(s) URL
and no override is stored. Nothing is broken in that state - installs and heartbeats fall back to
the raw string - but the panel cannot tell an operator what routers are dialling, so the fix is
to `PUT` an endpoint.

`403` for `viewer` and `operator`. The endpoint itself is public information (routers resolve
it), but the panel's own reachability details are not something every account needs.

### `PUT /api/v1/settings/agent-endpoint`

```json
{"scheme": "https", "host": "panel.example.com", "port": 8443, "verify_tls": false}
```

`scheme` is `http` or `https`; `host` is a hostname, an IPv4 literal or an IPv6 literal (bare or
bracketed) and must not carry a scheme, a port, a path, credentials or separators; `port` is
optional; `verify_tls` is optional and defaults to `true` - omit it and routers verify the
certificate. → `200` with the same envelope as `GET`, `source` now `database`.

One normalisation a client author should know about: `scheme: "http"` with `verify_tls: false`
comes back as `verify_tls: true`. It is not a rejection - there is no certificate on an `http`
endpoint to verify or to skip, so the flag is stored as the no-op it is. Read the response, not
the request, if you need to know what routers are being told.

Field-level validation failures are a `422` in the standard envelope, with one entry per bad
field so the SPA can highlight it:

```json
{"error": {"code": "validation_error", "message": "That endpoint is not usable",
  "details": {"fields": [
    {"loc": ["body", "host"], "msg": "Host must not contain spaces, paths, credentials or separators"},
    {"loc": ["body", "port"], "msg": "Port must be between 1 and 65535"}]}}}
```

Nothing is written when validation fails. A stored value is re-validated on every read: a row
that an older version wrote and that no longer parses is ignored with a log line and the
environment value applies again, so a bad row can never produce a URL that routers cannot parse.

Effect is immediate and needs no restart. The next `POST /api/v1/routers`, rotate-key and
`GET .../script` render the install command from the new value; the next bootstrap exchange hands
out the new `heartbeat_url`; the next heartbeat tells every already-installed router to move.
See `docs/INSTALL_SERVER.md`, "Moving the panel without re-installing routers".

The flag changes nothing about the address: the next `POST /api/v1/routers` renders a command
that fetches with `-k` / `--no-check-certificate` instead of verifying. It reaches **new**
installs only - a router that is already installed keeps the policy in its own UCI option, since
the heartbeat's `desired` payload carries the address and nothing else
(see [Heartbeat](#heartbeat-router-facing)).

Audit: `settings.agent_endpoint.save`, `detail: {agent_url, verify_tls}`.

### `DELETE /api/v1/settings/agent-endpoint`

Drops the override so `TUNNELGATE_PANEL_URL` applies again. → `200` with the now-effective
envelope (`source: environment`). **Idempotent**: deleting when nothing is stored is not an
error, it reports what is in effect. `409` if the override came out and the environment value is
still unusable - that combination is worth seeing rather than hiding.

Audit: `settings.agent_endpoint.reset`, `detail: {removed: bool, agent_url: ..., verify_tls}`.

### `POST /api/v1/settings/agent-endpoint/test`

Probes a **candidate** endpoint from the panel and reports what came back. Body is the same
`{scheme, host, port, verify_tls}`; it is validated exactly like `PUT` and validated **before**
anything is sent.

`verify_tls: false` is honoured here too, and it has to be: if the probe verified the certificate
of an endpoint whose routers are told not to, it would answer `ok: false` for a panel that works,
and the operator would go looking for the wrong fault.

→ `200`

```json
{"ok": true, "checked_url": "https://panel.example.com/api/v1/health",
 "status_code": 200, "latency_ms": 41, "error": null}
```

A failure is still `200` with `ok: false` and a reason in `error` - "connection refused" is an
answer, not a server error:

```json
{"ok": false, "checked_url": "https://panel.example.com/api/v1/health",
 "status_code": null, "latency_ms": null, "error": "ConnectError: [Errno -2] Name or service not known"}
```

`error` is one of three shapes: `"<ExceptionType>: <message>"` (DNS, TCP, TLS - truncated to 300
characters), `"HTTP <status> from <url>"` (something answered, not with a 200), or `"Reached
something, but it is not a TunnelGate panel (no health payload)"` (200 but no
`{"status": "ok"}` body - a captive portal, a proxy error page). `ok: true` requires **both**
HTTP 200 and a JSON body whose `status` is `ok`.

The probe is exactly one unauthenticated `GET <url>/api/v1/health` with redirects **not**
followed and a 5 s timeout, verifying the certificate unless the candidate says `verify_tls: false`.
It never persists the candidate: after a successful test the effective endpoint is unchanged.

This is the only reliable way to tell "the router will reach this address" apart from "my
browser can" - the panel's network position is the one that matters. It is admin-only because it
makes the panel issue an outbound request to an operator-chosen address, and every attempt is
audited (`settings.agent_endpoint.test`, `detail: {checked_url, error, verify_tls}`).

---

## Meta

### `GET /api/v1/health` (no auth)

```json
{"status": "ok", "version": "1.3.0", "time": "2026-11-17T21:42:34Z"}
```

### `GET /api/v1/config`

```json
{"panel_url": "http://127.0.0.1:8080", "subdomain_suffix": "panel.example.com",
 "route_mode": "subdomain", "gateway_host": "gate.panel.example.com",
 "bootstrap_ttl_minutes": 15, "poll_interval_seconds": 2, "proxy_driver": "nginx",
 "version": "1.3.0",
 "agent_url": "https://panel.example.com",
 "agent_endpoint": {"scheme": "https", "host": "panel.example.com", "port": null,
                    "source": "environment", "verify_tls": true},
 "agent_endpoint_testable": true}
```

The two URLs answer different questions and are deliberately not the same field:

| Field | Meaning |
|---|---|
| `panel_url` | where the panel listens for **its own** reverse proxy (`proxy_pass` target). Loopback in the shipped layout. |
| `agent_url` | the base URL a **router** dials - what the installer, bootstrap exchange and heartbeat use. |
| `agent_endpoint` | the parsed form of `agent_url` plus its `source` (`environment` or `database`) and its TLS policy `verify_tls`. `null` when `TUNNELGATE_PANEL_URL` is unparseable and no override is stored. |
| `agent_endpoint_testable` | `false` exactly when `agent_endpoint` is `null` - there is nothing well-formed to probe. |

`agent_url` is always populated: it falls back to the raw `TUNNELGATE_PANEL_URL` string even when
that string does not parse, so the SPA can show an operator what routers are being told.

When `TUNNELGATE_PANEL_URL` is loopback (the documented shape: nginx on the panel host forwards
to it) the endpoint comes from `TUNNELGATE_PUBLIC_URL` instead, because no router on a customer
network can dial `127.0.0.1` - and an install command naming loopback only works on the panel
host itself. A loopback origin in both places is still reported, so `doctor` can explain it. Setting
the override is `PUT /api/v1/settings/agent-endpoint` (see [Settings](#settings-admin-only-csrf)).

### `GET /api/v1/stats`

```json
{"routers_total": 12, "routers_online": 9, "routers_offline": 2, "routers_pending": 1,
 "ports_free": 456, "users_total": 3, "console_sessions_active": 1}
```

The router and console counters describe **the routers the caller may reach** (`admin` and
`operator`: all of them; a `viewer`: the granted set), because a fleet's size and health is
information about routers a viewer was not given. `users_total` is a panel-wide account count
and is not scoped.

---

## Internal: the router launch hand-off

Not part of the public API, but this is how a browser gets from the panel to a router's LuCI
without a domain-wide session cookie. `docs/SECURITY.md` §6 has the reasoning.

### `GET /__tg/launch?router=<slug|id>&next=<path>` *(session required)*

Runs on the panel host, where `tg_session` actually is.

```
GET /__tg/launch?router=office-ap&next=/cgi-bin/luci
-> 303 Location: https://office-ap.panel.example.com/__tg/enter?t=<ticket>
   Cache-Control: no-store
```

* The caller must hold a panel session (`401 not_authenticated` otherwise), **and** may reach
  the router: a `viewer` without a grant gets `403 forbidden` (or, when the request looks like a
  browser navigation, a `303` to the login form carrying `?router=`). A ticket is a credential
  for one router, so minting one asks the same question the gate asks.
* `next` is sanitised to a same-host absolute path (`/` on anything else - `//host`,
  `/\host`, `https://...` and a bare segment all become `/`).
* The ticket is 32 random bytes, valid for `TUNNELGATE_LAUNCH_TICKET_TTL_SECONDS` (120 s),
  **single use**, and bound to *(router, user, target path)*. Only its SHA-256 is stored, in
  memory, so a restart drops hand-offs in flight.
* `404 router_not_found` for an unknown or revoked router.
* Audits `luci.launch` with `detail: {"next": "<sanitised path>"}`.

This is the URL the SPA's "Open LuCI" and "Public route" controls follow, and the one the login
page redirects to when it is given `?router=`.

### `GET /__tg/enter?t=<ticket>&next=<path>` *(reached through a router vhost)*

Arrives at the panel **through the router vhost** (`location = /__tg/enter` is proxied here with
`router=$tg_slug`), which is what makes the `Set-Cookie` land on `<slug>.<suffix>` rather than
on the panel.

With `TUNNELGATE_ROUTE_MODE=path` the same endpoint is reached on the gateway host instead, and
the router is identified by the first path segment rather than by the `Host` header: nginx passes
the original URI in `X-Original-URI` and the panel reads `/<slug>/` from it. The cookie then
carries `Path=/<slug>/` and the target defaults to `/<slug>/` rather than `/`.

* Valid ticket, or an already-valid `tg_luci` for this router → `303` to the target path and
  `Set-Cookie: tg_luci=<router_id>.<user_id>.<expiry>.<hmac>; Path=/; HttpOnly; Secure;
  SameSite=Lax`, lifetime `TUNNELGATE_ROUTER_SESSION_TTL_MINUTES` (60).
* Expired ticket, replay, ticket minted for a different router, or a `Host` that does not belong
  to the router → `302` to `<panel>/login?router=<slug>&next=<path>`. Never an error page: a
  stale link has to end up somewhere the operator can sign in and continue.
* No `auth_request` guards this location - it is the way in, and it fails closed on its own.

### `GET /__tg/enter/status` 

Diagnostic JSON: `{"authorized": bool, "router": "<slug>", "user": "<name>|null",
"cookie": "<cookie name>"}`. Read-only; useful when a deployment thinks it is authenticated and
the gate disagrees.

### `GET /__tg/auth?router_id=<id>&uri=<original-uri>`

Called by nginx `auth_request` for every request to `https://<slug>.<domain>`, and in path
mode for every request to `https://<gateway>/<slug>/...` (the router id reaches nginx from the
matched `location`, so the browser still cannot choose it).

Accepts **either** credential:

1. the panel session (`tg_session`, sent by a browser on the panel host), or
2. `tg_luci` for exactly this `router_id`, read from the `X-Tg-Luci-Cookie` header that the
   rendered auth snippet sets from `$cookie_tg_luci` - never from the whole `$http_cookie`,
   so no other cookie can influence the decision. The cookie jar is consulted as well, for a
   direct request to the panel.

```
200  + X-Tg-User, X-Tg-Role, X-Tg-Router   -> nginx proxies the request
401  {"error": {"code": "not_authenticated"}} -> nginx redirects to the panel login
```

It fails closed: an unknown router, a disabled account, a forged signature, a cookie for a
different router, and a **router the caller was not granted** all produce the same `401`.
That last one matters: a viewer is refused with the identical body an unauthenticated caller
gets, so the status code and message never reveal whether a router id exists. Both responses
carry `Cache-Control: no-store`.

It audits `luci.open` (throttled) with `detail: {"uri": "...", "credential":
"panel-session"|"router-cookie"}`, so the audit log answers "who looked at which router, and
with which credential". A refusal is logged at INFO naming the router and the role, and is not
audited: the row that matters is the open that succeeded.

The decision is two questions in that order - *who* is calling (the credential above) and
*whether* that user may reach this router (`app/services/access.py`: `admin`/`operator` always,
`viewer` only with a grant). Keeping them separate is what makes the gate safe to call from
nginx on every subresource: it costs one indexed lookup on `router_grants` per request and
decides nothing else.
