# TunnelGate security model

This document states what TunnelGate protects, what it deliberately does **not** protect, and
how each control is implemented. Read it before you change `authorized_keys` rendering, the
bootstrap flow, or anything in `app/security.py`.

## 1. Threat model

### Assets

| Asset | Consequence of compromise |
|---|---|
| Router SSH private keys (tunnel + console) | An attacker with the tunnel key can open the *one* remote listener that key is restricted to; an attacker with the console key can log into that one router |
| Panel sessions | Full panel access within the user's role |
| Bootstrap tokens | A 15-minute, single-use ability to install *a specific router's* tunnel |
| VPS `authorized_keys` | Ability to run code as the tunnel user |
| LuCI itself (router admin UI) | Full router control |
| Audit log | Integrity of the "who did what" record |

### Adversaries considered

| # | Adversary | Goal | Mitigation |
|---|---|---|---|
| A1 | Internet scanner | Reach a router's LuCI | Nothing listens on a public port; listeners are `127.0.0.1` only; nginx requires a panel session |
| A2 | Someone who steals an install command (shoulder-surf, chat log) | Onboard a rogue router / hijack a router slot | Token single use, 15 min, hashed at rest, bound to one router row; unconsumed tokens are invalidated on rotate |
| A3 | Compromised **router** | Pivot into the VPS, reach other routers | Tunnel key is a `permitlisten`-only key: no shell, no pty, no local forwarding, no agent forwarding; sshd `Match user tunnelgate` additionally enforces `ForceCommand /bin/false`, `PermitOpen none`, `GatewayPorts no`, and `AllowTcpForwarding remote` only |
| A4 | Compromised **VPS panel** (RCE in the app) | Steal keys that grant access to routers | Tunnel private keys are never stored at all; console private keys are AES-GCM sealed and only unsealed per handshake (an RCE with the master key can still decrypt them - documented limitation) |
| A5 | Panel user without rights | Touch routers they should not | RBAC (`viewer` cannot create/rotate/delete or open a console); audit of every mutation |
| A6 | Panel user tampering with another router's URL | Access a router they were not authorised for | The `router_id` is injected by nginx from the matched `server` block, never taken from the request |
| A7 | CSRF from a malicious site | Perform panel mutations with the operator's cookie | Double-submit CSRF header on every mutating request + `SameSite=Lax` cookie |
| A8 | MITM during onboarding | Learn the private key | TLS to the panel; `ssh-keyscan` fingerprint is compared with the value returned by the API over TLS before `known_hosts` is written; `StrictHostKeyChecking=yes` afterwards |
| A9 | Dump of the panel database | Replay credentials | Passwords are scrypt-hashed; session and bootstrap tokens are stored as SHA-256; only public keys are stored in plaintext |
| A10 | Operator error (deleting the wrong router) | Outage | Delete is key revocation + port release, reversible by re-creating the router (the router keeps retrying/needs a reinstall) |
| A11 | Compromised **router** (or anything that can read the traffic reaching its LuCI) | Take over the panel: every router, every console, every mutation - not just the one device | The panel cookie is **host-only by default** (`TUNNELGATE_COOKIE_DOMAIN` unset), so the browser never sends `tg_session` to `<slug>.<suffix>`; every panel-generated router vhost additionally drops the header, in both drivers (`proxy_set_header Cookie "";` / `"delete": ["Cookie"]`); the console WS re-validates the session cookie on `console.<suffix>`, a host the browser reaches only over TLS. Enabling `COOKIE_DOMAIN` collapses this control - see §6 |

### Explicitly out of scope

* A **root** attacker on the VPS. They own the tunnels, the panel and the sealed console keys.
* A **root** attacker on a router. They own that router; the console gives them nothing new, and
  their tunnel key still cannot reach other routers. What such an attacker *does* get is the
  traffic proxied to their LuCI - which is why the panel session cookie is stripped on that hop
  (A11) and host-only by default.
* Physical access, DoS, and side channels.
* Protecting LuCI's own credentials - TunnelGate is the door, LuCI is the room. Use a strong
  LuCI password and, ideally, disable LuCI's WAN listener entirely.

## 2. The two-level token model

```
operator clicks "Add router"
        │
        ▼
bootstrap token  ── 256 bits, base64url, 15 min, single use, sha256 at rest
        │           delivered inside an HTTPS script body (not a URL)
        ▼
router proves possession by exchanging it  ──►  receives:
        │                                        · an ed25519 private key, ONCE
        │                                        · its remote port
        │                                        · the server host key fingerprint
        ▼
the private key is the long-lived credential; it can only open its permitted listeners
```

Why two levels: a long-lived key cannot be safely embedded in a copy-paste command (it would be
in shell history, in the operator's clipboard history, and valid forever if leaked). A
short-lived token cannot be used to reconnect. Splitting them gives a copy-paste artefact that
is worthless 15 minutes later, and a machine credential that is never typed by a human.

## 3. `authorized_keys` - the important part

Every router gets exactly one line, rendered by `app/security.py:authorized_key_line()`:

```
no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc,command="/bin/false",permitopen="none",
permitlisten="127.0.0.1:20001",permitlisten="127.0.0.1:25001" ssh-ed25519 AAAA... tunnelgate:office-ap:1
```

### The `restrict` trap (read this before "fixing" the line)

The obvious-looking line starts with `restrict`. It does **not** work. `restrict` expands to
`no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc`, and OpenSSH
evaluates `permitlisten` **after** the blanket `no-port-forwarding` denial, so every `ssh -R`
fails with `remote port forwarding failed for listen port N`. Verified against OpenSSH 10.2 with
a throwaway sshd during development. The renderer therefore spells the restrictions out and
adds `permitopen="none"` explicitly; a unit test (`tests/test_keys.py`) asserts that
`restrict` never appears in the output.

What the key **cannot** do: run a command, allocate a pty, forward the agent, forward X11, run
`~/.ssh/rc`, open any local forward, or listen on any port except its own.

What it **can** do: open a listener on `127.0.0.1:<its tunnel port>` and
`127.0.0.1:<its console port>`, and feed connections to the router's own sshd. That is the whole
capability, and it is exactly what is needed.

### sshd side (defence in depth)

`deploy/sshd_tunnelgate.conf`:

```
Match User tunnelgate
    PasswordAuthentication no
    PubkeyAuthentication yes
    AuthenticationMethods publickey
    AllowAgentForwarding no
    AllowTcpForwarding remote      # no local forwarding at all
    PermitOpen none                # -L is refused
    GatewayPorts no                # listeners stay on loopback
    PermitTTY no
    X11Forwarding no
    PermitUserRC no
    ForceCommand /bin/false
    AllowUsers tunnelgate
```

Load it with `Include /etc/ssh/sshd_config.d/tunnelgate.conf` and validate with `sshd -t`
before reloading - a broken `Match` block locks you out.

## 4. Key material lifecycle

| Key | Generated | Stored | Rotated by | Destroyed |
|---|---|---|---|---|
| Router tunnel ed25519 | at exchange | **never** (only the public half) | rotate-key | immediately after the exchange response is serialised |
| Router console ed25519 | lazily, on first console open | private half AES-256-GCM sealed in `routers.console_key_sealed`; public half in `console_public_key` | rotate-key | re-sealed on rotation |
| Panel session | at login | SHA-256 hash + CSRF token in `panel_sessions` | logout / TTL / password change | row deleted |
| Bootstrap token | at create/rotate/script | SHA-256 only | new token invalidates the old | row kept for audit, marked used |
| VPS host key | at VPS install | `/etc/ssh/ssh_host_ed25519_key` | never (pin it) | - |

### Console key material

The console inverts the trust direction (the panel logs into the router), so the panel does hold
a private key. It is sealed with AES-256-GCM; the key is derived from `TUNNELGATE_SECRET_KEY`
(SHA-256 of the configured value) and the nonce is per-secret, so the same plaintext seals to
different ciphertext each time. In `production` the app refuses to start without
`TUNNELGATE_SECRET_KEY`; in development a throwaway key file is generated at
`<data_dir>/secret.key` (mode 0600) so a checkout works without configuration.

Losing `TUNNELGATE_SECRET_KEY` means every console key must be reissued (rotate each router, or
drop `console_key_sealed` and let the heartbeat reinstall). Losing it does **not** affect
tunnels or LuCI access.

The router's own `authorized_keys` entry for the panel is:

```
from="127.0.0.1",no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA... tunnelgate-console
```

The option set is deliberately conservative: routers run **dropbear**, which understands only
`from=`, `no-port-forwarding`, `no-agent-forwarding`, `no-X11-forwarding` and `no-pty`. An
OpenSSH-only option makes dropbear reject the whole key. `no-pty` is **absent** on purpose - an
interactive shell is the point of this key.

`from="127.0.0.1"` works because the connection reaches the router's dropbear through an SSH
reverse forward: on the router, the peer really is 127.0.0.1. See ARCHITECTURE.md §6. If a
router has multiple interfaces and you want to be stricter, add `command=` with a shell wrapper
- not done by default because it breaks `ash` job control.

## 5. Console-specific risks

| Risk | Control |
|---|---|
| Anyone with a panel login gets root on 100 routers | Role gate: only `operator`/`admin`; every session is logged with user, IP, duration and byte counts; sessions can be force-closed |
| A stolen session cookie grants root | Ticket is bound to the session *and* to the router, is single-use, and lives 30 s; the browser cannot reuse a URL from a shared chat |
| Replay of the WebSocket URL | Ticket consumption is atomic (single use), and the WS handler re-validates the cookie |
| Someone leaves a shell open forever | `console_idle_timeout_seconds` (900) and `console_max_session_seconds` (7200) enforced server-side, not by the client |
| Too many concurrent shells | `console_max_sessions_per_user` (3) + global registry |
| Keystrokes leak into logs | The WS handler logs open/close only; never payloads. `paramiko` logging is pinned to WARNING and its transport log is not enabled |
| No trace of what happened | `ConsoleSession` row + `console.open`/`console.close` audit events; `bytes_in/out` give volume evidence |
| Router-side audit gap | The console connects as a real (usually `root`) user; the router's own `logread` records the dropbear login. Rotating the console key is the way to cut off a stolen one |

**Recommended production posture:** create a dedicated `tunnelgate` user on the router with
shell `/bin/ash` and no password, then set `TUNNELGATE_CONSOLE_SSH_USER` to it on the panel (and
re-register the router, or let the heartbeat deliver the new key). That user still needs write
access to `/etc/config` and `ubus` to be useful; the installer documents the trade-off
(root = full capability, dedicated user = least privilege but limited UCI access).

The account name is deliberately **one panel-side setting**, not a per-router field: the value
that is written into the router's `authorized_keys` by the key registration is the same value the
panel dials. Two sources could disagree - the panel dialling the tunnel login's name
(`tunnelgate`, an account that only exists on the VPS) was a real bug, and every console failed
while the UI still reported "ready".

## 6. Panel authentication

* **Passwords**: scrypt `n=2^14, r=8, p=1`, 16-byte salt, self-describing format
  `scrypt$n$r$p$salt$hash`. Constant-time comparison. Minimum 8 characters.
  *Limitation*: scrypt at these parameters is not memory-hard enough to make an offline attack
  on a leaked hash expensive. If your threat model includes DB exfiltration, raise
  `SCRYPT_N` (cost: ~0.5 s per login) or switch to Argon2id.
* **Sessions**: opaque 256-bit token in an `HttpOnly`, `SameSite=Lax` cookie; the DB stores only
  its SHA-256. Server-side revocation is immediate (logout, password change, admin action).
  `Secure` is set when the request arrived over HTTPS from a trusted proxy (the normal case
  behind a TLS terminator), or unconditionally when `TUNNELGATE_COOKIE_SECURE=true`; and
  also when the request reached the panel over HTTPS from a trusted proxy
  (`X-Forwarded-Proto: https`, see §7) - so a panel published as `https://...` cannot quietly
  hand out a non-Secure session cookie because one setting was forgotten.
* **Cookie scope - do not set `TUNNELGATE_COOKIE_DOMAIN`.** Unset (the default) the cookie is
  host-only: only `panel.example.com` sends it, never `<slug>.<suffix>` and never
  `console.<suffix>`. That is load-bearing, not cosmetic. A *domain* cookie
  (`Domain=.panel.example.com`) is attached by the browser to **every** router vhost, so the
  operator's live session is delivered to every router's LuCI on every page load. One compromised
  router - a device that is by definition cheap, physically reachable and internet-facing - would
  then yield the operator's **panel session**: every router, every console, every mutation. That
  is a strictly larger blast radius than a panel RCE (§10.1), which at least has to compromise
  the hardened VPS first. Every panel-generated router vhost therefore also strips the header -
  the static template, `render_nginx()` and `render_caddy_route()` all emit it - but the strip is
  defence in depth: it is one line in a generated file, whereas the host-only default is the
  structural control. Set the option only if the SPA and API really are on different hostnames.
* **CSRF**: double submit - the session row owns a random `csrf_token`, the SPA sends it in
  `X-CSRF-Token` on every mutating request, the server compares in constant time. A cross-site
  form post cannot set a custom header.
* **Rate limiting**: sliding window, per IP and per IP+username, on `/api/auth/login`
  (`429` + `Retry-After`). Bootstrap `/install` and `/bootstrap/exchange`: 60/min per IP
  (`EXCHANGE_LIMIT`, 60-second window, one counter per endpoint); `/install` additionally
  caps at 5 renders per 15 minutes **per token** (`SCRIPT_LIMIT`), because each render echoes
  the live credential into the body and rotating source addresses must not extend that. Console
  start: 10/min per user.
* **XSS**: React escapes by default, no `dangerouslySetInnerHTML` outside a single reviewed
  helper, and the app sends `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`
  (the SPA is not embeddable). Set a CSP at the nginx layer - the shipped config does.
* **Authorization**: every endpoint declares its dependency (`CurrentUser`, `OperatorUser`,
  `AdminUser`); the router's ownership is checked by scope, and there is no cross-tenant mode by
  design (single team deployment).

## 7. Transport and host hardening

* TLS 1.2+ only, HSTS in `deploy/nginx/tunnelgate.conf`, modern cipher list.
* The panel binds to loopback behind nginx; only 80/443 are public, plus SSH.
* The tunnel listener range is **never** opened in the firewall; it is loopback-only by design
  (`GatewayPorts no` + `permitlisten="127.0.0.1:..."`).
* `systemd` unit runs unprivileged with `NoNewPrivileges`, `ProtectSystem=strict`,
  `ProtectHome`, `PrivateTmp`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, and
  `ReadWritePaths` limited to the data directory.
* Docker image: non-root user, no build tools in the runtime layer, healthcheck on
  `/api/v1/health`.

### Who is the client? (reverse-proxy trust model)

The panel decides "who did this" from the request's **peer address**, and every security control
that depends on an address hangs off that one decision: login rate limiting, bootstrap throttle
counters, `luci.open` throttling, the `ip` column of the audit log, the source address recorded
against a router, and the console ticket binding. Getting it wrong is not cosmetic - it either
lets an attacker mint unlimited rate-limit buckets, or it attributes one operator's actions to
another.

Three settings define it, and **the default is closed**:

| Setting | Default | Meaning |
|---|---|---|
| `TUNNELGATE_TRUST_PROXY_HEADERS` | `true` | Whether forwarded headers are considered at all. With `false`, the peer address is always the answer and the rest of this section does not apply |
| `TUNNELGATE_TRUSTED_PROXIES` | `["127.0.0.1", "::1"]` | The addresses (or CIDR networks) whose forwarded headers are believed. Anything not in this list is an untrusted peer |
| `TUNNELGATE_FORWARDED_ALLOW_HOPS` | `1` | How many proxies append to `X-Forwarded-For` in front of the panel |

Rules, in order:

1. **Untrusted peer → the peer address wins.** `X-Forwarded-For`, `X-Real-IP` and
   `X-Forwarded-Proto` from a peer that is not in `TUNNELGATE_TRUSTED_PROXIES` are ignored
   entirely. A client cannot talk its way into a different identity by sending headers, which is
   what stops an attacker from rotating a forged `X-Forwarded-For` to get a fresh rate-limit
   bucket per attempt.
2. **Trusted peer → walk `X-Forwarded-For` from the right.** The chain is a comma-separated list,
   and everything to the *left* of the last proxy was written by the client and is untrusted. The
   panel takes the entry `len(chain) - hops` from the right. With the default of one hop,
   `"1.2.3.4, 5.6.7.8"` resolves to **`5.6.7.8`** - the address the proxy appended - and not to
   the `1.2.3.4` the client typed.
3. **Too few entries fails closed.** If the chain holds *fewer* entries than the configured hop
   count, the panel does not walk further left to make do: it falls back to the socket peer. A
   chain that short means some of the proxies this deployment trusts did not contribute, so its
   leftmost entry is whatever the client typed - reading it would hand the identity straight back
   to the attacker this rule exists to stop. The socket peer can be wrong (it names the proxy),
   but it can never be forged. Setting the hop count too *high* therefore degrades to "everything
   is attributed to the proxy" instead of "everything is attributed to whoever asked"; setting it
   too low names the wrong proxy hop. The setting moves the answer left, never right, so lower it
   rather than raise it when in doubt.
4. **CIDR entries are accepted** (`10.0.0.0/8`), and malformed entries are ignored with a log
   line rather than silently widening or narrowing the list. IPv4 and IPv6 are matched
   separately: a `127.0.0.0/8` entry does not trust an `::1` peer, and `::ffff:127.0.0.1` is
   normalised to `127.0.0.1` so a dual-stack listener behaves the same either way.

The shipped systemd unit and Docker entrypoint both bind loopback and pass
`--proxy-headers --forwarded-allow-ips 127.0.0.1` to uvicorn, so the loopback default is correct
out of the box. **uvicorn has its own trust list** - `--forwarded-allow-ips` - which is a
separate knob from `TUNNELGATE_TRUSTED_PROXIES`, and both matter: uvicorn rewrites the ASGI
scope's `client` and `scheme` for its trusted peers, while the app resolves the client address
from the raw header for its own trusted peers. The authoritative one for every control in this
document is the app's, which is why a narrow `--forwarded-allow-ips` does not by itself break
rate limiting or the audit log. Widen both anyway: leaving one narrow means `request.client` and
the request scheme disagree with the identity the app is using, and nothing warns you when some
future code reads the wrong one.

Moving the panel behind a proxy on another host, or behind a cloud load balancer, is covered in
`docs/INSTALL_SERVER.md`, "Behind a reverse proxy or load balancer"; the failure modes of both
mistakes are listed there. Note the two syntaxes differ:
`TUNNELGATE_TRUSTED_PROXIES` is parsed as a JSON list
(`["127.0.0.1", "10.0.0.5"]`) and the comma form stops the panel from starting, while
`--forwarded-allow-ips` takes a plain comma-separated list.

`TUNNELGATE_TRUST_FORWARDED_PROTO` (default `true`) controls one thing: whether
`X-Forwarded-Proto: https` from a **trusted** peer makes the panel treat the request as HTTPS.
When it does, the session cookie gets the `Secure` flag even if `TUNNELGATE_COOKIE_SECURE` was
left at its default (`app/api/auth.py` resolves this through
`app/forwarded.py::request_scheme`). That is the safety net for the common deployment where TLS
is terminated by a proxy and the operator never touched the cookie setting - without it the
panel would happily publish a non-Secure session cookie over HTTPS, which no browser will warn
about. From an **untrusted** peer the header is ignored, so a client cannot upgrade its own
request. `TUNNELGATE_COOKIE_SECURE=true` still forces the flag unconditionally and remains the
right explicit setting for an HTTPS deployment; with `trust_forwarded_proto` off, the cookie
follows only that setting, which is what you want if uvicorn's `--proxy-headers` already
rewrites the scope scheme (uvicorn consumes the same header for the same purpose).

One consequence of a wrong trust configuration that is easy to miss: the console ticket is bound
to the client address it was minted from (`app/api/console_ws.py` resolves it through the same
`app.forwarded.client_ip`), so that path inherits whatever identity the trust list resolves. It
is consistent by construction - one function, both call sites - which is why the setting can be
wrong without breaking the console, and why a trusting-too-much mistake widens the ticket
binding's "same client" test along with everything else.

## 8. Audit

Every mutation and every access to a router UI or shell is recorded:

| Event | Written when |
|---|---|
| `auth.login` / `auth.login_failed` / `auth.logout` / `auth.password` | login attempts and session lifecycle |
| `router.create` / `update` / `delete` / `rotate` / `script` | inventory changes |
| `router.exchange` | a router consumed its bootstrap token (includes the IP) |
| `luci.open` | an authenticated user hit a router vhost (throttled to 1/min/user/router) |
| `console.start` / `console.open` / `console.close` | shell lifecycle |
| `user.*` | user administration |
| `settings.agent_endpoint.save` / `.reset` / `.test` | the agent endpoint was changed, dropped, or probed from the panel |

The audit table is append-only in the application (there is no update or delete path) and each
row carries actor, role-derived username, router, IP and optional detail. Recommended retention:
ship to a log store you cannot rewrite (`journald` + off-host forwarding); the shipped
`systemd` unit keeps stdout in the journal.

## 9. Operational security checklist

- [ ] `TUNNELGATE_SECRET_KEY` set, backed up somewhere safe, **not** in the repo
- [ ] `TUNNELGATE_COOKIE_SECURE=true` and the panel served over HTTPS only
- [ ] `TUNNELGATE_COOKIE_DOMAIN` is **unset** (host-only cookie); if it is set, the §6 blast-radius
      trade-off has been accepted in writing
- [ ] Admin password is not the one from the docs; rotate after install
- [ ] `sshd -t` passes after installing the drop-in; a second root shell stays open while testing
- [ ] Firewall exposes only 22/tcp (or your SSH port) and 80/443
- [ ] `TUNNELGATE_TRUSTED_PROXIES` names **only** your proxy, and
      `--forwarded-allow-ips` names the same set; if there is no proxy in front, leave both at
      `127.0.0.1` and confirm that a request with a forged `X-Forwarded-For` from another host
      still audits the real peer address
- [ ] Port ranges 20000-30000 bound to loopback only (verify with `ss -ltn`)
- [ ] Wildcard DNS `*.<domain>` points at the VPS; the certificate covers it
- [ ] Backups include the SQLite file **and** `authorized_keys` (they must stay consistent)
- [ ] Rotate every router key at least once after the initial rollout to prove the flow
- [ ] Check `/api/v1/audit` for unexpected `router.exchange` rows
- [ ] Remove the demo data (`app.cli seed-demo`) if it was ever loaded

## 10. Known limitations (security-relevant)

1. **A panel RCE can decrypt console keys** - they must be unsealed to be used. Tunnel keys are
   not affected (never stored).
2. **scrypt parameters** are tuned for a login form, not for offline resistance (§6).
3. **No MFA.** The design supports adding TOTP in front of `POST /api/auth/login`; not
   implemented, tracked in README's Known limitations.
4. **No per-router ACL.** Any `operator` can reach any router. Groups are labels, not
   authorisation boundaries.
5. **The console runs as the installer's chosen user** (root unless a dedicated user could be
   created), so LuCI's own user accounts are bypassed - the panel becomes the router's root
   credential holder. This is inherent to "give me a shell".
6. **Audit is application-level.** A VPS root attacker can edit the DB. Forward the journal.
7. **`luci.open` audit is throttled** - bursty access shows one row per minute per user/router,
   not every request.
8. **The cookie strip only covers panel-generated vhosts.** Both drivers strip it now -
   `render_nginx()` emits `proxy_set_header Cookie "";` and `render_caddy_route()` emits
   `"delete": ["Cookie"]` - so a `PROXY_DRIVER=caddy` deployment is no longer weaker than nginx
   on this point. What remains true: a hand-written vhost, a second proxy added in front of the
   routers, or anything that bypasses the renderer inherits no strip. The host-only default (§6)
   is the control that survives all of that; the strip is a second layer. Do not enable
   `TUNNELGATE_COOKIE_DOMAIN` and rely on the strip.
