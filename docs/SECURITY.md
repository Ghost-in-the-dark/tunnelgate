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

### Explicitly out of scope

* A **root** attacker on the VPS. They own the tunnels, the panel and the sealed console keys.
* A **root** attacker on a router. They own that router; the console gives them nothing new, and
  their tunnel key still cannot reach other routers.
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
shell `/bin/ash` and no password, and set `console.ssh_user` to it. That user still needs
write access to `/etc/config` and `ubus` to be useful; the installer documents the trade-off
(root = full capability, dedicated user = least privilege but limited UCI access).

## 6. Panel authentication

* **Passwords**: scrypt `n=2^14, r=8, p=1`, 16-byte salt, self-describing format
  `scrypt$n$r$p$salt$hash`. Constant-time comparison. Minimum 8 characters.
  *Limitation*: scrypt at these parameters is not memory-hard enough to make an offline attack
  on a leaked hash expensive. If your threat model includes DB exfiltration, raise
  `SCRYPT_N` (cost: ~0.5 s per login) or switch to Argon2id.
* **Sessions**: opaque 256-bit token in an `HttpOnly`, `SameSite=Lax` cookie; the DB stores only
  its SHA-256. Server-side revocation is immediate (logout, password change, admin action).
  `Secure` is set when `TUNNELGATE_COOKIE_SECURE=true` (default in Docker/systemd installs).
* **CSRF**: double submit - the session row owns a random `csrf_token`, the SPA sends it in
  `X-CSRF-Token` on every mutating request, the server compares in constant time. A cross-site
  form post cannot set a custom header.
* **Rate limiting**: sliding window, per IP and per IP+username, on `/api/auth/login`
  (`429` + `Retry-After`). Exchange endpoint: 30/min per IP. Console start: 10/min per user.
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

The audit table is append-only in the application (there is no update or delete path) and each
row carries actor, role-derived username, router, IP and optional detail. Recommended retention:
ship to a log store you cannot rewrite (`journald` + off-host forwarding); the shipped
`systemd` unit keeps stdout in the journal.

## 9. Operational security checklist

- [ ] `TUNNELGATE_SECRET_KEY` set, backed up somewhere safe, **not** in the repo
- [ ] `TUNNELGATE_COOKIE_SECURE=true` and the panel served over HTTPS only
- [ ] Admin password is not the one from the docs; rotate after install
- [ ] `sshd -t` passes after installing the drop-in; a second root shell stays open while testing
- [ ] Firewall exposes only 22/tcp (or your SSH port) and 80/443
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
