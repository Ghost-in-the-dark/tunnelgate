# Installing the TunnelGate server

Target: a fresh Debian 12/13 or Ubuntu 22.04/24.04 VPS with a public IPv4 address and a domain
you control. Everything below is copy-pasteable and idempotent unless marked otherwise.
Commands are run as `root` (via `sudo -i`).

Examples use:

| Variable | Example value |
|---|---|
| `PANEL_DOMAIN` | `panel.example.com` |
| `TUNNELGATE_HOSTNAME` | `panel.example.com` (this is also `TUNNELGATE_PANEL_HOST`) |
| `VPS_IP` | `203.0.113.10` |

The router vhosts are `<slug>.<host_suffix>`, so with the values above a router named
"Office AP" is served at `https://office-ap.panel.example.com`.

---

## 0. Decide the DNS layout first

Two options; pick one before requesting certificates.

### Option A - wildcard (recommended)

```
panel.example.com          A     203.0.113.10
*.panel.example.com        A     203.0.113.10
```

A wildcard DNS record is enough for **any** router, including ones created later, with no DNS
step during onboarding. The certificate must be issued with the **DNS-01** challenge, because
Let's Encrypt will not issue `*.panel.example.com` over HTTP-01. That means a DNS plugin for
your provider (`certbot-dns-cloudflare`, `-route53`, `-digitalocean`, ...).

### Option B - per-router HTTP-01

One `A` record per router, added when the router is created, and a certificate per vhost. More
moving parts (creating a router has a DNS step and a certbot step), no wildcard, no DNS plugin.
Only sensible for a handful of routers.

The rest of this document assumes **Option A**.

> If you cannot use DNS-01, use Option B, or put Cloudflare in front and use its origin
> certificate; either way the panel's nginx config does not change.

---

## 1. Base system

```bash
apt-get update
apt-get upgrade -y
apt-get install -y --no-install-recommends \
    ca-certificates curl git nginx python3 python3-venv python3-pip \
    sqlite3 certbot openssh-server rsync ufw jq
```

Check the clock - TLS and token expiry depend on it:

```bash
timedatectl set-ntp true
timedatectl status | grep -E 'System clock synchronized|NTP service'
```

---

## 2. Firewall

Only SSH, HTTP and HTTPS are public. The tunnel port range (20000-25000) and the console range
(25001-30000) are **never** opened - the listeners are created on `127.0.0.1` by sshd and are
not reachable from outside by design.

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp        # or your SSH port
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
ufw status verbose
```

> **Before enabling ufw**: make sure your SSH port is allowed *and* that you have a second
> session open. `ufw --force enable` on a box where 22 is blocked locks you out.

---

## 3. The tunnel user

Routers log in as an unprivileged system user that exists only to hold port forwards.

```bash
useradd --system --create-home --home-dir /var/lib/tunnelgate \
        --shell /usr/sbin/nologin --comment "TunnelGate reverse tunnels" tunnelgate
install -d -m 0755 -o tunnelgate -g tunnelgate /var/lib/tunnelgate/.ssh
install -m 0600 -o tunnelgate -g tunnelgate /dev/null /var/lib/tunnelgate/.ssh/authorized_keys
```

The panel writes `authorized_keys` for this user. Point TunnelGate at it:

```bash
TUNNELGATE_AUTHORIZED_KEYS_PATH=/var/lib/tunnelgate/.ssh/authorized_keys
TUNNELGATE_SSH_USER=tunnelgate
TUNNELGATE_SSH_HOST=127.0.0.1
```

Keep `ssh_host` at `127.0.0.1` unless you split the panel and sshd onto different hosts: routers
connect to whatever value you put here, and the DNS record for `panel.example.com` already points
at this machine.

---

## 4. sshd for the tunnel user

The restrictions that make the tunnel key harmless live in sshd, not only in
`authorized_keys`; see `docs/SECURITY.md` §3 for why.

```bash
install -m 0644 deploy/sshd/tunnelgate.conf /etc/ssh/sshd_config.d/tunnelgate.conf
```

The file is:

```
Match User tunnelgate
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    AuthenticationMethods publickey
    AllowAgentForwarding no
    AllowTcpForwarding remote
    PermitOpen none
    GatewayPorts no
    PermitTTY no
    X11Forwarding no
    PermitUserRC no
    ForceCommand /bin/false
    ClientAliveInterval 30
    ClientAliveCountMax 3
```

`AllowTcpForwarding remote` is what lets `ssh -R` work while `-L` stays impossible.
`GatewayPorts no` keeps every listener on loopback even if a key asked otherwise.

**Validate before reloading.** A syntax error in a `Match` block can lock you out:

```bash
sshd -t && systemctl reload ssh
```

Keep your current session open until a *new* one succeeds:

```bash
ssh -o PreferredAuthentications=password root@203.0.113.10
```

If you changed the port or file and cannot log in, use the provider's console to run
`sshd -t` - the error message names the line.

---

## 5. Panel installation

```bash
git clone https://github.com/your-org/tunnelgate.git /opt/tunnelgate
cd /opt/tunnelgate
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
```

### Frontend build (only if `web/dist` is absent)

The repository ships a prebuilt SPA in `web/dist`. To rebuild it:

```bash
cd /opt/tunnelgate/web
npm ci
npm run build          # writes web/dist
```

### Environment file

```bash
install -m 0600 /dev/null /etc/tunnelgate.env
cat >/etc/tunnelgate.env <<'EOF'
TUNNELGATE_ENV=production
TUNNELGATE_LOG_LEVEL=info

# --- panel ---
TUNNELGATE_PANEL_URL=https://panel.example.com
TUNNELGATE_PANEL_HOST=panel.example.com
TUNNELGATE_SUBDOMAIN_SUFFIX=panel.example.com
TUNNELGATE_COOKIE_SECURE=true
TUNNELGATE_COOKIE_DOMAIN=.panel.example.com

# --- storage ---
TUNNELGATE_DB_URL=sqlite:////var/lib/tunnelgate/tunnelgate.db
TUNNELGATE_DATA_DIR=/var/lib/tunnelgate

# --- ssh ---
TUNNELGATE_SSH_HOST=127.0.0.1
TUNNELGATE_SSH_USER=tunnelgate
TUNNELGATE_AUTHORIZED_KEYS_PATH=/var/lib/tunnelgate/.ssh/authorized_keys
TUNNELGATE_SSHD_RELOAD_COMMAND=

# --- ports ---
TUNNELGATE_PORT_MIN=20000
TUNNELGATE_PORT_MAX=25000
TUNNELGATE_CONSOLE_PORT_MIN=25001
TUNNELGATE_CONSOLE_PORT_MAX=30000

# --- proxy ---
TUNNELGATE_PROXY_DRIVER=nginx
TUNNELGATE_PROXY_ROUTES_PATH=/etc/nginx/tunnelgate/routes.conf
TUNNELGATE_PROXY_RELOAD_COMMAND="nginx -t && nginx -s reload"

# --- secrets (generate: openssl rand -base64 48) ---
TUNNELGATE_SECRET_KEY=CHANGE-ME
TUNNELGATE_ADMIN_PASSWORD=CHANGE-ME
EOF
```

Generate the two secrets rather than inventing them:

```bash
openssl rand -base64 48     # -> TUNNELGATE_SECRET_KEY
openssl rand -base64 24     # -> TUNNELGATE_ADMIN_PASSWORD
```

`TUNNELGATE_SECRET_KEY` encrypts the console private keys. In `production` the app refuses to
start without it, and **losing it invalidates every console key** (tunnels and LuCI keep working).

### Initialise the database

```bash
cd /opt/tunnelgate
set -a; . /etc/tunnelgate.env; set +a
install -d -o tunnelgate -g tunnelgate /var/lib/tunnelgate
.venv/bin/python -m app.cli init-db
.venv/bin/python -m app.cli seed-admin --password "$TUNNELGATE_ADMIN_PASSWORD"
.venv/bin/python -m app.cli doctor
```

`doctor` checks: data dir writable, DB reachable, `authorized_keys` path, sshd reachability,
free ports in both pools, nginx present, route file path writable, secret key set. It exits
non-zero on a blocking problem and prints what to fix.

### systemd

```bash
install -m 0644 deploy/systemd/tunnelgate.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tunnelgate
systemctl status tunnelgate --no-pager
curl -fsS http://127.0.0.1:8080/api/v1/health
```

The unit runs as `tunnelgate`, binds `127.0.0.1:8080`, and needs write access to the data
directory, the routes file and `authorized_keys`. It restarts on failure with a 2 s backoff.

---

## 6. nginx and TLS

### Route include directory

The panel regenerates `routes.conf` on every router change and reloads nginx. Prepare the
directory and include it once:

```bash
install -d -m 0755 /etc/nginx/tunnelgate
install -m 0644 deploy/nginx/tunnelgate.conf /etc/nginx/sites-available/tunnelgate.conf
ln -sf /etc/nginx/sites-available/tunnelgate.conf /etc/nginx/sites-enabled/tunnelgate.conf
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
```

The shipped `tunnelgate.conf` defines:

* `server_name panel.example.com` - the SPA + API, with a CSP, HSTS, gzip and long cache for
  hashed assets;
* `server_name console.panel.example.com` - the console WebSocket vhost (a WebSocket cannot go
  through `auth_request` per router, so it lives on its own hostname and the router id comes from
  the ticket);
* an `include /etc/nginx/tunnelgate/routes.conf;` for the per-router vhosts.

### Certificates

With Cloudflare (or any supported DNS provider):

```bash
apt-get install -y python3-certbot-dns-cloudflare
install -m 0700 -d /etc/letsencrypt/dns
cat >/etc/letsencrypt/dns/cloudflare.ini <<'EOF'
dns_cloudflare_api_token = YOUR_TOKEN_SCOPED_TO_ZONE_DNS_EDIT
EOF
chmod 0600 /etc/letsencrypt/dns/cloudflare.ini

certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/dns/cloudflare.ini \
  -d 'panel.example.com' -d '*.panel.example.com' \
  --agree-tos -m you@example.com --non-interactive
```

Certificate paths the shipped config expects:

```
/etc/letsencrypt/live/panel.example.com/fullchain.pem
/etc/letsencrypt/live/panel.example.com/privkey.pem
```

Auto-renewal is a systemd timer from the `certbot` package. Add a deploy hook so nginx picks up
the new certificate:

```bash
cat >/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<'EOF'
#!/bin/sh
nginx -t && nginx -s reload
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
certbot renew --dry-run
```

> The wildcard `*.panel.example.com` also matches `console.panel.example.com`, so one
> certificate covers the panel, the console and every router vhost.

---

## 7. Verify the install

```bash
# panel API
curl -fsS https://panel.example.com/api/v1/health | jq

# login works and sets a cookie
curl -isS -X POST https://panel.example.com/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}' | head -20

# wildcard DNS resolves
dig +short test.panel.example.com

# nginx config is consistent
nginx -t
```

Then, in the browser:

1. `https://panel.example.com` → log in.
2. Create a router ("Office AP").
3. Copy the install command, run it on the router (`docs/INSTALL_ROUTER.md`).
4. Watch the wizard reach **Done**.
5. Click **Open LuCI** - you should land in LuCI at `https://office-ap.panel.example.com`.
6. Open the console and run `uci show system`.

If LuCI opens but the console times out, the router has not picked up the console key yet: the
heartbeat delivers it, so wait one heartbeat interval (60 s) or restart the tunnel service.

---

## 8. Upgrades

```bash
cd /opt/tunnelgate
git fetch --tags && git checkout v1.1.0
.venv/bin/pip install -r requirements.txt
(cd web && npm ci && npm run build)   # only if web/dist is not shipped
.venv/bin/python -m app.cli check-schema
systemctl restart tunnelgate
```

`check-schema` compares the SQLAlchemy models with the live SQLite schema and prints the missing
columns. TunnelGate has no migration engine by design (single-file SQLite, additive-only changes);
apply the printed `ALTER TABLE` statements manually, in a transaction, with a backup first:

```bash
sqlite3 /var/lib/tunnelgate/tunnelgate.db ".backup '/var/backups/tunnelgate-$(date +%F).db'"
```

A restart never disturbs live tunnels: the forwards are owned by sshd, not by the panel, so
LuCI keeps working while the panel is down and routers reconnect on their own. Only the
*status* view goes stale (it is reconciled on startup).

---

## 9. PostgreSQL instead of SQLite

SQLite is the default and is fine to a few hundred routers. For PostgreSQL:

```bash
apt-get install -y postgresql
su - postgres -c "psql -c \"CREATE USER tunnelgate WITH PASSWORD '...';\""
su - postgres -c "psql -c 'CREATE DATABASE tunnelgate OWNER tunnelgate;'"
.venv/bin/pip install 'psycopg[binary]'
```

```bash
TUNNELGATE_DB_URL=postgresql+psycopg://tunnelgate:...@127.0.0.1:5432/tunnelgate
```

Run `app.cli init-db` once. Nothing else changes - the application code is dialect-agnostic.

---

## 10. Backups

Two things must be backed up **together**, or a restore will leave routers unable to reconnect:

```bash
# DB (consistent snapshot even while running)
sqlite3 /var/lib/tunnelgate/tunnelgate.db ".backup /var/backups/tg.db"

# the keys that DB rows correspond to
cp /var/lib/tunnelgate/.ssh/authorized_keys /var/backups/tg.authorized_keys
```

`TUNNELGATE_SECRET_KEY` must be backed up **separately** (a password manager or a sealed
envelope). It is not in the DB and not in the authorized_keys file; without it console keys
cannot be decrypted.

Restore order: DB → `authorized_keys` → restart the panel → `app.cli doctor`. Routers that were
online reconnect within one retry interval.

---

## Appendix - all environment variables

See `app/config.py`; every field there is settable with `TUNNELGATE_<UPPER_NAME>`. The values you
are most likely to touch:

| Variable | Default | Meaning |
|---|---|---|
| `TUNNELGATE_PANEL_URL` | `http://127.0.0.1:8080` | Public base URL, used in install commands and links |
| `TUNNELGATE_PANEL_HOST` | `panel.example.com` | nginx `server_name` for the panel |
| `TUNNELGATE_SUBDOMAIN_SUFFIX` | =`panel_host` | Suffix for router vhosts |
| `TUNNELGATE_COOKIE_SECURE` | `false` | Set `true` behind HTTPS |
| `TUNNELGATE_DB_URL` | `sqlite:///./data/tunnelgate.db` | SQLAlchemy URL |
| `TUNNELGATE_SSH_USER` | `tunnelgate` | The system user holding forwards |
| `TUNNELGATE_AUTHORIZED_KEYS_PATH` | `./data/authorized_keys` | Where router keys are rendered |
| `TUNNELGATE_PORT_MIN/MAX` | 20000/25000 | LuCI tunnel port pool |
| `TUNNELGATE_CONSOLE_PORT_MIN/MAX` | 25001/30000 | Console port pool |
| `TUNNELGATE_PROXY_DRIVER` | `nginx` | `nginx` \| `caddy` \| `none` |
| `TUNNELGATE_PROXY_ROUTES_PATH` | `./data/tunnelgate.routes.conf` | Generated vhost include |
| `TUNNELGATE_PROXY_RELOAD_COMMAND` | `nginx -s reload` | Shell command after a route change |
| `TUNNELGATE_SECRET_KEY` | unset | **Required** in production |
| `TUNNELGATE_ADMIN_PASSWORD` | unset | Seeds the admin user on first start |
| `TUNNELGATE_SESSION_TTL_MINUTES` | 720 | Panel session lifetime |
| `TUNNELGATE_LOGIN_RATE_LIMIT` | 10 | Login attempts per window |
| `TUNNELGATE_CONSOLE_ENABLED` | `true` | Master switch for the web console |
| `TUNNELGATE_CONSOLE_IDLE_TIMEOUT_SECONDS` | 900 | Idle shell timeout |
| `TUNNELGATE_CONSOLE_MAX_SESSION_SECONDS` | 7200 | Hard shell duration cap |
