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

## Quick install (TLS terminated by your own proxy)

If you already run a reverse proxy - nginx, Caddy, Traefik, a cloud load balancer - and this
host needs **no certificate, no DNS record and no ACME client**, there is a one-command install
for exactly that shape:

```bash
curl -fsSL https://raw.githubusercontent.com/Ghost-in-the-dark/tunnelgate/main/scripts/quick-install.sh \
  | sudo sh -s -- --host gate.example.com
```

That is the whole install: the script downloads the sources it needs into a temporary
directory, installs the panel and removes that directory afterwards. Using the tag instead of
`main` pins a version:

```bash
curl -fsSL https://raw.githubusercontent.com/Ghost-in-the-dark/tunnelgate/v1.0.0/scripts/quick-install.sh \
  | sudo sh -s -- --host gate.example.com --ref v1.0.0
```

Piping a shell script to `sh` is only reasonable when you can read it first, so the script
carries its own documentation and every step it takes is printed as it runs. Read it with
`curl -fsSL <url> | less` before you run it, or run it from a checkout if you prefer (see below)
- both paths install the same thing.

It installs `deploy/nginx/tunnelgate-behind-proxy.conf`: plain HTTP on one port, **path routing
in the merged layout**, so every router is `<your-public-url>/<slug>/` on the panel's own name.
That is what makes a single ordinary name - including a free dynamic-DNS one - enough: no
wildcard DNS, no wildcard certificate, no per-router DNS step. It stops after nginx answers on
that port and prints the forwarding snippet your proxy has to replicate.

Before it touches anything it asks **which account the panel service should run as**. Press
Enter for the recommended answer, a dedicated `tunnelgate` system account. (It also asks the
public hostname unless `--host` supplied it.)

```
Which account should the PANEL SERVICE run as?
  1) a dedicated "tunnelgate" system account   [recommended]
  2) root                                      [NOT recommended]
Choice [1]:
```

Running the panel as `root` is supported because some operators want it, and it is not
recommended: the panel holds every router's key and your operator database, and the shipped
systemd unit's sandbox (`ProtectSystem=strict`, an empty `CapabilityBoundingSet`,
`SystemCallFilter=@system-service`, `NoNewPrivileges`) exists to contain exactly that. In root
mode the installer removes those directives from the installed unit and leaves a comment saying
so, because an empty `CapabilityBoundingSet` on root strips even root's capabilities and turns
writes into `EPERM` while the UID still says `root`. Switching back later needs
`chown -R tunnelgate:tunnelgate /var/lib/tunnelgate`.

Either way, the account the **routers** log in as is the unprivileged `tunnelgate` account:
a leaked router key stays confined whatever the panel runs as.

From a checkout, with the same flags:

```bash
git clone https://github.com/Ghost-in-the-dark/tunnelgate.git /opt/tunnelgate-src
cd /opt/tunnelgate-src
sudo ./scripts/quick-install.sh --host gate.example.com
```

Nothing is asked when the output is not a terminal (`| tee install.log`, a cloud-init run):
the hostname then has to come from `--host` and the account defaults to `user`.
`--non-interactive` says that out loud, so a run that would have prompted fails instead of
picking silently.

```bash
... | sudo sh -s -- --host 192.168.1.10 --public-scheme http   # IP / LAN
... | sudo sh -s -- --host gate.example.com --proxy-hops 2     # proxy in front of a proxy
... | sudo sh -s -- --host gate.example.com --run-as root      # panel as root, not recommended
... | sudo sh -s -- --host gate.example.com --dry-run          # print, change nothing
```

`--proxy-hops` is how many proxies append `X-Forwarded-For`; set it and
`TUNNELGATE_TRUSTED_PROXIES` to the addresses the panel actually sees (see
[Behind a reverse proxy](#behind-a-reverse-proxy-or-load-balancer)).

The merged layout costs origin isolation - a router page shares the panel's origin and can use
the operator's session. That is a documented, deliberate trade, not a side effect: read
[docs/SECURITY.md §6.1](SECURITY.md) before adding routers you do not physically control. If
you can spare a second name, prefer the separate layout and the manual walkthrough below.

What the script deliberately does **not** do: certificates, DNS, ACME, your edge proxy's config,
or opening the router ports. Section by section it mirrors steps 1-9 below, and `--help` lists
every flag.

### After the quick install

1. Point your proxy at `http://<this host>:<port>` (default port 80), forwarding `Host`,
   `X-Real-IP`, `X-Forwarded-For` and `X-Forwarded-Proto`. The summary block the script prints
   has the exact `proxy_set_header` lines.
2. Log in as `admin`; the generated password is in `TUNNELGATE_ADMIN_PASSWORD` in the
   environment file (mode 0600).
3. Create one router and open it end to end before adding the rest.

### Traps this script exists to get right

| Trap | What happens without the fix |
|---|---|
| the tunnel account's password field starts as `!` | `ssh` refuses the router key with "account is locked", indistinguishable from a bad key |
| `authorized_keys` under `/tmp` or another world-writable dir | sshd refuses it outright ("bad ownership or modes") even with `StrictModes no` |
| `authorized_keys` (or `.ssh`) owned by `root` because the panel runs as root | sshd opens the file AS `tunnelgate`, so a root-only file gives "Could not open user ... authorized keys: Permission denied" and every router gets "Permission denied (publickey)" - the installer leaves `.ssh` and the file with the tunnel account in both `--run-as` modes, and the panel preserves that owner when it rewrites |
| an empty router fleet renders a `routes.conf` that references `$tg_router` | `nginx -t` fails with `unknown "tg_router" variable` and nothing reloads |
| `TUNNELGATE_TRUSTED_PROXIES=[...]` unquoted in the env file | systemd strips the inner quotes, pydantic-settings fails to parse it, the panel never starts |
| `TUNNELGATE_PROXY_RELOAD_COMMAND` set | the unit runs `NoNewPrivileges=yes`, so the panel cannot reload nginx; the shipped `.path`/`.service` pair does it as root instead |
| `sshd -t` passes but the reload loses the listener | new logins are refused while the install reports success - the script checks `:22` after every reload and escalates to a restart only if it is gone |
| `app.cli doctor` run as `tunnelgate` | a false FAIL on the routes include (it cannot read the private key or the pid file) - run it as `root` |
| a `web/dist` that was never built | the API works and every page 404s - the script builds it and warns when it cannot |
| `systemctl restart` returning while the panel is still failing | the unit is "active" for a moment even when the panel cannot bind, so an install looking only at the unit exits 0 into a panel that never serves - the script polls `/api/v1/health` and stops with the journal when it does not answer |
| the panel run as `root` with the shipped unit | an empty `CapabilityBoundingSet` strips even root's capabilities, so writes fail with `EPERM` while the UID says `root`; `ProtectHome=yes` also hides `/root` - the installer removes those directives in `--run-as root` mode and records it in the unit |
| a plain-HTTP origin with the default settings | every router link and install command says `https://`, and no router can complete the handshake - the script writes `TUNNELGATE_PUBLIC_URL` with the scheme you asked for, which sets the scheme of router URLs and is also the agent address routers dial when `PANEL_URL` is loopback |

If demo routers are present in the database from a trial run, drop them before going live:

```bash
cd /opt/tunnelgate && .venv/bin/python -m app.cli seed-demo --purge
```

The rest of this document is the manual walkthrough. It is what the script automates, and the
reference when you need to do one step by hand.

---

## 0. Decide the DNS layout first

Three options; pick one before requesting certificates.

### Option A - wildcard (recommended for subdomain mode)

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

### Option C - no wildcard at all: path routing

Keep one name in DNS for the whole router fleet - the gateway - and publish every router under a
path on it:

```
gate.example.com           A     203.0.113.10          # every router lives here
panel.example.com          A     203.0.113.10          # the panel itself (separate layout)
# merged layout instead: no second record - point TUNNELGATE_PANEL_HOST at gate.example.com
```

```bash
TUNNELGATE_ROUTE_MODE=path
TUNNELGATE_GATEWAY_HOST=gate.example.com
TUNNELGATE_PROXY_DRIVER=nginx
```

A router is then `https://gate.example.com/lab-router/`. No wildcard DNS record, no wildcard
certificate, no DNS step when a router is added - the gateway's certificate covers all of them.
This is the option to pick when the domain is a free dynamic-DNS name (a wildcard record is
usually not available there) or when you have no DNS control at all.

Path mode has **two layouts**, and the panel picks one by comparing `TUNNELGATE_GATEWAY_HOST`
with `TUNNELGATE_PANEL_HOST`. There is no separate flag.

| | separate (recommended) | merged |
|---|---|---|
| `TUNNELGATE_GATEWAY_HOST` | `gate.example.com`, different from the panel | the **same** value as `TUNNELGATE_PANEL_HOST` |
| `routes.conf` holds | one full `server` block for the gateway, plus `map $http_upgrade $tg_connection_upgrade` | only `location`s |
| Included in | nginx **http** context (as always) | the **panel `server` block** |
| Origin shared with the panel | no | **yes** - see docs/SECURITY.md §6.1 |

**Separate** is the default when the two names differ and the one to prefer: a router page is a
different origin, so a compromised router cannot act inside the panel. **Merged** is for the case
where one public name is all you have - a free dynamic-DNS name with no wildcard, a single
certificate, or a panel on a bare IP. It costs origin isolation: whatever a router serves runs in
the panel's origin and can use the operator's session, including reading the CSRF token. Read
docs/SECURITY.md §6.1 before choosing it.

In the merged layout the include moves into the panel vhost:

```nginx
server {
    server_name gate.example.com;
    ...
    include /etc/nginx/tunnelgate/routes.conf;
    location / {
        proxy_pass http://127.0.0.1:8080;
        ...
    }
}
```

The panel vhost must also declare the upgrade map itself - the shipped `tunnelgate.conf`
already does for its own WebSocket blocks - because the merged file's router locations reference
`$connection_upgrade` and a `map` is illegal inside a `server` block:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

This is the one placement error nginx will not let slide. Include the merged file in the http
context and `nginx -t` stops with `"location" directive is not allowed here in
.../routes.conf:1`; include the separate-layout file inside a server block and it stops with
`"server" directive is not allowed here`. Both are caught before nginx reloads, which is the good
half of the story - the bad half is that the error names `routes.conf`, not the vhost that
included it. `app.cli doctor` runs `nginx -t` under `routes include` and, on failure, tells you
which context the layout in effect wants; it warns under `gateway host` for the merged layout
itself.

In practice merged mode means editing the shipped `deploy/nginx/tunnelgate.conf`: it places the
routes include in the http context (just after the upgrade map) for subdomain and separate mode,
so move that one line into the panel `server` block and keep the http-context copy out. Nothing
else in the file changes - the console vhost, the port-80 redirect and the CSP stay as they are.

Merged mode also puts the router prefixes into the panel's own path namespace, and that is a
real constraint, not a typo warning. A router slug becomes `location = /<slug>` plus
`location /<slug>/`, both more specific than the panel's `location /`, so the slug wins on that
host. Two consequences:

* **nginx refuses the file outright** when the slug duplicates a location the panel vhost already
  declares. `api` and `assets` do: the panel vhost has `location /api/` and `location /assets/`,
  and merging a router called `api` fails with `duplicate location "/api/"`, which takes the whole
  config down (doctor's `routes include` check reports it);
* **the panel page is shadowed** when the slug matches an SPA route instead - nothing in nginx
  declares `/login`, `/hosts`, `/settings`, `/audit` or `/routers`, so the config parses and the
  page simply becomes the router's prefix: `/hosts` answers `308 /hosts/`, the gate refuses, and
  the operator lands on `/login?router=hosts&next=/hosts/`, which signs them in and hands off to
  the *router* - so that panel page is unreachable, not merely broken. A router called `login`
  is the pathological case: the bounce target is the shadowed path itself, so `/login` ->
  `308 /login/` -> `401` -> `302 /login?router=login&...` -> `308` ... never resolves, and there
  is no way into the panel at all. Renaming the router is the only fix.

Neither the panel nor `app.cli doctor` reserves these names today, so rename before switching an
existing fleet over: `api`, `assets`, `login`, `hosts`, `settings`, `audit` and `routers` are
the ones that bite. The separate layout has none of this - the gateway host carries no panel
locations to collide with.

Requirements and trade-offs:

- the gateway host must be a real DNS name; a bare IP cannot get a certificate, so
  `app.cli doctor` fails an IP here, and fails an empty or dotless host too;
- if the gateway is the panel's own host, that is the merged layout described above: doctor
  warns (same-origin, docs/SECURITY.md §6.1) but the setup is supported. If the names differ you
  get the separate layout and the nginx include stays in the http context;
- only the **nginx** driver implements it - caddy refuses to start in this mode;
- the nginx build needs `--with-http_sub_module` (the distro `nginx` package has it; a minimal
  build may not). Doctor reports it as `sub_filter module`; without it LuCI pages load with
  unprefixed CSS and dead links;
- LuCI is rewritten (absolute links, redirects, cookie `Path`) because it assumes it owns a
  host; see docs/ARCHITECTURE.md §5.1. Subdomain mode has no such rewriting and stays the
  default.

The rest of this document assumes **Option A**.

> If you cannot use DNS-01, use Option B or C, or put Cloudflare in front and use its origin
> certificate; either way the panel's nginx config does not change much.

---

## 1. Base system

```bash
apt-get update
apt-get upgrade -y
apt-get install -y --no-install-recommends \
    ca-certificates curl git nginx python3 python3-venv python3-pip \
    sqlite3 certbot openssh-server rsync ufw jq iproute2
```

`iproute2` is not optional: the panel runs `ss -Hltnp` to find out which tunnels are
actually listening, and it refuses to guess. Without `ss` every router stays at
`awaiting`/`offline` no matter how healthy it is, while `/api/v1/health` still answers
`ok` - `app.cli doctor` fails on this under `socket inventory` and the monitor logs it
once at startup. It is in Debian's default install, but a minimal image or a stripped
cloud image may not have it.

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
# REQUIRED: unlock the password field (see "The account must not be locked" below).
usermod -p '*' tunnelgate
install -d -m 0755 -o tunnelgate -g tunnelgate /var/lib/tunnelgate/.ssh
install -m 0600 -o tunnelgate -g tunnelgate /dev/null /var/lib/tunnelgate/.ssh/authorized_keys
```

### The account must not be locked

`useradd` writes `!` into `/etc/shadow` for a new account, which sshd treats as *locked* and
refuses **even for public-key authentication**:

```
User tunnelgate not allowed because account is locked
```

The router only ever sees `Permission denied (publickey)`, so this is easy to misdiagnose as a
key problem. Set the password field to `*` ("no password", not "locked"):

```bash
usermod -p '*' tunnelgate     # or: passwd -d tunnelgate
getent shadow tunnelgate | cut -d: -f2   # must print * (or empty), never !
```

`passwd -l` and `usermod -L` have the opposite effect - do not use them here.

### `authorized_keys` must not live somewhere world-writable

sshd refuses an `authorized_keys` file when any directory on its path is writable by a non-owner:
`/tmp`, `/var/tmp`, `/run`, or a home directory with mode `0777`. `StrictModes no` relaxes the
checks on the *file*, not on its parent directories, so this bites even in throwaway setups:

```
Could not open user 'tunnelgate' authorized keys /tmp/.../authorized_keys: Permission denied
```

This is why the documented location is `/var/lib/tunnelgate/.ssh/authorized_keys`, with `0755`
parent directories, a `0600` file and owner `tunnelgate`. The same rule applies to
`console_authorized_keys_path` on the router; dropbear's default
`/etc/dropbear/authorized_keys` (mode `0600`/`0644`, inside `/etc`) is fine.

### The file and its directory must be readable **as** the tunnel user

sshd does not read `authorized_keys` as root. It switches to the target account first and then
opens the file, so both the `.ssh` directory and the file itself have to be traversable and
readable by `tunnelgate` - regardless of which account runs the panel. A root-owned directory
at mode `0700` produces exactly one log line and a fleet-wide outage:

```
Could not open user 'tunnelgate' authorized keys '/var/lib/tunnelgate/.ssh/authorized_keys': Permission denied
```

Every router then fails with `Permission denied (publickey)`, which reads like a broken key.
Measured on OpenSSH 10.0p2:

| `/var/lib/tunnelgate` | `.ssh` | `authorized_keys` | result |
| --- | --- | --- | --- |
| root:`0755` | tunnelgate:`0700` | tunnelgate:`0600` | works |
| root:`0755` | tunnelgate:`0700` | root:`0644` | works |
| root:`0755` | root:`0700` | tunnelgate:`0600` | **fails** |
| root:`0755` | root:`0700` | root:`0600` | **fails** |

So if you install with `--run-as root` (the panel as root), the data directory is root-owned as
you asked, but `.ssh` and `authorized_keys` stay `tunnelgate`-owned: that is what sshd reads.
The panel writes the file atomically and chooses the owner from what sshd needs, not from who is
writing: a file the SSH account can read keeps its owner, and anything it cannot read - including
a root-owned `0600` file left behind by an older release - is handed to the SSH account on the
next key change. The same rule covers the `.ssh` directory, because a root-owned `0700` directory
blocks the traversal before the file's mode ever matters. `app.cli doctor` checks readability as
the SSH account and names this fix if it is wrong.

If you suspect this, repair it by hand; the next rewrite will then keep the corrected owner:

```bash
chown -R tunnelgate:tunnelgate /var/lib/tunnelgate/.ssh
chmod 0700 /var/lib/tunnelgate/.ssh
chmod 0600 /var/lib/tunnelgate/.ssh/authorized_keys
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
git clone https://github.com/Ghost-in-the-dark/tunnelgate.git /opt/tunnelgate
cd /opt/tunnelgate
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
```

### Frontend build (required after a fresh clone)

`web/dist` is a build artefact and is **not** in the repository (it is in
`.gitignore`), so a fresh clone has no UI yet. `scripts/setup-server.sh` builds it for
you; doing it by hand:

```bash
cd /opt/tunnelgate/web
npm ci
npm run build          # writes web/dist
```

This needs Node 18 or newer plus npm. Without `web/dist` the panel still starts and
serves `/api/v1` and `/api/v1/health` - useful for checking a deployment headlessly -
but every page returns the API's 404, and `app.cli doctor` warns under `web UI`.

The container image does not have this step: `Dockerfile` builds the SPA in its own
`tg-web` stage and copies the result in, so `docker compose up --build` needs no
prebuilt directory either.

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
# Router addressing. subdomain = <slug>.panel.example.com (needs a wildcard cert).
# path = https://gate.panel.example.com/<slug>/ (needs one ordinary cert, nginx only).
TUNNELGATE_ROUTE_MODE=subdomain
# Path mode only. Different from TUNNELGATE_PANEL_HOST => separate layout (recommended,
# include routes.conf in the http context). Equal to it => merged layout, same origin as the
# panel: include routes.conf inside the panel server block instead. See docs/SECURITY.md §6.1.
# TUNNELGATE_GATEWAY_HOST=gate.panel.example.com
TUNNELGATE_COOKIE_SECURE=true
# Leave COOKIE_DOMAIN unset - see "Do not widen the session cookie" below.

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

### Do not widen the session cookie

`TUNNELGATE_COOKIE_DOMAIN` is **not** part of a normal install and the line above deliberately
leaves it unset. With it unset, `tg_session` is a host-only cookie: `panel.example.com` sets it
and the browser sends it back to `panel.example.com` and nowhere else - not to
`office-ap.panel.example.com`, not to `console.panel.example.com`.

Setting `TUNNELGATE_COOKIE_DOMAIN=.panel.example.com` makes the browser attach the same session
cookie to **every** name under the domain. That includes every router's LuCI vhost, so the
operator's panel session is handed to a fleet of cheap, physically-exposed devices. The blast
radius inverts: compromising *one* router (or merely reading one router's request log, or
whoever holds the SSH tunnel and can watch the forwarded request) yields a **live panel
session** - which is every router, every console, and every panel mutation - rather than that one
device. `docs/SECURITY.md` §6 records this as a documented threat.

Every router vhost drops the header on the way in, in all three places that can render one:
`deploy/nginx/router-vhost.conf.template` (`proxy_set_header Cookie "";`), and - because the
runtime renderer is the one that actually ships - `render_nginx()` in `app/services/proxy.py`
and `render_caddy_route()` for `TUNNELGATE_PROXY_DRIVER=caddy` (`"delete": ["Cookie"]`). That
strip is the mitigation; host-only is the structural fix that does not depend on one line
staying put. Treat the strip as defence in depth, not as permission to enable the option.

One caveat that makes host-only worth keeping: the strip protects you only if the proxy in front
of the router is panel-generated. A hand-written vhost, or a second proxy added later, does not
inherit it.

Only set it if the SPA and the API genuinely live on different hostnames, and accept the
trade-off in writing.

### How a router is opened (and why it is not the cookie)

A router's LuCI lives on `<slug>.panel.example.com`, a host the browser has no panel session
for. The panel therefore issues a **one-time launch ticket** and the router vhost redeems it:

```
browser, signed in on panel.example.com
  GET https://panel.example.com/__tg/launch?router=office-ap&next=/cgi-bin/luci
    -> 303 https://office-ap.panel.example.com/__tg/enter?t=<ticket>
  GET https://office-ap.panel.example.com/__tg/enter?t=<ticket>   (router vhost -> panel)
    -> Set-Cookie: tg_luci=...; Path=/; HttpOnly; Secure
    -> 303 /cgi-bin/luci
```

`tg_luci` is scoped to that one router host, valid for
`TUNNELGATE_ROUTER_SESSION_TTL_MINUTES` (default 60), and is the only thing the router's vhost
will accept besides a panel session. It grants that router - nothing else. This is what "Open
LuCI" and the "Public route" card in the UI link to; the plain `https://<slug>.<suffix>` URL
keeps working once that cookie exists, and falls back through `/login` when it does not.

Two consequences for an install:

* **The generated vhost must be current.** `/__tg/enter` and the `X-Tg-Luci-Cookie` header on
  the auth subrequest are part of `routes.conf` / `routes.auth.conf`. After upgrading, run
  `python -m app.cli render-proxy` (or restart the panel, which re-renders on startup) and
  reload nginx. `python -m app.cli doctor` fails with `launch config` if the files on disk
  predate the hand-off - that is the symptom to look for if "Open LuCI" starts bouncing through
  `/login` again.
* **Nothing needs `TUNNELGATE_COOKIE_DOMAIN`.** If a router login appears to work only with the
  domain cookie set, the config is stale, not the setting wrong.

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
directory and include it once (the include below is the subdomain-mode one; in path mode see
§0 Option C for which context the file belongs in - http for separate, the panel `server` block
for merged):

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
* an `include /etc/nginx/tunnelgate/routes.conf;` for the per-router vhosts, placed in the
  http context. That placement is right for subdomain mode and for the *separate* path layout;
  in the *merged* path layout the same line has to move inside the panel `server` block instead
  ("Option C - no wildcard at all: path routing" above). It is one include either way - never
  both.

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

## 7. Moving the panel, and running behind a proxy

There are two separate questions here and they are easy to conflate:

| Question | Setting |
|---|---|
| Where does the panel listen for its **own** proxy? | `TUNNELGATE_PANEL_URL` (usually `http://127.0.0.1:8080`) |
| Where do **browsers** reach the panel? | `TUNNELGATE_PUBLIC_URL` |
| Where do **routers** dial the panel? | the **agent endpoint** - `TUNNELGATE_PANEL_URL` when it is reachable, else `TUNNELGATE_PUBLIC_URL`, overridable from the UI |

On a flat install the first two are the same string and nothing needs doing. They diverge as soon
as a TLS terminator, a load balancer or a non-default port sits in front: the panel still binds
loopback, while browsers arrive on the public name. Do not "fix" that by pointing
`TUNNELGATE_PANEL_URL` at the public name - the panel's own proxy would then try to reach itself
through the public edge.

`TUNNELGATE_PUBLIC_URL` is the origin written into every redirect the panel emits: the login
bounce from a router vhost, and the one-time router launch hand-off. Unset, it is derived from
`TUNNELGATE_PANEL_URL`'s scheme plus `TUNNELGATE_PANEL_HOST`, which is correct on a flat
install. **Set it explicitly whenever `TUNNELGATE_PANEL_URL` is loopback** - otherwise a browser
that follows "Open LuCI" is redirected to `http://127.0.0.1:8080`, which cannot work.
`python -m app.cli doctor` warns about exactly that combination.

It also decides two things that used to be hardcoded:

* **the scheme of the router URLs.** `https`, unless this value is explicitly `http://...` - an
  install that only answers plain HTTP (TLS terminated by your own proxy in front, the shape
  `scripts/quick-install.sh` sets up) must not advertise `https` links that nothing listens on.
* **the agent endpoint.** Routers dial the origin in this value whenever `TUNNELGATE_PANEL_URL`
  is loopback, because a router cannot dial `127.0.0.1`. Without it a fresh install hands out an
  install command that only works on the panel host itself.

### Moving the panel without re-installing routers

Routers that are already installed learn their address from two places, and only one of them can
change after the fact:

* `TG_PANEL_URL` baked into the install script, and `heartbeat_url` handed over at exchange.
  Fixing these means re-running the installer on every device.
* **The heartbeat.** Every 60 s the router asks the panel for `desired.heartbeat_url`, and when
  that differs from what it has stored it rewrites its own UCI config. This is the only channel
  that reaches a device already in the field.

Both the install script and the heartbeat are rendered from the **agent endpoint**, so moving the
panel is one operation:

```bash
# from the UI: Settings -> Agent endpoint -> set host -> Test -> Save
# or, equivalently:
curl -X PUT https://panel.example.com/api/v1/settings/agent-endpoint \
  -H "Cookie: tg_session=$SESSION" -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' \
  -d '{"scheme": "https", "host": "new-panel.example.com", "port": null}'
```

Then:

1. Bring up the new name (DNS, certificate, proxy vhost) and verify it with the
   `POST .../agent-endpoint/test` button - that probe runs **from the panel**, which is the only
   vantage point that matters ("my browser reaches it" proves nothing about a router's network).
2. Save. From the next heartbeat on, routers converge within ~60 s; no reinstall, no SSH.
3. Installs issued after the change already carry the new address. Anything still running the
   old installer needs re-issuing.
4. Keep the old name alive until the routers have converged, then retire it. A router that
   cannot reach the panel cannot learn the new address either - that is the one real
   out-of-band case, and the answer is to re-run the installer on that device.

The override lives in the database, not the env file, for that reason: changing it needs no
systemd restart and no second file to keep in sync. `TUNNELGATE_PANEL_URL` stays the fallback
and applies again after `DELETE` on the same route.

`docs/API.md` documents the four routes and their exact responses.

### Behind a reverse proxy or load balancer

The panel needs to know the **real client address**, because rate limiting counts per IP and the
audit log records who did what. By default it believes only its own loopback: a request arriving
from anywhere else has its forwarded headers ignored. Proxies in front are supported by config;
the defaults deliberately do not trust them.

Three settings control it:

| Setting | Default | Meaning |
|---|---|---|
| `TUNNELGATE_TRUST_PROXY_HEADERS` | `true` | Consider forwarded headers at all |
| `TUNNELGATE_TRUSTED_PROXIES` | `["127.0.0.1", "::1"]` | Peers or CIDR networks whose headers are believed |
| `TUNNELGATE_FORWARDED_ALLOW_HOPS` | `1` | How many proxies append `X-Forwarded-For` |

and one thing outside the panel's config: uvicorn has its **own** trust list,
`--forwarded-allow-ips`, already set to `127.0.0.1` in the shipped systemd unit and Docker
entrypoint. **Both** lists must name your proxy. Widening one and not the other gives a
split-brain: the app resolves the client address from the raw header while uvicorn (and therefore
the request scheme) still sees the proxy. See `docs/SECURITY.md` §7 for the resolution rules.

> **Syntax trap.** `TUNNELGATE_TRUSTED_PROXIES` is a JSON list:
> `TUNNELGATE_TRUSTED_PROXIES=["127.0.0.1", "10.0.0.5"]`. The comma form
> (`127.0.0.1,10.0.0.5`) fails while `app.config` is imported and the panel does not start at all.
> `--forwarded-allow-ips`, by contrast, **does** take a comma-separated list - the two look
> similar and are not.

#### nginx on the same host (default)

Nothing to do: the proxy is `127.0.0.1`, which is already trusted. This is what
`deploy/nginx/tunnelgate.conf` and the systemd unit assume.

#### nginx on another host, or a container network

```bash
# /etc/tunnelgate.env
TUNNELGATE_TRUSTED_PROXIES=["10.20.30.40"]
TUNNELGATE_FORWARDED_ALLOW_HOPS=1
```

and widen uvicorn's list in the unit. The panel must also stop binding loopback - otherwise
nginx on the other host cannot reach it at all:

```ini
ExecStart=/opt/tunnelgate/.venv/bin/uvicorn app.main:app \
  --host 10.20.30.41 --port 8080 \
  --proxy-headers --forwarded-allow-ips 127.0.0.1,10.20.30.40
```

Binding a LAN address makes the panel reachable from that network, so the firewall must limit
8080 to the proxy. If you would rather keep it loopback-only, run the proxy on the same host
(the previous subsection) - there is no third option where uvicorn stays on `127.0.0.1` and a
remote nginx reaches it.

nginx must send the headers it is being trusted for:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name panel.example.com;

    location / {
        proxy_pass http://10.20.30.41:8080;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

`$proxy_add_x_forwarded_for` **appends** the client address to whatever the client sent - that
is why the resolution rule walks from the right and stops after one hop. If you would rather
defeat header spoofing at the proxy, `proxy_set_header X-Forwarded-For $remote_addr;` is a
valid choice and makes the hop count mostly irrelevant.

#### Caddy

```caddyfile
panel.example.com {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Real-IP {remote_host}
    }
}
```

Caddy appends `X-Forwarded-For` itself and sets `X-Forwarded-Proto`; a single `reverse_proxy` is
one hop. A cloud load balancer *in front of* Caddy or nginx is a second hop:
`TUNNELGATE_FORWARDED_ALLOW_HOPS=2`, and both edges must be in `TUNNELGATE_TRUSTED_PROXIES`
(uvicorn only needs the one that connects to it).

#### Cloud load balancer in front

The LB terminates TLS and forwards over HTTP to your nginx or Caddy, which forwards to the panel:

```
client -> LB (TLS) -> nginx -> panel
```

Two proxies append to `X-Forwarded-For`, so the hop count is 2. What you put in the trust list
depends only on **who connects to the panel** - the last proxy, never the LB:

```bash
# nginx on the panel's own host (the usual layout): peer is loopback -> default list, only hops change
TUNNELGATE_FORWARDED_ALLOW_HOPS=2

# nginx on a separate host: trust that host (or its network), and bind the panel to the LAN
TUNNELGATE_TRUSTED_PROXIES=["10.20.30.40"]
TUNNELGATE_FORWARDED_ALLOW_HOPS=2
```

Prefer a CIDR that is the *proxy network* over listing individual addresses, and prefer naming
the last proxy rather than the LB: the panel only ever sees the peer that connects to it, so
trusting the LB's address range does nothing except widen the list. Most LBs also offer an
authenticated-proxy mode (Cloudflare, AWS ALB) that rewrites the chain at the edge; enabling it
does not remove the need to trust the hop immediately in front of the panel.

Getting the hop count wrong here is the failure mode that bites: with `hops = 1` under two
proxies the panel resolves the **LB's** address for every user, which looks like the too-narrow
case in the table below (one shared rate-limit bucket, one IP in the audit log) even though the
trust list is correct.

#### Failure modes

| Mistake | Symptom |
|---|---|
| **Too narrow** - defaults kept, proxy is not loopback | Every request appears to come from the proxy's address. All operators share **one** rate-limit bucket, so one person fat-fingering a password locks the team out; the audit log names the proxy as the actor for everything, which quietly destroys its evidential value. Nothing looks broken, so this survives for months - only the security telemetry is wrong |
| **Too wide** - `0.0.0.0/0`, or the client's own network trusted | Any client can set `X-Forwarded-For` to an arbitrary address and get a fresh rate-limit bucket per attempt, defeating login throttling entirely, and can write a false address into the audit log |
| **Proxy forwards the client's `X-Forwarded-For` instead of appending** | The chain length looks right (one entry) so nothing else can detect it: the client chooses its own address. Rotate the header and every request gets a fresh rate-limit bucket - unlimited password guessing - and the audit log records whatever the attacker typed. Only the proxy can fix it (see the note below); the panel cannot tell "the proxy appended this" from "the client sent this" |
| **Hop count too high** | The panel walks past the proxy's entry into addresses the *client* wrote - the same defect as too-wide, without touching the trust list. The setting moves the answer left, never right. If the chain is shorter than the hop count the panel falls back to the socket peer, so the symptom here is "every request audits as the proxy", not a forged address |
| **uvicorn list not widened** | The panel still resolves the right client - `app/forwarded.py` reads the raw header itself - so rate limiting and the audit log are correct. What stays wrong is uvicorn's own view: `request.client` and the ASGI scheme remain the proxy's. The panel consumes both: it resolves the client address from the raw header (so that half is fine) and it reads the scheme for the `Secure` cookie flag - but only through `X-Forwarded-Proto` when the peer is trusted, so a narrow uvicorn list does not produce an insecure cookie. Widen both anyway: the two halves of the stack then agree, and the next piece of code that reads `request.client` or the scheme is not silently wrong |

#### Check that your proxy appends, not forwards

The rightmost-hop rule assumes each proxy **appends** the address it saw, which is what
`$proxy_add_x_forwarded_for` and Caddy's `reverse_proxy` do. A proxy configured to *set*
`X-Forwarded-For` to the incoming header (common in hand-written configs and some appliance
UIs) hands the client the pen: with one trusted hop, chain length 1 and hop count 1 line up
perfectly, and the panel believes a value the client wrote. Test it, do not assume:

```bash
curl -s -H 'X-Forwarded-For: 203.0.113.77' -X POST \
  https://panel.example.com/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"nobody","password":"wrong"}' >/dev/null
curl -s -b /tmp/tg.jar 'https://panel.example.com/api/v1/audit?action=auth.login_failed&limit=1' \
  | jq '.items[0].ip'
```

If that prints `203.0.113.77`, the proxy is forwarding rather than appending. Fix the proxy
(`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` in nginx, or
`header_up X-Forwarded-For {remote_host}` in Caddy), or make it overwrite the header outright
(`$remote_addr`) which also makes the hop count irrelevant. **Until it is fixed, take the proxy
out of `TUNNELGATE_TRUSTED_PROXIES`**: every request then resolves to the proxy's address -
one shared rate-limit bucket and a useless audit IP, but nothing forgeable. Remember to set
`TUNNELGATE_COOKIE_SECURE=true` in that interim state: the automatic `Secure` flag reads
`X-Forwarded-Proto` only from a *trusted* peer, so distrusting the proxy also switches that
safety net off.

Verify it from the outside once configured. The audit log records the address the panel
resolved for every request, so it is the honest check:

```bash
# log in from your own machine, keeping the session cookie in a file
curl -s -c /tmp/tg.jar -X POST https://panel.example.com/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"..."}' >/dev/null

# the row that login just produced must carry YOUR public address
curl -s -b /tmp/tg.jar \
  'https://panel.example.com/api/v1/audit?action=auth.login&limit=1' | jq '.items[0].ip'
# -> your public address. If it shows the proxy's address, the trust list is too narrow.
```

And confirm the boundary is closed, from a host that is **not** the proxy: a forged header must
be ignored, so the row still carries the real peer:

```bash
curl -s -H 'X-Forwarded-For: 203.0.113.77' -X POST \
  https://panel.example.com/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"nobody","password":"wrong"}' >/dev/null

# the failed-login row's ip must NOT be 203.0.113.77
curl -s -b /tmp/tg.jar \
  'https://panel.example.com/api/v1/audit?action=auth.login_failed&limit=1' | jq '.items[0].ip'
```

If it *is* `203.0.113.77`, the trust list is too wide - shrink it before doing anything else.

---

## 8. Verify the install


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

Then walk the whole lifecycle once, in the browser. This is the acceptance test: if every step
below behaves, the deployment is finished. It takes about ten minutes and is worth doing exactly
as written the first time.

| # | Do this | Expect |
|---|---|---|
| 1 | Open `https://panel.example.com` | login page; log in as `admin` |
| 2 | Create a router named "Office AP" | wizard step 2; note the slug it picks |
| 3 | Advance to the copy-command step | the command contains only `X-Bootstrap-Token` - no key, no port |
| 4 | Run the command on the router (`docs/INSTALL_ROUTER.md`) | the wizard goes Waiting → Connected → Done within a minute |
| 5 | `ss -ltnH \| grep <port>` on the panel | one listener on `127.0.0.1:<port>`, nothing on `0.0.0.0` |
| 6 | Click **Open LuCI** | you land in LuCI at `https://office-ap.panel.example.com/` and every page, stylesheet and XHR works (no 404s in the browser console) |
| 7 | Press the console button, run `uci show system` | a prompt and real output; the router's shell, not the panel's |
| 8 | Close the console, then open Settings → Audit | rows for `auth.login`, `router.create`, `bootstrap.exchange`, `luci.open`, `console.open`, `console.close` |
| 9 | Settings → Users → add an `operator` account, log in as it in a private window | it can add, rotate and delete routers and open consoles, but Settings → Users and Settings → Panel are refused (admin only) |
| 10 | Router → **Rotate key**, then run the new command on the router | the live tunnel drops at once and the panel shows **pending**; the **port does not change**; after the exchange the router is **online** again; the old key line is gone from `authorized_keys` and the new one is there |
| 11 | Router → **Delete** | the key line disappears, the port returns to the pool (`/api/v1/stats` → `ports_free` goes up) |
| 12 | `grep -c <slug> /var/lib/tunnelgate/.ssh/authorized_keys` | `0` - nothing is left behind; the router's LuCI URL now 404s |

Two failure modes that are *not* bugs, so as not to chase them:

* after step 10 the router sits in **pending** until the new install command has run - rotation does
  not push a key to the router (the private half is never stored, so it cannot);
* the console needs the console key, which the heartbeat delivers. Straight after installing, step 7
  can answer `console_not_installed` for a minute; wait for one heartbeat and try again.

If LuCI opens but the console times out, the router has not picked up the console key yet: the
heartbeat delivers it, so wait one heartbeat interval (60 s) or restart the tunnel service.

---

## 9. Upgrades

One command, on the panel host:

```bash
curl -fsSL https://raw.githubusercontent.com/Ghost-in-the-dark/tunnelgate/main/scripts/update.sh \
  | sudo sh -s -- --ref v1.1.0
```

Drop `--ref` to take the latest GitHub release. `--check-only` prints the installed and the
available version and exits without writing; `--dry-run` prints the whole plan.
`scripts/update.sh --help` lists every flag and the exit codes.

What it does, in this order, for a reason:

| step | why in that position |
| --- | --- |
| backup into `/var/backups/tunnelgate/update-<UTC stamp>/` (0700) | a backup taken after the first write records the damage instead of preventing it. It holds `sqlite3 .backup` of the database, `/etc/tunnelgate.env`, `authorized_keys`, both routes files, `pip freeze` and a `code.tar.gz` for an offline rollback |
| install the new dependencies into the existing venv | |
| run `check-schema` with the **new** code against a **snapshot** of the database | `check-schema` calls `init-db`, so pointing it at the live file would create tables in production while you are still deciding whether to continue. On drift the update stops **before** the swap, prints the `ALTER TABLE` statements, restores `pip freeze`, and leaves the running panel on the old version |
| build `web/dist` | it is not in the repository, so a code-only update serves a stale SPA |
| `rsync -a --delete` the staged code into place (keeps `.venv`, `data`, `web/node_modules`, `.git`) | only after dependencies, schema and SPA have all passed |
| `systemctl restart` and poll `/api/v1/health` for the reported version | `systemctl` returning 0 is not proof: a panel that dies on its first bind is briefly **active** and then in auto-restart. If the version never answers, it rolls the code and the freeze back and says whether the previous version is serving again |

It discovers the installation from systemd (`FragmentPath`, `ExecStart`, `User`,
`EnvironmentFiles`), so it works for the `quick-install.sh`, `setup-server.sh` and Docker-less
manual layouts alike; `--install-dir`, `--data-dir` and `--env-file` override the discovery.
It never rewrites your unit file - if the shipped unit has drifted from yours it prints the
`diff` command and leaves the decision to you.

It refuses, rather than half-applying: a dirty git checkout (`--force` overrides), the same
version as installed unless `--force`, a non-SQLite database for the schema check, and a
release whose schema needs hand work (`--skip-schema-check` is the documented way past a check
you know is fine).

Restart is safe for the fleet: the forwards are owned by sshd, not by the panel, so LuCI keeps
working while the panel is down and routers reconnect on their own. Only the *status* view goes
stale (it is reconciled on startup).

### Manual upgrade (if you have to)

```bash
cd /opt/tunnelgate
git fetch --tags && git checkout v1.1.0
.venv/bin/pip install -r requirements.txt
(cd web && npm ci && npm run build)   # required: web/dist is not in the repo
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

## 10. PostgreSQL instead of SQLite

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

## 11. Backups

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
| `TUNNELGATE_PANEL_URL` | `http://127.0.0.1:8080` | Where the panel listens for its own proxy - **not** necessarily what routers dial. Fallback for the agent endpoint; override it from the UI instead. See §7 |
| `TUNNELGATE_PANEL_HOST` | `panel.example.com` | nginx `server_name` for the panel |
| `TUNNELGATE_PUBLIC_URL` | derived from `PANEL_URL` + `PANEL_HOST` | Origin **browsers and routers** use: every redirect the panel writes (login bounce, router launch) names it, it sets the scheme of the advertised router URLs, and it is the agent endpoint when `PANEL_URL` is loopback. Required when `PANEL_URL` is loopback - see §7 |
| `TUNNELGATE_ROUTE_MODE` | `subdomain` | How routers are published: `subdomain` (`<slug>.<suffix>`, needs a wildcard certificate) or `path` (one gateway host, `<gateway>/<slug>/`, needs one ordinary certificate and **nginx**). Unknown values fall back to `subdomain` so a typo cannot stop the panel from booting; `app.cli doctor` reports it |
| `TUNNELGATE_SUBDOMAIN_SUFFIX` | =`panel_host` | Suffix for router vhosts - `subdomain` mode only |
| `TUNNELGATE_GATEWAY_HOST` | =`gate.<suffix>` | The single host routers are published under in `path` mode. Must be a DNS name, not an IP: a CA cannot issue for an IP. Equal to `TUNNELGATE_PANEL_HOST` selects the *merged* layout (shared origin; include `routes.conf` inside the panel `server` block), different gives *separate*, the recommended one. Checked by `app.cli doctor`, which warns on merged and fails an IP, empty or dotless value |
| `TUNNELGATE_COOKIE_SECURE` | `false` | Usually leave it. The cookie is already marked `Secure` when a request arrives over HTTPS from a trusted proxy, so a TLS-terminating deployment needs nothing. Set `true` only when the panel is **never** reachable over plain HTTP - forcing it on a LAN deployment makes browsers drop the cookie over `http://` and logins silently do not stick |
| `TUNNELGATE_COOKIE_DOMAIN` | unset (host-only) | **Leave unset.** Operator opt-in only; a domain cookie is sent to every router host - see §5 "Do not widen the session cookie" |
| `TUNNELGATE_DB_URL` | `sqlite:///./data/tunnelgate.db` | SQLAlchemy URL |
| `TUNNELGATE_SSH_USER` | `tunnelgate` | The system user holding forwards |
| `TUNNELGATE_AUTHORIZED_KEYS_PATH` | `./data/authorized_keys` | Where router keys are rendered |
| `TUNNELGATE_PORT_MIN/MAX` | 20000/25000 | LuCI tunnel port pool |
| `TUNNELGATE_CONSOLE_PORT_MIN/MAX` | 25001/30000 | Console port pool |
| `TUNNELGATE_PROXY_DRIVER` | `nginx` | `nginx` \| `caddy` \| `none` |
| `TUNNELGATE_PROXY_ROUTES_PATH` | `./data/tunnelgate.routes.conf` | Generated vhost include |
| `TUNNELGATE_PROXY_RELOAD_COMMAND` | `nginx -s reload` | Shell command after a route change |
| `TUNNELGATE_TRUST_PROXY_HEADERS` | `true` | Whether forwarded headers are considered at all. See §7 |
| `TUNNELGATE_TRUSTED_PROXIES` | `["127.0.0.1", "::1"]` | Peers/CIDRs whose forwarded headers are believed. **JSON list syntax** - the comma form stops the panel from starting |
| `TUNNELGATE_FORWARDED_ALLOW_HOPS` | `1` | Number of proxies appending `X-Forwarded-For`; raise only when you genuinely have more |
| `TUNNELGATE_TRUST_FORWARDED_PROTO` | `true` | Declared for symmetry and **unused by the app** - `X-Forwarded-Proto` is consumed by uvicorn's `--proxy-headers`, not by the panel |
| `TUNNELGATE_DOCS_ENABLED` | unset (off when `ENV=production`) | Serve `/api/docs` and `/api/openapi.json`. `TUNNELGATE_ENV` is set to `production` by the env example and `setup-server.sh`, so both return `404` on a normal install |
| `TUNNELGATE_SECRET_KEY` | unset | **Required** in production |
| `TUNNELGATE_ADMIN_PASSWORD` | unset | Seeds the admin user on first start |
| `TUNNELGATE_SESSION_TTL_MINUTES` | 720 | Panel session lifetime |
| `TUNNELGATE_LOGIN_RATE_LIMIT` | 10 | Login attempts per window |
| `TUNNELGATE_CONSOLE_ENABLED` | `true` | Master switch for the web console |
| `TUNNELGATE_CONSOLE_IDLE_TIMEOUT_SECONDS` | 900 | Idle shell timeout |
| `TUNNELGATE_CONSOLE_MAX_SESSION_SECONDS` | 7200 | Hard shell duration cap |
| `TUNNELGATE_CONSOLE_SSH_USER` | `root` | Account the console logs in as **on the router**. It is the same value used to install the console key, so the dial and the key cannot drift. Change it only after creating that account on the device (docs/SECURITY.md §5) |
