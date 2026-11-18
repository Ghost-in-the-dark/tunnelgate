#!/bin/sh
# TunnelGate quick install - for a host whose TLS is terminated SOMEWHERE ELSE.
#
# WHAT THIS IS FOR
#   You have one public name, no certificate on this box, and your own reverse proxy
#   (nginx, Caddy, Traefik, a cloud load balancer) will terminate TLS in front of it.
#   This script installs everything up to that point and stops there: it does not
#   touch certificates, DNS or your edge. You add the proxy afterwards.
#
#   It installs deploy/nginx/tunnelgate-behind-proxy.conf: plain HTTP on one port,
#   PATH routing with the MERGED layout, so every router is <public-url>/<slug>/ on
#   the same name as the panel. That is what makes a single ordinary name - including
#   a free dynamic-DNS one - enough: no wildcard DNS, no wildcard certificate. What
#   the merged layout costs is in docs/SECURITY.md 6.1; read it before you add
#   routers you do not physically control.
#
# WHAT IT DOES, IN ORDER
#    1. validates arguments and checks the host (existing vhost, busy ports)
#    2. installs the apt packages (nginx, python3-venv, openssh-server, iproute2, ...)
#    3. creates the unprivileged tunnel user and its authorized_keys
#    4. installs the sshd drop-in, validating with sshd -t BEFORE reloading
#    5. writes the environment file (secrets generated once, never overwritten)
#    6. installs the sources, builds the virtualenv and the SPA
#    7. initialises the database and seeds the admin user
#    8. installs and starts the systemd units (panel + nginx reload watcher)
#    9. installs the plain-HTTP vhost, seeds the route includes, reloads nginx
#   10. verifies the panel answers through nginx and prints your edge config
#
# USAGE
#   sudo ./scripts/quick-install.sh --host gate.example.duckdns.org
#   sudo ./scripts/quick-install.sh --host gate.example.duckdns.org --proxy-hops 2
#   sudo ./scripts/quick-install.sh --host 192.168.1.10 --public-scheme http
#   sudo ./scripts/quick-install.sh --host gate.example.duckdns.org --dry-run
#   sudo ./scripts/quick-install.sh --help
#
# ADVANCED (side-by-side instances, staging trees, tests)
#   --install-dir DIR    sources and the virtualenv          (default /opt/tunnelgate)
#   --data-dir DIR       database, keys, authorized_keys     (default /var/lib/tunnelgate)
#   --env-file FILE      environment file handed to systemd  (default /etc/tunnelgate.env)
#   --service-name NAME  systemd unit and nginx site name    (default tunnelgate)
#   --panel-port N       loopback port the panel listens on  (default 8080)
#
# FIREWALL - THE PART PEOPLE GET WRONG
#   Exactly ONE port is opened: the plain-HTTP port your proxy talks to, and only if
#   ufw is present here. The tunnel pool (20000-25000) and the console pool
#   (25001-30000) stay CLOSED. Both are sshd listeners on 127.0.0.1; publishing them
#   hands the internet every router's LuCI and every console port directly, bypassing
#   the panel's authentication. Verify at any time:
#       ss -ltnp | grep -E ':(2[0-9]{4})'
#   Every one of those sockets must show 127.0.0.1 as its local address.

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$SCRIPT_DIR/.." && pwd)

HOST=""
HTTP_PORT=80
PANEL_PORT=8080
PUBLIC_SCHEME=https
PROXY_HOPS=1
ADMIN_PASSWORD=""
INSTALL_DIR=/opt/tunnelgate
DATA_DIR=/var/lib/tunnelgate
ENV_FILE=/etc/tunnelgate.env
SERVICE=tunnelgate
DRY_RUN=0
SKIP_FIREWALL=0

usage() {
    sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  !\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Every mutation goes through this, so --dry-run is honest rather than aspirational.
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  [dry-run] %s\n' "$*"
        return 0
    fi
    "$@"
}

need_value() {
    if [ $# -lt 2 ] || [ -z "$2" ]; then
        die "$1 needs a value"
    fi
}

# Replacement text in a sed "s#...#...#" command cannot contain the delimiter, and a
# bare & means "the whole match". Both would silently corrupt a rendered unit or
# vhost, so every substituted value goes through this first.
sed_repl() {
    printf '%s' "$1" | sed -e 's/[&#\\]/\\&/g'
}

# ---------------------------------------------------------------- arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --host) need_value "$@"; HOST=$2; shift 2 ;;
        --host=*) HOST=${1#*=}; shift ;;
        --port) need_value "$@"; HTTP_PORT=$2; shift 2 ;;
        --port=*) HTTP_PORT=${1#*=}; shift ;;
        --panel-port) need_value "$@"; PANEL_PORT=$2; shift 2 ;;
        --panel-port=*) PANEL_PORT=${1#*=}; shift ;;
        --public-scheme) need_value "$@"; PUBLIC_SCHEME=$2; shift 2 ;;
        --public-scheme=*) PUBLIC_SCHEME=${1#*=}; shift ;;
        --proxy-hops) need_value "$@"; PROXY_HOPS=$2; shift 2 ;;
        --proxy-hops=*) PROXY_HOPS=${1#*=}; shift ;;
        --admin-password) need_value "$@"; ADMIN_PASSWORD=$2; shift 2 ;;
        --admin-password=*) ADMIN_PASSWORD=${1#*=}; shift ;;
        --install-dir) need_value "$@"; INSTALL_DIR=$2; shift 2 ;;
        --install-dir=*) INSTALL_DIR=${1#*=}; shift ;;
        --data-dir) need_value "$@"; DATA_DIR=$2; shift 2 ;;
        --data-dir=*) DATA_DIR=${1#*=}; shift ;;
        --env-file) need_value "$@"; ENV_FILE=$2; shift 2 ;;
        --env-file=*) ENV_FILE=${1#*=}; shift ;;
        --service-name) need_value "$@"; SERVICE=$2; shift 2 ;;
        --service-name=*) SERVICE=${1#*=}; shift ;;
        --skip-firewall) SKIP_FIREWALL=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; echo "try --help" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------- validation
if [ -z "$HOST" ]; then
    echo "--host is required: the public name a browser uses, e.g." >&2
    echo "  --host gate.example.duckdns.org" >&2
    echo "run with --help for every option" >&2
    exit 2
fi
case "$HOST" in
    *://*) die "--host takes a bare hostname, without http:// or https:// (the scheme is --public-scheme)" ;;
    */*)   die "--host takes a bare hostname, without a path" ;;
    *:*)   die "--host takes a bare hostname, without a port; --port is the port your proxy forwards to" ;;
esac
case "$PUBLIC_SCHEME" in
    http|https) ;;
    *) die "--public-scheme must be http or https" ;;
esac
case "$PROXY_HOPS" in
    ''|*[!0-9]*) die "--proxy-hops must be a whole number, 1 or more" ;;
esac
[ "$PROXY_HOPS" -ge 1 ] || die "--proxy-hops must be 1 or more"
case "$HTTP_PORT" in ''|*[!0-9]*) die "--port must be a number" ;; esac
case "$PANEL_PORT" in ''|*[!0-9]*) die "--panel-port must be a number" ;; esac
[ "$HTTP_PORT" -ge 1 ] && [ "$HTTP_PORT" -le 65535 ] || die "--port must be 1-65535"
[ "$PANEL_PORT" -ge 1 ] && [ "$PANEL_PORT" -le 65535 ] || die "--panel-port must be 1-65535"
[ "$HTTP_PORT" != "$PANEL_PORT" ] || die "--port and --panel-port must differ"
case "$SERVICE" in
    *[!a-zA-Z0-9_.-]*|'') die "--service-name may contain only letters, digits, dot, dash and underscore" ;;
esac

# Root is needed for what this script CHANGES - packages, a user, systemd units, nginx.
# A dry run changes nothing, so it must stay usable without sudo: an operator reading the
# plan before handing root to a script is the desired behaviour, not an error.
if [ "$DRY_RUN" -eq 1 ]; then
    [ "$(id -u)" -eq 0 ] || warn "dry run as a non-root user: the plan is complete, but the real run needs root"
else
    [ "$(id -u)" -eq 0 ] || die "run this as root: it installs packages, creates a user and writes systemd units"
fi

# Derived once, so nothing can drift half-way through the run.
ROUTES_DIR=/etc/nginx/tunnelgate
if [ "$SERVICE" = "tunnelgate" ]; then
    ROUTES=$ROUTES_DIR/routes.conf
else
    ROUTES=$ROUTES_DIR/$SERVICE.routes.conf
fi
AUTH_ROUTES=$ROUTES_DIR/$(basename "$ROUTES" .conf).auth.conf
VHOST_AVAILABLE=/etc/nginx/sites-available/$SERVICE.conf
VHOST_ENABLED=/etc/nginx/sites-enabled/$SERVICE.conf
AUTHORIZED_KEYS=$DATA_DIR/.ssh/authorized_keys
PANEL_URL=http://127.0.0.1:$PANEL_PORT
if [ "$HTTP_PORT" = "80" ]; then
    PUBLIC_AUTHORITY=$HOST
else
    PUBLIC_AUTHORITY=$HOST:$HTTP_PORT
fi
PUBLIC_URL=$PUBLIC_SCHEME://$PUBLIC_AUTHORITY
if [ "$PUBLIC_SCHEME" = "https" ]; then
    COOKIE_SECURE=true
else
    COOKIE_SECURE=false
fi

SED_INSTALL=$(sed_repl "$INSTALL_DIR")
SED_ENV=$(sed_repl "$ENV_FILE")
SED_DATA=$(sed_repl "$DATA_DIR")
SED_ROUTES=$(sed_repl "$ROUTES")
SED_AUTH_ROUTES=$(sed_repl "$AUTH_ROUTES")
SED_HOST=$(sed_repl "$HOST")
SED_SERVICE=$(sed_repl "$SERVICE")

say "installing TunnelGate ($SERVICE)"
printf '     public name   %s\n' "$PUBLIC_URL"
printf '     this host     http://0.0.0.0:%s  ->  panel %s\n' "$HTTP_PORT" "$PANEL_URL"
printf '     routers       %s/<slug>/   (path mode, merged layout)\n' "$PUBLIC_URL"
printf '     sources       %s\n' "$INSTALL_DIR"
printf '     data          %s\n' "$DATA_DIR"
printf '     environment   %s\n' "$ENV_FILE"
if [ "$DRY_RUN" -eq 1 ]; then
    warn "DRY RUN: nothing will be installed, written or started"
fi

# ---------------------------------------------------------------- 1. preflight
say "checking the host"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}${ID_LIKE:-}" in
        *debian*|*ubuntu*) ok "${PRETTY_NAME:-Debian-family system}" ;;
        *) warn "${PRETTY_NAME:-unknown distribution}: this script uses apt and Debian paths" ;;
    esac
else
    warn "cannot read /etc/os-release; assuming a Debian-family system"
fi

# The two shipped vhosts both declare "map $http_upgrade $connection_upgrade", and
# nginx allows one map per target variable. Installing this one on top of the TLS one
# would either silently drop the panel's upgrade handling or fail "nginx -t" with a
# message that names neither file.
if [ -e /etc/nginx/sites-enabled/tunnelgate.conf ] && [ "$VHOST_ENABLED" != /etc/nginx/sites-enabled/tunnelgate.conf ]; then
    die "the TLS vhost (deploy/nginx/tunnelgate.conf) is already enabled on this host.
       This script installs the plain-HTTP vhost for a proxy that terminates TLS
       elsewhere, and the two cannot coexist: both declare the same map.
       Remove it first (rm /etc/nginx/sites-enabled/tunnelgate.conf), or use
       scripts/setup-server.sh if you wanted certificates on THIS host."
fi
if [ -e /etc/nginx/conf.d/tunnelgate.conf ]; then
    die "/etc/nginx/conf.d/tunnelgate.conf exists. Use one vhost only: this script
       writes $VHOST_AVAILABLE and enables it from sites-enabled."
fi

if command -v ss >/dev/null 2>&1; then
    if ss -Hltn "sport = :$HTTP_PORT" 2>/dev/null | grep -q .; then
        warn "something already listens on :$HTTP_PORT - nginx -t will reject the vhost"
        warn "  pass --port N to listen somewhere else"
    fi
    if ss -Hltn "sport = :$PANEL_PORT" 2>/dev/null | grep -q .; then
        warn "something already listens on :$PANEL_PORT (the panel port)"
        warn "  pass --panel-port N, or stop that process"
    fi
fi
# The shipped unit sets PrivateTmp=yes, which gives the service its own /tmp. A data
# directory under /tmp therefore cannot be mounted into the namespace, and the unit
# dies with "Failed to set up mount namespacing: ... No such file or directory" -
# a message that names the data dir but not the reason.
case "$DATA_DIR" in
    /tmp/*|/var/tmp/*)
        die "--data-dir under $DATA_DIR cannot be used by the service: the shipped
       unit sets PrivateTmp=yes, so systemd cannot mount a /tmp path into the
       namespace and the panel dies with status 226/NAMESPACE. Use /var/lib/... ."
        ;;
esac
case "$INSTALL_DIR" in
    /tmp/*|/var/tmp/*) warn "--install-dir is under /tmp: PrivateTmp=yes means the service sees its own /tmp, so $INSTALL_DIR may be invisible to it. Use /opt/... ." ;;
esac

[ -f "$REPO/requirements.txt" ] || die "$REPO/requirements.txt is missing: is this a full checkout?"
[ -f "$REPO/deploy/sshd/tunnelgate.conf" ] || die "$REPO/deploy/sshd/tunnelgate.conf is missing"
[ -f "$REPO/deploy/nginx/tunnelgate-behind-proxy.conf" ] || die "$REPO/deploy/nginx/tunnelgate-behind-proxy.conf is missing"

# ---------------------------------------------------------------- 2. packages
say "installing packages"
export DEBIAN_FRONTEND=noninteractive
if [ "$DRY_RUN" -eq 0 ]; then
    apt-get update -qq
    # iproute2 is a runtime dependency, not a convenience: the monitor reads
    # "ss -Hltnp" to learn which tunnels are listening and treats an empty answer as
    # "cannot see anything". openssh-server is the tunnel endpoint. Deliberately no
    # certbot (TLS is the proxy's job here) and no ufw dependency.
    apt-get install -y -qq --no-install-recommends \
        ca-certificates curl rsync nginx openssl python3 python3-venv python3-pip \
        sqlite3 openssh-server openssh-client iproute2 >/dev/null
    ok "packages present"
    if ! command -v npm >/dev/null 2>&1; then
        apt-get install -y -qq --no-install-recommends nodejs npm >/dev/null 2>&1 || true
    fi
    if command -v npm >/dev/null 2>&1; then
        ok "node $(node --version 2>/dev/null || echo '?') / npm $(npm --version 2>/dev/null || echo '?')"
    else
        warn "no npm: the SPA cannot be built here, so the panel will serve the API and no UI"
        warn "install nodejs and npm, then re-run this script"
    fi
fi

# ---------------------------------------------------------------- 3. tunnel user
say "creating the tunnel user"
if id tunnelgate >/dev/null 2>&1; then
    ok "user tunnelgate already exists"
else
    run useradd --system --create-home --home-dir "$DATA_DIR" \
        --shell /usr/sbin/nologin --comment "TunnelGate reverse tunnels" tunnelgate
    ok "user tunnelgate created"
fi
# A useradd-created account carries '!' in the shadow password field, and sshd with
# "UsePAM no" then refuses it outright with "account is locked" - which looks exactly
# like a broken key. '*' keeps password logins impossible while public-key auth works.
if [ "$DRY_RUN" -eq 0 ]; then
    usermod -p '*' tunnelgate 2>/dev/null || true
fi
run install -d -m 0755 -o tunnelgate -g tunnelgate "$DATA_DIR"
run install -d -m 0700 -o tunnelgate -g tunnelgate "$DATA_DIR/.ssh"
if [ ! -f "$AUTHORIZED_KEYS" ]; then
    run install -m 0600 -o tunnelgate -g tunnelgate /dev/null "$AUTHORIZED_KEYS"
fi
ok "authorized_keys at $AUTHORIZED_KEYS"

# ---------------------------------------------------------------- 4. sshd
say "installing the sshd drop-in"
if ! grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config 2>/dev/null; then
    warn "/etc/ssh/sshd_config does not include sshd_config.d - adding it at the top"
    if [ "$DRY_RUN" -eq 0 ]; then
        cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%s)"
        printf 'Include /etc/ssh/sshd_config.d/*.conf\n\n' | cat - /etc/ssh/sshd_config \
            > /etc/ssh/sshd_config.new
        mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config
        chmod 0644 /etc/ssh/sshd_config
    fi
fi
run install -d -m 0755 /etc/ssh/sshd_config.d
if [ "$DRY_RUN" -eq 0 ]; then
    install -m 0644 "$REPO/deploy/sshd/tunnelgate.conf" /etc/ssh/sshd_config.d/tunnelgate.conf
    # sshd -t refuses to run without its privilege-separation directory, which ssh.service
    # normally creates at boot. On a host where sshd is not running yet, "Missing privilege
    # separation directory: /run/sshd" would abort the install for no real reason.
    install -d -m 0755 /run/sshd
    # Never reload a config that does not parse: a broken Match block locks the operator
    # out of the machine, and the symptom looks like a network fault, not a config fault.
    if ! sshd -t 2>/tmp/tg-sshd.err; then
        echo "sshd rejected the configuration, NOT reloading:" >&2
        cat /tmp/tg-sshd.err >&2
        echo "the drop-in is at /etc/ssh/sshd_config.d/tunnelgate.conf" >&2
        exit 1
    fi
    # Reload, then PROVE that :22 still answers. Both halves matter:
    #   - sshd -t passing does not mean the listener comes back. On some LXC images the
    #     first reload after a drop-in appears dies with "fatal: Cannot bind any address"
    #     and systemd has to restart the unit. Without a listener check the install would
    #     report success while new SSH logins are refused, which on a box the operator is
    #     reaching over SSH looks like a network fault, not an install step.
    #   - Escalating to restart is a last resort, not the default: a reload keeps every
    #     existing connection alive even on hosts where KillMode=stop-on-failure would
    #     tear down children on a restart. Only take it when :22 is actually gone.
    ssh_listening() {
        ss -ltn 2>/dev/null | grep -Eq '[:.]22[[:space:]]'
    }
    wait_for_ssh() {
        attempt=0
        while [ "$attempt" -lt 10 ]; do
            ssh_listening && return 0
            attempt=$((attempt + 1))
            sleep 1
        done
        return 1
    }
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    if wait_for_ssh; then
        ok "sshd accepts the drop-in, was reloaded and :22 is listening"
    elif systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
        if wait_for_ssh; then
            ok "sshd accepts the drop-in; a reload lost the listener and a restart restored it"
        else
            warn "sshd -t accepts the drop-in, but nothing is listening on :22 after a restart."
            warn "  KEEP THIS SHELL OPEN - your session survives, new logins do not."
            warn "  Recover with: systemctl restart ssh"
            warn "  Then: journalctl -u ssh -n 50 --no-pager; sshd -T | grep -i permitlisten"
        fi
    else
        warn "could not reload or restart ssh/sshd."
        warn "  KEEP THIS SHELL OPEN. Check: systemctl status ssh; sshd -t"
    fi
fi

# ---------------------------------------------------------------- 5. dirs + env
say "preparing directories and the environment file"
# The panel writes routes.conf with write-temp-then-rename, so it needs CREATE on the
# DIRECTORY. A root:root 0755 directory makes every monitor cycle fail with
# PermissionError while the panel keeps serving stale routes and looks healthy.
run install -d -m 0750 -o tunnelgate -g tunnelgate "$ROUTES_DIR"
run install -d -m 0755 -o tunnelgate -g tunnelgate /var/backups/tunnelgate
run install -d -m 0755 "$(dirname "$ENV_FILE")"
run install -d -m 0755 "$INSTALL_DIR"

if [ -f "$ENV_FILE" ]; then
    ok "$ENV_FILE already exists - leaving it alone"
    SECRET=$(grep -E '^TUNNELGATE_SECRET_KEY=' "$ENV_FILE" | cut -d= -f2- || true)
    ADMIN_PW=$(grep -E '^TUNNELGATE_ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2- || true)
    if ! grep -q '^TUNNELGATE_COOKIE_SECURE=' "$ENV_FILE"; then
        if [ "$DRY_RUN" -eq 0 ]; then
            printf '\nTUNNELGATE_COOKIE_SECURE=%s\n' "$COOKIE_SECURE" >>"$ENV_FILE"
        fi
        ok "added TUNNELGATE_COOKIE_SECURE=$COOKIE_SECURE"
    fi
else
    if [ -n "$ADMIN_PASSWORD" ]; then
        ADMIN_PW=$ADMIN_PASSWORD
    else
        ADMIN_PW=$(openssl rand -base64 24 | tr -d '/+=\n' | cut -c1-24)
    fi
    SECRET=$(openssl rand -base64 48 | tr -d '\n')
    if [ "$DRY_RUN" -eq 0 ]; then
        install -m 0600 /dev/null "$ENV_FILE"
        cat >"$ENV_FILE" <<ENVEOF
# TunnelGate - written by scripts/quick-install.sh on $(date -u '+%Y-%m-%dT%H:%M:%SZ').
# This script never overwrites an existing environment file: edit in place instead.
# Full reference: docs/INSTALL_SERVER.md section 5.
TUNNELGATE_ENV=production
TUNNELGATE_LOG_LEVEL=info

# --- panel ---------------------------------------------------------------
# PANEL_URL is what THIS host's nginx forwards to. Loopback on purpose: a public
# name here would make nginx dial out through your proxy and back, so every
# request would arrive twice and the redirects would fight the proxy.
TUNNELGATE_PANEL_URL=$PANEL_URL
# The name a BROWSER uses, i.e. what your proxy answers on. Every redirect the
# panel writes names it, and it is the address in the routers' install command.
TUNNELGATE_PANEL_HOST=$HOST
TUNNELGATE_PUBLIC_URL=$PUBLIC_URL
TUNNELGATE_SUBDOMAIN_SUFFIX=$HOST
TUNNELGATE_COOKIE_SECURE=$COOKIE_SECURE

# --- router addressing ---------------------------------------------------
# path: every router is <public-url>/<slug>/ - one name, no wildcard DNS, no
# per-router certificate. That is the point of this install shape.
TUNNELGATE_ROUTE_MODE=path
# Equal to PANEL_HOST, i.e. the MERGED layout: routes.conf then holds locations
# only and is included INSIDE the panel server block, which is what
# deploy/nginx/tunnelgate-behind-proxy.conf does. A path is not an origin
# boundary (docs/SECURITY.md 6.1): a hostile router page shares this origin.
TUNNELGATE_GATEWAY_HOST=$HOST

# --- real client addresses ----------------------------------------------
# The only peer the panel sees is this host's nginx, which is loopback and is
# therefore trusted. Anything else falls back to the socket peer.
# Single quotes are deliberate: the value is a JSON list, and this file is read by
# systemd AND sourced by sh. Unquoted, sh tries to expand it as a glob and the
# installer dies mid-run; double-quoted, systemd leaves the inner quotes in and the
# panel fails to parse the list.
TUNNELGATE_TRUSTED_PROXIES='["127.0.0.1", "::1"]'
# How many proxies append X-Forwarded-For. This host's nginx is one of them and
# always appends. With 1 the address in the audit log and the login rate-limit
# bucket is YOUR PROXY's, which is unforgeable. Set 2 only once your edge appends
# the client address AND :$HTTP_PORT is reachable from that edge alone; otherwise
# a client can type any address it likes into the header and the panel believes it.
TUNNELGATE_FORWARDED_ALLOW_HOPS=$PROXY_HOPS

# --- storage ------------------------------------------------------------
TUNNELGATE_DB_URL=sqlite:///$DATA_DIR/tunnelgate.db
TUNNELGATE_DATA_DIR=$DATA_DIR

# --- ssh ----------------------------------------------------------------
TUNNELGATE_SSH_HOST=127.0.0.1
TUNNELGATE_SSH_USER=tunnelgate
TUNNELGATE_AUTHORIZED_KEYS_PATH=$AUTHORIZED_KEYS
# Empty: authorized_keys is re-read on the next authentication, so a new key
# works without a reload.
TUNNELGATE_SSHD_RELOAD_COMMAND=

# --- ports (loopback only, NEVER opened in the firewall) -----------------
TUNNELGATE_BIND_ADDRESS=127.0.0.1
TUNNELGATE_PORT=$PANEL_PORT
TUNNELGATE_PORT_MIN=20000
TUNNELGATE_PORT_MAX=25000
TUNNELGATE_CONSOLE_PORT_MIN=25001
TUNNELGATE_CONSOLE_PORT_MAX=30000
TUNNELGATE_CONSOLE_ENABLED=true

# --- proxy --------------------------------------------------------------
TUNNELGATE_PROXY_DRIVER=nginx
TUNNELGATE_PROXY_ROUTES_PATH=$ROUTES
# Empty on purpose: the panel unit sets NoNewPrivileges=yes, so the panel cannot
# signal the root nginx master. $SERVICE-nginx-reload.path does that, as root.
TUNNELGATE_PROXY_RELOAD_COMMAND=

# --- secrets ------------------------------------------------------------
# Generated once. Back these up separately: losing SECRET_KEY invalidates every
# stored console key; ADMIN_PASSWORD can be reset with "app.cli seed-admin".
TUNNELGATE_SECRET_KEY=$SECRET
TUNNELGATE_ADMIN_PASSWORD=$ADMIN_PW
ENVEOF
        chmod 0600 "$ENV_FILE"
        ok "wrote $ENV_FILE"
    else
        printf '  [dry-run] generate %s (mode 0600) with a fresh SECRET_KEY and admin password\n' "$ENV_FILE"
    fi
fi

# ---------------------------------------------------------------- 6. sources
say "installing the sources into $INSTALL_DIR"
if [ "$REPO" = "$INSTALL_DIR" ]; then
    ok "already running from $INSTALL_DIR"
else
    if [ "$DRY_RUN" -eq 0 ]; then
        # --delete keeps an upgrade honest. The exclusions are what the install owns or
        # rebuilds: a venv is not portable, node_modules is regenerated, data is not
        # source, .git is not deployed.
        rsync -a --delete \
            --exclude '.venv/' --exclude 'web/node_modules/' --exclude 'web/dist/' \
            --exclude 'data/' --exclude '.git/' --exclude '*.db' --exclude '*.db-wal' \
            --exclude '*.db-shm' --exclude '__pycache__/' --exclude '*.pyc' \
            "$REPO/" "$INSTALL_DIR/"
        ok "sources copied"
    fi
fi
run chown -R tunnelgate:tunnelgate "$INSTALL_DIR"

say "creating the virtualenv"
if [ -x "$INSTALL_DIR/.venv/bin/python" ]; then
    ok "virtualenv already exists"
elif [ "$DRY_RUN" -eq 0 ]; then
    python3 -m venv "$INSTALL_DIR/.venv"
    "$INSTALL_DIR/.venv/bin/pip" install --upgrade pip >/dev/null
    "$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" >/dev/null
    chown -R tunnelgate:tunnelgate "$INSTALL_DIR/.venv"
    ok "virtualenv ready"
fi

say "building the SPA"
if [ -f "$INSTALL_DIR/web/dist/index.html" ] && \
   [ -z "$(find "$INSTALL_DIR/web" \( -name node_modules -o -name dist \) -prune -o \
            -type f -newer "$INSTALL_DIR/web/dist/index.html" -print 2>/dev/null | head -n 1)" ]; then
    ok "web/dist is up to date"
elif [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] build the SPA as tunnelgate in %s\n' "$INSTALL_DIR/web"
elif command -v npm >/dev/null 2>&1; then
    # As the service user: a root-owned node_modules or dist is a permission trap on
    # the next upgrade (npm ci refuses, and the panel cannot read what root wrote).
    if runuser -u tunnelgate -- env HOME="$DATA_DIR" sh -c \
            "cd '$INSTALL_DIR/web' && npm ci --no-audit --no-fund >/dev/null 2>&1 && npm run build >/dev/null 2>&1"; then
        ok "SPA built into web/dist"
    else
        warn "the SPA build failed; run it by hand to see why:"
        warn "  cd $INSTALL_DIR/web && npm ci && npm run build"
    fi
    [ -f "$INSTALL_DIR/web/dist/index.html" ] || warn "no web/dist/index.html: the panel will serve the API and no UI"
fi

# ---------------------------------------------------------------- 7. database
# The panel owns its database: running these as root would leave a root-owned sqlite
# file the service user cannot write, and the first write fails at runtime.
panel_cli() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  [dry-run] (as tunnelgate) app.cli %s\n' "$*"
        return 0
    fi
    runuser -u tunnelgate --preserve-environment -- \
        "$INSTALL_DIR/.venv/bin/python" -m app.cli "$@"
}

say "initialising the database"
if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] (as tunnelgate) init-db, then seed-admin, against sqlite://%s\n' "$DATA_DIR/tunnelgate.db"
else
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
    cd "$INSTALL_DIR"
    panel_cli init-db || die "init-db failed (see the error above)"
    if [ -n "${ADMIN_PW:-}" ]; then
        panel_cli seed-admin --password "$ADMIN_PW" >/dev/null || die "seed-admin failed"
        ok "admin user seeded from TUNNELGATE_ADMIN_PASSWORD"
    else
        warn "no admin password available; run: $INSTALL_DIR/.venv/bin/python -m app.cli seed-admin"
    fi
fi

# ---------------------------------------------------------------- 8. systemd
say "installing the systemd units"
if [ "$DRY_RUN" -eq 0 ]; then
    # The shipped units hardcode /opt/tunnelgate, /etc/tunnelgate.env and the default
    # routes path. Rewriting them keeps one source of truth in deploy/systemd while
    # still allowing a second instance on the same host.
    render_service() {
        sed -e "s#/opt/tunnelgate#$SED_INSTALL#g" \
            -e "s#/etc/tunnelgate\.env#$SED_ENV#g" \
            -e "s#/var/lib/tunnelgate#$SED_DATA#g" \
            -e "s#/etc/nginx/tunnelgate/routes\.auth\.conf#$SED_AUTH_ROUTES#g" \
            -e "s#/etc/nginx/tunnelgate/routes\.conf#$SED_ROUTES#g" \
            -e "s#--port 8080#--port $PANEL_PORT#g" \
            "$1"
    }
    render_service "$REPO/deploy/systemd/tunnelgate.service" >"/etc/systemd/system/$SERVICE.service"
    render_service "$REPO/deploy/systemd/tunnelgate-nginx-reload.service" \
        >"/etc/systemd/system/$SERVICE-nginx-reload.service"
    sed -e "s#Unit=tunnelgate-nginx-reload\.service#Unit=$SED_SERVICE-nginx-reload.service#" \
        -e "s#/etc/nginx/tunnelgate/routes\.auth\.conf#$SED_AUTH_ROUTES#g" \
        -e "s#/etc/nginx/tunnelgate/routes\.conf#$SED_ROUTES#g" \
        "$REPO/deploy/systemd/tunnelgate-nginx-reload.path" \
        >"/etc/systemd/system/$SERVICE-nginx-reload.path"
    chmod 0644 "/etc/systemd/system/$SERVICE.service" \
        "/etc/systemd/system/$SERVICE-nginx-reload.service" \
        "/etc/systemd/system/$SERVICE-nginx-reload.path"
    systemctl daemon-reload
    systemctl enable "$SERVICE" >/dev/null 2>&1 || true
    systemctl restart "$SERVICE"
    systemctl enable --now "$SERVICE-nginx-reload.path" >/dev/null 2>&1 || true
    # "systemctl restart" returns as soon as the unit is ACTIVE, so a panel that dies on
    # its first bind - the panel port already taken, a DATABASE_URL it cannot open - still
    # looks started here. A live test hit exactly that: the script printed "started,
    # listening on ..." and exited 0 while the service was in auto-restart, and the first
    # sign of trouble was a 404 from nginx three sections later. Ask the panel instead.
    attempt=0
    panel_ready=0
    while [ "$attempt" -lt 10 ]; do
        if curl -fsS -o /dev/null --max-time 2 "$PANEL_URL/api/v1/health" 2>/dev/null; then
            panel_ready=1
            break
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    if [ "$panel_ready" -eq 1 ]; then
        ok "$SERVICE started and answers on $PANEL_URL"
    else
        echo "the panel did not answer on $PANEL_URL within 10s:" >&2
        journalctl -u "$SERVICE" -n 20 --no-pager >&2 2>/dev/null || true
        die "the unit is installed but the panel is not serving.
       The usual cause is something already listening on :$PANEL_PORT (the preflight
       warning names it if so): pick another port with --panel-port N and run again.
       To look instead of reinstalling:
         systemctl status $SERVICE
         journalctl -u $SERVICE -n 50 --no-pager"
    fi
fi

# ---------------------------------------------------------------- 9. nginx
say "installing the plain-HTTP vhost on :$HTTP_PORT"
if [ "$DRY_RUN" -eq 0 ]; then
    # Substitutions: the listen port, the panel upstream, the name the CSP names for
    # the console WebSocket, and the routes include the panel generates.
    sed -e "s#listen 80 default_server;#listen $HTTP_PORT default_server;#" \
        -e "s#listen \[::\]:80 default_server;#listen [::]:$HTTP_PORT default_server;#" \
        -e "s#127\.0\.0\.1:8080#127.0.0.1:$PANEL_PORT#g" \
        -e "s#panel\.example\.com#$SED_HOST#g" \
        -e "s#/etc/nginx/tunnelgate/routes\.conf#$SED_ROUTES#g" \
        "$REPO/deploy/nginx/tunnelgate-behind-proxy.conf" >"$VHOST_AVAILABLE"
    chmod 0644 "$VHOST_AVAILABLE"
    ln -sf "$VHOST_AVAILABLE" "$VHOST_ENABLED"
    # nginx refuses to start when an include target is missing, so seed both generated
    # files before the first nginx -t. They belong to the panel's account: the write is
    # temp+rename inside a directory that account owns.
    for f in "$ROUTES" "$AUTH_ROUTES"; do
        if [ ! -f "$f" ]; then
            printf '# GENERATED by TunnelGate - DO NOT EDIT.\n' >"$f"
        fi
        chown tunnelgate:tunnelgate "$f" 2>/dev/null || true
        chmod 0640 "$f"
    done
    # The stock Debian vhost claims :80 as default_server, so it collides with the
    # listen line above when --port is 80. Moved aside (never deleted: it is a
    # distribution file), and moved straight back if nginx rejects the result, so a
    # failed install leaves the web server exactly as it found it.
    moved_default=""
    if [ -e /etc/nginx/sites-enabled/default ]; then
        moved_default=/etc/nginx/sites-available/default.disabled.$(date +%s)
        mv /etc/nginx/sites-enabled/default "$moved_default"
        ok "moved the stock nginx default vhost aside"
    fi
    if ! nginx -t 2>/tmp/tg-nginx.err; then
        echo "nginx rejected the configuration:" >&2
        cat /tmp/tg-nginx.err >&2
        echo "the vhost is at $VHOST_AVAILABLE" >&2
        if [ -n "$moved_default" ]; then
            mv "$moved_default" /etc/nginx/sites-enabled/default
            echo "restored /etc/nginx/sites-enabled/default" >&2
        fi
        exit 1
    fi
    # Reload, or start when it is not running. On a host where something else holds
    # :80 (a container, usually) nginx.service is failed while a stray master serves
    # traffic; a bare "systemctl reload" then prints "nginx.service is not active,
    # cannot reload" and the install stops with an unhelpful message.
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx
        ok "nginx accepts the vhost and was reloaded"
    elif systemctl start nginx 2>/dev/null; then
        ok "nginx accepts the vhost and was started"
    else
        warn "nginx -t accepts the vhost, but nginx.service could not be started."
        warn "  Something else already owns :$HTTP_PORT (a container?). Point your"
        warn "  reverse proxy at that listener, or move it and run: systemctl start nginx"
    fi
fi

# ---------------------------------------------------------------- 10. firewall
say "firewall"
if [ "$SKIP_FIREWALL" -eq 1 ]; then
    warn "skipped (--skip-firewall). Open exactly one port yourself: $HTTP_PORT/tcp"
elif [ "$DRY_RUN" -eq 0 ] && command -v ufw >/dev/null 2>&1; then
    ufw allow "$HTTP_PORT"/tcp >/dev/null
    ufw --force enable >/dev/null
    # Deliberately NOT opened: 20000-25000 (LuCI tunnels) and 25001-30000 (console).
    # Both are sshd listeners on 127.0.0.1 for the tunnel user. Publishing them gives
    # the internet direct, unauthenticated access to every router's LuCI and every
    # console port, which bypasses the panel's authentication entirely.
    ok "ufw allows $HTTP_PORT/tcp only; the tunnel and console pools stay closed"
else
    warn "ufw is not installed, so no firewall rule was added."
    warn "Open $HTTP_PORT/tcp to your proxy and NOTHING ELSE. In particular do NOT open"
    warn "20000-25000 (tunnel pool) or 25001-30000 (console pool): both are loopback"
    warn "sshd listeners, and exposing them bypasses the panel entirely."
fi

# ---------------------------------------------------------------- 11. verify
say "verifying"
if [ "$DRY_RUN" -eq 1 ]; then
    warn "dry run: nothing was started, so there is nothing to verify"
else
    health=http://127.0.0.1:$HTTP_PORT/api/v1/health
    attempt=0
    code=""
    while [ "$attempt" -lt 15 ]; do
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$health" 2>/dev/null || true)
        [ "$code" = "200" ] && break
        attempt=$((attempt + 1))
        sleep 1
    done
    if [ "$code" = "200" ]; then
        ok "the panel answers through nginx: $health -> 200"
    else
        warn "no 200 from $health (last code: ${code:-none})"
        warn "  systemctl status $SERVICE"
        warn "  journalctl -u $SERVICE -n 50 --no-pager"
        warn "  tail -n 50 /var/log/nginx/error.log"
    fi
    cd "$INSTALL_DIR"
    panel_cli doctor 2>/dev/null | tail -n 8 || true
fi

# ---------------------------------------------------------------- 12. summary
cat <<SUMMARY

TunnelGate is installed on this host.

  through nginx (your proxy forwards here)   http://127.0.0.1:$HTTP_PORT
  public name                                $PUBLIC_URL
  routers                                    $PUBLIC_URL/<slug>/
  admin user                                 admin
  admin password                             $ENV_FILE -> TUNNELGATE_ADMIN_PASSWORD (mode 0600)
  environment                                $ENV_FILE
  data                                       $DATA_DIR
  routes                                     $ROUTES  (generated, never edit)
  services                                   $SERVICE.service, $SERVICE-nginx-reload.path
  logs                                       journalctl -u $SERVICE -f

NEXT: point your reverse proxy at http://<this host>:$HTTP_PORT

  It must forward the Host header AND pass the client address and the original
  scheme, or every audit row and rate limit names the proxy and the session cookie
  is not marked Secure:

      proxy_set_header Host              \$host;
      proxy_set_header X-Real-IP         \$remote_addr;
      proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto \$scheme;

  nginx on your edge:

      server {
          listen 443 ssl;
          http2 on;
          server_name $PUBLIC_AUTHORITY;
          ssl_certificate     /etc/letsencrypt/live/$HOST/fullchain.pem;
          ssl_certificate_key /etc/letsencrypt/live/$HOST/privkey.pem;
          client_max_body_size 64m;
          location / {
              proxy_pass http://<this host>:$HTTP_PORT;
              proxy_http_version 1.1;
              proxy_set_header Host              \$host;
              proxy_set_header X-Real-IP         \$remote_addr;
              proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto \$scheme;
              proxy_set_header Upgrade           \$http_upgrade;
              proxy_set_header Connection        "upgrade";
              proxy_read_timeout 3600s;
              proxy_buffering off;
          }
      }

  Caddy on your edge:

      $PUBLIC_AUTHORITY {
          reverse_proxy http://<this host>:$HTTP_PORT
      }

  Two things your edge must not do:
    * must not strip X-Forwarded-For. Without it the panel cannot record a client
      address, and every login shares one rate-limit bucket.
    * must not expose :$HTTP_PORT on this host to the internet. It speaks plain HTTP
      and has no client authentication of its own; your proxy is its only peer.

  Verify end to end once the edge is up:

      curl -fsS $PUBLIC_URL/api/v1/health

SECURITY NOTES
  * Routers share the panel's origin in this layout (path mode, one name), so a
    hostile or compromised router page can act as a signed-in operator. Read
    docs/SECURITY.md 6.1 before adding routers you do not physically control.
    Putting the gateway on its own name removes this; see docs/INSTALL_SERVER.md 6.
  * The audit log records the address your proxy reports. With --proxy-hops 1 that is
    the proxy's own, which is unforgeable but shared by every client.
  * The tunnel and console pools stay CLOSED. Confirm sshd honours the drop-in:
      ss -ltnp | grep -E ':(2[0-9]{4})'     # every socket must be bound to 127.0.0.1
  * Back up, separately and together: $DATA_DIR/tunnelgate.db,
    $DATA_DIR/.ssh/authorized_keys, and TUNNELGATE_SECRET_KEY from $ENV_FILE.
    Losing the secret key invalidates every stored console key.

SUMMARY
