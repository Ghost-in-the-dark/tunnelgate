#!/bin/sh
# TunnelGate server bootstrap (Debian/Ubuntu).
#
# Automates docs/INSTALL_SERVER.md sections 1-6. It is idempotent: running it twice
# changes nothing the second time, and it never overwrites an existing secret.
#
# Usage:
#   sudo ./scripts/setup-server.sh --host panel.example.com --email you@example.com
#   sudo ./scripts/setup-server.sh --host panel.example.com --email you@example.com --skip-cert
#   sudo ./scripts/setup-server.sh --help
#
# What it does, in order:
#   1. installs the apt packages the panel and nginx need
#   2. creates the unprivileged tunnel user and its .ssh directory
#   3. installs deploy/sshd/tunnelgate.conf and validates it with sshd -t BEFORE reloading
#   4. creates the data dirs, writes /etc/tunnelgate.env (secrets generated, never overwritten)
#   5. installs the systemd units and starts the panel
#   6. initialises the database and seeds the admin user
#   7. installs the nginx vhost and the route include directory
#   8. requests the wildcard certificate (DNS-01, optional) and reloads nginx
#
# FIREWALL - the part people get wrong:
#   Only 22/tcp (or your SSH port), 80/tcp and 443/tcp are ever opened. The tunnel pool
#   (20000-25000) and the console pool (25001-30000) stay CLOSED. Both are listeners that
#   sshd creates on 127.0.0.1 for the tunnel user; nothing outside the host can reach them,
#   and opening them would publish every router's LuCI and every console port directly to
#   the internet, bypassing the panel's authentication entirely.
#   Verify at any time with:  ss -ltnp | grep -E ':(2[0-9]{4})'
#   Every one of those sockets must show 127.0.0.1 as its local address.

set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
HOST=""
EMAIL=""
SKIP_CERT=0
SSH_PORT=22

usage() {
    sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST=${2:?--host needs a value}; shift 2 ;;
        --email) EMAIL=${2:?--email needs a value}; shift 2 ;;
        --ssh-port) SSH_PORT=${2:?--ssh-port needs a value}; shift 2 ;;
        --skip-cert) SKIP_CERT=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "run this as root (it installs packages and units)" >&2
    exit 1
fi
if [ -z "$HOST" ]; then
    echo "--host is required, e.g. --host panel.example.com" >&2
    exit 2
fi

# The shipped systemd unit hardcodes WorkingDirectory=/opt/tunnelgate. Installing from
# anywhere else would start the service in the wrong directory, so say so up front.
if [ "$REPO" != "/opt/tunnelgate" ]; then
    printf '\033[1;33m  !\033[0m repo is %s, but deploy/systemd/tunnelgate.service expects /opt/tunnelgate\n' "$REPO"
    printf '    either move the checkout to /opt/tunnelgate, or edit WorkingDirectory/ExecStart in the unit.\n'
fi

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()  { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  !\033[0m %s\n' "$*"; }

ENV_FILE=/etc/tunnelgate.env
DATA_DIR=/var/lib/tunnelgate
ROUTES_DIR=/etc/nginx/tunnelgate

# ------------------------------------------------------------------ 1. packages
say "installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    ca-certificates curl nginx python3 python3-venv python3-pip \
    sqlite3 certbot openssh-server ufw jq >/dev/null
ok "packages present"

# ------------------------------------------------------------------ 2. tunnel user
say "creating the tunnel user"
if id tunnelgate >/dev/null 2>&1; then
    ok "user tunnelgate already exists"
else
    useradd --system --create-home --home-dir "$DATA_DIR" \
        --shell /usr/sbin/nologin --comment "TunnelGate reverse tunnels" tunnelgate
    ok "user tunnelgate created"
fi
install -d -m 0755 -o tunnelgate -g tunnelgate "$DATA_DIR/.ssh"
if [ ! -f "$DATA_DIR/.ssh/authorized_keys" ]; then
    install -m 0600 -o tunnelgate -g tunnelgate "$DATA_DIR"/.ssh/authorized_keys.tmp 2>/dev/null || true
    install -m 0600 -o tunnelgate -g tunnelgate /dev/null "$DATA_DIR/.ssh/authorized_keys"
fi
chown tunnelgate:tunnelgate "$DATA_DIR/.ssh/authorized_keys"
chmod 0600 "$DATA_DIR/.ssh/authorized_keys"
ok "authorized_keys ready at $DATA_DIR/.ssh/authorized_keys"

# ------------------------------------------------------------------ 3. sshd drop-in
say "installing the sshd drop-in"
if ! grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config; then
    warn "/etc/ssh/sshd_config does not include sshd_config.d - adding it at the top"
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%s)"
    printf 'Include /etc/ssh/sshd_config.d/*.conf\n\n' | cat - /etc/ssh/sshd_config \
        > /etc/ssh/sshd_config.new
    mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config
    chmod 0644 /etc/ssh/sshd_config
fi
install -m 0644 "$REPO/deploy/sshd/tunnelgate.conf" /etc/ssh/sshd_config.d/tunnelgate.conf
# never reload a config that does not parse: a broken Match block locks the operator out
if ! sshd -t 2>/tmp/sshd_test.err; then
    echo "sshd rejected the config, NOT reloading:" >&2
    cat /tmp/sshd_test.err >&2
    echo "the broken drop-in is at /etc/ssh/sshd_config.d/tunnelgate.conf" >&2
    exit 1
fi
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
ok "sshd accepts the drop-in and was reloaded"

# ------------------------------------------------------------------ 4. data dirs + env
say "preparing data directories and the environment file"
install -d -m 0755 -o tunnelgate -g tunnelgate "$DATA_DIR"
# The panel writes routes.conf atomically (temp file + rename) so it must be able to
# CREATE files here; nginx reads the include as root, so 0750 is enough. A root-owned
# directory makes every monitor cycle fail with PermissionError.
install -d -m 0750 -o tunnelgate -g tunnelgate "$ROUTES_DIR"
install -d -m 0755 -o tunnelgate -g tunnelgate /var/backups/tunnelgate

if [ -f "$ENV_FILE" ]; then
    ok "$ENV_FILE already exists - leaving it alone"
    SECRET=$(grep -E '^TUNNELGATE_SECRET_KEY=' "$ENV_FILE" | cut -d= -f2- || true)
    ADMIN_PW=$(grep -E '^TUNNELGATE_ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2- || true)
else
    SECRET=$(openssl rand -base64 48 | tr -d '\n')
    ADMIN_PW=$(openssl rand -base64 24 | tr -d '\n')
    install -m 0600 /dev/null "$ENV_FILE"
    cat >"$ENV_FILE" <<EOF
TUNNELGATE_ENV=production
TUNNELGATE_LOG_LEVEL=info

# --- panel ---
TUNNELGATE_PANEL_URL=https://$HOST
TUNNELGATE_PANEL_HOST=$HOST
TUNNELGATE_SUBDOMAIN_SUFFIX=$HOST
TUNNELGATE_COOKIE_SECURE=true
TUNNELGATE_COOKIE_DOMAIN=.$HOST

# --- storage ---
TUNNELGATE_DB_URL=sqlite:///$DATA_DIR/tunnelgate.db
TUNNELGATE_DATA_DIR=$DATA_DIR

# --- ssh ---
TUNNELGATE_SSH_HOST=127.0.0.1
TUNNELGATE_SSH_PORT=$SSH_PORT
TUNNELGATE_SSH_USER=tunnelgate
TUNNELGATE_AUTHORIZED_KEYS_PATH=$DATA_DIR/.ssh/authorized_keys
TUNNELGATE_SSHD_RELOAD_COMMAND=

# --- ports (loopback only, NEVER opened in the firewall) ---
TUNNELGATE_PORT_MIN=20000
TUNNELGATE_PORT_MAX=25000
TUNNELGATE_CONSOLE_PORT_MIN=25001
TUNNELGATE_CONSOLE_PORT_MAX=30000

# --- proxy ---
TUNNELGATE_PROXY_DRIVER=nginx
TUNNELGATE_PROXY_ROUTES_PATH=$ROUTES_DIR/routes.conf
# Empty on purpose: the systemd unit sets NoNewPrivileges, so the panel cannot sudo to
# signal the root nginx master. tunnelgate-nginx-reload.path runs the reload as root.
TUNNELGATE_PROXY_RELOAD_COMMAND=

# --- secrets (generated once, back these up separately) ---
TUNNELGATE_SECRET_KEY=$SECRET
TUNNELGATE_ADMIN_PASSWORD=$ADMIN_PW
EOF
    chmod 0600 "$ENV_FILE"
    ok "wrote $ENV_FILE"
fi

# ------------------------------------------------------------------ 5. sources + venv
if [ ! -d "$REPO/.venv" ]; then
    say "creating the virtualenv"
    python3 -m venv "$REPO/.venv"
    "$REPO/.venv/bin/pip" install --upgrade pip >/dev/null
    "$REPO/.venv/bin/pip" install -r "$REPO/requirements.txt" >/dev/null
    ok "virtualenv ready"
else
    ok "virtualenv already exists"
fi

# ------------------------------------------------------------------ 6. database
say "initialising the database"
set -a; . "$ENV_FILE"; set +a
# app.cli is imported as a module, so the cwd has to be the repo, not the caller's.
cd "$REPO"
"$REPO/.venv/bin/python" -m app.cli init-db
"$REPO/.venv/bin/python" -m app.cli seed-admin --password "$TUNNELGATE_ADMIN_PASSWORD"
ok "database ready (admin user seeded from TUNNELGATE_ADMIN_PASSWORD)"

# ------------------------------------------------------------------ 7. systemd
say "installing and starting the panel service"
install -m 0644 "$REPO/deploy/systemd/tunnelgate.service" /etc/systemd/system/tunnelgate.service
install -m 0644 "$REPO/deploy/systemd/tunnelgate-nginx-reload.service" \
    /etc/systemd/system/tunnelgate-nginx-reload.service
install -m 0644 "$REPO/deploy/systemd/tunnelgate-nginx-reload.path" \
    /etc/systemd/system/tunnelgate-nginx-reload.path
systemctl daemon-reload
systemctl enable --now tunnelgate
systemctl enable --now tunnelgate-nginx-reload.path
ok "panel started (127.0.0.1:8080)"

# ------------------------------------------------------------------ 8. nginx
say "installing the nginx vhost"
install -m 0644 "$REPO/deploy/nginx/tunnelgate.conf" /etc/nginx/sites-available/tunnelgate.conf
ln -sf /etc/nginx/sites-available/tunnelgate.conf /etc/nginx/sites-enabled/tunnelgate.conf
rm -f /etc/nginx/sites-enabled/default
# nginx refuses to start when an include target is missing, so seed both generated files
for f in "$ROUTES_DIR/routes.conf" "$ROUTES_DIR/routes.auth.conf"; do
    if [ ! -f "$f" ]; then
        printf '# GENERATED by TunnelGate - DO NOT EDIT.\n' > "$f"
    fi
    chmod 0640 "$f"
done
chgrp tunnelgate "$ROUTES_DIR/routes.conf" "$ROUTES_DIR/routes.auth.conf" 2>/dev/null || true
# the panel regenerates these on the first monitor cycle
if ! nginx -t 2>/tmp/nginx_test.err; then
    echo "nginx rejected the shipped config:" >&2
    cat /tmp/nginx_test.err >&2
    echo "the certificate is probably missing - run again without --skip-cert, or place one at" >&2
    echo "/etc/letsencrypt/live/$HOST/{fullchain,privkey}.pem" >&2
    exit 1
fi
systemctl reload nginx
ok "nginx accepts the config and was reloaded"

# ------------------------------------------------------------------ 9. certificate
if [ "$SKIP_CERT" -eq 1 ]; then
    warn "skipping certificate issuance (--skip-cert); nginx will not be ready for traffic"
elif [ -f "/etc/letsencrypt/live/$HOST/fullchain.pem" ]; then
    ok "certificate already present"
else
    say "requesting the wildcard certificate (DNS-01)"
    echo "This needs a DNS provider plugin. Install one and run certbot yourself, e.g.:"
    echo "  apt-get install -y python3-certbot-dns-cloudflare"
    echo "  certbot certonly --dns-cloudflare -d '$HOST' -d '*.$HOST' --agree-tos -m ${EMAIL:-you@example.com}"
    warn "certificate not issued automatically (DNS credentials cannot be guessed)"

    if [ -n "$EMAIL" ]; then
        printf '#!/bin/sh\n/usr/sbin/nginx -t && /usr/sbin/nginx -s reload\n' \
            > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
        chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
        ok "installed the certbot deploy hook that reloads nginx"
    fi
fi

# ------------------------------------------------------------------ 10. firewall
say "firewall"
if ! command -v ufw >/dev/null 2>&1; then
    warn "ufw is not installed - configure your firewall by hand"
else
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw allow "$SSH_PORT"/tcp >/dev/null
    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null
    # Deliberately NOT opened: 20000-25000 (LuCI tunnels) and 25001-30000 (console).
    # sshd binds those on 127.0.0.1 for the tunnelgate user; publishing them would give
    # the internet direct, unauthenticated access to every router's LuCI and every console
    # port. The panel is the only door, and it is authenticated.
    ufw --force enable >/dev/null
    ok "ufw allows only $SSH_PORT/tcp, 80/tcp, 443/tcp (tunnel and console pools stay closed)"
fi

# ------------------------------------------------------------------ 11. verify
say "verifying"
if [ -n "$SECRET" ]; then
    (cd "$REPO" && .venv/bin/python -m app.cli doctor) || warn "doctor reported a problem (see above)"
else
    warn "could not read TUNNELGATE_SECRET_KEY from $ENV_FILE - skipping doctor"
fi

echo
echo "TunnelGate is installed."
echo
echo "  panel      https://$HOST"
echo "  users      admin / the password in $ENV_FILE (TUNNELGATE_ADMIN_PASSWORD)"
echo "  env file   $ENV_FILE (mode 0600)"
echo "  data       $DATA_DIR"
echo "  routes     $ROUTES_DIR/routes.conf (generated, do not edit)"
echo
echo "Back up, separately and together: $DATA_DIR/tunnelgate.db, $DATA_DIR/.ssh/authorized_keys"
echo "and TUNNELGATE_SECRET_KEY (a password manager - losing it invalidates every console key)."
echo
echo "Tunnel and console ports stay CLOSED in the firewall. Check that sshd honours this:"
echo "  ss -ltnp | grep -E ':(2[0-9]{4})'   # every socket must be bound to 127.0.0.1"

