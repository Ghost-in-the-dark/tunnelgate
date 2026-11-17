#!/bin/sh
# =============================================================================
# TunnelGate container entrypoint
#
# Creates/upgrades the schema, then hands PID 1 to uvicorn. init-db is idempotent
# (create_all), so this is safe on every start.
# =============================================================================
set -eu

: "${TUNNELGATE_DATA_DIR:=/var/lib/tunnelgate}"
export TUNNELGATE_DATA_DIR

# The image runs read-only (/opt/tunnelgate is not writable) and its cwd is the
# code directory, so the app's relative defaults - ./data/... - would resolve to a
# path the process cannot create. Derive every path from DATA_DIR unless the
# operator overrode it explicitly (docker-compose / /etc/tunnelgate.env do).
: "${TUNNELGATE_DB_URL:=sqlite:///${TUNNELGATE_DATA_DIR}/tunnelgate.db}"
: "${TUNNELGATE_AUTHORIZED_KEYS_PATH:=${TUNNELGATE_DATA_DIR}/.ssh/authorized_keys}"
# Only used when PROXY_DRIVER is nginx AND the operator did not point it at the
# mounted /etc/nginx/tunnelgate; keeping it under DATA_DIR at least stays writable.
: "${TUNNELGATE_PROXY_ROUTES_PATH:=${TUNNELGATE_DATA_DIR}/tunnelgate.routes.conf}"
export TUNNELGATE_DB_URL TUNNELGATE_AUTHORIZED_KEYS_PATH TUNNELGATE_PROXY_ROUTES_PATH

if [ ! -w "$TUNNELGATE_DATA_DIR" ]; then
    echo "FATAL: $TUNNELGATE_DATA_DIR is not writable by uid $(id -u)." >&2
    echo "Fix:  sudo chown -R 10001:10001 /var/lib/tunnelgate" >&2
    exit 1
fi

echo "tunnelgate: applying database schema"
python -m app.cli init-db

echo "tunnelgate: starting uvicorn on ${TUNNELGATE_BIND_ADDRESS:-127.0.0.1}:${TUNNELGATE_PORT:-8080}"
exec python -m uvicorn app.main:app \
    --host "${TUNNELGATE_BIND_ADDRESS:-127.0.0.1}" \
    --port "${TUNNELGATE_PORT:-8080}" \
    --proxy-headers \
    --forwarded-allow-ips 127.0.0.1
