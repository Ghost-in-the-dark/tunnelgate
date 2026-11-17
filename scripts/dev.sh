#!/bin/sh
# Local development runner: ./scripts/dev.sh [port]
set -e
cd "$(dirname "$0")/.."
export TUNNELGATE_DATA_DIR="${TUNNELGATE_DATA_DIR:-$PWD/data}"
export TUNNELGATE_ADMIN_PASSWORD="${TUNNELGATE_ADMIN_PASSWORD:-admin-changeme-now}"
exec .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port "${1:-8080}" --reload
