#!/bin/sh
# =============================================================================
# nginx-side entrypoint for the compose deployment.
#
# In the container layout the panel cannot reload nginx: the panel is
# unprivileged and hardened, and handing it the docker socket would give it root
# on the host - a far worse trade than a watcher.
#
# So the panel writes routes.conf atomically (temp file + rename) and this
# watcher notices the mtime change, validates the new file with `nginx -t` and
# only then reloads. A bad render is rejected and the running config is kept,
# exactly like the systemd path unit does on a bare-metal install.
#
# TUNNELGATE_PROXY_RELOAD_COMMAND is empty in the compose environment for the
# same reason: the panel must not try to signal a process it cannot reach.
# =============================================================================
set -eu

ROUTES=/etc/nginx/tunnelgate/routes.conf
SNIPPET=/etc/nginx/tunnelgate/routes.auth.conf
POLL=2

stamp() {
    # mtime + size of both files, so an atomic rename always changes the value.
    for f in "$ROUTES" "$SNIPPET"; do
        if [ -f "$f" ]; then
            stat -c '%n:%Y:%s' "$f"
        else
            echo "$f:missing"
        fi
    done
}

# The include targets must exist before nginx starts or the config test fails on
# a fresh install. The panel seeds them at startup; this is the race-free backup.
mkdir -p /etc/nginx/tunnelgate
for f in "$ROUTES" "$SNIPPET"; do
    [ -f "$f" ] || : > "$f"
done

nginx -g 'daemon off;' &
NGINX_PID=$!

term() {
    echo "tunnelgate-nginx: shutting down"
    kill -QUIT "$NGINX_PID" 2>/dev/null || true
    wait "$NGINX_PID" 2>/dev/null || true
    exit 0
}
trap term TERM INT

last=$(stamp)
while kill -0 "$NGINX_PID" 2>/dev/null; do
    sleep "$POLL"
    now=$(stamp)
    [ "$now" = "$last" ] && continue
    last="$now"
    if nginx -t >/dev/null 2>&1; then
        echo "tunnelgate-nginx: routes changed, reloading"
        nginx -s reload || echo "tunnelgate-nginx: reload failed" >&2
    else
        echo "tunnelgate-nginx: routes.conf rejected by the config test, keeping the running config" >&2
        nginx -t || true
    fi
done

wait "$NGINX_PID"
