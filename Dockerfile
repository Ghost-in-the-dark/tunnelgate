# =============================================================================
# TunnelGate panel image
#
# Build:  docker build -t tunnelgate:latest .
# Run:    docker compose up -d   (see docker-compose.yml and deploy/README.md)
#
# Why host networking: the panel is not a self-contained service. It reads the
# SSH listeners sshd opened on 127.0.0.1, proxies LuCI at 127.0.0.1:<tunnel_port>
# and writes authorized_keys that the HOST sshd reads. Giving it its own network
# namespace would hide every tunnel it exists to serve.
# =============================================================================
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Baked in so `docker exec ... python -m app.cli doctor` sees the same paths
    # as the running service. Without them the app falls back to ./data, which is
    # not writable in this read-only image and doctor would report false failures.
    TUNNELGATE_DATA_DIR=/var/lib/tunnelgate \
    TUNNELGATE_DB_URL=sqlite:////var/lib/tunnelgate/tunnelgate.db \
    TUNNELGATE_AUTHORIZED_KEYS_PATH=/var/lib/tunnelgate/.ssh/authorized_keys \
    TUNNELGATE_PROXY_ROUTES_PATH=/etc/nginx/tunnelgate/routes.conf

# openssh-client: the console feature shells out to ssh. No curl and no compiler:
# the runtime has no business building anything, and the healthcheck below uses
# the interpreter that is already present.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first so a source change does not re-resolve the world.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Fixed unprivileged UID. The host data directory must be chowned to match;
# docker-compose.yml documents the one-liner. The user is created BEFORE the
# COPY steps so --chown can name it, and so no layer leaves root-owned files
# behind for the unprivileged process to trip over.
ARG TG_UID=10001
ARG TG_GID=10001
RUN groupadd --system --gid "${TG_GID}" tunnelgate \
    && useradd --system --uid "${TG_UID}" --gid "${TG_GID}" \
       --home-dir /var/lib/tunnelgate --shell /usr/sbin/nologin tunnelgate \
    && install -d -o tunnelgate -g tunnelgate -m 0750 /var/lib/tunnelgate \
    && install -d -o tunnelgate -g tunnelgate -m 0750 /var/lib/tunnelgate/.ssh \
    # The mount point for the generated router vhosts has to exist in the image:
    # with read_only: true the bind mount is writable, but its PARENT is not, so a
    # missing /etc/nginx/tunnelgate cannot be created at runtime.
    && install -d -o tunnelgate -g tunnelgate -m 0750 /etc/nginx/tunnelgate

WORKDIR /opt/tunnelgate
# --chown matters: a checkout on a hardened host can carry mode 0600 files, and
# COPY preserves that; root-owned 0600 sources would make the app unreadable to
# the unprivileged user (PermissionError on app/__init__.py at import time).
COPY --chown=tunnelgate:tunnelgate app /opt/tunnelgate/app
# The app serves the SPA itself (index.html fallback), so the build output has to
# be in the image. The repo ships web/dist; rebuild it with
#   cd web && npm ci && npm run build
COPY --chown=tunnelgate:tunnelgate web/dist /opt/tunnelgate/web/dist
COPY --chown=root:root deploy/docker/entrypoint.sh /usr/local/bin/tunnelgate-entrypoint
RUN chmod 0755 /usr/local/bin/tunnelgate-entrypoint

USER tunnelgate
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=4).status == 200 else 1)"

# init-db runs in the entrypoint (idempotent), then it execs uvicorn as PID 1 so
# SIGTERM reaches the app and the tunnel watcher stops cleanly.
ENTRYPOINT ["/usr/local/bin/tunnelgate-entrypoint"]
