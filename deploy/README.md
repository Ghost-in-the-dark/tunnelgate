# Deploying TunnelGate

Everything in `deploy/` is a **reference artefact for the host**, not application code.
The panel never imports any of it; it writes its own nginx include at runtime. This file says
what each artefact is, where it belongs, and what it depends on.

Two supported install paths:

| Path | Entry point | Use when |
|---|---|---|
| Bare metal | `scripts/setup-server.sh --host <fqdn> --email <you@example>` | the normal case: one host, host sshd, host nginx |
| Containers | `docker compose up -d --build` | the app and nginx are both containerised, sshd stays on the host |

The bare-metal script performs every step in `docs/INSTALL_SERVER.md`; the manual procedure
remains the source of truth if you want to do it by hand or on another distro.

---

## File inventory

| Artefact | Install target | Purpose |
|---|---|---|
| `deploy/nginx/tunnelgate.conf` | `/etc/nginx/sites-available/` + symlink in `sites-enabled/` | panel vhost, console vhost, port-80 ACME/redirect, and the `include` of the generated router vhosts |
| `deploy/nginx/router-vhost.conf.template` | nowhere | human-readable copy of the per-router server block that `app/services/proxy.py` renders. `tests/test_proxy.py` keeps the two in step, so it is documentation with a test attached |
| `deploy/sshd/tunnelgate.conf` | `/etc/ssh/sshd_config.d/` | the `Match` block that restricts the `tunnelgate` user to reverse forwards on the port pool |
| `deploy/systemd/tunnelgate.service` | `/etc/systemd/system/` | the panel, unprivileged, `127.0.0.1:8080` |
| `deploy/systemd/tunnelgate-nginx-reload.path` | `/etc/systemd/system/` | root-owned watcher: fires when the panel rewrites `routes.conf` and runs `nginx -t && nginx -s reload` |
| `deploy/systemd/tunnelgate-nginx-reload.service` | `/etc/systemd/system/` | the oneshot the `.path` unit starts |
| `deploy/caddy/Caddyfile` | `/etc/caddy/Caddyfile` | alternative to the nginx vhosts, for a host that runs Caddy instead |
| `deploy/env/tunnelgate.env.example` | `/etc/tunnelgate.env` (mode `0600`) | every setting, with production values |
| `deploy/docker/entrypoint.sh` | baked into the image | applies the schema, then `exec`s uvicorn as PID 1 |
| `deploy/docker/nginx-entrypoint.sh` | baked into the image | runs nginx, watches `routes.conf`, reloads on change |
| `Dockerfile`, `docker-compose.yml` | repo root | the container path |
| `scripts/setup-server.sh` | nowhere | the bare-metal installer |

---

## Why the nginx reload is not done by the panel

The panel unit sets `NoNewPrivileges=yes` and has an empty capability set. It cannot signal a
root-owned nginx master, and under `NoNewPrivileges` it cannot `sudo` to gain that either.
So the reload is inverted: the panel writes the file atomically (temp file + `rename`), and a
root-owned systemd `.path` unit sees the change and reloads.

Consequences worth knowing:

* `TUNNELGATE_PROXY_RELOAD_COMMAND` **must be empty** in `/etc/tunnelgate.env` for the systemd
  install. If it points at `nginx -s reload`, the panel fails that subprocess and reports
  `reload_pending` forever.
* The path unit watches `routes.conf` *and* `routes.auth.conf`, because the atomic rename
  replaces the inode - watching only one file would miss half the updates.
* `nginx -t` runs before the reload. A broken generated file therefore leaves the previous
  config serving traffic instead of taking the site down.
* `/api/v1/stats` reports `reload_pending`, so a stuck reload is visible instead of silent.

If you would rather let the panel reload nginx itself, drop the path unit, set
`TUNNELGATE_PROXY_RELOAD_COMMAND='nginx -t && nginx -s reload'`, add a narrow sudoers rule, and
set `NoNewPrivileges=no` (sudo cannot elevate under it). That is a real trade-off, not a
preference: it hands the panel a path to root.

---

## Ports: what is public and what is not

Public, because nginx listens on a real interface:

* `22/tcp` (or your SSH port)
* `80/tcp` - ACME HTTP-01 fallback and the redirect to HTTPS
* `443/tcp` - the panel, the console and every router vhost

**Never public**, because sshd creates them on `127.0.0.1` for the `tunnelgate` user:

* `20000-25000` - each router's LuCI, reachable only through its authenticated vhost
* `25001-30000` - each router's console SSH, consumed by the panel's terminal

`scripts/setup-server.sh` opens only 22/80/443 in ufw, and the shipped `tunnelgate.conf`
listens on 443 only. If you publish either pool you bypass the panel completely: a raw
`http://host:20001` would be an unauthenticated LuCI. Verify with:

```sh
ss -ltnp | grep -E ':(2[0-9]{4})'    # every socket must show 127.0.0.1
```

---

## Certificate requirement

One wildcard certificate covers all three vhost families:

* `panel.<suffix>` - the SPA and API
* `console.<suffix>` - the terminal WebSocket
* `<router>.<suffix>` - each router

HTTPS-01 cannot issue a wildcard, so the certificate must come from DNS-01 (see
`docs/INSTALL_SERVER.md` section 6). The shipped config expects
`/etc/letsencrypt/live/panel.example.com/{fullchain,privkey}.pem`; the panel's renderer uses the
same paths, overridable with `TUNNELGATE_TLS_CERT` / `TUNNELGATE_TLS_KEY`.

---

## Container path

`docker-compose.yml` runs the panel and nginx with `network_mode: host`. This is not a
shortcut: the panel's whole job is to reach the loopback listeners the **host** sshd created and
to write the `authorized_keys` the **host** sshd reads. In a bridge network those are invisible,
and publishing the 20000-25000 range instead would expose every router's LuCI on `0.0.0.0`.

Prerequisites are listed at the top of `docker-compose.yml`. Note the ownership requirement:
the data directory must be `10001:10001`, because the image runs as a fixed unprivileged UID.

Containerising sshd is not supported - the device keys and the tunnel listeners belong to the
host.

---

## Verifying an install

```sh
sudo -u tunnelgate /opt/tunnelgate/.venv/bin/python -m app.cli doctor   # or: docker exec ...
nginx -t
curl -fsS https://panel.<suffix>/api/v1/health
ssh -p <tunnel_port> tunnelgate@127.0.0.1        # from the panel host only
```

`doctor` checks the data directory, the database, `authorized_keys`, sshd reachability, free
ports in both pools, the routes path, the secret key, the console prerequisites and `web/dist`.
It exits non-zero on a blocking problem and prints the fix.
