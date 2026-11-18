# Operating TunnelGate

Day-2 guide: how the system behaves, how to look at it, and what to do when something is wrong.
Installation is in `docs/INSTALL_SERVER.md`; the model behind it is in `docs/ARCHITECTURE.md`.

## 1. What is running where

| Component | Process | Listen | Persistence |
|---|---|---|---|
| Panel API + SPA | `tunnelgate` (uvicorn) | `127.0.0.1:8080` | SQLite `/var/lib/tunnelgate/tunnelgate.db` |
| sshd (tunnel user) | `ssh` | `0.0.0.0:22` | `/var/lib/tunnelgate/.ssh/authorized_keys` |
| Reverse listeners | owned by **sshd**, not the panel | `127.0.0.1:20000-30000` | - |
| nginx | `nginx` | `0.0.0.0:80,443` | `/etc/nginx/...`, `routes.conf` |
| Router side | `tunnelgate` procd service | outbound ssh | `/etc/config/tunnelgate` |

Two consequences that explain most operational surprises:

1. **The reverse listeners belong to sshd.** Stopping or restarting the panel does **not**
   interrupt an open LuCI session or a console; it only freezes the status/reconciliation view.
   Restarting *sshd* does drop them (routers reconnect within ~10 s).
2. **The panel is a supervisor, not a data plane.** It observes, audits and issues credentials.
   If it is down, tunnels keep forwarding; nobody can *log in* to reach them.

## 2. Health and status

```bash
curl -fsS https://panel.example.com/api/v1/health            # liveness, no auth
curl -fsS -b "tg_session=..." https://panel.example.com/api/v1/stats
systemctl status tunnelgate --no-pager
journalctl -u tunnelgate -n 100 --no-pager
```

`GET /api/v1/stats` gives `routers_total`, `routers_online`, `routers_offline`,
`routers_pending`, `ports_free`, `users_total`, `console_sessions_active`. Alert on
`ports_free < 50` and on `routers_online` dropping.

### What the panel writes to the journal

The panel logs under the `tunnelgate` logger tree (`tunnelgate.proxy`, `tunnelgate.monitor`,
`tunnelgate.console`, `tunnelgate.launch`, `tunnelgate.api.*`). Verbosity follows
`TUNNELGATE_LOG_LEVEL` (default `info`); `debug` is for a reproduced problem, not a steady
state, because the monitor and the proxy renderer log per decision.

At `info` the lines worth knowing:

| line | means |
| --- | --- |
| `created initial admin user <name>` | first boot; the password came from `TUNNELGATE_ADMIN_PASSWORD` |
| `closed N console session(s) orphaned by a previous process` | the panel restarted mid-shell; those rows are now closed with reason `panel_restart` |
| `initial proxy sync failed` | nginx/caddy render failed at boot - the panel serves, routers do not |
| `api docs and OpenAPI schema are disabled` | production default, expected |

A warning is always written, whatever the level: `unknown TUNNELGATE_LOG_LEVEL ...: using info`
means a typo in the env file, and the panel silently used the default.

### What "online" means

`online` requires **both**: a listening port in the router's `tunnel_port` observed by the
monitor, **and** a successful HTTP health check against `127.0.0.1:<port>` (LuCI answering).
A bare listen socket with nothing behind it shows as not online, because that is what a
half-broken router looks like and it is exactly the case where the operator needs to see
trouble rather than a green dot.

The monitor loop (`TUNNELGATE_TUNNEL_POLL_SECONDS`, default 5 s):

1. lists listening sockets (`ss -ltnH`), maps ports to routers;
2. for each router with a listener, does `GET http://127.0.0.1:<port><health_path>`;
3. writes `router_runtime` (tunnel_present, health_ok, tunnel_pid, observed_at);
4. updates `status` + `last_seen_at`/`online_since` and clears `offline` when the tunnel returns;
5. touches the reverse proxy when the set of *routers* changed (not on every poll).

Statuses: `pending` (no key exchanged yet), `awaiting` (key issued, nothing seen),
`online`, `offline` (was online, then the tunnel vanished for `stale_offline_seconds`),
`revoked` (key revoked by rotate/delete).

## 3. Routine tasks

### Add a router

Panel → **Add router** → name → copy command → run on the router. The wizard polls
`GET /api/v1/routers/{id}/status` every 2 s and walks
`waiting → connected → reporting → done`.

### Show the install command again

*Not installed yet*: "Show install script" issues a **new** token and invalidates the old one.
*Already installed*: `409 already_installed`; use rotate (or, as admin, `?reissue=true`).

### Rotate a router's key

"Rotate key" revokes the old key immediately (the router's live ssh dies), keeps the **same**
ports and vhost, and gives a new install command. The router's status returns to `pending`
until it exchanges the token. Until then its LuCI vhost answers `502`.

### Delete a router

Removes the key line, releases both ports, deletes the row and regenerates nginx routes; the
vhost disappears. The router keeps retrying and gets `Permission denied` forever, so
**always run the uninstaller on the router** (`/etc/init.d/tunnelgate stop; tunnelgate-uninstall`)
- or, if you no longer have access, accept the retry noise on the router's log.

### Move the panel to a new address

Changing `TUNNELGATE_PANEL_URL` alone moves nothing that is already deployed: it is the panel's
*internal* address. Routers dial the **agent endpoint**, which defaults to it but is stored in
the database and is editable from **Settings → Agent endpoint**.

1. Bring the new name up (DNS, certificate, proxy vhost) and press **Test** - the probe runs from
   the panel, which is the only vantage point that predicts whether a router will reach it.
2. Save. Every heartbeat (~60 s) carries the new `heartbeat_url` and each router rewrites its own
   UCI config; installers issued afterwards carry it too.
3. Watch `routers_online` until the fleet has converged before retiring the old name. A router
   that is offline during the move cannot learn the new address - re-run the installer on it.

No restart, no re-install, no SSH into a single router. `docs/INSTALL_SERVER.md` §7 has the
curl form and the reasoning.

### Console sessions

Admins can see live sessions and force-close them: `GET /api/v1/console/sessions` lists
them, `DELETE /api/v1/console/sessions/{id}` ends one (the session closes with
`admin_terminated` and the kill is audited as `console.terminate`).

The console screen has a **Kill** button on every open row for admins. A session that is
already closed, or that no handler in the running panel owns, is reported instead of silently
"killed" - a 409 means look again, not that the shell is gone.

Deleting a router ends its live shells too (`router_disconnected`): a shell on a router the
panel no longer knows would keep a root prompt on that device with no session row and no way
back to it from the UI.

## 4. Common failures

| Symptom | Likely cause | Check | Fix |
|---|---|---|---|
| Wizard stuck on "Waiting for connection" | router never ran the script, or cannot reach the VPS on 22 | router: `logread \| grep tunnelgate`; VPS: `journalctl -u ssh` | rerun the installer; check outbound SSH |
| Wizard reaches "Connected" then "offline" | tunnel up but LuCI not answering | `ss -ltnp \| grep <port>`; on the router `/etc/init.d/uhttpd status` | start/reconfigure `uhttpd` |
| `502 Bad Gateway` on the router vhost | listener exists, nothing behind it (router rebooted) or the port is stale | `ss -ltnH \| grep <port>` | restart the tunnel service on the router |
| `403` from nginx on a router vhost | `/__tg/auth` denied: no session, or the router id in the vhost does not match | `journalctl -u tunnelgate \| grep __tg`; `nginx -T \| grep -A3 <slug>` | log in again; regenerate routes |
| Router vhost missing after adding a router | proxy sync failed (nginx config error) | `nginx -t`; `grep <slug> /etc/nginx/tunnelgate/routes.conf` | fix `nginx -t` output, then `systemctl reload tunnelgate` |
| Console: "console_not_ready" | key created but the router has not picked it up (heartbeat not yet in), or the router is offline | panel `GET .../console` `state`; router heartbeat log | wait one heartbeat (60 s), or restart the tunnel service |
| Console: "Connection refused" on start | `console_port` listener not present | `ss -ltnH \| grep <console_port>` | the router's ssh has no console forward: reinstall |
| Login always "rate_limited" | previous failures filled the window | `grep login_failed` in audit | wait `login_rate_window_seconds`, or clear the limiter by restarting the panel |
| Everyone shares one rate-limit bucket, or the audit log shows the proxy's IP for every action | the panel does not trust the proxy, so the socket peer is the proxy | `TUNNELGATE_TRUSTED_PROXIES` and the unit's `--forwarded-allow-ips`; `journalctl -u tunnelgate \| grep -i trusted-proxy` | name the proxy in both - see `docs/INSTALL_SERVER.md` §7 |
| `journalctl` shows the proxy address as the client, yet the audit log is right (or vice versa) | the two trust lists disagree: the app believes `TUNNELGATE_TRUSTED_PROXIES`, uvicorn believes `--forwarded-allow-ips` | the unit's `ExecStart` still says `--forwarded-allow-ips 127.0.0.1` while the proxy is elsewhere | widen `--forwarded-allow-ips` too, not just `TUNNELGATE_TRUSTED_PROXIES` - see `docs/INSTALL_SERVER.md` §7 |
| `no_free_port` on create | pool exhausted (deleted routers leak) | `GET /api/v1/stats` `ports_free` | delete stale routers; `app.cli doctor` reports leaks |
| Everything 500s after upgrade | schema drift (no migration engine) | `app.cli check-schema` | apply the printed `ALTER TABLE`s |
| Every router sits at `awaiting`/`offline` while `/api/v1/health` answers `ok`, and `ss -ltnp` on the host clearly shows the listeners | the panel cannot run `ss`, so it refuses to guess and treats the tunnels as unobservable | `journalctl -u tunnelgate \| grep "ss is not installed"`; `app.cli doctor` fails under `socket inventory` | install `iproute2` in whatever runs the panel (the container image ships it; a hand-rolled image often does not) |
| `app.cli doctor` dies with `PermissionError` on the database or `/var/lib/tunnelgate`, or reports "routes dir not writable" for files it should own | doctor is running as a different uid than the panel - typical with `docker exec` (uid 10001) against a host-owned data dir, or `sudo` vs the service user | `ls -ln /var/lib/tunnelgate` compared with the uid in the unit/container | run doctor as the service user, or `chown -R 10001:10001 /var/lib/tunnelgate` for the container path |

### Collecting a diagnosis bundle

```bash
mkdir -p /tmp/tg-diag
{ systemctl status tunnelgate --no-pager; journalctl -u tunnelgate -n 500 --no-pager; } >/tmp/tg-diag/panel.txt
{ ss -ltnH; } >/tmp/tg-diag/sockets.txt
{ nginx -T 2>/dev/null; } >/tmp/tg-diag/nginx.txt
{ sshd -T 2>&1 | head -50; } >/tmp/tg-diag/sshd.txt
sqlite3 /var/lib/tunnelgate/tunnelgate.db \
  "select id,name,status,tunnel_port,console_port,last_seen_at from routers;" >/tmp/tg-diag/routers.txt
```

The bundle contains no private keys (the panel never has any) but it does contain the panel's
`authorized_keys` if you add it - those are public keys, safe to share.

## 5. Backup, restore, upgrades

Back up **together**: `tunnelgate.db`, `authorized_keys`, `/etc/tunnelgate.env` (secret key
separately and encrypted), `routes.conf` and the nginx site.

```bash
sqlite3 /var/lib/tunnelgate/tunnelgate.db ".backup '/var/backups/tg.db'"
cp /var/lib/tunnelgate/.ssh/authorized_keys /var/backups/tg.keys
```

Restore: stop the panel → copy DB + authorized_keys → start → `app.cli doctor` → check
`/api/v1/stats`. Routers reconnect on their own; nothing needs to be touched on the router side.

Upgrade: `sudo sh scripts/update.sh` (or the pipe form in `docs/INSTALL_SERVER.md`
§9). It backs up first, checks the schema against a snapshot with the new code, rebuilds the SPA,
restarts, verifies the version over `/api/v1/health` and rolls itself back if the new build does
not come up. `scripts/update.sh --check-only` tells you whether you are behind without touching
anything; `--dry-run` prints the plan.

There is no migration engine: model changes are additive and `app.cli check-schema` prints the
DDL you must apply by hand. The updater treats that as a stop sign, not a warning - it will not
install a release whose schema needs hand work until you have applied it and re-run with
`--skip-schema-check`.

Backups taken by the updater live in `/var/backups/tunnelgate/update-<stamp>/` (mode 0700) and
contain enough to roll back offline: `code.tar.gz`, `pip-freeze.txt`, the database snapshot,
the env file, `authorized_keys` and both routes files. **The updater never deletes an old
backup** - each update adds one, so prune them yourself once you are confident in a version:

```bash
ls -dt /var/backups/tunnelgate/update-* | tail -n +6 | xargs -r rm -rf   # keep the newest five
```

## 6. Scaling and capacity

* Port pools: 5000 LuCI ports (20000-25000) and ~5000 console ports (25001-30000) by default;
  each router consumes one of each. Change the ranges before the fleet grows - a port that is
  already baked into a router's `authorized_keys` cannot be moved without a rotate.
* The monitor is O(routers) per tick with a bounded thread pool; 100+ routers is comfortable at
  the default 5 s tick. Above ~500, raise `TUNNELGATE_TUNNEL_POLL_SECONDS`.
* SQLite handles this write rate easily (a few writes per router per tick). Switch to PostgreSQL
  only if you run more than one panel instance - **the panel is single-instance by design**: two
  instances would fight over `authorized_keys` and `routes.conf`.
* nginx reloads on route changes only, not per poll.

## 7. Security operations

* Review `GET /api/v1/audit?action=router.exchange` weekly: every row should correspond to a
  router you onboarded.
* Review `console.open`/`console.close` rows: shells are the highest-value access this system
  grants.
* Check the `ip` column occasionally against reality: if every row shows the same private
  address, the proxy trust list is too narrow and the audit trail has lost its value (see
  `docs/INSTALL_SERVER.md` §7). Review `settings.agent_endpoint.*` rows - an endpoint change is
  the one control that can silently redirect every router in the fleet.
* Rotate router keys after any operator leaves. Rotation is online and takes seconds per router
  (the command must be run on the router - do it during a maintenance window if you cannot
  automate it).
* Rotate `TUNNELGATE_SECRET_KEY` only deliberately: it invalidates every sealed console key.
  Plan: set the new key, then rotate every router, or clear `console_key_sealed` for all routers
  and let the next console open reissue (the router then reinstalls the public key on the next
  heartbeat).
* Delete the seeded admin password from the environment file after first login
  (`TUNNELGATE_ADMIN_PASSWORD` is only read at first start; changing it later does nothing).
* `sshd` logs every tunnel connection at `INFO`. Ship `/var/log/auth.log` off-host so a VPS
  compromise cannot rewrite the access history.

## 8. Runbook: panel is down

1. Tunnels and LuCI: **still working at the TCP level, but nobody can log in** - nginx's
   `auth_request` fails closed, so router vhosts return `403`/`502`.
2. `systemctl status tunnelgate`; `journalctl -u tunnelgate -n 200`.
3. If the DB is corrupt: restore the last backup, restart, `app.cli doctor`.
4. If nginx config is broken by a bad `routes.conf`: `nginx -t` names the line;
   `routes.conf` is regenerated on startup, so a restart fixes it.
5. If `authorized_keys` is damaged: restore from backup; routers reconnect on the next retry.

## 9. Runbook: a router must be cut off now

1. Panel → **Delete** (fastest, also frees ports) or **Rotate key** (keeps the inventory row).
2. Force the ssh session closed immediately (revocation only blocks the *next* login):
   ```bash
   pkill -u tunnelgate            # drops every tunnel for every router
   ```
   then check `ss -ltnH | grep -E '2[0-9]{4}|30[0-9]{3}'` is empty for the ranges.
3. If the router might have the console key: rotate it too (that regenerates the console
   keypair) and `pkill` again.
4. Confirm in audit: `GET /api/v1/audit?router_id=<id>`.

## 10. Metrics worth alerting on

| Signal | Where | Alert |
|---|---|---|
| `routers_online` drop | `/api/v1/stats` | any drop > 20 % in 10 min |
| `ports_free` | `/api/v1/stats` | < 50 |
| panel `/api/v1/health` | probe | 2 consecutive failures |
| `auth.login_failed` rate | audit | > 20/min from one IP |
| `console.open` outside business hours | audit | per policy |
| disk usage of `/var/lib/tunnelgate` | OS | > 80 % |
