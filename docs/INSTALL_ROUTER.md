# Installing a router agent

This is the router side of TunnelGate. You do not download or edit anything: the panel serves
the installer, already bound to one router and one single-use token.

- Panel setup: [INSTALL_SERVER.md](INSTALL_SERVER.md)
- What breaks later: [OPERATIONS.md](OPERATIONS.md)
- Why it is built this way: [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md)

---

## 1. Before you start

| Requirement | Why |
|---|---|
| OpenWrt 21.02 or newer (or a stock Linux with `procd`) | `procd`, UCI |
| Outbound SSH to the panel's `ssh_port` (default 22) | the tunnel is an outbound `ssh -R`; nothing listens on the router |
| Outbound HTTPS to the panel URL | the exchange and the heartbeat |
| Root shell on the router | the installer writes `/etc/config`, `/root/.ssh` and the init script |
| Working DNS and a sane clock | TLS fails with a wrong date; the bootstrap token has a 15-minute TTL |
| `openssh-client` | installed automatically with `apk`/`opkg` when `ssh` is missing |

The router does **not** need a public IP, a port forward or a DNS record. Every connection is
outbound. That is the whole point: this works behind CGNAT.

Check the clock before anything else - a router that booted without a battery-backed RTC often
starts in 1970, and every HTTPS request then fails certificate validation:

    date ; ntpdate -q pool.ntp.org 2>/dev/null || true

---

## 2. Create the router in the panel

Panel -> **Routers** -> **Add** -> fill in a name, optionally a model and notes -> save.
Saving shows a **Connect** dialog with the command to paste. The router's ed25519 key pair
and its two ports are **not** created here: they are minted by the first successful exchange,
so a router that is never installed never consumes a pool entry.

The dialog contains one line:

    curl -fsSL -H 'X-Bootstrap-Token: <token>' 'https://panel.example.com/api/v1/routers/install?os=linux' | sh

Three properties of that line matter, and they are all deliberate:

* the token is in a **header**, not in the URL, so it does not land in the nginx access log,
  in the router's shell history or in `ps` output;
* the token is **single-use** and expires in 15 minutes. Re-running the same command after a
  successful exchange returns `401 invalid_token` and changes nothing;
* `| sh` runs the script from stdin, so nothing is left in `/tmp` on the router.

The command is also available later from the router page (**Install command**); issuing a new
one invalidates the previous one.

---

## 3. Run it on the router

    ssh root@192.168.1.1
    curl -fsSL -H 'X-Bootstrap-Token: <token>' 'https://panel.example.com/api/v1/routers/install?os=linux' | sh

A successful run ends with:

      TunnelGate router agent installed.

        panel           https://panel.example.com
        ssh endpoint    203.0.113.10:22
        reverse tunnel  127.0.0.1:20001 -> 127.0.0.1:80
        console         25001
        luci url        https://branch-one.panel.example.com
        config          /etc/config/tunnelgate (mode 0600, contains the API token)
        private key     /root/.ssh/tunnelgate_ed25519 (mode 0600, never leaves this router)

      Verify:  /etc/init.d/tunnelgate status ; logread -e tunnelgate | tail -20
      Remove:  /usr/bin/tunnelgate-uninstall [--purge]  (or re-run: sh install.sh --uninstall)

The panel should flip the router to **online** within about a minute, and the LuCI URL should
open the router's own LuCI through the tunnel.

### What the installer actually does

1. refuses to run without the two substituted lines (see the marker note below), without root,
   and on a non-OpenWrt host unless `TG_FORCE=1`;
2. installs `openssh-client` if `ssh` is missing;
3. posts `hostname`, `model`, `openwrt_version`, `mac`, `uptime_seconds` and `client_version`
   to `/api/v1/routers/bootstrap/exchange` with the `X-Bootstrap-Token` header;
4. writes the ed25519 private key from the response to `/root/.ssh/tunnelgate_ed25519` (0600)
   - this is the only time the key exists outside the router;
5. scans the panel's host key and **aborts** unless the fingerprint matches the one in the
   response, then pins it in `/root/.ssh/known_hosts`;
6. writes `/etc/config/tunnelgate` (UCI, 0600) with the panel host/port, ports, API token
   and heartbeat URL;
7. installs `/usr/bin/ssh-loop`, `/usr/bin/tunnelgate-heartbeat`,
   `/usr/bin/tunnelgate-uninstall`, `/usr/lib/tunnelgate/json.sh` and
   `/etc/init.d/tunnelgate`;
8. enables and starts the service.

Every step is idempotent: running the installer a second time with a **fresh** token leaves
the same files, the same pinned host key and the same key bytes. It is the documented recovery
path when something looks wrong.

---

## 4. Verify

On the router:

    /etc/init.d/tunnelgate status
    logread -e tunnelgate | tail -20
    ps w | grep -E 'ssh-loop|tunnelgate-heartbeat'
    netstat -tnp 2>/dev/null | grep ':22 '

`logread` shows either `ssh exited rc=0, reconnecting in 10s` (normal churn) or the
concrete reason: `Permission denied` means the panel revoked the key, `Host key verification failed`
means the panel's host key changed, `Network unreachable` means the router cannot reach
the panel at all.

On the panel:

    ss -ltnH | grep 20001
    curl -s -o /dev/null -w '%{http_code}\n' https://branch-one.panel.example.com/

A `502` means the listener is up but nothing is behind it - the router's LuCI is down.
Look at `/etc/init.d/uhttpd status` on the router.

---

## 5. The web console

The panel reaches the router's own dropbear through a **second** reverse forward on the same
SSH connection. It authenticates with a sealed key pair that exists only on the panel; the
router only ever holds the public half.

Timeline after the first heartbeat:

1. heartbeat -> panel returns a `console` block with `serial`, `user`, `public_key`;
2. `tunnelgate-heartbeat` compares that serial with `option console_serial` in UCI;
3. when the serial moved it rewrites the `tunnelgate-console` line in the key file
   (default `/etc/dropbear/authorized_keys`, mode 0600) and stores the new serial;
4. the same heartbeat run then POSTs again with `console_installed: true`; the panel reads
   that flag off the raw body (`HeartbeatIn` does not declare it) and sets
   `Router.console_installed_at`, after which it stops advertising the registration.

The line written is restricted:

    from="127.0.0.1",no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA... tunnelgate-console

`no-pty` is deliberately **absent**: an interactive shell is the point of a console. The
`from=` restriction means only the panel's own reverse forward can use that key - not the
LAN, not the WAN.

Requirements on the router: **dropbear must be running** (the installer enables and starts
`/etc/init.d/dropbear` when the panel says the console is enabled). The console user defaults
to `root`; if you set a dedicated user in the panel the installer creates it once, without
a password.

> Revoking access is done on the panel (rotate or delete the console key). The router keeps a
> stale line until the next heartbeat delivers a higher serial, so rotate rather than hand-edit
> `authorized_keys`.

---

## 6. Removing the agent

    /usr/bin/tunnelgate-uninstall --dry-run     # show what would go
    /usr/bin/tunnelgate-uninstall               # remove it
    /usr/bin/tunnelgate-uninstall --purge       # also remove openssh-client and the console user

It removes the init script, the UCI config, both supervisor scripts, the state directory, the
private key and **only** the `tunnelgate-console` line from `authorized_keys` - another
operator's keys in that file are kept. Then delete the router in the panel, which releases the
ports and drops the key line from the panel's own `authorized_keys`.

If you still have the original script, `sh install.sh --uninstall [--purge]` does the same
from the installer itself. Deleting the router in the panel **before** running the uninstaller
is safe but noisier: the loop keeps retrying and gets `Permission denied` until it is
removed.

A firmware upgrade that preserves `/etc` keeps the agent working; one that resets to
defaults removes everything except the panel-side record. In that case create a fresh install
command in the panel and run it again - it reuses the same router row and the same ports.

---

## 7. When something looks wrong

| Symptom | Cause | Fix |
|---|---|---|
| `TG_PANEL_URL is not set: this script must be served by the panel` | you saved or copied the script by hand | run the command from the panel |
| `panel refused the bootstrap token: ...` | token reused, expired, or from another router | generate a new install command |
| `HOST KEY MISMATCH ...: no key from ssh-keyscan matches` | the panel's SSH host key changed, or a MITM | confirm the panel fingerprint, then fix the panel; the installer refuses on purpose |
| `curl: (6) Could not resolve host` | router DNS | check `nslookup panel.example.com`, fix `resolv.conf` |
| `curl: (60) certificate is not yet valid` | router clock is wrong | sync NTP, re-run |
| `curl: (60) mbedTLS: The certificate Common Name (CN) does not match with the expected CN` / `BADCERT_CN_MISMATCH` and/or `The certificate is not correctly signed by the trusted CA`, while the panel itself answers fine | the router is resolving the panel name to **its own WAN address** and the packet hairpins back into the router, so the TLS handshake is answered by LuCI (`uhttpd`) with its self-signed `CN=OpenWrt` cert - not by the edge proxy | see below: this is a router-side DNS/NAT reflex, not a panel or nginx fault |
| exchange succeeds, tunnel never comes up | outbound port blocked | `nc -vz <panel_host> 22` |
| tunnel up, panel says **offline** | LuCI down or wrong `router_http_port` | `/etc/init.d/uhttpd status` |
| panel 502 on the LuCI URL | listener up, LuCI dead | start `uhttpd`, `logread | grep uhttpd` |
| console connects then closes | dropbear not running, or key serial not consumed yet | `logread -e tunnelgate | grep console` |

### The router dials its own WAN address

This is the failure that looks exactly like a broken panel or a broken proxy, and is
neither. Its signature is that mbedTLS reports **both** a CN mismatch and an untrusted
certificate in the same message.

It happens when the device you run the installer on **is the gateway that owns the panel's
public IP**. The name resolves to the public address; that address is one of the device's
own; the kernel delivers the packet to local port 443 - and on OpenWrt port 443 is
`uhttpd` (LuCI), not the edge proxy. So the TLS handshake is answered by LuCI's
self-signed `CN=OpenWrt` certificate, which fails both checks. `BADCERT_CN_MISMATCH` alone
would mean a misdirected packet; getting it *together with* "not correctly signed" means
"this is somebody else's self-signed certificate", i.e. you never reached the edge at all.

The panel's own log cannot settle this, because TLS terminates at the edge: the panel sees the
edge's address as its client, never the router's. Use the two probes below instead.

Confirm it in one command each, on the router itself:

    # what the name resolves to, and who owns that address
    nslookup gate.example.com ; ip -4 addr

    # the name pinned to the edge's LAN address: must answer 401/200, never (60)
    curl -fsSL --resolve gate.example.com:443:<edge-lan-ip> -H 'X-Bootstrap-Token: x' \
        'https://gate.example.com/api/v1/routers/install?os=linux'

If the second command answers and the first one points at the router, that is the whole
problem. Note that **NAT loopback (hairpin) does not fix this**: a packet addressed to the
device's own IP never enters the `nat` tables, so there is no DNAT to redirect it. The fix
is to stop the name resolving to the router itself.

Pick one:

* **DNS override on the router** (best when the router is also the DNS server for the LAN).
  Point the name at the edge proxy's LAN address - not at the panel:

      uci add dhcp domain
      uci set dhcp.@domain[-1].name='gate.example.com'
      uci set dhcp.@domain[-1].ip='192.168.1.89'      # the edge, NOT the panel
      uci commit dhcp && /etc/init.d/dnsmasq restart
      nslookup gate.example.com                        # must now be the edge

* **Run the installer from another machine** on the same LAN - any host that is not the
  gateway resolves the public name normally and the hairpin reaches the edge correctly.

* **Give the panel a LAN-reachable agent endpoint** - in the panel, **Settings -> Panel ->
  Agent endpoint**, set scheme `http` and the panel's LAN address, then generate a fresh
  install command. This changes where *every* router dials, so use it only when the routers
  are all inside this LAN.

Do not "fix" this with `curl -k`. The installer deliberately verifies TLS: the bootstrap token
is a credential, and disabling verification turns a misdirected packet into a leaked token.

Useful overrides for debugging on a stripped or unusual image - they exist so the tests can
drive the real scripts, but they also work on a device:

| Variable | Default |
|---|---|
| `TG_FORCE=1` | skip the OpenWrt check |
| `TG_STATE_DIR` | `/usr/lib/tunnelgate` |
| `TG_CONFIG` | `/etc/config/tunnelgate` |
| `TG_KEY_PATH` | `/root/.ssh/tunnelgate_ed25519` |
| `TG_KNOWN_HOSTS` | `/root/.ssh/known_hosts` |
| `TG_INITD`, `TG_LOOP_BIN`, `TG_HB_BIN`, `TG_UNINSTALL_BIN` | the system paths above |

### Files the agent owns

    /etc/init.d/tunnelgate              procd service (START=95)
    /etc/config/tunnelgate              0600, holds the API token
    /usr/bin/ssh-loop                   reconnect loop
    /usr/bin/tunnelgate-heartbeat       heartbeat + console key delivery
    /usr/bin/tunnelgate-uninstall       removed via the installer or itself
    /usr/lib/tunnelgate/json.sh         POSIX awk JSON reader used by the heartbeat
    /root/.ssh/tunnelgate_ed25519       0600, never leaves the router
    /root/.ssh/known_hosts              the panel's pinned host key

The private key is never stored server-side and never written by any panel code path.
[docs/SECURITY.md](SECURITY.md) section 3 explains what the key is allowed to do on the panel
side.
