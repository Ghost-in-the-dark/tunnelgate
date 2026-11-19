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
| OpenWrt 21.02 or newer (or a stock Linux with `procd`) | `procd`, UCI, and a TLS stack that actually checks a certificate chain - see section 8. **19.07 also works**, with one extra package and one caveat: install `libustream-wolfssl` or the installer never downloads, and `tls_verify=1` is recorded but not enforced there (section 8) |
| Outbound SSH to the panel's `ssh_port` (default 22) | the tunnel is an outbound `ssh -R`; nothing listens on the router |
| Outbound HTTPS to the panel URL | the exchange and the heartbeat (on 19.07 see section 8 before trusting this) |
| Root shell on the router | the installer writes `/etc/config`, `/root/.ssh` and the init script |
| Working DNS and a sane clock | TLS fails with a wrong date; the bootstrap token has a 15-minute TTL |
| OpenSSH client (three packages, see below) | installed automatically when the client on the router is not OpenSSH |

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

The dialog contains this block:

    TK='<token>'; U='https://panel.example.com/api/v1/routers/install?os=linux'; F=/tmp/tg-install.$$.sh
    if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$F" -u "$TK:" "$U"
    elif command -v wget >/dev/null 2>&1; then wget -q -O "$F" --user="$TK" --password=x "$U"
    else echo 'TunnelGate: neither curl nor wget is installed on this router' >&2; exit 1; fi
    grep -q 'TunnelGate router agent installer' "$F" 2>/dev/null || { echo "TunnelGate: the panel did not return the installer; mint a fresh install command and retry" >&2; rm -f "$F"; exit 1; }
    sh "$F"

Every line of that is deliberate, and each one was forced by how a stock router behaves:

* **`curl` first, `wget` second, and never `curl ... || wget ...`.** No official OpenWrt image
  ships curl, and its `/usr/bin/wget` is a symlink to `uclient-fetch`. The fetcher is probed
  once; a failed curl must not fire a second request, because every render burns the same
  per-token quota.
* **The token rides as the basic-auth username**, not in the URL and not in a header.
  `uclient-fetch` before 24.10 has no `--header` at all, and an unknown option there is not
  even a hard failure - it prints usage and exits 0, so a header would silently send nothing and
  still look like success. URL userinfo is out too: GNU wget 1.25 refuses it outright. The
  `--password=x` is a placeholder whose only job is to keep the colon in `base64(TOKEN:x)`;
  with an empty password `uclient-fetch` sends `base64(TOKEN)` and the panel answers 401.
* **Fetch to a file, check it, then run it.** A 401 answers an empty body, and `| sh` on an
  empty body is a silent success that leaves the operator watching a router that never dials in.
  `uclient-fetch` exits 0 on an HTTP error, so the sentinel - not the fetch status - is what
  separates the installer from any other body. The installer repeats the same check on itself.
* The token is **single-use** and expires in 15 minutes. Re-running the same command after a
  successful exchange returns `401 invalid_token` and changes nothing.
* The token **does** land in the router's shell history (it is an argument, not a URL). It is
  single-use and short-lived, and the credential the panel logs is not this one.

The fetched script is left in `/tmp/tg-install.$$.sh`. The panel injects **four** assignments at
the top of it - `TG_PANEL_URL`, `TG_BOOTSTRAP_TOKEN`, `TG_OS_TYPE` and `TG_TLS_VERIFY` - of
which the URL and the token are required; nothing else in the file is secret. The private key
is not there at all: it is minted by the exchange, after the script is already running.

The command is also available later from the router page (**Install command**); issuing a new
one invalidates the previous one.

---

## 3. Run it on the router

    ssh root@192.168.1.1
    # then paste the block from the panel (it starts with TK='...')

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

1. refuses to run without the injected URL and token, without root, and on a non-OpenWrt host
   unless `TG_FORCE=1` - and it refuses to run at all when it is not the file the panel meant to
   serve, see [the sentinel check](#the-sentinel-check) below;
2. makes sure an **OpenSSH** client is usable, and installs whatever is missing. It does not
   ask "does `ssh` exist" - on every stock image `/usr/bin/ssh` is a symlink to `/usr/sbin/dropbear`,
   so that test always passes and nothing gets installed. Instead it probes three capabilities:
   `ssh -V` must mention `OpenSSH_`; `ssh-keygen` must be able to *generate* an OpenSSH-format
   key (dropbear's cannot) and read it back; `ssh-keyscan` must exist. Each failing capability
   names the package that supplies it - `openssh-client` (the `ssh` binary), `openssh-keygen`
   and `openssh-client-utils` (`ssh-keyscan` lives there) - and all three are installed together
   with `apk add` on images that use apk and `opkg install` on the rest. Evidence level: the
   opkg path was run end to end on 19.07.10, 23.05.5 and 24.10.1, while the apk path (the
   development snapshot - 24.10.x still uses opkg) is exercised by `apk add --simulate` only:
   the three package names resolve to `openssh-client`, `openssh-keygen` and
   `openssh-client-utils`, but the install itself has not been replayed on an apk image.
   Note the trap: on 19.07 `uclient-fetch` advertises `--no-check-certificate` but has no TLS
   library linked, so an https fetch dies with "SSL support not available";
   `opkg install libustream-wolfssl` fixes it
   (on 19.07 the exact package name is `libustream-wolfssl20150806`). The installer detects and
   names this case itself;
3. posts `hostname`, `model`, `openwrt_version`, `mac`, `uptime_seconds`, `client_version`
   and `bootstrap_token` to `/api/v1/routers/bootstrap/exchange`. The token travels **in the
   JSON body and nowhere else** - it is never on a command line, because every local user can
   read `/proc/<pid>/cmdline`. On a stock router the body is also the only channel that works,
   see section 2;
4. writes the ed25519 private key from the response to `/root/.ssh/tunnelgate_ed25519` (0600)
   - this is the only time the key exists outside the router;
5. scans the panel's host key and **aborts** unless the fingerprint matches the one in the
   response, then pins it in `/root/.ssh/known_hosts`;
6. writes `/etc/config/tunnelgate` (UCI, 0600) with the panel host/port, ports, API token,
   heartbeat URL and `tls_verify` (section 8);
7. installs `/usr/bin/ssh-loop`, `/usr/bin/tunnelgate-heartbeat`,
   `/usr/bin/tunnelgate-uninstall`, `/usr/lib/tunnelgate/json.sh` and
   `/etc/init.d/tunnelgate`;
8. enables and starts the service.

Every step is idempotent: running the installer a second time with a **fresh** token leaves
the same files, the same pinned host key and the same key bytes. It is the documented recovery
path when something looks wrong.

Before any of this, the fetch itself can fail on a **bare** 19.07 image: the `uclient-fetch`
shipped there has no TLS library linked, so an `https` panel answers `wget: SSL support not
available, please install one of the libustream-.*[ssl|tls] packages ...` and no installer is
ever downloaded - the operator sees only "the panel did not return the installer". The
installer's own `ensure_tls_lib()` cannot rescue this one, by construction: it runs *inside*
the script that was never fetched. Install the package first (`opkg install
libustream-wolfssl ca-bundle`) and mint a fresh command - see the matching row in section 7
and the 19.07 caveat in section 8.

### The sentinel check

The panel does not pipe the script into `sh`. It fetches it to `/tmp/tg-install.$$.sh`, greps
that file for one line - the sentinel

    # TunnelGate router agent installer (OpenWrt, POSIX sh / busybox ash).

- and only then runs `sh "$F"`. The sentinel is line 2 of what the panel serves, right under
`#!/bin/sh`, and the four `TG_*` assignments are injected below it.

Three things depend on it, which is why the installer repeats the check on itself before touching
anything:

* **A refusal cannot be executed.** A 401 from the panel answers an empty body, a captive portal
  answers its login page, a proxy answers an error page - all of which a shell would happily run
  as a no-op and exit 0 on, leaving an operator convinced the install worked.
* **A truncated write is caught.** `uclient-fetch` exits 0 even when the transfer was cut short;
  a body without the sentinel is not the installer, whatever its exit status was.
* **A re-saved script is still recognised.** The check reads a window (`SELF_SCAN_LINES=40`), not
  line 2 alone, so a future panel that injects more lines does not turn every install into
  "does not look like the TunnelGate installer". A window, not "grep the whole file": a stray
  copy of the sentinel far down in some other page must not vouch for the file.

If you see that message, the file is not the installer - the panel did not return the script.
Mint a fresh install command and retry; do not edit the file to get past the check.

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
to `root`.

If you set a dedicated user in the panel, the installer tries to create it once, without a
password. Two things decide whether that works, and it is worth knowing which one you are in,
because the panel's `console.user` field is stored on the router as `option console_user` and
is what dropbear will be asked for:

* **The account exists or was created.** The key is written to *that account's* key file -
  `$HOME/.ssh/authorized_keys`, mode 0600 in a 0700 directory - not to root's. Dropbear reads a
  user's own file only for that user; a `from=` line in `/etc/dropbear/authorized_keys` does
  not authenticate a non-root login. The account is given a shell and no password, and it keeps
  its home directory precisely so the key has somewhere to live.
* **The account cannot be created** (`adduser` missing, read-only rootfs, full flash). The
  installer does **not** leave the panel asking for a user that does not exist: it logs a
  `WARNING`, writes `option console_user 'root'` into `/etc/config/tunnelgate` and puts the
  key where root's dropbear reads it. The console then works, as root, and the panel's next
  heartbeat sees the account the router actually has. Create the account by hand and re-run the
  installer if you want it.

A third option is recorded for removal: `option console_user_created '1'` is written only when
the installer really created the account. Both uninstallers check it before deleting anything,
so `--purge` removes the console account **only** if the agent created it - a user account that
was there first is left alone.

> Revoking access is done on the panel (rotate or delete the console key). The router keeps a
> stale line until the next heartbeat delivers a higher serial, so rotate rather than hand-edit
> `authorized_keys`.

---

## 6. Removing the agent

    /usr/bin/tunnelgate-uninstall --dry-run     # show what would go
    /usr/bin/tunnelgate-uninstall               # remove it
    /usr/bin/tunnelgate-uninstall --purge       # also remove the OpenSSH packages and the
                                                # console user

It removes the init script, the UCI config, both supervisor scripts, the state directory, the
private key and **only** the `tunnelgate-console` line from `authorized_keys` - another
operator's keys in that file are kept. `--purge` additionally removes `openssh-client`,
`openssh-keygen` and `openssh-client-utils` - exactly the three packages the installer may have
installed, one log line each, best effort. Then delete the router in the panel, which releases
the ports and drops the key line from the panel's own `authorized_keys`.

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
| `wget: SSL support not available, please install one of the libustream-.*[ssl\|tls] packages ...` followed by `TunnelGate: the panel did not return the installer; mint a fresh install command and retry` | the fetcher itself has no TLS: 19.07 builds `uclient-fetch` without a TLS library, so the **very first https fetch** - the one that downloads the installer - dies before any of our code runs. The panel was fine. | `opkg update && opkg install libustream-wolfssl ca-bundle` (the exact 19.07 package name is `libustream-wolfssl20150806`), then mint a **fresh** command: the old token was never spent, but the fetch that uses it failed |
| `curl: (6) Could not resolve host` | router DNS | check `nslookup panel.example.com`, fix `resolv.conf` |
| `curl: (60) certificate is not yet valid` | router clock is wrong | sync NTP, re-run |
| `curl: (60) mbedTLS: The certificate Common Name (CN) does not match with the expected CN` / `BADCERT_CN_MISMATCH` and/or `The certificate is not correctly signed by the trusted CA`, while the panel itself answers fine | the router is resolving the panel name to **its own WAN address**, so the packet is answered locally on port 443 by LuCI (`uhttpd`) with its self-signed `CN=OpenWrt` cert - never reaching the edge proxy | see below: this is a router-side DNS problem, not a panel or nginx fault |
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
The supported way to accept a certificate the router cannot validate is the panel setting
described in section 8 - it is scoped to this one connection and it is written down where the
next operator can find it, which `-k` in a shell history is not.

Useful overrides for debugging on a stripped or unusual image - they exist so the tests can
drive the real scripts, but they also work on a device:

| Variable | Default |
|---|---|
| `TG_FORCE=1` | skip the OpenWrt check |
| `TG_STATE_DIR` | `/usr/lib/tunnelgate` |
| `TG_CONFIG` | `/etc/config/tunnelgate` |
| `TG_KEY_PATH` | `/root/.ssh/tunnelgate_ed25519` |
| `TG_KNOWN_HOSTS` | `/root/.ssh/known_hosts` |
| `TG_TLS_VERIFY` | injected by the panel; otherwise `tunnelgate.main.tls_verify` (section 8) |
| `TG_TLS_WARN_FILE` | `/tmp/.tunnelgate-tls-warning` (rate limits the once-per-boot warning) |
| `TG_TLS_CAP_WARN_FILE` | `/tmp/.tunnelgate-tls-capability-warning` (the same for the "cannot verify" warning) |
| `TG_TLS_LIB_DIRS` | `/lib /usr/lib` (where a TLS-capable libustream is looked for) |
| `TG_OPENWRT_RELEASE` | `/etc/openwrt_release` (the file the version checks read) |
| `TG_PASSWD` | `/etc/passwd` (the account database the console-user step reads) |
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

---

## 8. TLS verification, and how to turn it off for one panel

Every router checks the panel's certificate against the CA store in the image. That is not
negotiable by default and it is the right default: the bootstrap exchange hands the router its
private key and, on the same connection, its API token.

What an operator actually hits is a **self-signed panel**. The symptom depends on the fetcher:

    curl:  curl: (60) SSL certificate problem: self-signed certificate
           (or "certificate is not correctly signed by a trusted CA")

    uclient-fetch: SSL verify error: certificate is self-signed or not signed by a trusted CA
                   (older uclient-fetch is quieter; the exchange then fails with no HTTP status)

Either way the installer stops before touching the router, with

    cannot reach the panel at <url>: <the fetcher's own line>
    DNS, TLS, firewall or a wrong panel URL could each do this. ...

### The setting

It is **per panel**, not per router, and it lives in the panel UI:
**Settings -> Panel -> Agent endpoint -> "Ignore SSL self-signed certificates"**. Ticking it
(and saving) makes the panel render `TG_TLS_VERIFY=0` into every install command from then on.
Over plain `http` the checkbox is greyed out - there is no certificate to check - and the panel
still records verification as on, because nothing is being skipped.

On the router the same choice is the UCI option `tunnelgate.main.tls_verify`, readable in
`/etc/config/tunnelgate`:

    uci get tunnelgate.main.tls_verify      # '1' verify, '0' skip the check

The installer writes it from whatever the panel injected, so a saved script re-run by hand keeps
the decision, and a value set by hand survives a re-install: when `TG_TLS_VERIFY` is absent the
installer falls back to the option already in the file.

To change it on a live router without a new token:

    uci set tunnelgate.main.tls_verify=0
    uci commit tunnelgate
    /etc/init.d/tunnelgate restart

Both the reconnect loop and the heartbeat read the option at every start, so the restart is what
applies it. Setting it back to `1` is the same three commands with `=1`. `/etc/init.d/tunnelgate
restart` also re-runs the two procd instances, which is enough - there is no separate fetch step
to redo.

### What it costs

Turning verification off means **whoever can answer for that hostname receives the bootstrap
token and the API token**. Not a theoretical downgrade: a poisoned DNS entry, a wrong
`/etc/hosts` line, or a captive portal on the WAN port all become a working key. The tunnel
itself is still encrypted to that party, so the mistake is silent afterwards - the panel shows
the router as offline and nothing else looks wrong.

Use it when the panel's certificate genuinely cannot be validated (self-signed, or an internal
CA the image does not carry) and keep the endpoint on a network you control. The heartbeat logs
one warning per boot when it is off, and the installer prints one at install time - that warning
in `logread` is the reminder to switch it back.

### When the value is wrong

Only the exact string `0` disables the check. `1`, `yes`, `2`, `false`, an empty value or any
typo mean **verify**. That direction is deliberate: a setting we cannot parse must not be able to
downgrade the connection that carries credentials, so the failure mode is a refused connection
and a message, never a silent `-k`.

```
uci get tunnelgate.main.tls_verify     # empty or missing: verification is ON
```

### OpenWrt 19.07: `tls_verify=1` does not mean what it says

Measured, not inferred. On **19.07.10** with `libustream-wolfssl20150806` and `ca-bundle`
installed, `uclient-fetch` **accepts a self-signed certificate**: it fetched our self-signed test
panel and got as far as the panel's own `401`, where 21.02.7, 22.03.7, 23.05.5 and 24.10.1 all
stop with `Connection error: Invalid SSL certificate`. A **hostname mismatch is still caught**
(`Server hostname does not match SSL certificate`), so the failure is specifically the chain
check.

That means on 19.07 the option is recorded as `1`, the installer does not print its
"verification is OFF" warning, and the connection is nevertheless not authenticated - a
self-signed impostor on the path is accepted. The installer therefore prints a second, different
warning on images older than 21.02:

    WARNING: on OpenWrt 19.07.10 the fetcher cannot check a certificate chain: it accepts
    self-signed certificates (a wrong hostname is still caught). tls_verify=1 is recorded,
    but it is not being enforced. 21.02 or newer is required for real verification

21.02 is the supported floor for this reason and others (see section 1). If a router must stay
on 19.07, treat the agent endpoint as unauthenticated: keep the panel on a network you control,
or use `http` deliberately rather than believing `https` bought you anything.

### On such a router the installer refuses, unless you said so

A warning in `logread` is not consent, and it is not even read: the exchange is the first
https request the router ever makes, and the host key fingerprint arrives **in the same
response** as the private key. A machine on the path can substitute the key, the fingerprint and
the pinned `known_hosts` entry together, so `pin_host_key` cannot detect it - its input was
attacker-controlled from the start.

So when the panel URL is `https` and the fetcher cannot check a chain, the installer stops
**before** the POST, when `tls_verify=1`:

    error: this router's TLS stack cannot check a certificate (OpenWrt 19.07.10 is a
    19.07-generation release, and such a fetcher was measured to accept a self-signed
    certificate), so the panel cannot be authenticated over it. ...
    Two ways forward: upgrade the router to OpenWrt 21.02 or newer ..., or - if the panel
    really does use a self-signed certificate - open Settings > Agent endpoint in the panel and
    turn the certificate check off for this panel. ...
    Nothing has been sent: the bootstrap token already crossed the wire in the download command
    you pasted, but no private key or API token has.

Two ways out, both explicit:

* **Upgrade to 21.02 or newer.** Real verification, nothing else to decide.
* **Turn the check off in the panel** (section above). Then the acknowledgement is a setting
  with an audit trail instead of a silent acceptance, the installer proceeds with one warning,
  and the heartbeat repeats that warning once per boot. "Once per boot" is literal: procd
  mounts `/tmp` as a fresh `tmpfs` (`mode=01777`) during early init, so the marker file cannot
  survive a reboot and a router that power-blips warns once per blip - not once ever, and not
  every 60 seconds.

There is deliberately no environment-variable bypass for this. `TG_FORCE` exists to skip the
OpenWrt check on a test host; mixing "not OpenWrt" and "I accept an unauthenticated panel" into
one switch is how both get used by accident.

### Why `http` is different

A plain-`http` endpoint has no certificate at all, so there is nothing to verify and nothing to
skip - the exchange and the heartbeat ride in clear text on whatever network the router sits on.
That is acceptable only when the panel is on the same trusted LAN as the routers (for example
the "panel behind the router" case in section 7). Over the internet, use `https`, with a real
certificate, and leave `tls_verify` alone.
