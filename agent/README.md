# Router agent

POSIX sh (busybox ash / dash) code that runs on the router. Operator-facing documentation is
[docs/INSTALL_ROUTER.md](../docs/INSTALL_ROUTER.md); this file is about the code.

    install.sh          panel-served installer; the only thing an operator runs
    uninstall.sh        standalone uninstaller (installed as /usr/bin/tunnelgate-uninstall)
    tunnelgate.init     procd service, installed as /etc/init.d/tunnelgate
    lib/json.sh         POSIX awk JSON reader (no jq on OpenWrt)
    lib/ssh-loop.sh     reconnect loop, installed as /usr/bin/ssh-loop
    lib/heartbeat.sh    heartbeat + console-key delivery, installed as /usr/bin/tunnelgate-heartbeat

## install.sh ships the other four

`install.sh` is the only file that reaches the router, so the other files are embedded in
it as heredocs and written out at install time:

| marker | written to | source of truth |
|---|---|---|
| `TG_EOF_JSON` | `/usr/lib/tunnelgate/json.sh` | `lib/json.sh` |
| `TG_EOF_LOOP` | `/usr/bin/ssh-loop` | `lib/ssh-loop.sh` |
| `TG_EOF_HB` | `/usr/bin/tunnelgate-heartbeat` | `lib/heartbeat.sh` |
| `TG_EOF_INIT` | `/etc/init.d/tunnelgate` | `tunnelgate.init` |
| `TG_EOF_UNINSTALL` | `/usr/bin/tunnelgate-uninstall` | `uninstall.sh` |

**After editing any of the standalone files, re-embed them.** `tests/test_installer.py`
asserts that the embedded copy is byte-identical, so a forgotten re-embed fails the suite
rather than shipping a stale script:

    .venv/bin/python - `<<'PY'`
    import pathlib, re
    root = pathlib.Path("agent")
    inst_p = root / "install.sh"
    inst = inst_p.read_text()
    for marker, rel in [
        ("TG_EOF_JSON", "lib/json.sh"),
        ("TG_EOF_LOOP", "lib/ssh-loop.sh"),
        ("TG_EOF_HB", "lib/heartbeat.sh"),
        ("TG_EOF_INIT", "tunnelgate.init"),
        ("TG_EOF_UNINSTALL", "uninstall.sh"),
    ]:
        src = (root / rel).read_text().rstrip("\n")
        pat = re.compile(r"(<<'" + marker + r"'\n)(.*?)(\n" + marker + r"\n)", re.S)
        inst = inst[: pat.search(inst).start(2)] + src + inst[pat.search(inst).end(2) :]
    inst_p.write_text(inst)
    PY

## The two placeholder lines

`install.sh` contains two comment lines that the panel replaces before serving it:

    #@@PANEL_URL_LINE@@
    #@@BOOTSTRAP_TOKEN_LINE@@

They must each appear **exactly once** and **alone on their line**. They are the only channel
through which the panel URL and the single-use bootstrap token reach the router; putting the
token in a URL would land it in the nginx access log, the shell history and `ps` output.
`app/services/bootstrap.py` does the substitution; `tests/test_installer.py` performs
the same substitution on the shipped file, so a broken marker breaks tests, not a router.

Those two markers are what the file itself needs. The **served** file additionally carries
`TG_OS_TYPE` and `TG_TLS_VERIFY`, which `render_install_script` injects above the body - four
assignments in total, of which only the URL and the token are required (the other two have safe
defaults: linux, verify). Anything that renders this script must keep the sentinel within
`SELF_SCAN_LINES` lines of the top; see the regression tests that render through
`bootstrap.render_install_script` rather than through `stage_installer`.

## Every path is overridable

Each absolute path is a `${TG_*:-default}` assignment, so the real scripts run verbatim
in a temp tree during tests:

| variable | default |
|---|---|
| `TG_STATE_DIR` | `/usr/lib/tunnelgate` |
| `TG_KEY_PATH` | `/root/.ssh/tunnelgate_ed25519` |
| `TG_KNOWN_HOSTS` | `/root/.ssh/known_hosts` |
| `TG_CONFIG` | `/etc/config/tunnelgate` |
| `TG_INITD` | `/etc/init.d/tunnelgate` |
| `TG_LOOP_BIN` / `TG_HB_BIN` / `TG_UNINSTALL_BIN` | `/usr/bin/...` |
| `TG_KEYS` | `/etc/dropbear/authorized_keys` |
| `TG_SKIP_SERVICE` | `0` (set `1` to skip every init-system call) |
| `TG_FORCE` | `0` (set `1` to skip the OpenWrt check) |
| `TG_TLS_VERIFY` | injected by the panel; falls back to `uci get tunnelgate.main.tls_verify` |
| `TG_TLS_WARN_FILE` | `/tmp/.tunnelgate-tls-warning` (once-per-boot warning sentinel) |
| `TG_TLS_CAP_WARN_FILE` | `/tmp/.tunnelgate-tls-capability-warning` (same, for "cannot verify") |
| `TG_TLS_LIB_DIRS` | `/lib /usr/lib` (where libustream is looked for) |
| `TG_OPENWRT_RELEASE` | `/etc/openwrt_release` (read by the version checks) |
| `TG_PASSWD` | `/etc/passwd` (the console-user lookup) |

## The fetcher, and where the token travels

`install.sh` probes the fetcher **once** (`detect_fetcher`) and every request reuses the
answer. The two are not interchangeable, and the reason is measured, not stylistic:

* **No curl on stock OpenWrt.** No generation of the official images ships it.
* **`/usr/bin/wget` is `uclient-fetch`.** Before 24.10 it has no `--header`, no `-S` and no
  `-w`. An unknown option there is *not* a hard failure - it prints usage and exits 0, so a
  header-carrying wget silently sends nothing and still reports success.
* **Basic auth does not authenticate a POST on it.** uclient-fetch is a challenge-response
  client: it sends no `Authorization` on the first request and does not retry a POST after the
  401, so `--user`/`--password` cannot carry the credential on that path.
* **URL userinfo is out.** GNU wget 1.25 rejects a userinfo URL outright (exit 6).

So the token has one reliable channel on every generation: **the JSON request body**
(`bootstrap_token` for the exchange, `api_token` for the heartbeat). That is the only channel
used - the legacy `X-Bootstrap-Token`/`X-Api-Token` header and `-u "$TOKEN:"` were removed
from the curl path even though curl could send them:

* every argument of a running process is world-readable in `/proc/<pid>/cmdline`, so a header
  or a `-u` value is a credential on display for the whole life of the request - and the
  heartbeat survives long enough to matter, since procd restarts it every 60 seconds;
* the body channel is already required and already authenticated by the panel
  (`app/api/heartbeat.py` accepts the token there), so the extra channel bought nothing.

The rule that follows: **no credential ever appears in an argument list**; it goes into a file
with mode 0600 inside the private temporary directory, and `--data-binary @file` carries it.

The status is derived per fetcher: curl keeps `-w '%{http_code}'` (`000` means the request
never completed - DNS, TLS, refused - not an HTTP status); the wget path runs **without `-q`**
because the status exists only in the progress output, and parses three spellings
(`HTTP error NNN` / `awaiting response... NNN` / `ERROR NNN`). Exit 0 with no status line counts
as 200, and the body is still validated, so a captive-portal page cannot pass as an exchange
response.

The panel hands out a command that fetches to a file, greps `TunnelGate router agent installer`
and only then runs it - a 401 answers an empty body and `| sh` on it would be a silent success.
`install.sh` repeats that check on itself (`check_self`), so a body that loses its header line
is refused even when it is run directly.

## TLS verification

The panel connection is verified unless the panel explicitly says otherwise. The switch is
per-panel, in **Settings → Agent endpoint**, and reaches the router as `TG_TLS_VERIFY`
(`1` / `0`) injected alongside the URL and the token. It becomes the UCI option
`tunnelgate.main.tls_verify` so heartbeats keep the same policy after the installer exits,
and so `uci set tunnelgate.main.tls_verify=1` survives a re-install.

Resolution order, in both `install.sh` and `lib/heartbeat.sh`:

1. `TG_TLS_VERIFY` when it is set (the panel injected it, or the operator overrode it);
2. otherwise `uci get tunnelgate.main.tls_verify` (read with a `sed` fallback where `uci` is
   absent, like every other option);
3. otherwise **verify**.

Only the exact string `0` turns verification off. `1`, `yes`, `2`, `false`, `TRUE`, an empty
value and anything else mean verify - a value we do not understand must never silently
downgrade the connection that carries the bootstrap token and, afterwards, the API token.

The flags are `-k` (curl) and `--no-check-certificate` (wget), inserted as their own argv word
so a reader can see the check being disabled in the command they paste. Nothing else in either
script disables certificate checking, and `http_post`/`post()` are the only call sites.

When verification is off the installer logs one warning naming the host and the fix, and the
heartbeat warns **once per boot** (sentinel file `TG_TLS_WARN_FILE`) rather than every minute.
"Once per boot" is literal on OpenWrt: procd mounts `/tmp` as a fresh `tmpfs` (`mode=01777`) in
early init (`/sbin/init`), so the marker is gone after a reboot and there is no accumulation.

### Where "verified" is not true: OpenWrt 19.07

Measured on `openwrt/rootfs:x86-64-19.07.10` with `libustream-wolfssl20150806` + `ca-bundle`:
`uclient-fetch` **accepts a self-signed certificate**. It fetched our self-signed test panel and
reported the panel's `401`, where 21.02.7, 22.03.7, 23.05.5 and 24.10.1 all stop with
`Connection error: Invalid SSL certificate`. A **hostname mismatch is still caught**
(`Server hostname does not match SSL certificate`), so the gap is specifically the chain check.

So `tls_verify=1` on that generation records a promise the fetcher cannot keep.
`tls_stack_cannot_verify` detects it (fetcher is wget and `DISTRIB_RELEASE` major < 21, or the
release could not be parsed at all - `[0-9]*` also matches `19x`, the numeric comparison then
returns 2, and inside an `if` that reads as "safe", so an unparsable version is treated as
unverified and never as modern).

The detection has two consequences, and the difference between them is the point:

* `tls_verify=1` (the default) - `do_exchange` **refuses before the POST**. A warning in a log
  is not consent, and it could not help anyway: the host key fingerprint arrives in the same
  response as the private key, so a machine on the path substitutes the key, the fingerprint and
  the pinned entry together and `pin_host_key` sees a perfect match. The refusal names both ways
  out (OpenWrt 21.02+, or turn the check off in the panel) and states what it did and did not
  protect: the bootstrap token already crossed the wire in the download command, the private key
  and the API token have not.
* `tls_verify=0` - the acknowledgement already exists as a panel setting with an audit trail,
  so the installer proceeds with one warning, and `lib/heartbeat.sh` repeats a *different*
  warning once per boot (its own sentinel, `TG_TLS_CAP_WARN_FILE`, so it cannot be suppressed by
  the `tls_verify=0` one). The heartbeat deliberately does not refuse: a router installed before
  this check must not silently lose its liveness signal.

There is no environment override for the refusal. `TG_FORCE` means "not OpenWrt, do not check" -
one switch for two unrelated risks is how both get used by accident. 21.02 is the floor for real
verification, which is why the docs state it as a requirement.

## Conventions

* **Certificate verification is on unless the panel turned it off.** `tls_verify=0` is a
  per-panel decision made in the UI, arrives as `TG_TLS_VERIFY`, and is persisted to UCI; only
  the exact string `0` disables it, and a malformed value verifies.
* **POSIX sh only.** No bashisms (no `$(( ))`, no `[[ ]]`, no `function`, no arrays,
  no `local`). Both `dash` and busybox ash run every script, and the test suite checks it.
* **Log through `log()`.** It writes to syslog as `tunnelgate` and to stderr, so the
  same message shows up in `logread -e tunnelgate` and in an interactive run.
* **Never print the private key.** It goes from the exchange response straight into the key
  file (0600) and is only ever handed to `ssh -i`.
* **Fail loudly on security decisions, quietly on convenience.** A host key mismatch aborts the
  install; a failed heartbeat retry only logs.
* **Idempotent.** Re-running the installer is the documented recovery path: it must not
  duplicate UCI sections, append `known_hosts` lines or rewrite an unchanged key.
* **No `jq`.** OpenWrt does not ship it; `lib/json.sh` is a small awk recursive-descent
  reader with the same dotted-path interface (`json_get router_id`, `json_get ssh.port`).
* **No `uci` dependency at runtime.** `uci` when present, otherwise a sed fallback parses
  `option name 'value'` lines - which is also what makes the scripts testable off-device.

## Testing

    .venv/bin/python -m pytest tests/test_installer.py -q              # 62 tests, needs root
    .venv/bin/python -m pytest tests/test_installer.py -m e2e -q      # 4 tests, needs a local sshd
    .venv/bin/python -m pytest tests/test_installer.py -k 'not e2e' -q # 58 tests, no sshd

The suite drives the shipped scripts through the `TG_*` overrides against a mock panel
(single-use token, heartbeat, console registration) and a throwaway sshd, so it proves the
reverse forwards really open and the console key really lands. Static classes cover `sh -n`
under dash and busybox, the absence of bashisms, the placeholder contract and the
embedded/standalone drift check.

The fetcher and TLS behaviour is proved by recording the **real argv** of each request, not by
grepping the source: a wrapper around the real `curl`/`wget` appends `<name> $*` to a log and
then execs it, so the assertions see exactly the words the process received. The wget cases run
under a session-scoped PATH clone without `curl`, which is what a stock router looks like.

The scripts are also linted:

    .venv/bin/shellcheck -s sh -S warning agent/*.sh agent/lib/*.sh agent/tunnelgate.init

## The console channel

The web console reuses the same sshd the tunnel already authenticates to, in the opposite
direction. Two things have to be true on the router:

1. **dropbear stays running** on port 22 (the console forwards to `127.0.0.1:22`, so the
   panel's session lands in the router's own sshd, not in a shell the agent spawns).
2. **the panel's console key is in the router's `authorized_keys`.** The key pair is
   created by the panel the first time an operator opens a console, so the installer cannot
   ship the public half. Delivery therefore goes over the heartbeat that is already running:
   the panel puts a `console` registration into the heartbeat response, and
   `lib/heartbeat.sh` acts on it only when the serial is **greater** than the stored
   `console_serial` - so the key is written once, not on every poll.

The line written is the one `app/security.py:console_authorized_key_line` builds, kept
deliberately to the option subset dropbear understands:

    from="<allowed_from>",no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA... tunnelgate-console

There is **no `no-pty` here on purpose** - an interactive shell is the whole point of this
key, unlike the tunnel key, which has `no-pty` and `command="/bin/false"`. Neither key
can open anything the other can: the tunnel key may only listen on its two authorized
reverse ports, the console key may only get a shell from the allowed source address.

The rewrite is atomic (temp file, `chmod 600`, `mv`) because a half-written
`authorized_keys` would lock the operator out of dropbear, which is exactly the state
nobody can debug remotely. Only lines ending in `tunnelgate-console` are replaced; other
keys in the file survive, and the uninstaller removes only that comment tag.

## Security notes

* The private key is generated by the panel, exists only inside the exchange response, and is
  never stored server-side.
* The panel's host key is pinned on first install and verified against the fingerprint the
  panel reports; the installer refuses to write it otherwise.
* The public key installed on the panel is restricted with `permitlisten` for exactly the two
  reverse ports, plus `no-pty`, `command="/bin/false"` and `permitopen="127.0.0.1:1"` (`none` is
  an sshd_config-only keyword: as a key option sshd rejects the entire line).
* The console key the heartbeat installs is restricted with `from="127.0.0.1"` plus
  `no-port-forwarding`, `no-agent-forwarding` and `no-X11-forwarding`; it keeps a pty
  because an interactive shell is the point.
* The uninstaller removes only the `tunnelgate-console` line it wrote; other operators'
  keys in `authorized_keys` are untouched.
