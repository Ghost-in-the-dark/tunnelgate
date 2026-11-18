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

## Conventions

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

    .venv/bin/python -m pytest tests/test_installer.py -q          # 39 tests, needs root
    .venv/bin/python -m pytest tests/test_installer.py -m e2e -q  # needs a local sshd

The suite drives the shipped scripts through the `TG_*` overrides against a mock panel
(single-use token, heartbeat, console registration) and a throwaway sshd, so it proves the
reverse forwards really open and the console key really lands. Static classes cover `sh -n`
under dash and busybox, the absence of bashisms, the placeholder contract and the
embedded/standalone drift check.

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
