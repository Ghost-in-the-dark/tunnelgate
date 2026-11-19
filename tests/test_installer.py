"""Router agent (agent/) tests: shipped-script behaviour against a mock panel and a real sshd.

These tests exercise the SHIPPED scripts, not a copy. The installer reads every absolute
path from a TG_* environment variable (whose defaults are the real OpenWrt paths), so a test
run stages a complete agent into tmp_path without ever touching /etc or /root.

The e2e tests need a local sshd (marked "e2e", skipped when it is absent): they prove the
reconnect loop really opens the reverse forwards and that the heartbeat really installs the
console key - neither is established by static checking.
"""

from __future__ import annotations

import base64
import contextlib
import http.server
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
AGENT = REPO / "agent"
INSTALL = AGENT / "install.sh"
INIT = AGENT / "tunnelgate.init"
JSON_LIB = AGENT / "lib" / "json.sh"
SSH_LOOP = AGENT / "lib" / "ssh-loop.sh"
HEARTBEAT = AGENT / "lib" / "heartbeat.sh"
UNINSTALL = AGENT / "uninstall.sh"

SHELLS = [sh for sh in ("dash", "busybox") if shutil.which(sh)]
SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").exists() else None)

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0, reason="the installer refuses to run as non-root"
)

needs_sshd = pytest.mark.skipif(SSHD is None, reason="no sshd on this host")
needs_shells = pytest.mark.skipif(not SHELLS, reason="no POSIX shell to run the scripts with")


# ---------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------


def run(cmd: list, **kw) -> subprocess.CompletedProcess:
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("timeout", 120)
    return subprocess.run(cmd, **kw)


def shell_argv(shell: str, script: Path, *args: str) -> list:
    """Both busybox and dash run a POSIX script the same way; busybox needs its applet name."""
    if Path(shell).name == "busybox":
        return [shell, "sh", str(script), *args]
    return [shell, str(script), *args]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for_port(port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.05)
    return False


def stage_installer(dest: Path, panel_url: str, token: str) -> Path:
    """Do what the panel does: substitute the two marker lines. Asserts that contract first."""
    src = INSTALL.read_text()
    assert src.count("#@@PANEL_URL_LINE@@") == 1, "the panel URL marker must appear exactly once"
    assert src.count("#@@BOOTSTRAP_TOKEN_LINE@@") == 1, "the token marker must appear exactly once"
    src = src.replace("#@@PANEL_URL_LINE@@", f'TG_PANEL_URL="{panel_url}"')
    src = src.replace("#@@BOOTSTRAP_TOKEN_LINE@@", f'TG_BOOTSTRAP_TOKEN="{token}"')
    out = Path(dest) / "install.sh"
    out.write_text(src)
    out.chmod(0o755)
    return out


def agent_env(tmp: Path, **extra) -> dict:
    """Redirect every path the installer writes into a temp tree."""
    env = dict(os.environ)
    env.update(
        {
            "TG_FORCE": "1",  # do not insist on a real OpenWrt
            "TG_SKIP_SERVICE": "1",  # never call the host init system
            "TG_STATE_DIR": str(tmp / "usr/lib/tunnelgate"),
            "TG_KEY_PATH": str(tmp / "ssh/tunnelgate_ed25519"),
            "TG_KNOWN_HOSTS": str(tmp / "ssh/known_hosts"),
            "TG_CONFIG": str(tmp / "etc/config/tunnelgate"),
            "TG_INITD": str(tmp / "etc/init.d/tunnelgate"),
            "TG_LOOP_BIN": str(tmp / "usr/bin/ssh-loop"),
            "TG_HB_BIN": str(tmp / "usr/bin/tunnelgate-heartbeat"),
            "TG_UNINSTALL_BIN": str(tmp / "usr/bin/tunnelgate-uninstall"),
            "TG_KEYS": str(tmp / "dropbear/authorized_keys"),
            # The two once-per-boot TLS markers default to fixed /tmp names, so on a host where
            # an earlier run already wrote one, a warning test would pass or fail depending on
            # history. Redirect both into the test tree: same code, no shared state.
            "TG_TLS_WARN_FILE": str(tmp / "tls-verify-warning"),
            "TG_TLS_CAP_WARN_FILE": str(tmp / "tls-capability-warning"),
        }
    )
    env.pop("TG_TLS_VERIFY", None)
    env.update(extra)
    return env


def uci_options(config: Path) -> dict:
    """Read the UCI file the way the agent does when uci(1) is not installed."""
    out = {}
    for line in Path(config).read_text().splitlines():
        line = line.strip()
        if not line.startswith("option "):
            continue
        _, name, value = line.split(None, 2)
        out[name] = value.strip("'")
    return out


_INVALID_TOKEN = (
    b'{"error":{"code":"invalid_token","message":"Bootstrap token is invalid or expired"}}'
)


class MockPanel:
    """The panel's two router-facing endpoints, with single-use bootstrap semantics."""

    def __init__(
        self,
        response: dict,
        token: str,
        console: dict | None = None,
        desired: dict | None = None,
    ):
        self.response = response
        self.token = token
        self.console = console
        self.desired = desired
        self.calls: list = []
        self.token_used = False
        self.port = free_port()
        panel = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):  # keep the pytest output clean
                pass

            def _reply(self, code: int, payload: bytes) -> None:
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _token(self, header: str, field: str, body: dict):
                """The three channels the real panel accepts (app/api/bootstrap.py).

                Stock OpenWrt has no curl and its uclient-fetch cannot send a header before
                24.10, so the body field is the only channel a router really has.
                """
                value = self.headers.get(header)
                if value:
                    return value
                if isinstance(body, dict) and body.get(field):
                    return str(body[field])
                auth = self.headers.get("Authorization") or ""
                if auth.startswith("Basic "):
                    try:
                        raw = base64.b64decode(auth[6:]).decode()
                    except Exception:
                        return None
                    return raw.split(":", 1)[0]
                return None

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                try:
                    parsed = json.loads(body) if body else None
                except ValueError:
                    parsed = None
                panel.calls.append(
                    {
                        "path": self.path,
                        "bootstrap": self.headers.get("X-Bootstrap-Token"),
                        "api": self.headers.get("X-Api-Token"),
                        "authorization": self.headers.get("Authorization"),
                        "content_type": self.headers.get("Content-Type"),
                        "body": parsed,
                    }
                )
                if self.path.endswith("/bootstrap/exchange"):
                    # Unknown and already-used tokens both answer 401 invalid_token on the
                    # real panel (app/services/bootstrap.py:find_token), so the mock must too.
                    if (
                        self._token("X-Bootstrap-Token", "bootstrap_token", parsed) != panel.token
                        or panel.token_used
                    ):
                        self._reply(401, _INVALID_TOKEN)
                        return
                    panel.token_used = True
                    self._reply(200, json.dumps(panel.response).encode())
                    return
                if self.path.endswith("/heartbeat"):
                    if (
                        self._token("X-Api-Token", "api_token", parsed)
                        != panel.response["api_token"]
                    ):
                        self._reply(401, b"{}")
                        return
                    out = {"ok": True, "status": "active", "server_time": "2026-01-01T00:00:00Z"}
                    if panel.console is not None:
                        out["console"] = panel.console
                    if panel.desired is not None:
                        out["desired"] = panel.desired
                    self._reply(200, json.dumps(out).encode())
                    return
                self._reply(404, b"{}")

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class SshdFixture:
    """A throwaway sshd on a loopback port: the "panel host" the agent connects to."""

    def __init__(self, port: int, fingerprint: str, keys_file: Path, config: Path, proc):
        self.port = port
        self.fingerprint = fingerprint
        self.keys_file = keys_file
        self.config = config
        self.proc = proc

    def authorize(self, pubkey: str) -> None:
        self.keys_file.write_text(pubkey + "\n")
        self.keys_file.chmod(0o600)

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            self.proc.kill()
            self.proc.wait(timeout=10)


def _start_sshd(tmp_path: Path) -> SshdFixture:
    d = tmp_path / "sshd"
    d.mkdir()
    hostkey = d / "hostkey"
    run(["ssh-keygen", "-t", "ed25519", "-f", str(hostkey), "-N", "", "-q"])
    port = free_port()
    keys = d / "authorized_keys"
    keys.touch()
    keys.chmod(0o600)
    config = d / "sshd_config"
    config.write_text(
        "\n".join(
            [
                f"Port {port}",
                "ListenAddress 127.0.0.1",
                f"HostKey {hostkey}",
                "PidFile %s" % (d / "sshd.pid"),
                f"AuthorizedKeysFile {keys}",
                "StrictModes no",
                "PermitRootLogin yes",
                "PasswordAuthentication no",
                "KbdInteractiveAuthentication no",
                "UsePAM no",
                "AllowTcpForwarding yes",
                "GatewayPorts no",
                "LogLevel VERBOSE",
            ]
        )
        + "\n"
    )
    Path("/run/sshd").mkdir(exist_ok=True)
    # -D keeps sshd in the foreground. Without it sshd daemonises and the Popen handle
    # refers to an already-exited parent, so terminate() leaves a listening orphan behind.
    proc = subprocess.Popen(
        [SSHD, "-D", "-f", str(config), "-E", str(d / "sshd.log")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not wait_for_port(port, timeout=15):  # pragma: no cover
        proc.kill()
        pytest.skip("the test sshd did not start")
    fp = run(["ssh-keygen", "-lf", str(hostkey) + ".pub"]).stdout.split()[1]
    return SshdFixture(port, fp, keys, config, proc)


class _PageHandler(http.server.BaseHTTPRequestHandler):
    """The router-side web UI the tunnel is supposed to expose."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"router-stage page"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def test_sshd(tmp_path: Path):
    sshd = _start_sshd(tmp_path)
    try:
        yield sshd
    finally:
        sshd.stop()


@pytest.fixture()
def local_http():
    """A stand-in for the router web interface reachable at 127.0.0.1:<port>."""
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _PageHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield int(srv.server_address[1])
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture()
def panel(tmp_path: Path, test_sshd: SshdFixture, local_http: int):
    """A mock that answers with a realistic exchange response carrying a real ed25519 key."""
    key = tmp_path / "router_key"
    run(["ssh-keygen", "-t", "ed25519", "-f", str(key), "-N", "", "-q", "-C", "tunnelgate-test"])
    test_sshd.authorize(key.with_suffix(".pub").read_text().strip())
    tunnel_port = free_port()
    response = {
        "router_id": "r-test001",
        "router_name": 'Branch "One" & <lab>',
        "slug": "branch-one",
        "ssh": {
            "host": "127.0.0.1",
            "port": test_sshd.port,
            "username": "root",
            "host_key_fingerprint": test_sshd.fingerprint,
            "host_key_type": "ssh-ed25519",
        },
        "tunnel": {
            "remote_port": tunnel_port,
            "bind_address": "127.0.0.1",
            "router_http_port": local_http,
            "local_target": f"127.0.0.1:{local_http}",
            "url": "https://r-test001.panel.test",
        },
        "console": {
            "enabled": True,
            "ssh_user": "root",
            "allowed_from": "127.0.0.1",
            "console_port": free_port(),
            "target_port": test_sshd.port,
            "authorized_keys_path": str(tmp_path / "dropbear/authorized_keys"),
            "shell": "/bin/ash",
        },
        "private_key": key.read_text(),
        "private_key_path_hint": "/root/.ssh/tunnelgate_ed25519",
        "api_token": "tok_test",
        "heartbeat_url": "",
        "key_fingerprint": test_sshd.fingerprint,
        "server_time": "2026-01-01T00:00:00Z",
    }
    with MockPanel(response, token="bootstrap-token-0123456789abcdef") as mock:
        mock.response["heartbeat_url"] = mock.url + "/api/v1/routers/r-test001/heartbeat"
        mock.tunnel_port = tunnel_port  # type: ignore[attr-defined]
        yield mock


# ---------------------------------------------------------------------------------------
# syntax and marker contract
# ---------------------------------------------------------------------------------------


@needs_shells
@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("script", [INSTALL, INIT, SSH_LOOP, HEARTBEAT, UNINSTALL])
def test_script_parses(shell: str, script: Path) -> None:
    """sh -n with a real POSIX shell: the router has busybox ash, not bash."""
    argv = (
        shell_argv(shell, script)
        if Path(shell).name != "busybox"
        else [shell, "sh", "-n", str(script)]
    )
    if Path(shell).name != "busybox":
        argv = [shell, "-n", str(script)]
    result = run(argv)
    assert result.returncode == 0, result.stderr


def test_scripts_have_no_bashisms() -> None:
    """Grep-level guard: bash-only syntax fails on the router, not in CI."""
    banned = {
        "<<<": "bash herestring",
        "declare -": "bash declare",
        "$" + chr(39): "bash ANSI-C quoting",
    }
    # A real bash test is "[[ " as a command; "[[:space:]]" is a POSIX bracket expression.
    bash_test = re.compile(r"(?<!\[)\[\[(?!:)")
    # "function name()" is a bash keyword, but "function name(args)" is awk and is expected:
    # the JSON reader is an awk program embedded verbatim in install.sh.
    bash_function = re.compile(r"^\s*function\s+[A-Za-z_][A-Za-z0-9_]*\s*\(\)")
    for script in (INSTALL, INIT, SSH_LOOP, HEARTBEAT, JSON_LIB):
        for lineno, line in enumerate(script.read_text().splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            assert not bash_function.match(stripped), (
                f"{script.name}:{lineno} uses the bash function keyword"
            )
            assert not bash_test.search(stripped), (
                f"{script.name}:{lineno} uses the bash [[ ]] test"
            )
            for needle, why in banned.items():
                assert needle not in stripped, f"{script.name}:{lineno} uses {why}: {stripped}"


def test_markers_appear_on_their_own_line() -> None:
    """The panel substitutes whole lines; a marker mid-line would break the served script."""
    lines = INSTALL.read_text().splitlines()
    for marker in ("#@@PANEL_URL_LINE@@", "#@@BOOTSTRAP_TOKEN_LINE@@"):
        hits = [line for line in lines if marker in line]
        assert hits == [marker], hits


def test_served_script_carries_no_credentials_by_default() -> None:
    """Before substitution the served script must carry no URL, token or key material."""
    text = INSTALL.read_text()
    assert "TG_PANEL_URL=" not in text
    assert "TG_BOOTSTRAP_TOKEN=" not in text
    assert "ssh-ed25519 AAAA" not in text
    assert "BEGIN OPENSSH PRIVATE KEY" not in text


@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_installer_usage_without_a_panel_url(tmp_path: Path) -> None:
    """Run bare: it must explain itself and exit 1 rather than half-install."""
    out = tmp_path / "install.sh"
    out.write_text(
        INSTALL.read_text()
        .replace("#@@PANEL_URL_LINE@@", "")
        .replace("#@@BOOTSTRAP_TOKEN_LINE@@", "")
    )
    result = run(["dash", str(out)], env=agent_env(tmp_path))
    assert result.returncode == 1
    assert "TG_PANEL_URL is not set" in result.stderr + result.stdout


@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_placeholder_validation(tmp_path: Path) -> None:
    """A truncated token or a junk URL is caught before the router is touched."""
    script = stage_installer(tmp_path, "http://127.0.0.1:1", "abc")
    result = run(["dash", str(script)], env=agent_env(tmp_path))
    assert result.returncode == 1
    assert "looks truncated" in result.stderr + result.stdout

    script2 = stage_installer(tmp_path, "ftp://nope", "bootstrap-token-0123456789abcdef")
    result2 = run(["dash", str(script2)], env=agent_env(tmp_path))
    assert result2.returncode == 1
    assert "must start with http://" in result2.stderr + result2.stdout


# ---------------------------------------------------------------------------------------
# the JSON reader (busybox has no jq)
# ---------------------------------------------------------------------------------------

DOC = {
    "router_id": "r-abc123",
    "router_name": 'Branch <Office> "one" & more',
    "nested": {"port": 2222, "flag": True, "none": None},
    "list": [{"name": "a"}, {"name": "b"}],
    "escaped": 'line1\nline2\ttabbed "quoted" back\\slash',
    "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n-----END OPENSSH PRIVATE KEY-----\n",
}


@needs_shells
@pytest.mark.parametrize("shell", SHELLS)
def test_json_reader(shell: str, tmp_path: Path) -> None:
    """Every field the installer reads has to survive both GNU awk and busybox awk."""
    doc = tmp_path / "doc.json"
    doc.write_text(json.dumps(DOC))
    script = tmp_path / "probe.sh"
    script.write_text(
        "#!/bin/sh\n"
        ". " + str(JSON_LIB) + "\n"
        'json_get router_id "$1"; printf "|"\n'
        'json_get nested.port "$1"; printf "|"\n'
        'json_get nested.flag "$1"; printf "|"\n'
        'json_get list.1.name "$1"; printf "|"\n'
        'json_get escaped "$1"; printf "|"\n'
        'json_get private_key "$1"\n'
    )
    result = run(shell_argv(shell, script, str(doc)))
    assert result.returncode == 0, result.stderr
    head = result.stdout.split("|")
    assert head[0] == "r-abc123"
    assert head[1] == "2222"
    assert head[2] == "true"
    assert head[3] == "b"
    assert head[4] == DOC["escaped"]
    assert "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n" in result.stdout


@needs_shells
@pytest.mark.parametrize("shell", SHELLS)
def test_json_reader_missing_path_is_a_clean_failure(shell: str, tmp_path: Path) -> None:
    doc = tmp_path / "doc.json"
    doc.write_text(json.dumps(DOC))
    script = tmp_path / "probe.sh"
    script.write_text("#!/bin/sh\n. " + str(JSON_LIB) + '\njson_get no.such.path "$1"\n')
    result = run(shell_argv(shell, script, str(doc)))
    assert result.returncode == 1
    assert result.stdout.strip() == ""


@needs_shells
@pytest.mark.parametrize("shell", SHELLS)
def test_json_reader_rejects_a_truncated_document(shell: str, tmp_path: Path) -> None:
    doc = tmp_path / "doc.json"
    doc.write_text('{"a": "b"')
    script = tmp_path / "probe.sh"
    script.write_text("#!/bin/sh\n. " + str(JSON_LIB) + '\njson_get a "$1"\n')
    result = run(shell_argv(shell, script, str(doc)))
    assert result.returncode == 3
    assert "json parse error" in result.stderr


# ---------------------------------------------------------------------------------------
# embedded copies must be byte-identical to the standalone library files
# ---------------------------------------------------------------------------------------


def _embedded(script_text: str, marker: str) -> str:
    """Extract the body of the heredoc whose delimiter is <marker>."""
    lines = script_text.splitlines()
    for i, line in enumerate(lines):
        # The opener may carry a trailing "|| err \"cannot write ...\"" guard, so match the
        # delimiter anywhere on the line instead of requiring it to end the line.
        if line.strip() == "cat >" or ("<<'" + marker + "'") in line:
            body = []
            for follow in lines[i + 1 :]:
                if follow.strip() == marker:
                    return "\n".join(body) + "\n"
                body.append(follow)
    raise AssertionError(f"heredoc {marker} not found in install.sh")


@pytest.mark.parametrize(
    "marker,source",
    [
        ("TG_EOF_JSON", JSON_LIB),
        ("TG_EOF_LOOP", SSH_LOOP),
        ("TG_EOF_HB", HEARTBEAT),
        ("TG_EOF_UNINSTALL", UNINSTALL),
    ],
)
def test_embedded_library_matches_standalone(marker: str, source: Path) -> None:
    """install.sh ships the libraries inline; a drift between the two would be a silent bug."""
    assert _embedded(INSTALL.read_text(), marker) == source.read_text()


def test_init_script_is_not_bash_and_uses_procd() -> None:
    text = INIT.read_text()
    assert text.startswith("#!/bin/sh /etc/rc.common"), text.splitlines()[0]
    assert "USE_PROCD=1" in text
    assert "START=95" in text
    assert "procd_set_param respawn 3600" in text
    assert "tunnelgate-heartbeat" in text or "HEARTBEAT_PROG" in text


def test_ssh_loop_hardcodes_the_required_ssh_options() -> None:
    """The reliability options are the whole point of the loop; assert them literally."""
    text = SSH_LOOP.read_text()
    for option in (
        "BatchMode=yes",
        "ExitOnForwardFailure=yes",
        "ServerAliveInterval=30",
        "ServerAliveCountMax=3",
        "StrictHostKeyChecking=yes",
    ):
        assert option in text, option
    assert "autossh" in text  # only mentioned in the comment explaining why it is not used


# ---------------------------------------------------------------------------------------
# full install against the mock panel
# ---------------------------------------------------------------------------------------


@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_install_end_to_end(panel, tmp_path: Path) -> None:
    """One real install: key, pin, UCI config, libraries and init script on disk."""
    script = stage_installer(tmp_path, panel.url, panel.token)
    result = run(["dash", str(script)], env=agent_env(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr

    key = tmp_path / "ssh/tunnelgate_ed25519"
    assert key.exists()
    assert key.stat().st_mode & 0o777 == 0o600
    assert "PRIVATE KEY" in key.read_text()

    known = tmp_path / "ssh/known_hosts"
    assert known.exists()
    lines = [ln for ln in known.read_text().splitlines() if ln.strip()]
    assert len(lines) == 1, lines
    assert f"[127.0.0.1]:{panel.response['ssh']['port']}" in lines[0]

    config = tmp_path / "etc/config/tunnelgate"
    assert config.exists()
    assert config.stat().st_mode & 0o777 == 0o600
    options = uci_options(config)
    assert options["router_id"] == "r-test001"
    assert options["api_token"] == "tok_test"
    assert options["ssh_host"] == "127.0.0.1"
    assert options["tunnel_port"] == str(panel.response["tunnel"]["remote_port"])
    assert options["console_enabled"] == "1"
    assert options["console_serial"] == "0"
    assert options["heartbeat_url"].endswith("/heartbeat")

    assert (tmp_path / "usr/lib/tunnelgate/json.sh").exists()
    assert (tmp_path / "usr/bin/ssh-loop").exists()
    assert (tmp_path / "usr/bin/tunnelgate-heartbeat").exists()
    assert (tmp_path / "etc/init.d/tunnelgate").exists()

    body = panel.calls[0]["body"]
    assert body["hostname"]
    assert body["client_version"]
    assert panel.calls[0]["path"].endswith("/api/v1/routers/bootstrap/exchange")


@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_second_install_is_idempotent(panel, tmp_path: Path) -> None:
    """Running the installer twice must not duplicate the key, the UCI section or the pin."""
    script = stage_installer(tmp_path, panel.url, panel.token)
    env = agent_env(tmp_path)
    first = run(["dash", str(script)], env=env)
    assert first.returncode == 0, first.stdout + first.stderr

    key = tmp_path / "ssh/tunnelgate_ed25519"
    before = (key.stat().st_mtime_ns, key.read_text())
    config = tmp_path / "etc/config/tunnelgate"
    before_cfg = config.read_text()

    panel.token_used = False  # the operator regenerated the command: a fresh token
    second = run(["dash", str(script)], env=env)
    assert second.returncode == 0, second.stdout + second.stderr

    assert (key.stat().st_mtime_ns, key.read_text()) == before
    after_cfg = config.read_text()
    assert after_cfg == before_cfg
    assert after_cfg.count("config tunnelgate 'main'") == 1
    known = [ln for ln in (tmp_path / "ssh/known_hosts").read_text().splitlines() if ln.strip()]
    assert len(known) == 1, known


@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_a_reused_bootstrap_token_is_refused(panel, tmp_path: Path) -> None:
    """The panel enforces single use; the installer must surface that, not retry blindly."""
    script = stage_installer(tmp_path, panel.url, panel.token)
    env = agent_env(tmp_path)
    assert run(["dash", str(script)], env=env).returncode == 0
    again = run(["dash", str(script)], env=env)
    assert again.returncode == 1
    assert "panel refused the bootstrap token" in again.stdout + again.stderr


@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_wrong_host_key_fingerprint_aborts_the_install(panel, tmp_path: Path) -> None:
    """A panel that reports the wrong fingerprint must be a hard stop, never a warning."""
    panel.response["ssh"]["host_key_fingerprint"] = "SHA256:" + "A" * 43
    script = stage_installer(tmp_path, panel.url, panel.token)
    result = run(["dash", str(script)], env=agent_env(tmp_path))
    assert result.returncode == 1
    combined = result.stdout + result.stderr
    assert "HOST KEY MISMATCH" in combined
    assert not (tmp_path / "etc/config/tunnelgate").exists(), (
        "must not write a config it cannot trust"
    )


@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_uninstall_removes_only_our_console_key(panel, tmp_path: Path) -> None:
    """Uninstall has to leave somebody else's authorized_keys entries alone."""
    keys = Path(panel.response["console"]["authorized_keys_path"])
    keys.parent.mkdir(parents=True, exist_ok=True)
    foreign = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIForeign operator@laptop"
    keys.write_text(
        foreign + "\n"
        'from="127.0.0.1",no-port-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOurs tunnelgate-console\n'
    )
    keys.chmod(0o600)

    script = stage_installer(tmp_path, panel.url, panel.token)
    env = agent_env(tmp_path)
    assert run(["dash", str(script)], env=env).returncode == 0
    assert (tmp_path / "etc/config/tunnelgate").exists()

    result = run(["dash", str(script), "--uninstall"], env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path / "etc/config/tunnelgate").exists()
    assert not (tmp_path / "usr/bin/ssh-loop").exists()
    assert not (tmp_path / "ssh/tunnelgate_ed25519").exists()

    remaining = keys.read_text()
    assert foreign in remaining
    assert "tunnelgate-console" not in remaining


@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_installer_ships_the_uninstaller(panel, tmp_path: Path) -> None:
    """The operator needs a way out without the installer: it must be installed too."""
    script = stage_installer(tmp_path, panel.url, panel.token)
    env = agent_env(tmp_path)
    assert run(["dash", str(script)], env=env).returncode == 0

    installed = tmp_path / "usr/bin/tunnelgate-uninstall"
    assert installed.exists()
    assert installed.stat().st_mode & 0o777 == 0o755
    assert installed.read_text() == UNINSTALL.read_text()
    assert "UNINSTALL_BIN" in script.read_text()


@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_installed_uninstaller_removes_the_agent_only(panel, tmp_path: Path) -> None:
    """The shipped uninstaller has to work standalone, with the agent already installed."""
    keys = Path(panel.response["console"]["authorized_keys_path"])
    keys.parent.mkdir(parents=True, exist_ok=True)
    foreign = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIForeign operator@laptop"
    keys.write_text(
        foreign + '\nfrom="127.0.0.1",no-port-forwarding ssh-ed25519 AAAAours tunnelgate-console\n'
    )
    keys.chmod(0o600)

    script = stage_installer(tmp_path, panel.url, panel.token)
    env = agent_env(tmp_path)
    assert run(["dash", str(script)], env=env).returncode == 0

    installed = tmp_path / "usr/bin/tunnelgate-uninstall"
    result = run(["dash", str(installed)], env=env)
    assert result.returncode == 0, result.stdout + result.stderr

    assert not (tmp_path / "etc/init.d/tunnelgate").exists()
    assert not (tmp_path / "etc/config/tunnelgate").exists()
    assert not (tmp_path / "usr/bin/ssh-loop").exists()
    assert not (tmp_path / "usr/bin/tunnelgate-heartbeat").exists()
    assert not (tmp_path / "usr/lib/tunnelgate").exists()
    assert not (tmp_path / "ssh/tunnelgate_ed25519").exists()

    remaining = keys.read_text()
    assert foreign in remaining
    assert "tunnelgate-console" not in remaining


@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_uninstall_dry_run_changes_nothing(panel, tmp_path: Path) -> None:
    """--dry-run is what an operator runs first; it must not delete anything."""
    script = stage_installer(tmp_path, panel.url, panel.token)
    env = agent_env(tmp_path)
    assert run(["dash", str(script)], env=env).returncode == 0

    installed = tmp_path / "usr/bin/tunnelgate-uninstall"
    result = run(["dash", str(installed), "--dry-run"], env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "dry-run" in result.stdout + result.stderr

    for rel in (
        "etc/init.d/tunnelgate",
        "etc/config/tunnelgate",
        "usr/bin/ssh-loop",
        "usr/lib/tunnelgate/json.sh",
        "ssh/tunnelgate_ed25519",
    ):
        assert (tmp_path / rel).exists(), rel


@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_installer_uninstall_path_removes_the_uninstaller(panel, tmp_path: Path) -> None:
    """install.sh --uninstall has to leave no trace either, including the uninstaller itself."""
    script = stage_installer(tmp_path, panel.url, panel.token)
    env = agent_env(tmp_path)
    assert run(["dash", str(script)], env=env).returncode == 0
    assert (tmp_path / "usr/bin/tunnelgate-uninstall").exists()

    result = run(["dash", str(script), "--uninstall"], env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path / "usr/bin/tunnelgate-uninstall").exists()


# ---------------------------------------------------------------------------------------
# e2e: the loop really opens the reverse forwards (needs a local sshd)
# ---------------------------------------------------------------------------------------


@pytest.fixture()
def installed(panel, tmp_path: Path):
    """A fully installed agent staged into tmp_path (no init system is touched)."""
    script = stage_installer(tmp_path, panel.url, panel.token)
    env = agent_env(tmp_path)
    result = run(["dash", str(script)], env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    return {"tmp": tmp_path, "env": env, "script": script, "panel": panel}


def _spawn(cmd: list, env: dict, log: Path) -> subprocess.Popen:
    with open(log, "wb") as handle:
        return subprocess.Popen(
            cmd, env=env, stdout=handle, stderr=subprocess.STDOUT, start_new_session=True
        )


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover
        proc.kill()


@needs_sshd
@pytest.mark.e2e
@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_ssh_loop_opens_both_reverse_forwards(installed) -> None:
    """The panel-side ports must appear and the tunnel one must serve the router page."""
    tmp, env = installed["tmp"], installed["env"]
    config = uci_options(tmp / "etc/config/tunnelgate")
    log = tmp / "loop.log"
    proc = _spawn(["dash", str(tmp / "usr/bin/ssh-loop")], env, log)
    try:
        tunnel_port = int(config["tunnel_port"])
        console_port = int(config["console_port"])
        assert wait_for_port(tunnel_port, timeout=25), log.read_text()
        assert wait_for_port(console_port, timeout=25), log.read_text()

        url = f"http://127.0.0.1:{tunnel_port}/"
        with urllib.request.urlopen(url, timeout=10) as resp:
            assert resp.read() == b"router-stage page"
    finally:
        _stop(proc)


@needs_sshd
@pytest.mark.e2e
@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_the_console_port_reaches_the_router_sshd(installed) -> None:
    """ssh -p <console_port> must land on the router's own sshd, not on the panel's."""
    tmp, env = installed["tmp"], installed["env"]
    config = uci_options(tmp / "etc/config/tunnelgate")
    log = tmp / "loop2.log"
    proc = _spawn(["dash", str(tmp / "usr/bin/ssh-loop")], env, log)
    try:
        console_port = int(config["console_port"])
        assert wait_for_port(console_port, timeout=25), log.read_text()
        result = run(
            [
                "ssh",
                "-i",
                str(tmp / "ssh/tunnelgate_ed25519"),
                "-p",
                str(console_port),
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=10",
                "root@127.0.0.1",
                "echo console-ok",
            ],
            timeout=30,
        )
        assert "console-ok" in result.stdout, result.stdout + result.stderr
    finally:
        _stop(proc)


@needs_sshd
@pytest.mark.e2e
@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_heartbeat_installs_the_console_key(installed) -> None:
    """The console public key only exists after the panel creates it, so it arrives here."""
    panel = installed["panel"]
    tmp, env = installed["tmp"], installed["env"]
    keys = Path(panel.response["console"]["authorized_keys_path"])
    keys.parent.mkdir(parents=True, exist_ok=True)
    keys.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIForeign operator@laptop\n")
    keys.chmod(0o600)

    panel.console = {
        "serial": 7,
        "user": "root",
        "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIConsolePanelKey tunnelgate",
        "fingerprint": "SHA256:" + "B" * 43,
        "authorized_keys_path": str(keys),
        "shell": "/bin/ash",
    }

    result = run(["dash", str(tmp / "usr/bin/tunnelgate-heartbeat")], env=env)
    assert result.returncode == 0, result.stdout + result.stderr

    text = keys.read_text()
    assert "tunnelgate-console" in text
    assert 'from="127.0.0.1"' in text
    assert "no-port-forwarding" in text
    assert "no-pty" not in text, "the console key must allow an interactive pty"
    assert "operator@laptop" in text, "a foreign key must never be dropped"
    assert uci_options(tmp / "etc/config/tunnelgate")["console_serial"] == "7"

    # same serial again: a no-op, not a second copy of the key
    run(["dash", str(tmp / "usr/bin/tunnelgate-heartbeat")], env=env)
    assert keys.read_text().count("tunnelgate-console") == 1


@needs_sshd
@pytest.mark.e2e
@pytest.mark.skipif(not shutil.which("dash"), reason="needs dash")
def test_heartbeat_adopts_a_moved_panel(installed) -> None:
    """The panel can move; an installed router must follow it without a re-install.

    The address arrives in the heartbeat response's "desired" payload, and adopting it is what
    keeps a fleet alive across a panel hostname or port change.
    """
    panel = installed["panel"]
    tmp, env = installed["tmp"], installed["env"]
    config = tmp / "etc/config/tunnelgate"

    moved = "http://moved.example.com:8443/api/v1/routers/r-test001/heartbeat"
    panel.desired = {"heartbeat_url": moved}

    result = run(["dash", str(tmp / "usr/bin/tunnelgate-heartbeat")], env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert uci_options(config)["heartbeat_url"] == moved

    # A non-http(s) value is ignored rather than written: the response is untrusted input.
    panel.desired = {"heartbeat_url": "ftp://attacker.example.com/x"}
    run(["dash", str(tmp / "usr/bin/tunnelgate-heartbeat")], env=env)
    assert uci_options(config)["heartbeat_url"] == moved

    # An empty desired payload leaves the stored value alone.
    panel.desired = {}
    run(["dash", str(tmp / "usr/bin/tunnelgate-heartbeat")], env=env)
    assert uci_options(config)["heartbeat_url"] == moved


# ---------------------------------------------------------------------------------------
# the stock-router toolchain: no curl, and uclient-fetch has no --header before 24.10
# ---------------------------------------------------------------------------------------

SENTINEL = "TunnelGate router agent installer"

DASH = shutil.which("dash")


@pytest.fixture(scope="session")
def stock_image(tmp_path_factory) -> Path:
    """A PATH that looks like a stock OpenWrt image: every host tool EXCEPT curl.

    Stock OpenWrt ships no curl at all and /usr/bin/wget is a symlink to uclient-fetch. A test
    that keeps the host's curl never reaches the wget branch, which is precisely the bug that
    made the agent work only on routers that happened to have curl installed.
    """
    bindir = Path(tmp_path_factory.mktemp("stock-image")) / "bin"
    bindir.mkdir()
    for src in ("/usr/bin", "/usr/sbin"):
        for entry in Path(src).iterdir():
            if entry.name in ("curl", "wget"):
                continue
            with contextlib.suppress(OSError):
                (bindir / entry.name).symlink_to(entry)
    return bindir


def _record_fetcher(bindir: Path, name: str, log: Path) -> bool:
    """Wrap <name> so a test can read the exact argv the agent built, then really run it.

    Recording and delegating (instead of a stub that only prints a fake status) keeps the whole
    install real: the mock panel still has to accept the request, so the test cannot pass on a
    request that was never sent.
    """
    real = shutil.which(name)
    if real is None:
        return False
    wrapper = bindir / name
    wrapper.write_text(f'#!/bin/sh\nprintf "%s\n" "{name} $*" >> "{log}"\nexec "{real}" "$@"\n')
    wrapper.chmod(0o755)
    return True


@pytest.fixture()
def fake_fetchers(tmp_path: Path):
    """Recording wrappers for curl and wget, one directory each.

    Separate directories matter: a PATH that still finds curl would pick the curl branch and
    quietly skip the wget one, which is the branch under test.
    """
    dirs = {}
    log = tmp_path / "fetch.log"
    for name in ("curl", "wget"):
        bindir = tmp_path / ("fake-" + name)
        bindir.mkdir()
        if _record_fetcher(bindir, name, log):
            dirs[name] = bindir
    return {"dirs": dirs, "log": log}


def fetcher_lines(log: Path, name: str) -> list:
    if not log.exists():
        return []
    return [line for line in log.read_text().splitlines() if line.startswith(name + " ")]


def _router_env(tmp: Path, fake_fetchers: dict, stock_image: Path, fetcher: str, **extra) -> dict:
    """Env for one fetcher: wget runs on a curl-less PATH, curl on the host's."""
    bindir = fake_fetchers["dirs"].get(fetcher)
    if bindir is None:
        pytest.skip(f"no {fetcher} on this host")
    path = f"{bindir}:{stock_image}" if fetcher == "wget" else f"{bindir}:{os.environ['PATH']}"
    env = agent_env(tmp, PATH=path, **extra)
    # The host environment must not decide the TLS policy of a test.
    if "TG_TLS_VERIFY" not in extra:
        env.pop("TG_TLS_VERIFY", None)
    return env


def _fetch_flag(line: str, fetcher: str) -> str:
    return "-k" if fetcher == "curl" else "--no-check-certificate"


def _carries_flag(line: str, fetcher: str) -> bool:
    """True when the recorded argv really carries the flag as its own word (-k, not -keyfile)."""
    return _fetch_flag(line, fetcher) in line.split()[1:]


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_no_fetch_command_carries_a_header() -> None:
    """A --header on the wget path is worse than useless before 24.10.

    uclient-fetch does not know the option there, prints its usage and exits 0 - so the agent
    would report a successful exchange that never left the router. The credential therefore
    rides in the JSON body, and no fetch command line may carry a header at all.
    """
    for script in (INSTALL, HEARTBEAT):
        for lineno, line in enumerate(script.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue  # the comments explain the absence, they do not issue a request
            assert "--header" not in line, f"{script.name}:{lineno} sends a header: {line}"


@needs_sshd
@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_wget_post_path_sends_the_token_in_the_body(
    panel, tmp_path: Path, fake_fetchers, stock_image: Path
) -> None:
    """The only credential channel a pre-24.10 uclient-fetch has on a POST is the JSON body."""
    script = stage_installer(tmp_path, panel.url, panel.token)
    env = _router_env(tmp_path, fake_fetchers, stock_image, "wget")
    result = run([DASH, str(script)], env=env)
    assert result.returncode == 0, result.stdout + result.stderr

    call = panel.calls[0]
    assert call["path"].endswith("/bootstrap/exchange")
    assert call["body"]["bootstrap_token"] == panel.token
    assert call["bootstrap"] is None, "no header on the wget path"
    assert call["authorization"] is None, "no basic auth on the wget path"

    line = fetcher_lines(fake_fetchers["log"], "wget")[0]
    assert "--post-file=" in line, line
    for option in ("--header", "--user", "--password"):
        assert option not in line, f"{option} cannot work on uclient-fetch before 24.10: {line}"


@needs_sshd
@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_heartbeat_token_rides_in_the_body_when_there_is_no_curl(
    installed, fake_fetchers, stock_image: Path
) -> None:
    """The heartbeat carries the same credential the same way, on its own copy of post()."""
    tmp = installed["tmp"]
    env = _router_env(tmp, fake_fetchers, stock_image, "wget")
    result = run([DASH, str(tmp / "usr/bin/tunnelgate-heartbeat")], env=env)
    assert result.returncode == 0, result.stdout + result.stderr

    call = installed["panel"].calls[-1]
    assert call["path"].endswith("/heartbeat")
    assert call["body"]["api_token"] == "tok_test"
    assert call["api"] is None, "no header on the wget path"

    line = fetcher_lines(fake_fetchers["log"], "wget")[0]
    assert "--post-file=" in line, line
    assert "--header" not in line, line


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_installer_refuses_a_body_that_is_not_the_installer(panel, tmp_path: Path) -> None:
    """The panel greps for the sentinel; the script enforces the same contract on itself.

    A 401 answers an empty body, a captive portal answers HTML and a broken renderer answers
    half a file. Running any of those is at best a no-op and at worst a half-configured router,
    so the guard must be in the file too, not only in the command that fetched it.
    """
    staged = stage_installer(tmp_path, panel.url, panel.token)
    lines = staged.read_text().splitlines()
    assert SENTINEL in lines[1], "the panel greps this exact line out of the shipped script"

    # A body that lost its header line: everything else still runs, so only the guard stops it.
    truncated = tmp_path / "not-the-installer.sh"
    truncated.write_text("\n".join(line for line in lines if SENTINEL not in line) + "\n")
    result = run([DASH, str(truncated)], env=agent_env(tmp_path))
    assert result.returncode == 1
    combined = result.stdout + result.stderr
    assert "does not look like the TunnelGate installer" in combined
    assert panel.calls == [], "must not spend the single-use token on a body it does not trust"


# ---------------------------------------------------------------------------------------
# TLS: -k / --no-check-certificate only when the panel's verify_tls is exactly "0"
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("fetcher", ["curl", "wget"])
@needs_sshd
@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_tls_flag_present_when_verify_is_off(
    panel, tmp_path: Path, fake_fetchers, stock_image: Path, fetcher: str
) -> None:
    """A panel behind a self-signed certificate needs exactly one flag, and only then."""
    script = stage_installer(tmp_path, panel.url, panel.token)
    env = _router_env(tmp_path, fake_fetchers, stock_image, fetcher, TG_TLS_VERIFY="0")
    result = run([DASH, str(script)], env=env)
    assert result.returncode == 0, result.stdout + result.stderr

    lines = fetcher_lines(fake_fetchers["log"], fetcher)
    assert lines, f"no {fetcher} request was made"
    assert all(_carries_flag(line, fetcher) for line in lines), lines

    # The operator is told, in words that name the switch that turns it back on.
    assert "tls_verify" in result.stdout + result.stderr


@pytest.mark.parametrize("fetcher", ["curl", "wget"])
@pytest.mark.parametrize("value", [None, "1"])
@needs_sshd
@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_tls_flag_absent_when_verify_is_on(
    panel, tmp_path: Path, fake_fetchers, stock_image: Path, fetcher: str, value
) -> None:
    """Unset and "1" both mean verify, and neither adds a flag."""
    script = stage_installer(tmp_path, panel.url, panel.token)
    extra = {} if value is None else {"TG_TLS_VERIFY": value}
    env = _router_env(tmp_path, fake_fetchers, stock_image, fetcher, **extra)
    result = run([DASH, str(script)], env=env)
    assert result.returncode == 0, result.stdout + result.stderr

    lines = fetcher_lines(fake_fetchers["log"], fetcher)
    assert lines, f"no {fetcher} request was made"
    assert not any(_carries_flag(line, fetcher) for line in lines), lines
    assert "verification is OFF" not in result.stdout + result.stderr


@pytest.mark.parametrize("value", ["yes", "2", "false", "TRUE", "", " 0"])
@needs_sshd
@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_tls_garbage_value_still_verifies(
    panel, tmp_path: Path, fake_fetchers, stock_image: Path, value: str
) -> None:
    """Fail safe: a value we do not understand must never downgrade the connection.

    "0" is the only string that disables verification. A typo, a boolean spelled "false" or a
    stray space must all leave the certificate checked - the connection carries the bootstrap
    token and, from then on, the API token.
    """
    script = stage_installer(tmp_path, panel.url, panel.token)
    env = _router_env(tmp_path, fake_fetchers, stock_image, "curl", TG_TLS_VERIFY=value)
    result = run([DASH, str(script)], env=env)
    assert result.returncode == 0, result.stdout + result.stderr

    lines = fetcher_lines(fake_fetchers["log"], "curl")
    assert lines
    assert not any(_carries_flag(line, "curl") for line in lines), lines


@pytest.fixture()
def installed_no_verify(panel, tmp_path: Path):
    """An agent installed from a panel that turned verification off."""
    script = stage_installer(tmp_path, panel.url, panel.token)
    env = agent_env(tmp_path, TG_TLS_VERIFY="0")
    result = run([DASH, str(script)], env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    return {"tmp": tmp_path, "env": env, "panel": panel}


@needs_sshd
@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_installer_persists_tls_verify_into_uci(installed_no_verify) -> None:
    """The heartbeat outlives the installer, so the policy has to be written to UCI."""
    options = uci_options(installed_no_verify["tmp"] / "etc/config/tunnelgate")
    assert options["tls_verify"] == "0"


@needs_sshd
@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_heartbeat_honours_the_uci_tls_option(
    installed_no_verify, fake_fetchers, stock_image: Path, tmp_path: Path
) -> None:
    """At runtime the UCI option decides, so 'uci set ... && restart' works without a reinstall.

    TG_TLS_VERIFY is deliberately cleared here: this is the process procd starts from the
    config file alone.
    """
    tmp = installed_no_verify["tmp"]
    warn_file = tmp / "tls-warning"
    env = _router_env(tmp, fake_fetchers, stock_image, "wget", TG_TLS_WARN_FILE=str(warn_file))
    assert "TG_TLS_VERIFY" not in env

    result = run([DASH, str(tmp / "usr/bin/tunnelgate-heartbeat")], env=env)
    assert result.returncode == 0, result.stdout + result.stderr

    lines = fetcher_lines(fake_fetchers["log"], "wget")
    assert lines, "the heartbeat made no request"
    assert "--no-check-certificate" in lines[0], lines
    assert warn_file.exists(), "the operator must be warned at least once"

    # Exactly one warning: the next run must not repeat it, or it becomes noise nobody reads.
    before = (result.stdout + result.stderr).count("verification is OFF")
    assert before == 1, before
    second = run([DASH, str(tmp / "usr/bin/tunnelgate-heartbeat")], env=env)
    assert (second.stdout + second.stderr).count("verification is OFF") == 0


# ---------------------------------------------------------------------------------------
# The script the panel actually serves is NOT the bare body: render_install_script
# prepends a header of TG_* assignments, so anything that reads "$0" by line number must
# survive that header growing. A raw-file-only test cannot catch this class of bug - the
# raw file is not what a router executes.
# ---------------------------------------------------------------------------------------


def panel_render(settings, token: str) -> str:
    """The exact bytes app/services/bootstrap.py serves, injected header included.

    Imported rather than re-implemented: a hand-written copy of the header would drift from
    the renderer silently, which is precisely the failure being guarded against here.
    """
    from app.services import bootstrap

    rendered = bootstrap.render_install_script(token, "linux", settings, db=None)
    assert rendered.count("TG_PANEL_URL=") == 1
    assert "TG_TLS_VERIFY=" in rendered, "the renderer always injects the TLS policy"
    assert rendered.count(SENTINEL) >= 1
    return rendered


def _served(tmp_path: Path, settings, token: str, name: str = "served.sh") -> Path:
    """Write the panel-rendered script, with the URL pointed at a port that refuses."""
    rendered = panel_render(settings, token).replace(
        "TG_PANEL_URL='http://testserver'", f"TG_PANEL_URL='{_dead_url()}'"
    )
    out = tmp_path / name
    out.write_text(rendered)
    out.chmod(0o755)
    return out


def _dead_url() -> str:
    """A URL that is certain to refuse: the run must get PAST the local checks to reach it."""
    return f"http://127.0.0.1:{free_port()}"


def _self_scan_lines() -> int:
    """SELF_SCAN_LINES as shipped, so the test tracks the constant instead of a copy."""
    match = re.search(r"^SELF_SCAN_LINES=(\d+)$", INSTALL.read_text(), re.M)
    assert match, "the self-check window must stay a named constant"
    return int(match.group(1))


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_the_self_check_window_covers_the_panel_header(settings, tmp_path: Path) -> None:
    """Guard the guard: the scan window must be wider than the header the panel injects.

    This is the test that would have caught the shipped bug. It compares the constant against
    the renderer's real output, so adding a field to the header fails here - in CI - instead of
    on a router, where every install command silently stopped working.
    """
    lines = panel_render(settings, "tok-window-check").splitlines()
    body_start = next(i for i, line in enumerate(lines) if line.startswith("#!"))
    sentinel_line = next(i + 1 for i, line in enumerate(lines) if SENTINEL in line)

    window = _self_scan_lines()
    assert window >= sentinel_line, (
        f"SELF_SCAN_LINES={window} does not reach the sentinel on line {sentinel_line} "
        f"of the served script (the panel injects its preamble at line {body_start + 1})"
    )
    # Ordering is the renderer's business - it may put the preamble before or after the
    # installer's own header. What the agent must not do is assume the sentinel is line 2.
    if body_start > 0:
        assert window > body_start, (
            f"SELF_SCAN_LINES={window} but the panel preamble occupies {body_start} lines "
            "ahead of the body: a panel-rendered script would reject itself"
        )


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_a_panel_rendered_script_passes_its_own_checks(settings, tmp_path: Path) -> None:
    """The invariant that broke in production: what the panel serves must actually install.

    The injected URL points at a closed port on purpose. The run has to get past check_self
    AND check_placeholders and fail at the network step, which is what proves control reached
    the exchange - asserting only "did not report the installer error" would pass on any early
    exit.
    """
    script = _served(tmp_path, settings, "tok-rendered-0123456789abcdef")
    result = run(shell_argv(DASH, script), env=agent_env(tmp_path, TG_FORCE="1"))
    combined = result.stdout + result.stderr

    assert "does not look like the TunnelGate installer" not in combined, combined
    assert "still contains a placeholder line" not in combined, combined
    assert "TG_PANEL_URL is not set" not in combined, combined
    assert "cannot reach the panel" in combined, combined


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_the_self_check_tolerates_a_header_that_grows(settings, tmp_path: Path) -> None:
    """The header grew by one line when tls_verify arrived; assume it will grow again."""
    script = _served(tmp_path, settings, "tok-grown-0123456789abcdef", name="grown.sh")
    rendered = script.read_text()
    marker = "#!/bin/sh\n"
    assert marker in rendered
    # Insert AFTER the shebang line, so the file still starts correctly but the sentinel is
    # pushed 8 lines further down - what a renderer gaining fields would do.
    script.write_text(
        rendered.replace("#!/bin/sh\n", "#!/bin/sh\n" + "# a future field\nTG_EXTRA='x'\n" * 8, 1)
    )

    result = run(shell_argv(DASH, script), env=agent_env(tmp_path, TG_FORCE="1"))
    combined = result.stdout + result.stderr
    assert "does not look like the TunnelGate installer" not in combined, combined
    assert "cannot reach the panel" in combined, combined


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_a_rendered_body_without_the_sentinel_is_still_refused(settings, tmp_path: Path) -> None:
    """Widening the window must not turn the guard into a no-op."""
    script = _served(tmp_path, settings, "tok-nosentinel-0123456789ab", name="stripped.sh")
    stripped = "\n".join(line for line in script.read_text().splitlines() if SENTINEL not in line)
    script.write_text(stripped + "\n")

    result = run(shell_argv(DASH, script), env=agent_env(tmp_path, TG_FORCE="1"))
    combined = result.stdout + result.stderr
    assert result.returncode == 1, combined
    assert "does not look like the TunnelGate installer" in combined, combined
    assert "cannot reach the panel" not in combined, "must refuse before touching the panel"


# ---------------------------------------------------------------------------------------
# Regression tests for the hardening pass (task-18 / the audit amber list).
#
# Each test below is written to FAIL on the pre-fix code: every defect here was found by reading
# the shipped scripts, so a test that cannot tell the two versions apart is worth nothing.
# ---------------------------------------------------------------------------------------


def _payload_lib(tmp_path: Path) -> Path:
    """install.sh with the final main call removed: every function defined, nothing executed."""
    body = [line for line in INSTALL.read_text().splitlines() if line.strip() != 'main "$@"']
    lib = tmp_path / "install-lib.sh"
    lib.write_text("\n".join(body) + "\n")
    return lib


def _source(tmp_path: Path, snippet: str) -> subprocess.CompletedProcess:
    """Run a shell snippet with the installer's functions in scope (no panel, no init system)."""
    lib = _payload_lib(tmp_path)
    driver = tmp_path / "driver.sh"
    driver.write_text('set -u\n. "$1"\nshift\n' + snippet + "\n")
    return run(shell_argv(DASH, driver, str(lib)), env=agent_env(tmp_path))


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_every_stage_helper_is_defined_before_it_is_called(tmp_path: Path) -> None:
    """A function nested inside another is defined only once the outer one runs.

    write_uninstall_bin once ended up inside write_heartbeat_bin, so it did not exist in the
    namespace sourcing the script produces: --dry-run printed "write_uninstall_bin: not found"
    and carried on (there is no set -e), and a real install shipped no uninstaller while the
    install itself looked successful. The invariant that catches it - every stage helper is
    defined the moment the script is sourced - is what this asserts. Verified to bite by
    renaming write_uninstall_bin's definition.
    """
    names = (
        "write_json_lib write_loop_bin write_heartbeat_bin write_uninstall_bin write_init_script"
    )
    result = _source(
        tmp_path,
        f'for _fn in {names}; do command -v "$_fn" >/dev/null || {{ echo "MISSING $_fn"; }}; done'
        "; echo ALL_DEFINED",
    )
    combined = result.stdout + result.stderr
    assert "MISSING" not in combined, combined
    assert result.returncode == 0
    assert "ALL_DEFINED" in combined, combined


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_dry_run_preview_shows_the_marker_and_never_writes_the_token(tmp_path: Path) -> None:
    """A dry run is the first thing an operator runs, and its output ends up in bug reports.

    The token must be replaced by a marker BEFORE the report is written, not redacted out of a
    file that already holds it: a sed-based redaction left the file on disk with the secret in
    it, and died outright on a base64 token containing "/" ("unknown option to s").
    """
    token = "bootstrap-token-with/slash+and=padding-0123456789"
    script = stage_installer(tmp_path, "http://127.0.0.1:9/api/v1/routers/install", token)
    runtime = tmp_path / "runtime"
    runtime.mkdir()

    result = run([DASH, str(script), "--dry-run"], env=agent_env(tmp_path, TMPDIR=str(runtime)))
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined

    # The preview is still useful: it shows the shape of the report with the secret removed.
    assert '"bootstrap_token":"***"' in combined, combined
    assert token not in combined, "the dry-run preview must never echo the token"

    leftovers = sorted(p.name for p in runtime.iterdir())
    assert leftovers == [], f"a dry run must leave nothing behind: {leftovers}"
    for path in runtime.rglob("*"):
        if path.is_file():
            assert token not in path.read_text(errors="replace"), path


def _hanging_fetcher(tmp_path: Path, name: str = "curl") -> Path:
    """A fetcher that blocks, so a test can look (or signal) while the exchange is in flight."""
    bindir = tmp_path / "slow-bin"
    bindir.mkdir()
    slow = bindir / name
    slow.write_text("#!/bin/sh\nsleep 30\nexit 0\n")
    slow.chmod(0o755)
    return bindir


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_the_exchange_keeps_a_credential_private_while_it_is_in_flight(tmp_path: Path) -> None:
    """The body file holds the bootstrap token, so its directory must be 0700 and the file 0600.

    The old paths were "/tmp/tunnelgate-exchange.$$": world-readable and pid-predictable, which
    is both a disclosure and a symlink race for a process that runs as root.
    """
    token = "bootstrap-token-midflight-0123456789"
    script = stage_installer(tmp_path, "http://127.0.0.1:9/api/v1/routers/install", token)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    bindir = _hanging_fetcher(tmp_path)

    env = agent_env(tmp_path, TMPDIR=str(runtime), PATH=f"{bindir}:{os.environ['PATH']}")
    proc = subprocess.Popen(
        [DASH, str(script)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        private_dir = None
        bodies: list = []
        deadline = time.time() + 20
        while time.time() < deadline:
            dirs = [p for p in runtime.iterdir() if p.is_dir()]
            # Wait for the BODY, not just the directory: make_tmp_dir runs a moment before
            # build_report writes the token into it, and the interesting state is the one with
            # the credential on disk. The fetcher blocks right after that.
            if dirs:
                private_dir = dirs[0]
                bodies = list(private_dir.glob("*.json"))
                if bodies:
                    break
            time.sleep(0.05)
        assert private_dir is not None, "the installer never created its private directory"
        assert bodies, "the exchange never wrote its body file"

        mode = private_dir.stat().st_mode & 0o777
        assert mode == 0o700, f"the private directory is {oct(mode)}, must be 0700"
        for body in bodies:
            bmode = body.stat().st_mode & 0o777
            assert bmode & 0o077 == 0, f"{body.name} is {oct(bmode)}, must be 0600 or stricter"

        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        out, _ = proc.communicate(timeout=30)
    finally:
        if proc.poll() is None:  # pragma: no cover
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=10)

    assert proc.returncode == 130, f"a trapped signal must exit 130, got {proc.returncode}: {out}"
    assert sorted(p.name for p in runtime.iterdir()) == [], "the private directory must be gone"
    assert token not in out


# --- the heartbeat's own temporary directory (the same defect, in the 60-second process) ----


def _fake_token_panel(tmp_path: Path, token: str) -> str:
    """A URL that answers 401 immediately: enough to prove what the heartbeat leaves behind."""
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _RefusingHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _FAKE_SERVERS.append(srv)
    return f"http://127.0.0.1:{srv.server_address[1]}"


_FAKE_SERVERS: list = []


class _RefusingHandler(http.server.BaseHTTPRequestHandler):
    """Answers every request 401 with an empty body - what a stale token really gets."""

    def log_message(self, *a):
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.send_response(401)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture()
def heartbeat_tree(tmp_path: Path):
    """A minimal installed layout: just the config the heartbeat reads, plus its own TMPDIR."""
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    return runtime


def _heartbeat_config(tmp: Path, url: str, token: str = "tok_test") -> Path:
    config = tmp / "etc/config/tunnelgate"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        "\n".join(
            [
                "config tunnelgate 'main'",
                f"\toption heartbeat_url '{url}'",
                f"\toption api_token '{token}'",
                "\toption console_enabled '0'",
            ]
        )
        + "\n"
    )
    config.chmod(0o600)
    return config


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_heartbeat_keeps_its_credential_in_a_private_directory(tmp_path: Path) -> None:
    """The heartbeat writes the API token to a body file every 60 seconds, as root.

    "/tmp/tunnelgate-heartbeat-body.$$" made that world-readable, and its predictable name let
    any local user pre-create it as a symlink. A credential must never be written to a path this
    process did not create itself.
    """
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    url = _fake_token_panel(tmp_path, "tok_test")
    config = _heartbeat_config(tmp_path, url)

    env = agent_env(tmp_path, TMPDIR=str(runtime), TG_CONFIG=str(config))
    result = run([DASH, str(HEARTBEAT)], env=env)
    assert result.returncode == 0, result.stdout + result.stderr

    # Nothing is left behind, under any name.
    assert sorted(p.name for p in runtime.iterdir()) == [], "the heartbeat left files behind"

    # And no code path falls back to a fixed /tmp name. The comments NAME the old paths on
    # purpose (they explain why the directory exists), so only executable lines count.
    for lineno, line in enumerate(HEARTBEAT.read_text().splitlines(), 1):
        code = line.split("#", 1)[0]
        for stale in ("/tmp/tunnelgate-heartbeat-body", "/tmp/tunnelgate-heartbeat-response"):
            assert stale not in code, f"heartbeat.sh:{lineno} still writes {stale}: {line}"


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_a_signal_mid_heartbeat_leaves_no_directory(tmp_path: Path) -> None:
    """procd stops the heartbeat with a signal, so the exit path has to run on SIGTERM too."""
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    url = _fake_token_panel(tmp_path, "tok_test")
    config = _heartbeat_config(tmp_path, url)
    bindir = _hanging_fetcher(tmp_path, "curl")

    env = agent_env(tmp_path, TMPDIR=str(runtime), TG_CONFIG=str(config))
    env["PATH"] = f"{bindir}:{os.environ['PATH']}"
    proc = subprocess.Popen(
        [DASH, str(HEARTBEAT)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        deadline = time.time() + 20
        made = []
        while time.time() < deadline:
            made = [p for p in runtime.iterdir() if p.is_dir()]
            if made:
                break
            time.sleep(0.05)
        assert made, "the heartbeat never created its private directory"
        assert (made[0].stat().st_mode & 0o777) == 0o700

        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        out, _ = proc.communicate(timeout=30)
    finally:
        if proc.poll() is None:  # pragma: no cover
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=10)

    assert proc.returncode == 143, f"SIGTERM must exit 143, got {proc.returncode}: {out}"
    assert sorted(p.name for p in runtime.iterdir()) == [], "the private directory must be gone"


# --- item 1: no credential in argv (it is readable by every local user) --------------------


def _argv_lines(log: Path) -> list:
    if not log.exists():
        return []
    return [line for line in log.read_text().splitlines() if line.strip()]


@needs_sshd
@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_no_credential_reaches_a_command_line(
    panel, tmp_path: Path, fake_fetchers, stock_image: Path
) -> None:
    """A token in argv is public: /proc/PID/cmdline is world-readable, and this repeats hourly.

    Both scripts therefore send the credential in the JSON body only - which is also the only
    channel a pre-24.10 uclient-fetch has. This asserts the negative for BOTH fetchers and for
    the installer AND the heartbeat, because they carry separate copies of post().
    """
    script = stage_installer(tmp_path, panel.url, panel.token)
    for fetcher in ("curl", "wget"):
        log = fake_fetchers["log"]
        if log.exists():
            log.unlink()
        # Bootstrap tokens are single use, so a second install needs a second token. Re-arming
        # the mock is the honest way to say "a fresh command was minted in the panel"; reusing
        # one token would test the refusal path instead of the fetch path.
        panel.token_used = False
        env = _router_env(tmp_path, fake_fetchers, stock_image, fetcher)
        result = run([DASH, str(script)], env=env)
        assert result.returncode == 0, result.stdout + result.stderr

        argv = _argv_lines(log)
        assert argv, "the fetcher was never called"
        for line in argv:
            assert panel.token not in line, f"the bootstrap token is on a command line: {line}"
            assert "X-Bootstrap-Token" not in line, line
            assert "--user" not in line and "-u " not in line, line


@needs_sshd
@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_the_heartbeat_keeps_the_api_token_out_of_argv(
    installed, fake_fetchers, stock_image: Path
) -> None:
    """The heartbeat runs every 60 s forever, so its argv matters more than the installer's."""
    tmp = installed["tmp"]
    for fetcher in ("curl", "wget"):
        log = fake_fetchers["log"]
        if log.exists():
            log.unlink()
        env = _router_env(tmp, fake_fetchers, stock_image, fetcher)
        result = run([DASH, str(tmp / "usr/bin/tunnelgate-heartbeat")], env=env)
        assert result.returncode == 0, result.stdout + result.stderr
        for line in _argv_lines(log):
            assert "tok_test" not in line, f"the API token is on a command line: {line}"
            assert "X-Api-Token" not in line, line
            assert "-u " not in line and "--user" not in line, line


# --- item 2: both uninstallers remove the same packages, and neither deletes a foreign user --


def _openssh_pkgs(script: Path) -> list:
    match = re.search(r'^OPENSSH_PKGS="([^"]+)"', script.read_text(), re.MULTILINE)
    assert match, f"{script.name} does not define OPENSSH_PKGS"
    return match.group(1).split()


def test_both_uninstallers_remove_the_same_packages() -> None:
    """The installer adds three packages; removing one of them leaves a broken ssh-keygen.

    On 24.10 a leftover openssh-keygen shadows dropbear's own, and the agent then writes keys
    it cannot read - so this is a functional bug, not tidiness.
    """
    installer = _openssh_pkgs(INSTALL)
    standalone = _openssh_pkgs(UNINSTALL)
    assert set(installer) == set(standalone), (installer, standalone)
    assert set(installer) == {"openssh-client", "openssh-keygen", "openssh-client-utils"}


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_purge_never_removes_a_console_account_the_installer_did_not_create(
    tmp_path: Path,
) -> None:
    """--purge deletes an account only when UCI says WE created it.

    Deleting somebody's login because it is mentioned in a config file is unrecoverable, so the
    installer records the fact and both uninstallers honour it.
    """
    shim = tmp_path / "shim"
    shim.mkdir()
    called = tmp_path / "called.log"
    for name in ("apk", "opkg", "deluser"):
        path = shim / name
        path.write_text(f'#!/bin/sh\nprintf "%s %s\\n" "{name}" "$*" >> "{called}"\nexit 0\n')
        path.chmod(0o755)
    ident = shim / "id"
    ident.write_text("#!/bin/sh\necho 0\nexit 0\n")
    ident.chmod(0o755)

    for created, expect_removal in (("0", False), ("1", True)):
        config = tmp_path / "etc/config/tunnelgate"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            "\n".join(
                [
                    "config tunnelgate 'main'",
                    "\toption console_user 'tg-operator'",
                    f"\toption console_user_created '{created}'",
                ]
            )
            + "\n"
        )
        if called.exists():
            called.unlink()
        env = agent_env(tmp_path, PATH=f"{shim}:{os.environ['PATH']}")
        result = run([DASH, str(UNINSTALL), "--purge"], env=env)
        combined = result.stdout + result.stderr
        assert result.returncode == 0, combined
        log = called.read_text() if called.exists() else ""
        if expect_removal:
            assert "deluser tg-operator" in log, log
        else:
            assert "deluser" not in log, log
            assert "keeping console user tg-operator" in combined, combined
        # Either way the three packages are gone: that part is not conditional.
        assert log.count("opkg") + log.count("apk") >= 1, log


# --- item 3: pin the ONE key the panel named, and say which failure it was ----------------


def _keyscan_with_two_ed25519_keys(tmp_path: Path) -> tuple:
    """A fake ssh-keyscan that offers TWO ed25519 keys, so the pinning filter is observable.

    This has to be faked rather than produced with a real sshd: sshd publishes at most ONE host
    key per algorithm (measured - two HostKey lines of the same type yield one keyscan line), so
    a real host cannot present the case. The defect being guarded against is in how the scan
    OUTPUT is filtered, which is exactly what this reproduces without pretending sshd can.
    """
    d = tmp_path / "twokeys"
    bindir = d / "bin"
    bindir.mkdir(parents=True)
    fps = {}
    lines = []
    for name in ("k1", "k2"):
        path = d / name
        run(["ssh-keygen", "-t", "ed25519", "-f", str(path), "-N", "", "-q"])
        fps[name] = run(["ssh-keygen", "-lf", str(path) + ".pub"]).stdout.split()[1]
        lines.append(f"[127.0.0.1]:2222 {path.with_suffix('.pub').read_text().strip()}")
    # A real ssh-keyscan prefixes each block with a banner comment; include one so the filter's
    # comment-skipping is exercised too (it used to accumulate one line per run in known_hosts).
    payload = "# 127.0.0.1:2222 SSH-2.0-OpenSSH_9.9\n" + "\n".join(lines) + "\n"
    scan = bindir / "ssh-keyscan"
    scan.write_text(f'#!/bin/sh\ncat <<"EOF"\n{payload}EOF\n')
    scan.chmod(0o755)
    return bindir, fps


@needs_sshd
@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_only_the_fingerprint_the_panel_named_is_pinned(panel, tmp_path: Path) -> None:
    """Pinning every key a host publishes keeps accepting one after it is revoked.

    The old code appended the whole ssh-keyscan pool for the type. With two ed25519 keys the
    known_hosts file grew to two lines and the second stayed trusted forever - so a key rotated
    out of service was still accepted.
    """
    bindir, fps = _keyscan_with_two_ed25519_keys(tmp_path)
    known = tmp_path / "ssh/known_hosts"
    script = stage_installer(tmp_path, panel.url, panel.token)
    panel.response["ssh"]["host_key_fingerprint"] = fps["k2"]

    env = agent_env(tmp_path, TG_KNOWN_HOSTS=str(known), PATH=f"{bindir}:{os.environ['PATH']}")
    result = run([DASH, str(script)], env=env)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined

    lines = [line for line in known.read_text().splitlines() if line.strip()]
    assert len(lines) == 1, f"exactly one key must be pinned, got {lines}"
    nonce = tmp_path / "pinned.pub"
    nonce.write_text(lines[0].split(" ", 1)[1] + "\n")
    pinned = run(["ssh-keygen", "-lf", str(nonce)]).stdout.split()[1]
    assert pinned == fps["k2"], f"pinned {pinned}, the panel named {fps['k2']}"


@needs_sshd
@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_the_pin_filters_the_scan_comment_lines(panel, tmp_path: Path) -> None:
    """The banner comment carries no key; pinning it would grow known_hosts by a line per run."""
    bindir, _fps = _keyscan_with_two_ed25519_keys(tmp_path)
    known = tmp_path / "ssh/known_hosts"
    script = stage_installer(tmp_path, panel.url, panel.token)
    panel.response["ssh"]["host_key_fingerprint"] = _fps["k1"]

    env = agent_env(tmp_path, TG_KNOWN_HOSTS=str(known), PATH=f"{bindir}:{os.environ['PATH']}")
    assert run([DASH, str(script)], env=env).returncode == 0
    pinned = [line for line in known.read_text().splitlines() if line.strip()]
    assert not any(line.startswith("#") for line in pinned), pinned


@needs_sshd
@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_a_wrong_fingerprint_is_reported_as_a_mismatch(panel, tmp_path: Path) -> None:
    """The host DID answer and nothing matches, which is the alarming case."""
    bindir, _fps = _keyscan_with_two_ed25519_keys(tmp_path)
    script = stage_installer(tmp_path, panel.url, panel.token)
    panel.response["ssh"]["host_key_fingerprint"] = "SHA256:" + "A" * 43

    env = agent_env(tmp_path, PATH=f"{bindir}:{os.environ['PATH']}")
    result = run([DASH, str(script)], env=env)
    combined = result.stdout + result.stderr
    assert result.returncode == 1, combined
    assert "HOST KEY MISMATCH" in combined, combined
    assert "the host answered" in combined, combined
    assert "no answer at all" not in combined, combined


def test_an_unreachable_host_is_not_reported_as_a_key_mismatch(
    panel, tmp_path: Path, test_sshd: SshdFixture
) -> None:
    """A firewall and a MITM produce the same empty ssh-keyscan output; the messages differ.

    Sending an operator hunting a man in the middle when the truth is a blocked port wastes an
    hour and teaches them to ignore the warning that matters.
    """
    script = stage_installer(tmp_path, panel.url, panel.token)
    panel.response["ssh"]["port"] = free_port()  # nothing listens there

    env = agent_env(tmp_path)
    result = run([DASH, str(script)], env=env)
    combined = result.stdout + result.stderr
    assert result.returncode == 1, combined
    assert "ssh-keyscan got no answer at all" in combined, combined
    assert "NOT a key mismatch" in combined, combined
    assert "HOST KEY MISMATCH" not in combined, combined


# --- item 5: cfg_set must not treat a value as a sed program -----------------------------


@pytest.mark.skipif(DASH is None, reason="needs dash")
def _function_body(script: Path, name: str) -> str:
    """Extract one shell function's text from a script that runs top-level code when sourced.

    agent/lib/heartbeat.sh does its work at the top level, so it cannot simply be sourced in a
    test; its cfg_set can, and must, be exercised as the shipped bytes rather than a copy.
    """
    text = script.read_text().splitlines(keepends=True)
    start = next(i for i, line in enumerate(text) if line.rstrip() == f"{name}() {{")
    end = next(i for i in range(start + 1, len(text)) if text[i].rstrip() == "}")
    return "".join(text[start : end + 1])


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_cfg_set_survives_a_value_full_of_shell_metacharacters(tmp_path: Path) -> None:
    """Every character that is special in a sed replacement, in one URL.

    A panel behind a path prefix and a query string is not exotic, and the sed-based rewrite
    silently corrupted the config on exactly the hosts that have no uci to fall back on - which
    is the only path that fallback exists for.

    cfg_set lives in the heartbeat, not the installer: it is the process that persists
    console_serial and an adopted heartbeat_url. The function is extracted from the shipped file
    rather than retyped, so the test cannot drift away from the code it is about.
    """
    nasty = "https://panel.example.com/hb?a=1&b=2|c&d=e=f\\g%20h"
    config = tmp_path / "etc/config/tunnelgate"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("config tunnelgate 'main'\n\toption heartbeat_url 'old'\n")
    config.chmod(0o600)

    funcs = tmp_path / "cfg.sh"
    funcs.write_text(_function_body(HEARTBEAT, "cfg_set") + "\n")
    driver = tmp_path / "set.sh"
    driver.write_text(
        'set -u\n. "$1"\nshift\n'
        'CONFIG_FILE="$1"\n'
        "export CONFIG_FILE\n"
        'cfg_set heartbeat_url "$2" || { echo SET_FAILED; exit 3; }\n'
        "echo SET_OK\n",
    )
    env = agent_env(tmp_path)
    # No uci anywhere, so the awk fallback is the branch under test.
    env["PATH"] = "/usr/bin:/bin"
    result = run(shell_argv(DASH, driver, str(funcs), str(config), nasty), env=env)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert "SET_OK" in combined, combined
    assert uci_options(config)["heartbeat_url"] == nasty
    # And the file is still a valid single section: a rewrite must not duplicate the option.
    assert config.read_text().count("heartbeat_url") == 1, config.read_text()


# --- item 6: a write that fails must stop the install, not continue with no file ----------


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_a_failed_heredoc_write_is_reported(tmp_path: Path) -> None:
    """A full or read-only filesystem used to produce a "successful" install with no scripts.

    err() exits, so "the write failed" is observed as a non-zero exit carrying the message - not
    as a returned status. A driver that continues past the call would be testing a shell that
    does not exist.
    """
    lib = _payload_lib(tmp_path)
    for target, marker in (
        ("LOOP_BIN", "write_loop_bin"),
        ("HB_BIN", "write_heartbeat_bin"),
        ("UNINSTALL_BIN", "write_uninstall_bin"),
    ):
        driver = tmp_path / f"broken-{marker}.sh"
        # /proc is read-only on every Linux: the write must fail there.
        driver.write_text(
            'set -u\n. "$1"\nshift\n'
            f"{target}=/proc/tunnelgate-cannot-write\n"
            f"{marker}\n"
            "echo WROTE_ANYWAY\n"
        )
        result = run(shell_argv(DASH, driver, str(lib)), env=agent_env(tmp_path))
        combined = result.stdout + result.stderr
        assert result.returncode != 0, f"{marker} continued after a failed write: {combined}"
        assert "WROTE_ANYWAY" not in combined, (
            f"{marker} continued after a failed write: {combined}"
        )
        assert "cannot write" in combined, f"{marker} failed without saying why: {combined}"


# --- the status command must read the config it claims to describe -------------------------


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_status_reads_the_config_instead_of_reporting_a_default(tmp_path: Path) -> None:
    """--status called cfg_get, which existed only inside heredocs, so it printed "not found".

    The failure was quiet and misleading: the shell error went to stderr while the command
    carried on, and every option it could not read was reported at its default. An operator
    debugging a broken tunnel was told "verify (default)" and "plain http" for a panel that is
    https with verification on - the opposite of what the config said. Nothing failed, so only a
    positive assertion on the printed value catches it.
    """
    config = tmp_path / "etc/config/tunnelgate"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        "\n".join(
            [
                "config tunnelgate 'main'",
                "\toption panel_url 'https://panel.example.com:8443'",
                "\toption tls_verify '0'",
                "",
            ]
        )
    )
    config.chmod(0o600)

    lib = _payload_lib(tmp_path)
    driver = tmp_path / "status.sh"
    driver.write_text('set -u\n. "$1"\nshift\ndo_status\n')
    env = agent_env(tmp_path, TG_CONFIG=str(config))
    result = run(shell_argv(DASH, driver, str(lib)), env=env)
    combined = result.stdout + result.stderr

    # The defect's signature: a shell error the operator is expected to ignore, followed by a
    # confident report of the wrong thing.
    assert "not found" not in combined, combined
    # Both of these are only printed when the option could be READ back. Without a working
    # cfg_get the command reported "verify (default)" and "plain http" - so asserting the values
    # it should have found, rather than the absence of a failure, is what proves it read them.
    assert "NOT verified" in combined, combined
    assert "plain http" not in combined, combined
    assert "checks the certificate chain" in combined, combined


# --- item 7 + 9: a TLS stack that cannot verify must fail CLOSED, not open -----------------


def _fake_tls_lib(tmp_path: Path) -> Path:
    """A directory that looks like /lib with a TLS-capable libustream in it."""
    libdir = tmp_path / "fakelib"
    libdir.mkdir(exist_ok=True)
    (libdir / "libustream-ssl.so").write_text("")
    return libdir


def _fake_release(tmp_path: Path, release: str) -> Path:
    """An /etc/openwrt_release lookalike, so the version gate can be exercised off-device."""
    path = tmp_path / "openwrt_release"
    path.write_text(f"DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='{release}'\nDISTRIB_TARGET='x86/64'\n")
    return path


@pytest.mark.skipif(DASH is None, reason="needs dash")
@pytest.mark.parametrize("release", ["19.07.10", "19.07", "19", "18.06.9", "19.07-beta"])
def test_a_fetcher_that_cannot_verify_is_detected(tmp_path: Path, release: str) -> None:
    """curl validates through its own TLS stack; a uclient-fetch this old does not (measured)."""
    lib = _payload_lib(tmp_path)
    driver = tmp_path / "cap.sh"
    driver.write_text(
        'set -u\n. "$1"\nFETCHER=wget\nif tls_stack_cannot_verify; then echo CANNOT; else echo CAN; fi\n'
    )
    env = agent_env(tmp_path, TG_OPENWRT_RELEASE=str(_fake_release(tmp_path, release)))
    combined = run(shell_argv(DASH, driver, str(lib)), env=env)
    assert "CANNOT" in combined.stdout + combined.stderr, combined.stdout + combined.stderr


@pytest.mark.skipif(DASH is None, reason="needs dash")
@pytest.mark.parametrize("release", ["21.02.7", "22.03.7", "23.05.5", "24.10.1"])
def test_a_modern_fetcher_is_not_accused_of_being_unverifiable(
    tmp_path: Path, release: str
) -> None:
    """The gate must not fire on releases that do verify, or the refusal becomes noise."""
    lib = _payload_lib(tmp_path)
    driver = tmp_path / "cap.sh"
    driver.write_text(
        'set -u\n. "$1"\nFETCHER=wget\nif tls_stack_cannot_verify; then echo CANNOT; else echo CAN; fi\n'
    )
    env = agent_env(tmp_path, TG_OPENWRT_RELEASE=str(_fake_release(tmp_path, release)))
    combined = run(shell_argv(DASH, driver, str(lib)), env=env)
    assert "CAN" in combined.stdout, combined.stdout + combined.stderr
    assert "CANNOT" not in combined.stdout, combined.stdout


@pytest.mark.skipif(DASH is None, reason="needs dash")
@pytest.mark.parametrize("release", ["19x", "abc", "", "2O.02.1", "unknown"])
def test_an_unparsable_release_fails_closed(tmp_path: Path, release: str) -> None:
    """'[0-9]*' matched "19x", the numeric compare then returned 2, and 2 read as "safe".

    Treating an unknown release as modern is the wrong direction: the only thing known about it
    is that it is not PROVEN to verify, and the cost of being wrong is a private key.
    """
    lib = _payload_lib(tmp_path)
    driver = tmp_path / "cap.sh"
    driver.write_text(
        'set -u\n. "$1"\nFETCHER=wget\nTLS_UNPARSED_RELEASE=0\nif tls_stack_cannot_verify; then echo CANNOT; else echo CAN; fi\necho "unparsed=$TLS_UNPARSED_RELEASE"\n'
    )
    env = agent_env(tmp_path, TG_OPENWRT_RELEASE=str(_fake_release(tmp_path, release)))
    combined = run(shell_argv(DASH, driver, str(lib)), env=env)
    assert "CANNOT" in combined.stdout, combined.stdout + combined.stderr
    assert "unparsed=1" in combined.stdout, combined.stdout


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_curl_is_never_treated_as_unverifiable(tmp_path: Path) -> None:
    """curl links its own TLS and does validate; the 19.07 finding is about uclient-fetch only."""
    lib = _payload_lib(tmp_path)
    driver = tmp_path / "cap.sh"
    driver.write_text(
        'set -u\n. "$1"\nFETCHER=curl\nif tls_stack_cannot_verify; then echo CANNOT; else echo CAN; fi\n'
    )
    env = agent_env(tmp_path, TG_OPENWRT_RELEASE=str(_fake_release(tmp_path, "19.07.10")))
    combined = run(shell_argv(DASH, driver, str(lib)), env=env)
    assert "CAN" in combined.stdout, combined.stdout


@needs_sshd
@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_an_unverifiable_stack_refuses_to_send_the_key(
    panel, tmp_path: Path, fake_fetchers, stock_image: Path
) -> None:
    """The refusal must happen BEFORE the exchange, so no private key and no API token move.

    A warning in a log is not consent: the host key fingerprint arrives in the same response as
    the private key, so a MITM substitutes the key, the fingerprint and the pin together and
    pin_host_key cannot tell. This is the one place the installer can still say no.
    """
    script = stage_installer(tmp_path, panel.url.replace("http://", "https://"), panel.token)
    env = _router_env(tmp_path, fake_fetchers, stock_image, "wget")
    env["TG_OPENWRT_RELEASE"] = str(_fake_release(tmp_path, "19.07.10"))
    # Pretend the image already carries a TLS-capable libustream: that is the state on 19.07 once
    # the package is installed, and it is what makes this test about the DECISION, not about a
    # missing package (ensure_tls_lib would otherwise stop the run for a different reason).
    env["TG_TLS_LIB_DIRS"] = str(_fake_tls_lib(tmp_path))
    result = run([DASH, str(script)], env=env)
    combined = result.stdout + result.stderr

    assert result.returncode == 1, combined
    assert "cannot check a certificate" in combined, combined
    assert "Nothing has been sent" in combined, combined
    # Two concrete ways out, named. A refusal that does not say what to do next gets bypassed by
    # whatever the operator finds first.
    assert "21.02" in combined, combined
    assert "Agent endpoint" in combined, combined
    # The properties that matter: nothing was POSTed and no key was written.
    assert not panel.calls, f"the panel was contacted anyway: {panel.calls}"
    assert not (tmp_path / "ssh/tunnelgate_ed25519").exists()


@needs_sshd
@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_the_consent_path_warns_instead_of_refusing(
    panel, tmp_path: Path, fake_fetchers, stock_image: Path
) -> None:
    """tls_verify=0 is the audited acknowledgement, so it is warned about and then honoured.

    Refusing here would make a self-signed panel un-installable on such a router; the point of
    the split is that turning verification off is a recorded DECISION, not a silent default.
    """
    script = stage_installer(tmp_path, panel.url.replace("http://", "https://"), panel.token)
    env = _router_env(tmp_path, fake_fetchers, stock_image, "wget", TG_TLS_VERIFY="0")
    env["TG_OPENWRT_RELEASE"] = str(_fake_release(tmp_path, "19.07.10"))
    env["TG_TLS_LIB_DIRS"] = str(_fake_tls_lib(tmp_path))
    result = run([DASH, str(script)], env=env)
    combined = result.stdout + result.stderr

    assert "WARNING:" in combined, combined
    assert "unauthenticated" in combined, combined
    assert "Nothing has been sent" not in combined, combined


# --- item 8: the heartbeat must nag too, or a 19.07 router is silently unauthenticated forever


def _openwrt_fetcher_env(tmp_path: Path, fake_fetchers, stock_image: Path, **extra) -> dict:
    """A PATH and environment that look like a stock router running the given fetcher.

    The distinction is the whole point of the capability check: curl validates a chain through its
    own TLS (never "unverifiable"), while on OpenWrt wget IS uclient-fetch. Keeping the host's curl
    on PATH would silently select the branch that cannot fail and hide the defect.
    """
    bindir = fake_fetchers["dirs"]["wget"]
    env = agent_env(tmp_path, TMPDIR=str(tmp_path / "runtime"), **extra)
    env["PATH"] = f"{bindir}:{stock_image}"
    return env


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_the_heartbeat_warns_when_the_stack_cannot_verify(
    tmp_path: Path, fake_fetchers, stock_image: Path
) -> None:
    """The installer's warning is scrolled away by the next boot; the left-behind process nags."""
    (tmp_path / "runtime").mkdir()
    url = _fake_token_panel(tmp_path, "tok_test")
    config = _heartbeat_config(tmp_path, url)
    marker = tmp_path / "cap-warning"

    env = _openwrt_fetcher_env(
        tmp_path,
        fake_fetchers,
        stock_image,
        TG_CONFIG=str(config),
        TG_OPENWRT_RELEASE=str(_fake_release(tmp_path, "19.07.10")),
        TG_TLS_CAP_WARN_FILE=str(marker),
    )
    result = run([DASH, str(HEARTBEAT)], env=env)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert "WARNING:" in combined, combined
    assert "cannot check a certificate chain" in combined, combined
    assert marker.exists(), "the once-per-boot marker was not written"


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_the_heartbeat_nag_is_once_per_boot(
    tmp_path: Path, fake_fetchers, stock_image: Path
) -> None:
    """This process restarts every 60 s; a warning every minute is a warning nobody reads."""
    (tmp_path / "runtime").mkdir()
    url = _fake_token_panel(tmp_path, "tok_test")
    config = _heartbeat_config(tmp_path, url)
    marker = tmp_path / "cap-warning"
    env = _openwrt_fetcher_env(
        tmp_path,
        fake_fetchers,
        stock_image,
        TG_CONFIG=str(config),
        TG_OPENWRT_RELEASE=str(_fake_release(tmp_path, "19.07.10")),
        TG_TLS_CAP_WARN_FILE=str(marker),
    )

    first = run([DASH, str(HEARTBEAT)], env=env)
    assert "cannot check a certificate chain" in first.stdout + first.stderr
    second = run([DASH, str(HEARTBEAT)], env=env)
    assert "cannot check a certificate chain" not in second.stdout + second.stderr


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_the_two_tls_warnings_do_not_suppress_each_other(
    tmp_path: Path, fake_fetchers, stock_image: Path
) -> None:
    """The markers are separate files because the two facts are independent, not ranked.

    A router can be told to stop verifying (tls_verify=0) and later be put back on (tls_verify=1)
    while the fetcher still cannot check a chain. One marker file for both would silence the
    second warning forever after the first, which is exactly how a stale acknowledgement becomes
    a permanent hole.
    """
    (tmp_path / "runtime").mkdir()
    url = _fake_token_panel(tmp_path, "tok_test")
    config = _heartbeat_config(tmp_path, url)
    config.write_text(config.read_text() + "\toption tls_verify '0'\n")
    env = _openwrt_fetcher_env(
        tmp_path,
        fake_fetchers,
        stock_image,
        TG_CONFIG=str(config),
        TG_OPENWRT_RELEASE=str(_fake_release(tmp_path, "19.07.10")),
    )

    # Step 1: verification is off, so the consent warning is due.
    result = run([DASH, str(HEARTBEAT)], env=env)
    combined = result.stdout + result.stderr
    assert "certificate verification is OFF" in combined, combined

    # Step 2: the operator turns it back on, and the stack still cannot verify. The marker the
    # first warning wrote must not stand in for this one.
    config.write_text(config.read_text().replace("tls_verify '0'", "tls_verify '1'"))
    result = run([DASH, str(HEARTBEAT)], env=env)
    combined = result.stdout + result.stderr
    assert "cannot check a certificate chain" in combined, combined


# --- item D: the console account the config names must be the account that can log in -----


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_a_console_user_that_cannot_be_created_is_recorded_as_root(tmp_path: Path) -> None:
    """adduser -D -H gave no HOME and the key went to root's file, so the named user could not log in.

    Worse, when adduser FAILED the code logged "console will connect as root" while UCI still
    named the requested user, so the panel asked dropbear for an account that did not exist.
    """
    lib = _payload_lib(tmp_path)
    # A shim that refuses: this is the firmware without adduser, or a full filesystem.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("adduser", "passwd"):
        path = bindir / name
        path.write_text("#!/bin/sh\nexit 1\n")
        path.chmod(0o755)
    driver = tmp_path / "console.sh"
    driver.write_text(
        'set -u\n. "$1"\n'
        # get() reads the panel response through the JSON library; stub the two lookups instead so
        # this test is about the account decision, not about JSON parsing.
        'get() { case "$1" in console.ssh_user) echo tg-operator ;; '
        "console.shell) echo /bin/ash ;; console.authorized_keys_path) echo /etc/dropbear/authorized_keys ;; "
        '*) echo "" ;; esac; }\n'
        'log() { printf "%s\\n" "$*"; }\n'
        'err() { echo "ERR $*"; exit 1; }\n'
        "ensure_console_user\n"
        'echo "effective=$CONSOLE_USER_EFFECTIVE created=$CONSOLE_USER_CREATED keys=$CONSOLE_KEYS_EFFECTIVE"\n'
    )
    env = agent_env(tmp_path)
    env["PATH"] = f"{bindir}:{os.environ['PATH']}"
    env["TG_PASSWD"] = str(tmp_path / "passwd")
    (tmp_path / "passwd").write_text("root:x:0:0:root:/root:/bin/ash\n")

    combined = run(shell_argv(DASH, driver, str(lib)), env=env)
    text = combined.stdout + combined.stderr
    # The account really in use is recorded, so the panel and the router cannot disagree.
    assert "effective=root" in text, text
    assert "created=0" in text, text
    # And the operator is told loudly, not in a line that says "console will connect as root"
    # while the config says otherwise.
    assert "WARNING" in text, text


# --- item 4: a state field nobody writes is worse than no field ---------------------------


def test_the_dead_tunnel_pid_is_gone_from_both_scripts() -> None:
    """Nothing ever wrote tunnel_pid, so both readers reported a value that could not exist.

    The panel derives it from its own monitor (app/services/monitor.py), which is the only value
    that can be correct; a router-supplied pid would also be about the wrong process, since the
    ssh process is respawned by procd and its pid is not stable across a reconnect.
    """
    for path in (INSTALL, HEARTBEAT):
        text = path.read_text()
        for lineno, line in enumerate(text.splitlines(), 1):
            code = line.split("#", 1)[0]
            assert "tunnel_pid" not in code, (
                f"{path.name}:{lineno} still mentions tunnel_pid: {line}"
            )


def test_the_heartbeat_payload_still_carries_the_fields_the_panel_reads() -> None:
    """Removing a dead field must not remove a live one: the panel parses these by name.

    The list is the heartbeat's, not the exchange's: app/api/heartbeat.py:86 maps hostname, model,
    openwrt_version, mac and client_version onto the router row, and uptime_seconds is read
    separately at :91. mac is carried by the EXCHANGE only (app/api/bootstrap.py:168) - it is an
    identity fact the router reports once, not something that changes per minute - so asserting it
    here would demand a field the heartbeat never had.
    """
    text = HEARTBEAT.read_text()
    for field in ("hostname", "model", "openwrt_version", "uptime_seconds", "client_version"):
        assert f'"{field}"' in text, f"heartbeat no longer reports {field}"


def test_the_console_key_path_prefers_the_routers_own_configuration() -> None:
    """The panel always sends /etc/dropbear/authorized_keys; a non-root console needs its own file.

    app/services/keys.py console_key_registration() returns ROUTER_AUTHORIZED_KEYS_PATH
    unconditionally, so taking that field at face value would undo the layout the installer chose
    for a non-root console account and the key would land where that account's dropbear never
    looks.
    """
    text = HEARTBEAT.read_text()
    assert "console_authorized_keys_path" in text
    # The UCI read must come FIRST and the response field only as a fallback.
    uci_at = text.index("cfg_get console_authorized_keys_path")
    fallback_at = text.index("authorized_keys_path")
    assert uci_at < fallback_at or "reg_keys_path" in text[: fallback_at + 400]


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_a_console_user_that_can_be_created_gets_its_own_key_file(tmp_path: Path) -> None:
    """The non-root console happy path: the DECISION is what was broken, so stub the primitives.

    A real account cannot be created portably inside the suite (no adduser on the test host, and
    creating one would be a side effect no test may leave behind). But nothing that was wrong
    here is a syscall: the bug was that the installer decided "console user = tg-operator" for the
    panel while pointing the key at /etc/dropbear/authorized_keys, which dropbear reads for ROOT
    only - so the named account could never authenticate. That is a decision about three values
    (effective user, effective key path, console_user_created), and all three are computed here
    with adduser and id stubbed.

    What is NOT reached without a live account: the actual account creation (adduser's own
    work) and dropbear's actual read of the file at login. Both are named in docs/INSTALL_ROUTER.md
    as the operator's step; everything the installer decides is asserted below.
    """
    home = tmp_path / "home" / "tg-operator"
    home.mkdir(parents=True)
    passwd = tmp_path / "passwd"
    # The passwd entry must name the home THIS test owns, because that is the path the installer
    # resolves from /etc/passwd (field 6) and the path prepare_console will actually create.
    passwd.write_text(
        f"root:x:0:0:root:/root:/bin/ash\ntg-operator:x:1000:65534::{home}:/bin/ash\n"
    )

    # id says the account does NOT exist yet (so the creation branch runs) and adduser succeeds.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "id").write_text("#!/bin/sh\nexit 1\n")
    (bindir / "adduser").write_text("#!/bin/sh\nexit 0\n")
    for name in ("id", "adduser"):
        (bindir / name).chmod(0o755)

    lib = _payload_lib(tmp_path)
    driver = tmp_path / "console-ok.sh"
    driver.write_text(
        'set -u\n. "$1"\n'
        # get() is the panel response; stub it so this test is about the account decision only.
        'get() { case "$1" in console.ssh_user) echo tg-operator ;; '
        "console.shell) echo /bin/ash ;; console.enabled) echo true ;; "
        "console.authorized_keys_path) echo /etc/dropbear/authorized_keys ;; "
        '*) echo "" ;; esac; }\n'
        'log() { printf "%s\\n" "$*"; }\n'
        'err() { echo "ERR $*"; exit 1; }\n'
        # require_field() reads through get() too, so the response fields the config needs are
        # stubbed here rather than parsed out of a JSON fixture: this test is about the account.
        'require_field() { case "$1" in router_id) echo r-test001 ;; api_token) echo tok_test ;; '
        "heartbeat_url) echo https://panel.test/hb ;; ssh.host) echo 127.0.0.1 ;; "
        "ssh.port) echo 22 ;; ssh.username) echo tunnelgate ;; tunnel.remote_port) echo 20001 ;; "
        '*) echo "" ;; esac; }\n'
        "ensure_console_user\n"
        "prepare_console\n"
        "write_config\n"
        'echo "effective=$CONSOLE_USER_EFFECTIVE created=$CONSOLE_USER_CREATED '
        'keys=$CONSOLE_KEYS_EFFECTIVE"\n'
    )
    env = agent_env(tmp_path)
    env["PATH"] = f"{bindir}:{os.environ['PATH']}"
    env["TG_PASSWD"] = str(passwd)
    env["TG_PANEL_URL"] = "https://panel.test"

    combined = run(shell_argv(DASH, driver, str(lib)), env=env)
    text = combined.stdout + combined.stderr

    # (a) the account actually in use is the requested one, NOT root
    assert "effective=tg-operator" in text, text
    # (b) the key path is that account's own file, never root's dropbear file
    assert f"keys={home}/.ssh/authorized_keys" in text, text
    assert "/etc/dropbear/authorized_keys" not in text.split("effective=")[-1], text
    # (d) recorded as created by US, so a later --purge is allowed to remove it
    assert "created=1" in text, text
    # ... and the file the console will read really was prepared with the right modes
    keys_file = home / ".ssh" / "authorized_keys"
    assert keys_file.is_file(), list(home.rglob("*"))
    assert keys_file.stat().st_mode & 0o777 == 0o600
    assert (home / ".ssh").stat().st_mode & 0o777 == 0o700

    # (c) the persisted configuration names the same account and the same file
    options = uci_options(Path(env["TG_CONFIG"]))
    assert options["console_user"] == "tg-operator", options
    assert options["console_authorized_keys_path"] == f"{home}/.ssh/authorized_keys", options
    assert options["console_user_created"] == "1", options


@pytest.mark.skipif(DASH is None, reason="needs dash")
def test_an_existing_console_user_is_used_but_never_claimed_as_created(tmp_path: Path) -> None:
    """The other half of the same decision: id says the account is already there.

    Then the installer must NOT record console_user_created=1, because the uninstaller is only
    allowed to delete an account this installer made. Getting this wrong destroys somebody's
    pre-existing login on --purge.
    """
    home = tmp_path / "home" / "tg-operator"
    home.mkdir(parents=True)
    passwd = tmp_path / "passwd"
    passwd.write_text("root:x:0:0:root:/root:/bin/ash\ntg-operator:x:1000:65534::/tmp/x:/bin/ash\n")

    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "id").write_text("#!/bin/sh\nexit 0\n")
    (bindir / "adduser").write_text("#!/bin/sh\necho ADDUSER_MUST_NOT_RUN\nexit 0\n")
    for name in ("id", "adduser"):
        (bindir / name).chmod(0o755)

    lib = _payload_lib(tmp_path)
    driver = tmp_path / "console-exists.sh"
    driver.write_text(
        'set -u\n. "$1"\n'
        'get() { case "$1" in console.ssh_user) echo tg-operator ;; '
        "console.shell) echo /bin/ash ;; console.enabled) echo true ;; "
        "console.authorized_keys_path) echo /etc/dropbear/authorized_keys ;; "
        '*) echo "" ;; esac; }\n'
        'log() { printf "%s\\n" "$*"; }\n'
        'err() { echo "ERR $*"; exit 1; }\n'
        "ensure_console_user\n"
        'echo "effective=$CONSOLE_USER_EFFECTIVE created=$CONSOLE_USER_CREATED"\n'
    )
    env = agent_env(tmp_path)
    env["PATH"] = f"{bindir}:{os.environ['PATH']}"
    env["TG_PASSWD"] = str(passwd)

    combined = run(shell_argv(DASH, driver, str(lib)), env=env)
    text = combined.stdout + combined.stderr
    assert "effective=tg-operator" in text, text
    assert "created=0" in text, text
    assert "ADDUSER_MUST_NOT_RUN" not in text, text
