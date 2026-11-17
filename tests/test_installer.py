"""Router agent (agent/) tests: shipped-script behaviour against a mock panel and a real sshd.

These tests exercise the SHIPPED scripts, not a copy. The installer reads every absolute
path from a TG_* environment variable (whose defaults are the real OpenWrt paths), so a test
run stages a complete agent into tmp_path without ever touching /etc or /root.

The e2e tests need a local sshd (marked "e2e", skipped when it is absent): they prove the
reconnect loop really opens the reverse forwards and that the heartbeat really installs the
console key - neither is established by static checking.
"""

from __future__ import annotations

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
        }
    )
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

    def __init__(self, response: dict, token: str, console: dict | None = None):
        self.response = response
        self.token = token
        self.console = console
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

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                panel.calls.append(
                    {
                        "path": self.path,
                        "bootstrap": self.headers.get("X-Bootstrap-Token"),
                        "api": self.headers.get("X-Api-Token"),
                        "body": json.loads(body) if body else None,
                    }
                )
                if self.path.endswith("/bootstrap/exchange"):
                    # Unknown and already-used tokens both answer 401 invalid_token on the
                    # real panel (app/services/bootstrap.py:find_token), so the mock must too.
                    if self.headers.get("X-Bootstrap-Token") != panel.token or panel.token_used:
                        self._reply(401, _INVALID_TOKEN)
                        return
                    panel.token_used = True
                    self._reply(200, json.dumps(panel.response).encode())
                    return
                if self.path.endswith("/heartbeat"):
                    if self.headers.get("X-Api-Token") != panel.response["api_token"]:
                        self._reply(401, b"{}")
                        return
                    out = {"ok": True, "status": "active", "server_time": "2026-01-01T00:00:00Z"}
                    if panel.console is not None:
                        out["console"] = panel.console
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
        if line.strip() == "cat >" or line.rstrip().endswith("<<'" + marker + "'"):
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
