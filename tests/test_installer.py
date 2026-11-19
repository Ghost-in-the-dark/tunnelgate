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
