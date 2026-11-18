"""Guards for scripts/quick-install.sh.

That script exists for one deployment shape: TLS is terminated by the operator's own
reverse proxy, so this host speaks plain HTTP on one port and the installer must stop
before any certificate work. These tests pin the decisions that shape makes, because
every one of them is a security or availability claim that a later edit could quietly
undo.
"""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
QUICK_SH = REPO / "scripts" / "quick-install.sh"
BEHIND_PROXY_CONF = REPO / "deploy" / "nginx" / "tunnelgate-behind-proxy.conf"
TLS_CONF = REPO / "deploy" / "nginx" / "tunnelgate.conf"


def _text() -> str:
    return QUICK_SH.read_text()


def _directives(text: str) -> list[str]:
    """Lines that actually execute, so comments may discuss a forbidden thing."""
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def _ufw_lines() -> list[str]:
    return [line.strip() for line in _directives(_text()) if line.strip().startswith("ufw ")]


def test_quick_install_is_executable_and_parses(tmp_path: Path) -> None:
    assert QUICK_SH.exists(), "scripts/quick-install.sh is missing"
    assert QUICK_SH.stat().st_mode & stat.S_IXUSR, "quick-install.sh must be executable"
    result = subprocess.run(
        ["sh", "-n", str(QUICK_SH)], capture_output=True, text=True, check=False, cwd=REPO
    )
    assert result.returncode == 0, result.stderr


def test_quick_install_never_opens_the_console_or_tunnel_pools() -> None:
    """Both pools are 127.0.0.1 sshd listeners; publishing them bypasses the panel.

    This is the single most damaging thing an installer of this shape could do: the
    tunnel pool answers a plain SSH server for router shells, and the console pool
    answers the panel's own console sockets. Neither has any authentication of its own.
    """
    opened = _ufw_lines()
    assert opened, "the quick installer must still state a firewall posture"
    for line in opened:
        for forbidden in ("20000", "25000", "25001", "30000", "20000:25000", "25001:30000"):
            assert forbidden not in line, f"{line!r} opens a loopback-only range"
    text = _text()
    # It also has to say so out loud, or an operator "helpfully" opens them later.
    assert "25001-30000" in text
    assert "20000-25000" in text
    assert "127.0.0.1" in text


def test_quick_install_only_opens_the_one_http_port() -> None:
    for line in _ufw_lines():
        if line.startswith("ufw allow"):
            assert "$HTTP_PORT" in line, f"{line!r} opens more than the proxy port"
    # --skip-firewall is a supported opt-out, and it must warn rather than go quiet.
    assert "--skip-firewall" in _text()


def test_quick_install_makes_the_routes_dir_writable_for_the_panel() -> None:
    """The panel writes routes.conf with temp+rename, so it needs CREATE on the dir."""
    text = _text()
    line = next(
        (ln.strip() for ln in _directives(text) if "$ROUTES_DIR" in ln and "install -d" in ln),
        None,
    )
    assert line is not None, "the installer must create the nginx routes directory"
    assert "-o tunnelgate" in line
    # 0750 leaves the panel CREATE but keeps the directory unlistable by others.
    assert "-m 0750" in line


def test_quick_install_unlocks_the_tunnel_account() -> None:
    """useradd writes '!' and sshd with UsePAM no then says "account is locked".

    The symptom is indistinguishable from a broken key, so the installer must fix the
    password field explicitly.
    """
    text = _text()
    assert "usermod -p '*'" in text
    assert "account is locked" in text


def test_quick_install_validates_sshd_before_reloading_it() -> None:
    """A broken Match block locks the operator out of the machine."""
    text = _text()
    assert "sshd -t" in text
    check = text.index("sshd -t")
    reload = text.index("systemctl reload ssh")
    assert check < reload, "sshd -t must run before the reload"
    assert "sh -c" not in text[check:reload], "the comparison above only holds for one file"


def test_quick_install_proves_ssh_still_listens_before_claiming_success() -> None:
    """A reload that passes sshd -t can still leave :22 with no listener.

    Some LXC images lose the socket on the first reload after a drop-in appears
    ("fatal: Cannot bind any address"). sshd -t cannot detect that - only a look at the
    socket can - so the installer must check the listener and, when it is gone, say so
    instead of reporting success while new logins are refused. The operator is usually
    connected over that very port, so the message has to say the session survives.
    """
    text = _text()
    reload_at = text.index("systemctl reload ssh")
    # The check must be a socket check, not a "did the unit start" check.
    assert "ssh_listening()" in text or "ss -ltn" in text
    check_at = text.index("ssh_listening()") if "ssh_listening()" in text else text.index("ss -ltn")
    assert check_at < reload_at, "define the listener check before using it"
    # A restart is the escalation, not the first move: it can kill existing children on
    # hosts whose unit uses KillMode=stop, so it may only follow a lost listener.
    restart_at = text.index("systemctl restart ssh")
    assert restart_at > reload_at, "reload first; restart only when :22 is gone"
    assert ":22 is listening" in text
    fallback = text[restart_at:]
    assert "KEEP THIS SHELL OPEN" in fallback, "a lost listener must be reported loudly"
    # And the escalation must be re-verified, otherwise a failed restart looks like a win.
    assert fallback.count("wait_for_ssh") >= 1


def test_quick_install_proves_the_panel_answers_before_claiming_success() -> None:
    """`systemctl restart` returns while a panel that cannot bind is still restarting.

    A live run printed "started, listening on ..." and exited 0 with the service in
    auto-restart, because something else held the panel port; the operator's first clue
    was a 404 from nginx three sections later. The installer has to ask the panel.
    """
    text = _text()
    restart_at = text.index('systemctl restart "$SERVICE"')
    health_at = text.index('"$PANEL_URL/api/v1/health"')
    assert restart_at < health_at, "the readiness probe must follow the unit start"
    assert 'journalctl -u "$SERVICE" -n 20' in text
    # And a panel that never answers must stop the install, not print a happy summary.
    assert 'die "the unit is installed but the panel is not serving' in text
    # The summary section must not be reachable when the panel never came up.
    assert text.index('die "the unit is installed but the panel is not serving') < text.index(
        "TunnelGate is installed on this host."
    )


def test_quick_install_validates_nginx_before_reloading_it() -> None:
    text = _text()
    assert text.index("nginx -t") < text.index("systemctl reload nginx")
    # And it restores the distribution vhost if the result is rejected.
    assert "restored /etc/nginx/sites-enabled/default" in text


def test_quick_install_refuses_the_tls_vhost_side_by_side() -> None:
    """Both vhosts declare map $http_upgrade $connection_upgrade - one map per target.

    Installing this one over the TLS one either fails nginx -t with a message naming
    neither file, or silently drops upgrade handling, which looks like "the console
    connects and then hangs".
    """
    text = _text()
    assert "sites-enabled/tunnelgate.conf" in text
    assert "cannot coexist" in text
    assert "deploy/nginx/tunnelgate-behind-proxy.conf" in text


def test_quick_install_ships_the_plain_http_vhost_not_the_tls_one() -> None:
    text = _text()
    sources = [ln.strip() for ln in _directives(text) if "deploy/nginx/" in ln]
    assert sources, "the installer must render a vhost from deploy/nginx/"
    assert any("tunnelgate-behind-proxy.conf" in ln for ln in sources)
    assert not [ln for ln in sources if ln.endswith("tunnelgate.conf")]


def test_quick_install_never_itself_handles_certificates() -> None:
    """TLS is the operator's job here: certificates, DNS and ACME must not run here.

    certbot may still be *named* in a comment (to explain why it is absent), so only
    executable lines are inspected.
    """
    for line in _directives(_text()):
        stripped = line.strip()
        for tool in ("certbot", "acme.sh", "lego"):
            assert tool not in stripped, f"the installer must not run {tool}: {stripped!r}"


def test_quick_install_preserves_an_existing_environment_file() -> None:
    """Secrets are generated once: a re-run must never rotate SECRET_KEY."""
    text = _text()
    guard = text.index('if [ -f "$ENV_FILE" ]')
    write = text.index('cat >"$ENV_FILE" <<ENVEOF')
    assert guard < write
    assert "leaving it alone" in text
    assert "never overwrites an existing environment file" in text


def test_quick_install_keeps_the_single_trusted_hop_documented() -> None:
    """FORWARDED_ALLOW_HOPS=2 is only safe when the edge appends and is private.

    The panel cannot tell "the proxy appended this" from "the client sent this", so the
    installer documents the trade instead of silently trusting two hops.
    """
    text = _text()
    assert "TUNNELGATE_FORWARDED_ALLOW_HOPS=$PROXY_HOPS" in text
    assert "--proxy-hops" in text
    assert "TUNNELGATE_COOKIE_SECURE=$COOKIE_SECURE" in text
    assert "TUNNELGATE_TRUSTED_PROXIES=" in text


def test_quick_install_runs_the_panel_commands_as_the_service_user() -> None:
    """init-db as root leaves a root-owned sqlite file the panel cannot write."""
    text = _text()
    assert "runuser -u tunnelgate" in text
    assert "panel_cli init-db" in text
    assert "seed-admin" in text


def test_quick_install_is_honest_about_dry_run() -> None:
    """Every mutation goes through run(), which prints instead of executing."""
    text = _text()
    assert 'if [ "$DRY_RUN" -eq 1 ]; then' in text
    assert "[dry-run]" in text
    # The steps that cannot go through run() (heredocs, sed, package installs) must sit
    # inside an explicit guard, not merely print and continue.
    assert text.count('if [ "$DRY_RUN" -eq 0 ]') >= 5


def test_quick_install_help_and_argument_errors() -> None:
    ok_run = subprocess.run(
        ["sh", str(QUICK_SH), "--help"], capture_output=True, text=True, check=False, cwd=REPO
    )
    assert ok_run.returncode == 0
    assert "--host" in ok_run.stdout
    assert "--dry-run" in ok_run.stdout

    missing = subprocess.run(
        ["sh", str(QUICK_SH)], capture_output=True, text=True, check=False, cwd=REPO
    )
    assert missing.returncode == 2
    assert "--host is required" in missing.stderr

    for bad in (
        ["--host", "https://gate.example.com"],
        ["--host", "gate.example.com/luci"],
        ["--host", "gate.example.com:8443"],
        ["--host", "gate.example.com", "--public-scheme", "ftp"],
        ["--host", "gate.example.com", "--proxy-hops", "0"],
        ["--host", "gate.example.com", "--port", "8080", "--panel-port", "8080"],
    ):
        run = subprocess.run(
            ["sh", str(QUICK_SH), *bad], capture_output=True, text=True, check=False, cwd=REPO
        )
        assert run.returncode == 1, f"{bad} should be rejected"
        assert "error:" in run.stderr


def test_quick_install_dry_run_touches_nothing() -> None:
    """A dry run must be safe for an operator to run against a production host."""
    before = sorted(str(p) for p in REPO.rglob("scripts/*") if p.is_file())
    run = subprocess.run(
        ["sh", str(QUICK_SH), "--host", "gate.example.com", "--dry-run"],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO,
    )
    # It exits non-zero only when a preflight check fires (a TLS vhost or a busy port);
    # it must never exit successfully having written something.
    assert "[dry-run]" in run.stdout
    assert "DRY RUN" in run.stdout
    after = sorted(str(p) for p in REPO.rglob("scripts/*") if p.is_file())
    assert before == after


def test_behind_proxy_conf_is_http_only_and_includes_the_routes_inside_the_server() -> None:
    """The merged layout includes routes.conf INSIDE the panel server block.

    Including it at http level would install the per-router locations globally, and a
    separate server{} for the same name would shadow the panel - nginx serves the FIRST
    server block matching a name, so the panel would 404 while nginx -t stayed green.
    """
    text = BEHIND_PROXY_CONF.read_text()
    assert "listen 80 default_server;" in text
    directives = "\n".join(_directives(text))
    assert "ssl_certificate" not in directives, "this vhost must not reference a certificate"
    # HSTS over a plain-HTTP hop is a lie; the comment explaining that must survive, so
    # only directive lines are inspected.
    assert "Strict-Transport-Security" not in directives
    # The include must sit inside the server block: after "server {" and before the
    # first location, which is where nginx accepts server-level directives.
    start = text.index("server {")
    include = text.index("include /etc/nginx/tunnelgate/routes.conf;")
    first_location = text.index("location /assets/ {")
    assert start < include < first_location, "routes.conf must be included in the server block"
    assert "location / {" in text
    # One map per target variable, and never the one the TLS vhost already declares.
    assert text.count("map $http_upgrade $connection_upgrade {") == 1
    assert "map $http_upgrade $tg_connection_upgrade" not in text
    # The console WebSocket rides /api/, so that location must forward the upgrade.
    api = text[text.index("location /api/ {") :]
    api = api[: api.index("\n    }")]
    assert "proxy_http_version 1.1;" in api
    assert "proxy_set_header Upgrade" in api
    assert "$connection_upgrade" in api
    assert "proxy_read_timeout 3600s;" in api
    assert "proxy_buffering" in api and "off" in api


def test_behind_proxy_conf_and_the_tls_vhost_are_mutually_exclusive() -> None:
    """They both declare the same map, so an operator must be told which one to use."""
    behind = BEHIND_PROXY_CONF.read_text()
    assert "tunnelgate.conf" in behind
    assert TLS_CONF.exists()
    directive_maps = [
        line
        for line in _directives(TLS_CONF.read_text())
        if line.strip().startswith("map $http_upgrade")
    ]
    assert directive_maps == ["map $http_upgrade $connection_upgrade {"]
    assert behind.count("map $http_upgrade $connection_upgrade {") == 1
