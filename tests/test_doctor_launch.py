"""`doctor` must explain a deployment that would loop, not just refuse to start.

The launch hand-off only works when router hostnames exist and the rendered proxy config
carries /__tg/enter plus the router-cookie header on the auth subrequest. Both are invisible
from the UI - a stale config just bounces the browser through /login forever - so the only
place an operator can be told about it is here.
"""

from __future__ import annotations

import os
import pwd
from pathlib import Path
from unittest import mock

import pytest

from app.cli import (
    FAIL,
    OK,
    WARN,
    Report,
    _check_agent_endpoint,
    _check_authorized_keys_readable,
    _check_launch,
    _check_proxy,
    _check_routes_include,
    _check_ss,
    _check_storage,
    _check_sub_filter,
    _hostname_problem,
    _nginx_modules,
)
from app.services.launch import cookie_header_name
from app.services.proxy import (
    auth_snippet_path,
    render_nginx,
    render_nginx_auth_snippet,
)


def pwd_account(name: str, uid: int, gid: int) -> pwd.struct_passwd:
    """A passwd entry for an account that need not exist on the machine running the tests.

    The check must be judgeable from the mode bits alone, so the account is described rather
    than looked up: otherwise the result depends on whether the suite runs as root (as it does
    on a developer box) or as an ordinary user (as it does in CI), and a test that passes in
    one and fails in the other proves nothing.
    """
    return pwd.struct_passwd((name, "x", uid, gid, "", "/nonexistent", "/usr/sbin/nologin"))


STRANGER = pwd_account("tunnelgate", 12345, 12345)


def _as_account(account: pwd.struct_passwd):
    return mock.patch("pwd.getpwnam", return_value=account)


def test_doctor_fails_when_sshd_could_not_read_authorized_keys(tmp_path, settings):
    """sshd opens authorized_keys AS the tunnel account; root-only is a fleet outage.

    Nothing else in the report notices it: the file exists, the path is right and the panel
    keeps serving - every router just gets "Permission denied (publickey)".
    """
    zone = tmp_path / "zone"
    zone.mkdir()
    zone.chmod(0o755)
    keys = zone / "authorized_keys"
    keys.write_text("ssh-ed25519 AAAA test\n")
    keys.chmod(0o600)
    os.chown(keys, os.getuid(), os.getgid())
    s = settings.model_copy(update={"ssh_user": STRANGER.pw_name, "authorized_keys_path": keys})

    with _as_account(STRANGER):
        report = Report()
        _check_authorized_keys_readable(s, report, s.ssh_user)
    # 0600 owned by somebody else: the account sshd drops to cannot read it.
    assert _statuses(report)["authorized_keys"] == FAIL

    # The directory is what blocks it: a world-readable file inside a 0700 directory is
    # unreachable even though every mode bit on the file itself says otherwise.
    keys.chmod(0o644)
    zone.chmod(0o700)
    with _as_account(STRANGER):
        report = Report()
        _check_authorized_keys_readable(s, report, s.ssh_user)
    assert _statuses(report)["authorized_keys"] == FAIL

    # Make both reachable by that account and the same check must pass.
    zone.chmod(0o755)
    with _as_account(STRANGER):
        report = Report()
        _check_authorized_keys_readable(s, report, s.ssh_user)
    assert _statuses(report)["authorized_keys"] == OK


def test_doctor_names_the_chown_when_authorized_keys_is_unreadable(tmp_path, settings):
    """The fix text has to be the command that puts it right, with the SSH account name."""
    zone = tmp_path / "locked"
    zone.mkdir()
    zone.chmod(0o755)
    keys = zone / "authorized_keys"
    keys.write_text("ssh-ed25519 AAAA test\n")
    keys.chmod(0o600)
    os.chown(keys, os.getuid(), os.getgid())
    s = settings.model_copy(update={"ssh_user": STRANGER.pw_name, "authorized_keys_path": keys})

    with _as_account(STRANGER):
        report = Report()
        _check_authorized_keys_readable(s, report, s.ssh_user)
    check = next(c for c in report.checks if c.name == "authorized_keys")
    assert check.status == FAIL
    assert f"chown {s.ssh_user}:{s.ssh_user}" in check.fix
    assert "Permission denied (publickey)" in check.fix


def test_doctor_does_not_treat_a_missing_file_as_a_failure(tmp_path, settings):
    """Before the first router exists there is nothing to read; that is not a fault."""
    s = settings.model_copy(update={"authorized_keys_path": tmp_path / "data" / "authorized_keys"})
    (tmp_path / "data").mkdir(exist_ok=True)
    # Describe the account: on a runner where settings.ssh_user does not exist the check has
    # nothing to judge and stays silent, which would turn this into a KeyError instead of the
    # WARN the behaviour is supposed to produce.
    with _as_account(STRANGER):
        report = Report()
        _check_authorized_keys_readable(s, report, s.ssh_user)
    assert _statuses(report)["authorized_keys"] == WARN


def _statuses(report: Report) -> dict[str, str]:
    return {check.name: check.status for check in report.checks}


@pytest.mark.parametrize("host", ["192.168.88.107", "localhost", "", "bad host", "*."])
def test_a_hostname_that_cannot_resolve_is_named(host: str) -> None:
    assert _hostname_problem(host) != ""


@pytest.mark.parametrize("host", ["panel.example.com", "*.example.com", "a-b.example.co.uk"])
def test_a_usable_hostname_passes(host: str) -> None:
    assert _hostname_problem(host) == ""


def test_an_ip_suffix_fails_the_doctor(settings) -> None:
    settings.subdomain_suffix = "192.168.88.107"
    report = Report()
    _check_launch(settings, report)
    assert _statuses(report)["router hostnames"] == FAIL
    check = next(c for c in report.checks if c.name == "router hostnames")
    # The fix has to be actionable, not just "that is wrong".
    assert "TUNNELGATE_SUBDOMAIN_SUFFIX" in check.fix


def test_a_real_suffix_passes(settings) -> None:
    report = Report()
    _check_launch(settings, report)
    assert _statuses(report)["router hostnames"] == OK


def test_a_domain_wide_cookie_is_warned_about(settings) -> None:
    # It still works, but it is the trade-off the launch hand-off exists to avoid.
    settings.cookie_domain = ".panel.test"
    report = Report()
    _check_launch(settings, report)
    statuses = _statuses(report)
    assert statuses["cookie scope"] == WARN
    assert report.failures == []


def test_missing_config_is_a_warning_not_a_failure(settings) -> None:
    # A fresh install has not rendered anything yet; that is not a broken deployment.
    settings.proxy_driver = "nginx"
    report = Report()
    _check_launch(settings, report)
    assert _statuses(report)["launch config"] == WARN


def _write_rendered(settings, routes: str, snippet: str) -> None:
    routes_path = Path(settings.proxy_routes_path)
    routes_path.parent.mkdir(parents=True, exist_ok=True)
    routes_path.write_text(routes)
    auth_snippet_path(routes_path).write_text(snippet)


def test_config_rendered_before_the_handoff_fails_with_a_fix(settings) -> None:
    header = cookie_header_name(settings.router_cookie_name)
    settings.proxy_driver = "nginx"
    _write_rendered(settings, "server { auth_request /__tg/auth; }", "location = /__tg/auth {}")
    report = Report()
    _check_launch(settings, report)
    check = next(c for c in report.checks if c.name == "launch config")
    assert check.status == FAIL
    assert "/__tg/enter" in check.detail
    assert header in check.detail
    assert "render-proxy" in check.fix


def test_a_half_upgraded_snippet_is_still_caught(settings) -> None:
    # The routes file knows about the hand-off but the gate was never given the cookie:
    # this is the exact state a partial re-render leaves behind, and it still loops.
    settings.proxy_driver = "nginx"
    _write_rendered(settings, "location = /__tg/enter {}", "location = /__tg/auth {}")
    report = Report()
    _check_launch(settings, report)
    assert _statuses(report)["launch config"] == FAIL


def test_current_config_passes(settings) -> None:
    header = cookie_header_name(settings.router_cookie_name)
    settings.proxy_driver = "nginx"
    _write_rendered(settings, "location = /__tg/enter {}", f"proxy_set_header {header} x;")
    report = Report()
    _check_launch(settings, report)
    assert _statuses(report)["launch config"] == OK


def test_a_loopback_panel_url_without_a_public_origin_is_warned_about(settings) -> None:
    # panel_url=loopback is the documented shape behind a TLS terminator, and it is right for
    # proxy_pass - but redirects are written for the BROWSER, which cannot reach 127.0.0.1.
    settings.panel_url = "http://127.0.0.1:8080"
    settings.panel_host = "panel.test"
    settings.public_url = None
    report = Report()
    _check_launch(settings, report)
    check = next(c for c in report.checks if c.name == "public origin")
    assert check.status == WARN
    assert "TUNNELGATE_PUBLIC_URL" in check.fix


def test_an_explicit_public_origin_quietens_the_warning(settings) -> None:
    settings.panel_url = "http://127.0.0.1:8080"
    settings.panel_host = "panel.test"
    settings.public_url = "https://panel.test"
    report = Report()
    _check_launch(settings, report)
    assert "public origin" not in _statuses(report)


def test_a_public_panel_url_needs_no_extra_setting(settings) -> None:
    # A flat install where panel_url already names the public host is correct as written.
    settings.panel_url = "https://panel.test"
    settings.public_url = None
    report = Report()
    _check_launch(settings, report)
    assert "public origin" not in _statuses(report)


def test_caddy_cannot_be_inspected_and_says_so(settings) -> None:
    settings.proxy_driver = "caddy"
    report = Report()
    _check_launch(settings, report)
    assert _statuses(report)["launch config"] == WARN


# --------------------------------------------------------------------- path routing mode
def _path_mode(settings, **kw):
    params = {"route_mode": "path", "gateway_host": "gate.panel.test"}
    params.update(kw)
    for key, value in params.items():
        setattr(settings, key, value)
    return settings


def test_path_mode_renders_a_gateway_and_no_per_router_hosts(settings):
    from app.services.proxy import RouteSpec

    _path_mode(settings)
    settings.proxy_driver = "nginx"
    spec = RouteSpec(router_id="r1", slug="edge-one", bind_address="127.0.0.1", port=20001)
    rendered = render_nginx([spec], settings)
    routes_path = Path(settings.proxy_routes_path)
    routes_path.parent.mkdir(parents=True, exist_ok=True)
    routes_path.write_text(rendered)
    auth_snippet_path(routes_path).write_text(render_nginx_auth_snippet(settings))
    report = Report()
    _check_launch(settings, report)
    statuses = _statuses(report)
    assert statuses["router hostnames"] == OK
    assert statuses["launch config"] == OK
    check = next(c for c in report.checks if c.name == "router hostnames")
    # The useful thing to print is the shape an operator has to hand out.
    assert "gate.panel.test/<slug>/" in check.detail


def test_path_mode_rejects_an_ip_gateway(settings):
    _path_mode(settings, gateway_host="192.168.88.107")
    report = Report()
    _check_launch(settings, report)
    check = next(c for c in report.checks if c.name == "router hostnames")
    assert check.status == FAIL
    assert "TUNNELGATE_GATEWAY_HOST" in check.fix


def test_path_mode_warns_when_the_gateway_is_the_panel_host(settings):
    """Supported layout, but it costs the origin boundary - so warn, do not refuse.

    An operator whose only public name is the panel's own has no way to satisfy a FAIL, and
    a doctor that refuses a layout the renderer supports just pushes them into editing files
    by hand. The warning has to say what it costs and what the layout changes, because the
    include context is the one part that fails silently.
    """
    _path_mode(settings, gateway_host=settings.panel_host)
    report = Report()
    _check_launch(settings, report)
    check = next(c for c in report.checks if c.name == "gateway host")
    assert check.status == WARN
    assert "panel" in check.detail.lower()
    assert "docs/SECURITY.md" in check.fix
    assert "INSIDE the panel server block" in check.fix


def test_path_mode_reports_the_plain_http_separate_layout_as_ok(settings):
    """The shape scripts/quick-install.sh --gateway-host installs, and doctor must agree.

    It is a separate origin (so the merged-layout warning does not apply) reached over a
    plain-HTTP hop (so routes.conf is locations only, included inside the gateway vhost).
    Anything doctor said here other than OK would send an operator to "fix" a correct
    install.
    """
    _path_mode(settings, gateway_host="gate." + settings.panel_host)
    settings.proxy_plain_http = True
    report = Report()
    _check_launch(settings, report)
    check = next(c for c in report.checks if c.name == "gateway host")
    assert check.status == OK
    assert "plain-HTTP hop" in check.detail
    assert "docs/SECURITY.md" not in (check.fix or "")


def test_path_mode_accepts_a_gateway_next_to_the_panel_host(settings):
    _path_mode(settings, gateway_host="gate." + settings.panel_host)
    report = Report()
    _check_launch(settings, report)
    statuses = _statuses(report)
    assert statuses["router hostnames"] == OK
    assert statuses["gateway host"] == OK


def test_path_mode_rejects_a_gateway_without_a_dot(settings):
    _path_mode(settings, gateway_host="gateway")
    report = Report()
    _check_launch(settings, report)
    assert _statuses(report)["router hostnames"] == FAIL


def test_an_unknown_route_mode_is_reported(settings):
    settings.route_mode = "pathh"
    report = Report()
    _check_launch(settings, report)
    assert _statuses(report)["route mode"] == WARN


def test_path_mode_reads_the_auth_location_from_routes_conf(settings):
    """Path mode has no shared snippet: both facts live in the gateway server block."""
    _path_mode(settings)
    settings.proxy_driver = "nginx"
    header = cookie_header_name(settings.router_cookie_name)
    routes_path = Path(settings.proxy_routes_path)
    routes_path.parent.mkdir(parents=True, exist_ok=True)
    routes_path.write_text(
        f"location = /edge-one/__tg/enter {{}}\n"
        f"location = /__tg/auth {{}}\n"
        f"proxy_set_header {header} x;\n"
    )
    auth_snippet_path(routes_path).write_text("")
    report = Report()
    _check_launch(settings, report)
    assert _statuses(report)["launch config"] == OK


def test_path_mode_catches_a_gateway_that_forgets_the_router_cookie(settings):
    _path_mode(settings)
    settings.proxy_driver = "nginx"
    routes_path = Path(settings.proxy_routes_path)
    routes_path.parent.mkdir(parents=True, exist_ok=True)
    routes_path.write_text("location = /edge-one/__tg/enter {}\nlocation = /__tg/auth {}\n")
    auth_snippet_path(routes_path).write_text("")
    report = Report()
    _check_launch(settings, report)
    check = next(c for c in report.checks if c.name == "launch config")
    assert check.status == FAIL
    assert "Tg-Luci" in check.detail or "tg_luci" in check.detail.lower()


# --------------------------------------------------- path checks must not traceback
def test_a_path_that_cannot_be_statted_reads_as_absent(tmp_path, monkeypatch):
    """doctor used to die with PermissionError before printing a single check.

    stat() needs +x on every parent, so a uid mismatch (container 10001 vs a host-owned
    0750 directory, or sudo against the service user's data dir) turned the whole report
    into a stack trace. Absence is the truthful answer there: the writability check
    reports the real problem with a fix line.
    """
    import errno

    real_exists = Path.exists

    def boom(self):
        if self.name == "tg.db":
            raise PermissionError(errno.EACCES, "Permission denied", str(self))
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", boom)
    report = Report()
    _check_storage(_settings_for_storage(tmp_path), report)
    check = next(c for c in report.checks if c.name == "database")
    assert check.status == WARN
    assert "init-db" in check.fix


def _settings_for_storage(tmp_path):
    from app.config import Settings

    return Settings(
        env="test",
        data_dir=str(tmp_path),
        db_url=f"sqlite:///{tmp_path / 'tg.db'}",
        authorized_keys_path=str(tmp_path / "keys" / "authorized_keys"),
    )


# ------------------------------------------------------------- socket inventory (ss)
def test_missing_ss_is_a_failure_that_names_iproute2(monkeypatch):
    """Without ss the panel cannot see a single tunnel, so it must not pass as a warning.

    tunnels.py returns an empty map when ss is absent and the monitor reads that as
    "unobservable", which parks every router at awaiting/offline while /api/v1/health
    still reports ok. A minimal image (python:slim, no iproute2) hits exactly this.
    """
    monkeypatch.setattr("app.cli.shutil.which", lambda name: None)
    report = Report()
    _check_ss(report)
    check = next(c for c in report.checks if c.name == "socket inventory")
    assert check.status == FAIL
    assert "iproute2" in (check.fix or "")


def test_present_ss_passes(monkeypatch):
    monkeypatch.setattr("app.cli.shutil.which", lambda name: "/usr/bin/ss")
    report = Report()
    _check_ss(report)
    check = next(c for c in report.checks if c.name == "socket inventory")
    assert check.status == OK


# ------------------------------------------------------- routes.conf include context
def _nginx_that_validates_ok(tmp_path):
    path = tmp_path / "nginx"
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    return str(path)


def _nginx_that_rejects(tmp_path, message):
    path = tmp_path / "nginx"
    path.write_text("#!/bin/sh\nprintf '%s\\n' \"nginx: [emerg] " + message + '" >&2\nexit 1\n')
    path.chmod(0o755)
    return str(path)


def test_routes_include_passes_when_nginx_accepts_the_config(settings, tmp_path):
    _path_mode(settings)
    Path(settings.proxy_routes_path).parent.mkdir(parents=True, exist_ok=True)
    Path(settings.proxy_routes_path).write_text("location = /x/ { }\n")
    report = Report()
    _check_routes_include(settings, report, _nginx_that_validates_ok(tmp_path))
    check = next(c for c in report.checks if c.name == "routes include")
    assert check.status == OK


def test_routes_include_blames_the_include_context_when_merged(settings, tmp_path):
    """The merged layout's one silent failure: locations included in the http context."""
    _path_mode(settings, gateway_host=settings.panel_host)
    Path(settings.proxy_routes_path).parent.mkdir(parents=True, exist_ok=True)
    Path(settings.proxy_routes_path).write_text("location = /x/ { }\n")
    nginx = _nginx_that_rejects(
        tmp_path, '"location" directive is not allowed here in /etc/nginx/nginx.conf:41'
    )
    report = Report()
    _check_routes_include(settings, report, nginx)
    check = next(c for c in report.checks if c.name == "routes include")
    assert check.status == FAIL
    # The nginx text itself has to survive: it names the file and line that broke.
    assert "not allowed here" in check.detail
    assert "INSIDE the panel" in check.fix


def _nginx_that_parses_then_dies(tmp_path, message):
    """nginx -t on a good config as an unprivileged user: parse ok, then a runtime denial.

    Not hypothetical: this is exactly what doctor does under the tunnelgate account on a
    real host, and the include analysis must not turn it into "your include is wrong".
    """
    path = tmp_path / "nginx"
    path.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok"\n'
        'printf "%s\\n" "nginx: [emerg] ' + message + '" >&2\n'
        "exit 1\n"
    )
    path.chmod(0o755)
    return str(path)


def test_routes_include_does_not_blame_the_include_when_nginx_could_not_run(settings, tmp_path):
    """A permission failure after a successful parse says nothing about the include layout.

    Observed live: doctor run as the service account reported FAIL "routes include ... include
    it INSIDE the panel server block" for a config that was correct, because nginx could not
    open /run/nginx.pid. An operator following that fix moves a working include and never
    learns the actual cause.
    """
    _path_mode(settings, gateway_host=settings.panel_host)
    Path(settings.proxy_routes_path).parent.mkdir(parents=True, exist_ok=True)
    Path(settings.proxy_routes_path).write_text("location = /x/ { }\n")
    nginx = _nginx_that_parses_then_dies(
        tmp_path, 'open() "/run/nginx.pid" failed (13: Permission denied)'
    )
    report = Report()
    _check_routes_include(settings, report, nginx)
    check = next(c for c in report.checks if c.name == "routes include")
    assert check.status == WARN  # not FAIL: the config itself is accepted
    assert "Permission denied" in check.detail
    assert "INSIDE the panel server block" not in check.fix
    assert "root" in check.fix


def test_routes_include_still_fails_when_nginx_rejects_the_config(settings, tmp_path):
    """The new leniency must not swallow a real rejection: an [emerg] with NO "syntax is ok"
    line is a config the parser refused."""
    _path_mode(settings, gateway_host=settings.panel_host)
    Path(settings.proxy_routes_path).parent.mkdir(parents=True, exist_ok=True)
    Path(settings.proxy_routes_path).write_text("location = /x/ { }\n")
    nginx = _nginx_that_rejects(
        tmp_path, '"location" directive is not allowed here in /etc/nginx/nginx.conf:41'
    )
    report = Report()
    _check_routes_include(settings, report, nginx)
    check = next(c for c in report.checks if c.name == "routes include")
    assert check.status == FAIL


def test_routes_include_blames_the_http_context_when_separate(settings, tmp_path):
    _path_mode(settings)  # gateway_host gate.panel.test != panel_host
    Path(settings.proxy_routes_path).parent.mkdir(parents=True, exist_ok=True)
    Path(settings.proxy_routes_path).write_text("server { }\n")
    nginx = _nginx_that_rejects(
        tmp_path, '"server" directive is not allowed here in /etc/nginx/sites-enabled/panel:9'
    )
    report = Report()
    _check_routes_include(settings, report, nginx)
    check = next(c for c in report.checks if c.name == "routes include")
    assert check.status == FAIL
    assert "http" in check.fix.lower()
    assert "not inside a server" in check.fix


def test_routes_include_is_skipped_before_the_first_render(settings, tmp_path):
    """A fresh install has no routes file yet; that is _check_launch's problem, not this one."""
    _path_mode(settings)
    report = Report()
    _check_routes_include(settings, report, _nginx_that_validates_ok(tmp_path))
    assert "routes include" not in _statuses(report)


def test_a_missing_nginx_is_a_warning_because_it_may_run_elsewhere(settings, monkeypatch):
    """The panel image has no nginx by design: docker-compose runs it as its own service.

    deploy/README.md documents 'docker exec ... doctor', so a hard failure here would make
    every containerised deployment look broken. The panel only writes config either way.
    """
    settings.proxy_driver = "nginx"
    settings.proxy_routes_path = str(settings.data_dir / "routes.conf")
    monkeypatch.setattr("app.cli.shutil.which", lambda name: None)
    monkeypatch.setattr("app.cli.os.path.exists", lambda path: False)
    report = Report()
    _check_proxy(settings, report)
    check = next(c for c in report.checks if c.name == "nginx")
    assert check.status == WARN
    assert "container" in check.fix


def test_caddy_in_path_mode_is_refused_by_the_doctor(settings):
    _path_mode(settings)
    settings.proxy_driver = "caddy"
    report = Report()
    _check_proxy(settings, report)
    check = next(c for c in report.checks if c.name == "proxy driver")
    assert check.status == FAIL
    assert "nginx" in check.fix


# ------------------------------------------------------------------ sub_filter probe
def _fake_nginx(tmp_path, args: str):
    path = tmp_path / "nginx"
    path.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"nginx version: nginx/9\" >&2\n"
        f"printf '%s\\n' \"configure arguments: {args}\" >&2\n"
    )
    path.chmod(0o755)
    return str(path)


def test_nginx_without_sub_filter_fails_in_path_mode(tmp_path, settings):
    _path_mode(settings)
    nginx = _fake_nginx(tmp_path, "--prefix=/usr --with-http_ssl_module")
    report = Report()
    _check_sub_filter(nginx, report)
    check = next(c for c in report.checks if c.name == "sub_filter module")
    assert check.status == FAIL
    assert "with-http_sub_module" in check.detail
    assert "nginx" in check.fix


def test_nginx_with_sub_filter_is_ok(tmp_path, settings):
    _path_mode(settings)
    nginx = _fake_nginx(tmp_path, "--prefix=/usr --with-http_sub_module")
    report = Report()
    _check_sub_filter(nginx, report)
    assert _statuses(report)["sub_filter module"] == OK


def test_an_unreadable_module_list_is_a_warning(tmp_path, settings):
    # A wrapper that prints nothing must not be reported as a missing module:
    # a probe failure is not evidence about the deployment.
    _path_mode(settings)
    path = tmp_path / "nginx"
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    report = Report()
    _check_sub_filter(str(path), report)
    assert _statuses(report)["sub_filter module"] == WARN


def test_a_missing_nginx_binary_is_not_a_crash(tmp_path, settings):
    _path_mode(settings)
    assert _nginx_modules(str(tmp_path / "missing")) is None


# ------------------------------------------------------- slug namespace (path mode)
def _add_router(db, *, slug: str, name: str = "R") -> None:
    from app.models import Router

    db.add(Router(id=slug.replace("-", "")[:32].ljust(32, "0"), name=name, slug=slug))


def _slug_check(report):
    return next(c for c in report.checks if c.name == "slug namespace")


@pytest.mark.parametrize("slug", ["api", "assets"])
def test_a_slug_that_would_break_nginx_fails_the_doctor(settings, slug):
    """nginx declares location /api/ and /assets/ in the panel vhost, so a router on those
    paths renders a duplicate location and nginx -t rejects the WHOLE config: the panel can
    no longer publish any route until the collision is gone."""
    from app.cli import _check_slug_namespace
    from app.db import session_scope

    _path_mode(settings, gateway_host="gate." + settings.panel_host)
    with session_scope() as db:
        _add_router(db, slug=slug, name=slug.upper())
    report = Report()
    _check_slug_namespace(settings, report)
    check = _slug_check(report)
    assert check.status == FAIL
    assert slug in check.detail
    assert "nginx" in check.fix or "reject" in check.fix


def test_a_slug_that_shadows_a_panel_page_fails_the_doctor(settings):
    """A router called "login" is worse than a shadow: /login -> 308 /login/ -> 401 -> 302
    /login?router=login, a loop that locks the operator out of the panel itself."""
    from app.cli import _check_slug_namespace
    from app.db import session_scope

    _path_mode(settings, gateway_host="gate." + settings.panel_host)
    with session_scope() as db:
        _add_router(db, slug="login", name="Login")
    report = Report()
    _check_slug_namespace(settings, report)
    check = _slug_check(report)
    assert check.status == FAIL
    assert "login" in check.detail
    assert "re-create" in check.fix or "re-create" in check.fix.lower()


def test_a_clean_namespace_passes(settings):
    from app.cli import _check_slug_namespace
    from app.db import session_scope

    _path_mode(settings, gateway_host="gate." + settings.panel_host)
    with session_scope() as db:
        _add_router(db, slug="lab-router", name="Lab")
    report = Report()
    _check_slug_namespace(settings, report)
    assert _slug_check(report).status == OK


def test_subdomain_mode_never_checks_the_namespace(settings):
    """Subdomain routers are hostnames, not path segments - nothing can collide."""
    from app.cli import _check_slug_namespace

    settings.route_mode = "subdomain"
    report = Report()
    _check_slug_namespace(settings, report)
    assert [c for c in report.checks if c.name == "slug namespace"] == []


# ------------------------------------------------------- agent endpoint (behind a proxy)
def test_a_loopback_agent_endpoint_is_warned_about(settings) -> None:
    """The install command is unrunnable and the panel's own logs say nothing."""
    settings.panel_url = "http://127.0.0.1:8080"
    settings.public_url = None
    report = Report()
    _check_agent_endpoint(settings, report)
    check = next(c for c in report.checks if c.name == "agent endpoint")
    assert check.status == WARN
    assert "127.0.0.1" in check.detail
    assert "TUNNELGATE_PUBLIC_URL" in check.fix


def test_a_public_agent_endpoint_passes(settings) -> None:
    settings.panel_url = "http://127.0.0.1:8080"
    settings.public_url = "https://panel.example.com"
    report = Report()
    _check_agent_endpoint(settings, report)
    check = next(c for c in report.checks if c.name == "agent endpoint")
    assert check.status == OK
    assert "https://panel.example.com" in check.detail
