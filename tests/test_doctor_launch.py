"""`doctor` must explain a deployment that would loop, not just refuse to start.

The launch hand-off only works when router hostnames exist and the rendered proxy config
carries /__tg/enter plus the router-cookie header on the auth subrequest. Both are invisible
from the UI - a stale config just bounces the browser through /login forever - so the only
place an operator can be told about it is here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.cli import (
    FAIL,
    OK,
    WARN,
    Report,
    _check_launch,
    _check_proxy,
    _check_routes_include,
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
