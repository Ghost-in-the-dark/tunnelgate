"""Tests for the reverse-proxy renderer and manager.

Two things are being protected here. First, the generated nginx include is a config file
built by string interpolation from database values, so the escaping/validation rules get
their own tests. Second, deploy/nginx/router-vhost.conf.template is the human-readable copy
of the same server block, and it silently rots unless a test keeps the two in step.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

from app.db import session_scope
from app.models import (
    STATUS_OFFLINE,
    STATUS_ONLINE,
    STATUS_PENDING,
    STATUS_REVOKED,
    Router,
)
from app.services import proxy as proxy_module
from app.services.launch import cookie_header_name, launch_url
from app.services.proxy import (
    CADDY_ROUTE_PREFIX,
    ProxyError,
    ProxyManager,
    RouteSpec,
    _needs_write,
    _write_atomic,
    auth_snippet_path,
    load_routes,
    panel_endpoint,
    public_origin,
    render_caddy_route,
    render_nginx,
    render_nginx_auth_snippet,
    run_command,
)

REPO = Path(__file__).resolve().parents[1]
TEMPLATE = REPO / "deploy" / "nginx" / "router-vhost.conf.template"


# --------------------------------------------------------------------------- fixtures
def _make_router(db, settings, **kw) -> Router:
    defaults = {
        "name": "Edge One",
        "slug": "edge-one",
        "status": STATUS_ONLINE,
        "http_port": 80,
        "remote_port": 20001,
        "console_port": 25001,
        "bind_address": "127.0.0.1",
        "ssh_user": "tunnelgate",
    }
    defaults.update(kw)
    item = Router(**defaults)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def _block(text: str, host: str) -> str:
    """The server block whose server_name is <host> - handy for narrowing assertions."""
    marker = f"server_name {host};"
    assert marker in text, f"no vhost for {host} in:\n{text}"
    start = text.index(marker)
    start = text.rfind("server {", 0, start)
    end = text.index("\n}\n", start)
    return text[start:end]


@pytest.fixture()
def edge(db, settings) -> Router:
    return _make_router(db, settings)


# ------------------------------------------------------------------------- load_routes
def test_load_routes_includes_online_and_offline_routers(db, settings, edge):
    offline = _make_router(db, settings, slug="edge-two", status=STATUS_OFFLINE, remote_port=20002)
    routes = load_routes(db)
    assert {route.slug for route in routes} == {edge.slug, offline.slug}
    assert [route.slug for route in routes] == sorted(["edge-one", "edge-two"])


def test_load_routes_skips_pending_revoked_and_portless_routers(db, settings, edge):
    _make_router(db, settings, slug="pending-one", status=STATUS_PENDING, remote_port=20003)
    _make_router(db, settings, slug="revoked-one", status=STATUS_REVOKED, remote_port=20004)
    _make_router(db, settings, slug="no-port", status=STATUS_ONLINE, remote_port=None)
    routes = load_routes(db)
    assert [route.slug for route in routes] == ["edge-one"]


def test_load_routes_falls_back_to_the_default_bind_address(db, settings):
    _make_router(db, settings, slug="blank-bind", status=STATUS_ONLINE, bind_address="")
    routes = load_routes(db)
    assert routes[0].bind_address == settings.bind_address


def test_load_routes_refuses_a_slug_that_could_inject_nginx_syntax(db, settings, edge):
    """A quote or newline in a slug would let a router rewrite the proxy config."""
    hostile = _make_router(
        db,
        settings,
        slug="evil",
        name="evil",
        status=STATUS_ONLINE,
        remote_port=20005,
    )
    hostile.slug = "x; } server { listen 80; server_name pwned;\n"
    db.commit()
    routes = load_routes(db)
    assert [route.slug for route in routes] == ["edge-one"]


# ---------------------------------------------------------------------- nginx renderer
def test_render_nginx_emits_one_server_block_per_route(db, settings, edge):
    _make_router(db, settings, slug="edge-two", remote_port=20002)
    rendered = render_nginx(load_routes(db), settings)
    assert rendered.count("server {") == 2
    assert "server_name edge-one.panel.test;" in rendered
    assert "server_name edge-two.panel.test;" in rendered
    assert rendered.startswith(proxy_module.GENERATED_MARKER)


def test_render_nginx_wires_the_authorization_subrequest(db, settings, edge):
    block = _block(render_nginx(load_routes(db), settings), "edge-one.panel.test")
    assert "auth_request /__tg/auth;" in block
    assert "error_page 401 = @tg_login;" in block
    assert "include " + str(auth_snippet_path(settings.proxy_routes_path)) in block
    assert f"set $tg_router '{edge.id}';" in block
    assert "set $tg_slug 'edge-one';" in block


def test_render_nginx_proxies_the_tunnel_port_with_websocket_upgrade(db, settings, edge):
    block = _block(render_nginx(load_routes(db), settings), "edge-one.panel.test")
    assert f"proxy_pass http://127.0.0.1:{edge.remote_port};" in block
    assert "proxy_http_version 1.1;" in block
    assert "proxy_set_header Upgrade    $http_upgrade;" in block
    assert "proxy_set_header Connection $tg_connection_upgrade;" in block
    # A literal "upgrade" in Connection would break every non-upgraded request.
    assert 'proxy_set_header Connection "upgrade"' not in block
    assert "proxy_buffering         off;" in block


def test_render_nginx_strips_the_panel_cookie_before_the_router(db, settings, edge):
    """The session cookie must never reach a router's LuCI.

    A router is a lower-trust device: whoever owns one - or reads one router's request log -
    would otherwise hold a live panel session for the operator who opened it.
    """
    block = _block(render_nginx(load_routes(db), settings), "edge-one.panel.test")
    assert 'proxy_set_header Cookie "";' in block


def test_render_caddy_route_deletes_the_cookie_before_the_router(db, settings, edge):
    """Same guarantee as the nginx renderer, in Caddy's expanded JSON form.

    handle[0] is the auth subrequest (which must keep the cookie: it is how the panel
    identifies the operator), handle[1] is the router upstream (which must not see it).
    """
    _launch, auth, upstream = _caddy_steps(render_caddy_route(load_routes(db)[0], settings))
    auth_headers = auth["headers"]["request"]
    router_headers = upstream["headers"]["request"]
    assert "delete" not in auth_headers
    assert router_headers["delete"] == ["Cookie"]


def test_render_nginx_serves_the_launch_handoff_outside_the_gate(db, settings, edge):
    """Redeeming a launch ticket cannot itself require a credential for this host.

    "/__tg/enter" must be its own location without auth_request, and it must be proxied to
    the panel - not to the router - because only the panel can mint the Set-Cookie that this
    reply carries back to the router host.
    """
    block = _block(render_nginx(load_routes(db), settings), "edge-one.panel.test")
    assert "location = /__tg/enter {" in block
    enter = block[block.index("location = /__tg/enter {") : block.index("location / {")]
    assert "auth_request /__tg/auth;" not in enter
    assert (
        "proxy_pass http://testserver/__tg/enter?router=$tg_slug&t=$arg_t&next=$arg_next;" in enter
    )
    # It must be declared before the catch-all, and the catch-all keeps its gate.
    assert block.index("/__tg/enter") < block.index("auth_request /__tg/auth;")


def test_render_nginx_keeps_the_body_limit_for_luci_uploads(db, settings, edge):
    block = _block(render_nginx(load_routes(db), settings), "edge-one.panel.test")
    assert "client_max_body_size 64m;" in block


def test_render_nginx_uses_a_tls_certificate_and_modern_protocols(db, settings, edge):
    block = _block(render_nginx(load_routes(db), settings), "edge-one.panel.test")
    assert "listen 443 ssl;" in block
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in block
    assert proxy_module.DEFAULT_TLS_CERT in block
    assert proxy_module.DEFAULT_TLS_KEY in block


def test_render_nginx_declares_its_own_upgrade_map(db, settings, edge):
    """nginx allows one map per target variable: the two include files must not collide."""
    rendered = render_nginx(load_routes(db), settings)
    assert "map $http_upgrade $tg_connection_upgrade {" in rendered
    assert "map $http_upgrade $connection_upgrade {" not in rendered


def test_render_nginx_without_routes_is_a_valid_empty_include(settings):
    rendered = render_nginx([], settings)
    assert "server {" not in rendered
    assert "# No routers currently have an allocated tunnel port." in rendered


def test_render_nginx_uses_the_host_suffix_from_settings(settings):
    settings.subdomain_suffix = "tunnel.example.com"
    spec = RouteSpec(router_id="abc123", slug="edge-one", port=20001, bind_address="127.0.0.1")
    assert "server_name edge-one.tunnel.example.com;" in render_nginx([spec], settings)


def test_render_nginx_rejects_a_broken_panel_url(settings):
    settings.panel_url = "not-a-url"
    spec = RouteSpec(router_id="abc123", slug="edge-one", port=20001, bind_address="127.0.0.1")
    with pytest.raises(ProxyError):
        render_nginx([spec], settings)


# ------------------------------------------------------------------- auth snippet
def test_auth_snippet_builds_the_panel_subrequest(settings):
    snippet = render_nginx_auth_snippet(settings)
    assert "location = /__tg/auth {" in snippet
    assert "internal;" in snippet
    assert (
        "proxy_pass http://testserver/__tg/auth?router_id=$tg_router&uri=$request_uri;" in snippet
    )
    # auth_request is a GET with no body: forwarding one confuses the panel's CSRF check.
    assert "proxy_method GET;" in snippet
    assert "proxy_pass_request_body off;" in snippet
    assert 'proxy_set_header Content-Length "";' in snippet


def test_auth_snippet_redirects_a_human_to_the_panel_login(settings):
    snippet = render_nginx_auth_snippet(settings)
    assert "location @tg_login {" in snippet
    assert "return 302 http://panel.test/login?router=$tg_slug&next=$request_uri;" in snippet


def test_auth_snippet_path_sits_next_to_the_routes_include():
    path = auth_snippet_path("/etc/nginx/tunnelgate/routes.conf")
    assert str(path) == "/etc/nginx/tunnelgate/routes.auth.conf"


# ---------------------------------------------------------------------- helpers
def test_panel_endpoint_splits_the_public_url(settings):
    settings.panel_url = "https://panel.example.com:8443"
    assert panel_endpoint(settings) == ("https", "panel.example.com:8443")


def test_panel_endpoint_brackets_an_ipv6_literal(settings):
    settings.panel_url = "http://[::1]:8080"
    assert panel_endpoint(settings) == ("http", "[::1]:8080")


def test_panel_endpoint_rejects_a_non_http_url(settings):
    settings.panel_url = "ftp://panel.example.com"
    with pytest.raises(ProxyError):
        panel_endpoint(settings)


def test_public_origin_follows_panel_url_on_a_flat_install(settings):
    settings.panel_url = "https://panel.example.com"
    settings.panel_host = "panel.example.com"
    settings.public_url = None
    assert public_origin(settings) == "https://panel.example.com"


def test_public_origin_can_be_stated_explicitly(settings):
    # The documented shape behind a TLS terminator: panel_url stays loopback for proxy_pass,
    # and the browser-facing origin is named separately.
    settings.panel_url = "http://127.0.0.1:8080"
    settings.public_url = "https://panel.example.com"
    assert public_origin(settings) == "https://panel.example.com"


def test_public_origin_keeps_a_non_default_port(settings):
    settings.public_url = "https://panel.example.com:8443"
    assert public_origin(settings) == "https://panel.example.com:8443"


def test_public_origin_never_mixes_a_loopback_port_into_a_public_host(settings):
    # panel_host names a different host from panel_url, so panel_url's port is meaningless
    # for the browser: 8080 on the public name would be wrong.
    settings.panel_url = "http://127.0.0.1:8080"
    settings.panel_host = "panel.example.com"
    settings.public_url = None
    assert public_origin(settings) == "http://panel.example.com"


def test_public_origin_rejects_a_non_http_url(settings):
    settings.public_url = "ftp://panel.example.com"
    with pytest.raises(ProxyError):
        public_origin(settings)


# --------------------------------------------------------------------- template drift
def test_router_vhost_template_still_matches_the_renderer(settings):
    """The reference template in deploy/ must describe the block the code actually emits."""
    assert TEMPLATE.exists(), "deploy/nginx/router-vhost.conf.template is missing"
    template = TEMPLATE.read_text()
    spec = RouteSpec(
        router_id="router-id-abc", slug="edge-one", port=20001, bind_address="127.0.0.1"
    )
    rendered = _block(render_nginx([spec], settings), "edge-one.panel.test")

    # Directives that must appear in both, ignoring the values each one carries.
    for directive in (
        "listen 443 ssl;",
        "http2 on;",
        "ssl_protocols TLSv1.2 TLSv1.3;",
        "ssl_prefer_server_ciphers off;",
        "client_max_body_size 64m;",
        "location = /__tg/enter {",
        "auth_request /__tg/auth;",
        "error_page 401 = @tg_login;",
        "proxy_http_version 1.1;",
        "proxy_set_header Upgrade    $http_upgrade;",
        "proxy_set_header Connection $tg_connection_upgrade;",
        "proxy_read_timeout    300s;",
        "proxy_send_timeout    300s;",
        "proxy_connect_timeout 10s;",
        "proxy_buffering         off;",
        "proxy_request_buffering off;",
    ):
        assert directive in rendered, f"renderer lost {directive!r}"
        assert directive in template, f"{TEMPLATE.name} lost {directive!r}"


def test_router_vhost_template_has_no_unexpanded_leftovers(settings):
    template = TEMPLATE.read_text()
    for placeholder in (
        "<slug>",
        "<suffix>",
        "<router_id>",
        "<tunnel_port>",
        "<bind>",
        "<panel_host>",
    ):
        assert placeholder in template
    # The template must never carry a real hostname or a real certificate path.
    assert "panel.example.com" not in template.replace(
        "/etc/letsencrypt/live/panel.example.com", ""
    )


# --------------------------------------------------------------------------- file IO
def test_write_atomic_replaces_the_file_in_place(tmp_path):
    target = tmp_path / "routes.conf"
    _write_atomic(target, "one\n")
    assert target.read_text() == "one\n"
    _write_atomic(target, "two\n")
    assert target.read_text() == "two\n"
    assert target.stat().st_mode & 0o777 == 0o640


def test_write_atomic_leaves_no_temporary_file_behind(tmp_path):
    target = tmp_path / "routes.conf"
    _write_atomic(target, "x\n")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["routes.conf"]


def test_needs_write_detects_only_real_changes(tmp_path):
    target = tmp_path / "routes.conf"
    assert _needs_write(target, "x\n") is True
    _write_atomic(target, "x\n")
    assert _needs_write(target, "x\n") is False
    assert _needs_write(target, "y\n") is True


def test_run_command_returns_the_exit_code_and_output():
    code, output = __import__("asyncio").run(run_command("printf 'hello'", 5))
    assert code == 0
    assert "hello" in output


def test_run_command_times_out():
    with pytest.raises(ProxyError, match="timed out"):
        __import__("asyncio").run(run_command("sleep 5", 0.2))


# --------------------------------------------------------------------------- manager
def _manager(settings, **kw) -> ProxyManager:
    settings.proxy_driver = kw.pop("driver", "nginx")
    settings.proxy_reload_command = kw.pop("reload", "")
    return ProxyManager(settings)


def test_manager_seeds_the_include_files_before_the_first_router(settings):
    """nginx -t fails on a missing include target, so both files must exist up front."""
    routes_path = Path(settings.proxy_routes_path)
    snippet_path = auth_snippet_path(routes_path)
    import asyncio

    asyncio.run(_manager(settings).startup())

    assert routes_path.exists()
    assert snippet_path.exists()
    assert "GENERATED" in routes_path.read_text()


def test_manager_sync_writes_both_files_and_counts_the_routes(db, settings):
    import asyncio

    _make_router(db, settings, slug="edge-one")
    manager = _manager(settings)
    changed = asyncio.run(manager.sync_routes())

    assert changed is True
    assert manager.info()["routes"] == 1
    assert "server_name edge-one.panel.test;" in Path(settings.proxy_routes_path).read_text()
    assert "/__tg/auth" in auth_snippet_path(settings.proxy_routes_path).read_text()
    assert manager.last_error is None


def test_manager_writes_nothing_when_the_route_set_did_not_change(db, settings):
    import asyncio

    _make_router(db, settings, slug="edge-one")
    manager = _manager(settings)
    assert asyncio.run(manager.sync_routes()) is True
    assert asyncio.run(manager.sync_routes()) is False


def test_manager_drops_the_vhost_of_a_deleted_router(db, settings, edge):
    import asyncio

    manager = _manager(settings)
    asyncio.run(manager.sync_routes())
    assert "edge-one" in Path(settings.proxy_routes_path).read_text()

    with session_scope() as session:
        session.delete(session.get(Router, edge.id))
        session.flush()

    assert asyncio.run(manager.sync_routes()) is True
    assert "edge-one" not in Path(settings.proxy_routes_path).read_text()


def test_manager_runs_the_reload_command_only_when_something_changed(db, settings, tmp_path):
    import asyncio

    stamp = tmp_path / "reloaded"
    manager = _manager(settings, reload=f"printf x >> {stamp}")
    _make_router(db, settings, slug="edge-one")

    asyncio.run(manager.sync_routes())
    assert stamp.read_text() == "x"
    asyncio.run(manager.sync_routes())
    assert stamp.read_text() == "x"


def test_manager_records_a_failing_reload_without_raising(db, settings):
    import asyncio

    manager = _manager(settings, reload="exit 3")
    _make_router(db, settings, slug="edge-one")

    assert asyncio.run(manager.sync_routes()) is False
    info = manager.info()
    assert info["last_error"] is not None
    assert "exit" in info["last_error"]
    assert info["reload_pending"] is True


def test_manager_keeps_the_config_when_the_driver_is_none(db, settings):
    import asyncio

    manager = _manager(settings, driver="none")
    _make_router(db, settings, slug="edge-one")
    assert asyncio.run(manager.sync_routes()) is False
    assert not Path(settings.proxy_routes_path).exists()


def test_manager_reports_an_unknown_driver_as_an_error(settings):
    import asyncio

    manager = _manager(settings, driver="haproxy")
    assert asyncio.run(manager.sync_routes()) is False
    assert "haproxy" in (manager.last_error or "")


def test_manager_uses_the_monitor_alias(db, settings):
    import asyncio

    manager = _manager(settings)
    _make_router(db, settings, slug="edge-one")
    assert asyncio.run(manager.sync(db)) is True


def test_manager_accepts_a_caller_supplied_session(db, settings, edge):
    import asyncio

    manager = _manager(settings)
    assert asyncio.run(manager.sync_routes(db)) is True
    assert manager.info()["routes"] == 1


# --------------------------------------------------------------------------- caddy
def _caddy_transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def _caddy_steps(route) -> tuple[dict, dict, dict]:
    """(launch hand-off, auth subrequest, router upstream) out of a rendered route.

    The route wraps its work in one subroute because the launch hand-off has to run before
    the gate; each step is then a plain reverse_proxy the tests can inspect by name.
    """
    subroute = route["handle"][0]
    assert subroute["handler"] == "subroute"
    launch = subroute["routes"][0]
    steps = subroute["routes"][1]["handle"]
    assert [step["handler"] for step in steps] == ["reverse_proxy", "reverse_proxy"]
    return launch, steps[0], steps[1]


def test_render_caddy_route_matches_the_host_and_hides_the_tunnel(settings):
    spec = RouteSpec(router_id="rid-1", slug="edge-one", port=20001, bind_address="127.0.0.1")
    route = render_caddy_route(spec, settings)

    assert route["@id"] == CADDY_ROUTE_PREFIX + "rid-1"
    assert route["match"] == [{"host": ["edge-one.panel.test"]}]
    _launch, auth, upstream = _caddy_steps(route)
    auth_uri = auth["rewrite"]["uri"]
    assert auth_uri == "/__tg/auth?router_id=rid-1&uri={http.request.uri}"
    assert upstream["upstreams"] == [{"dial": "127.0.0.1:20001"}]


def test_render_caddy_route_serves_the_launch_handoff_before_the_gate(settings):
    """The hand-off cannot sit behind auth_request: redeeming it is what creates the cookie."""
    spec = RouteSpec(router_id="rid-1", slug="edge-one", port=20001, bind_address="127.0.0.1")
    launch, auth, _upstream = _caddy_steps(render_caddy_route(spec, settings))

    assert launch["match"] == [{"path": ["/__tg/enter"]}]
    assert "/__tg/auth" not in json.dumps(launch)
    handler = launch["handle"][0]
    assert handler["handler"] == "reverse_proxy"
    assert handler["rewrite"]["method"] == "GET"
    uri = handler["rewrite"]["uri"]
    assert uri.startswith("/__tg/enter?router=edge-one")
    assert "t={query.t}" in uri
    # The auth subrequest must stay a separate step, or the gate would never run.
    assert auth["rewrite"]["uri"].startswith("/__tg/auth?")


def test_render_caddy_route_redirects_an_unauthenticated_browser(settings):
    spec = RouteSpec(router_id="rid-1", slug="edge-one", port=20001, bind_address="127.0.0.1")
    _launch, auth, _upstream = _caddy_steps(render_caddy_route(spec, settings))
    handlers = [item for entry in auth["handle_response"] for item in entry["routes"]]
    redirects = [handler["handle"][0] for handler in handlers if handler["handle"]]
    location = [entry for entry in redirects if entry.get("status_code") == 302]
    assert location, "a 401 from the gate must send the browser to the login page"
    # ... and the login page must send them back HERE, not to the panel dashboard.
    target = location[0]["headers"]["Location"][0]
    assert "router=edge-one" in target
    assert "next={http.request.uri}" in target


def test_render_caddy_route_only_forwards_the_identity_header_on_success(settings):
    spec = RouteSpec(router_id="rid-1", slug="edge-one", port=20001, bind_address="127.0.0.1")
    _launch, auth, _upstream = _caddy_steps(render_caddy_route(spec, settings))
    success = [entry for entry in auth["handle_response"] if entry["match"] == {"status_code": [2]}]
    assert success, "the 2xx branch that carries X-Tg-User is missing"
    body = json.dumps(success[0])
    assert "X-Tg-User" in body
    assert "http.reverse_proxy.header.X-Tg-User" in body


def _caddy_handler(requests: list[tuple[str, str]], *, server_exists: bool = True):
    routes: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        path = request.url.path
        if path.endswith("/apps/http/servers/srv0") and request.method == "GET":
            if not server_exists:
                return httpx.Response(404, json={"error": "not found"})
            return httpx.Response(200, json={"routes": list(routes)})
        if path.endswith("/servers/srv0") and request.method == "PUT":
            return httpx.Response(200, json={})
        if path.endswith("/routes") and request.method == "POST":
            routes.append(json.loads(request.content))
            return httpx.Response(200, json={})
        if "/id/" in path and request.method == "PUT":
            route_id = path.rsplit("/", 1)[-1]
            for index, route in enumerate(routes):
                if route.get("@id") == route_id:
                    routes[index] = json.loads(request.content)
            return httpx.Response(200, json={})
        if "/id/" in path and request.method == "DELETE":
            route_id = path.rsplit("/", 1)[-1]
            routes[:] = [route for route in routes if route.get("@id") != route_id]
            return httpx.Response(200, json={})
        return httpx.Response(404, json={"error": "unexpected"})

    return handler, routes


def test_caddy_driver_creates_the_server_then_posts_each_route(db, settings):
    import asyncio

    requests: list[tuple[str, str]] = []
    handler, routes = _caddy_handler(requests, server_exists=False)
    settings.proxy_driver = "caddy"
    manager = ProxyManager(settings, caddy_transport=_caddy_transport(handler))
    _make_router(db, settings, slug="edge-one")

    assert asyncio.run(manager.sync_routes()) is True
    assert ("PUT", "/config/apps/http/servers/srv0") in requests
    assert len(routes) == 1
    assert routes[0]["match"] == [{"host": ["edge-one.panel.test"]}]


def test_caddy_driver_is_idempotent(db, settings):
    import asyncio

    requests: list[tuple[str, str]] = []
    handler, routes = _caddy_handler(requests)
    settings.proxy_driver = "caddy"
    manager = ProxyManager(settings, caddy_transport=_caddy_transport(handler))
    _make_router(db, settings, slug="edge-one")

    assert asyncio.run(manager.sync_routes()) is True
    requests.clear()
    assert asyncio.run(manager.sync_routes()) is False
    assert routes and not [method for method, _ in requests if method != "GET"]


def test_caddy_driver_deletes_the_route_of_a_forgotten_router(db, settings, edge):
    import asyncio

    requests: list[tuple[str, str]] = []
    handler, routes = _caddy_handler(requests)
    settings.proxy_driver = "caddy"
    manager = ProxyManager(settings, caddy_transport=_caddy_transport(handler))

    asyncio.run(manager.sync_routes())
    assert len(routes) == 1

    with session_scope() as session:
        session.delete(session.get(Router, edge.id))
        session.flush()

    assert asyncio.run(manager.sync_routes()) is True
    assert routes == []


def test_caddy_driver_never_touches_routes_it_does_not_own(db, settings):
    import asyncio

    requests: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        if request.method == "GET":
            foreign = {"@id": "someone-elses-route", "match": [{"host": ["other.test"]}]}
            return httpx.Response(200, json={"routes": [foreign]})
        return httpx.Response(200, json={})

    settings.proxy_driver = "caddy"
    manager = ProxyManager(settings, caddy_transport=_caddy_transport(handler))

    asyncio.run(manager.sync_routes())
    assert not [path for method, path in requests if method == "DELETE"]


def test_caddy_driver_surfaces_an_unreachable_admin_api(settings):
    import asyncio

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise httpx.ConnectError("connection refused", request=request)

    settings.proxy_driver = "caddy"
    manager = ProxyManager(settings, caddy_transport=_caddy_transport(handler))

    assert asyncio.run(manager.sync_routes()) is False
    assert "caddy" in (manager.last_error or "").lower()


# --------------------------------------------------- shipped deploy artefacts (addendum)
PANEL_CONF = REPO / "deploy" / "nginx" / "tunnelgate.conf"
SETUP_SH = REPO / "scripts" / "setup-server.sh"


def _artifact_block(text: str, host: str) -> str:
    """The server block of a shipped .conf - same helper, but no rendering involved."""
    marker = f"server_name {host};"
    assert marker in text, f"no vhost for {host} in deploy/nginx/tunnelgate.conf"
    start = text.rindex("server {", 0, text.index(marker))
    end = text.index("\n}", text.index(marker))
    return text[start:end]


def test_shipped_nginx_conf_has_the_console_vhost() -> None:
    """The console lives on console.<host_suffix>: one host, not one per router.

    A WebSocket cannot be authorised by auth_request (the 101 response has nowhere to
    carry an injected header), so the router id travels inside the single-use ticket
    instead. That is why the shipped file must expose exactly one console vhost.
    """
    text = PANEL_CONF.read_text()
    block = _artifact_block(text, "console.panel.example.com")

    assert "proxy_pass http://127.0.0.1:8080;" in block
    # The upgrade must actually be forwarded, or LuCI/xterm connects then hangs.
    assert "proxy_http_version 1.1;" in block
    assert "proxy_set_header Upgrade           $http_upgrade;" in block
    assert "proxy_set_header Connection        $connection_upgrade;" in block
    # A quiet shell must outlive nginx's default 60 s read timeout.
    assert "proxy_read_timeout 3600s;" in block
    # Terminal output must never be buffered.
    assert "proxy_buffering         off;" in block
    # The gate subrequest is internal to nginx and must not be publicly reachable.
    assert "location /__tg/ {" in block and "return 404;" in block


def test_shipped_nginx_conf_exposes_the_panel_launch_handoff() -> None:
    """The hand-off starts on the panel host, so this vhost must proxy it."""
    text = PANEL_CONF.read_text()
    block = _artifact_block(text, "panel.example.com")

    assert "location = /__tg/launch {" in block
    launch = block[block.index("location = /__tg/launch {") : block.index("location /__tg/ {")]
    assert "proxy_pass http://127.0.0.1:8080;" in launch
    # It must come BEFORE the blanket /__tg/ 404, or nginx never reaches it.
    assert block.index("location = /__tg/launch {") < block.index("location /__tg/ {")
    # The gate and the router-side redemption stay unreachable from the panel host.
    assert "location /__tg/ {" in block and "return 404;" in block


def test_shipped_nginx_conf_declares_the_upgrade_map_once() -> None:
    """nginx allows one map per target variable; the generated include declares its own."""
    text = PANEL_CONF.read_text()
    assert text.count("map $http_upgrade $connection_upgrade {") == 1
    # The renderer uses a DIFFERENT target variable so the two files can coexist.
    # Comments mention it (and must be allowed to: the warning matters), so only
    # directive lines are inspected.
    directives = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    assert not [line for line in directives if "$tg_connection_upgrade" in line]
    assert "include /etc/nginx/tunnelgate/routes.conf;" in text


def test_shipped_nginx_conf_agrees_with_the_settings_defaults(settings) -> None:
    """The console hostname baked into the file must be the one the app prints."""
    text = PANEL_CONF.read_text()
    # The shipped file ships with panel.example.com; host_suffix follows the same rule.
    expected = "console.panel.example.com"
    assert f"server_name {expected};" in text
    assert f"connect-src 'self' wss://{expected};" in text
    # And the rule the app implements: console.<host_suffix>, never console.<panel_host>
    # when a distinct subdomain_suffix is configured.
    settings.panel_host = "panel.example.com"
    settings.subdomain_suffix = "routers.example.com"
    assert settings.host_suffix == "routers.example.com"


def test_setup_script_never_opens_the_console_or_tunnel_pools() -> None:
    """Both pools are 127.0.0.1 sshd listeners; publishing them bypasses the panel."""
    text = SETUP_SH.read_text()
    opened = [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith("ufw allow") and not line.strip().startswith("#")
    ]
    assert opened, "the setup script must configure a firewall"
    for line in opened:
        for forbidden in ("20000", "25000", "25001", "30000", "20000:25000", "25001:30000"):
            assert forbidden not in line, f"{line!r} opens a loopback-only range"
    # It must say so out loud, so an operator does not 'helpfully' open them later.
    assert "25001-30000" in text
    assert "127.0.0.1" in text


def test_setup_script_makes_the_routes_dir_writable_for_the_panel() -> None:
    """The panel writes with temp+rename, so it needs CREATE on the directory.

    A root-owned 0755 directory makes every monitor cycle fail with
    `PermissionError: [Errno 13] ... .routes.conf.<rand>.tmp`, which is silent
    apart from a log line - nginx keeps serving a stale route set.
    """
    text = SETUP_SH.read_text()
    line = next(
        candidate
        for candidate in text.splitlines()
        if candidate.startswith("install -d") and "ROUTES_DIR" in candidate
    )
    assert "-o tunnelgate" in line, line
    assert "-g tunnelgate" in line, line
    assert "-m 0750" in line, line


def test_setup_script_installs_the_shipped_units_and_dropins() -> None:
    """The script is the supported install path; it must not invent its own config."""
    text = SETUP_SH.read_text()
    for path in (
        "deploy/sshd/tunnelgate.conf",
        "deploy/systemd/tunnelgate.service",
        "deploy/nginx/tunnelgate.conf",
    ):
        assert f'"$REPO/{path}"' in text, f"the script never installs {path}"
    # An invalid sshd config must abort before the reload, or the operator is locked out.
    assert "sshd -t" in text
    assert "nginx -t" in text


# --------------------------------------------------------------- path mode (one gateway host)
def _path_settings(settings, **kw):
    """Settings in path mode, gateway on its OWN name, with the fixture's routes path."""
    params = {
        "route_mode": "path",
        "gateway_host": "gate.panel.test",
        "proxy_driver": "nginx",
    }
    params.update(kw)
    for key, value in params.items():
        setattr(settings, key, value)
    return settings


def _merged_path_settings(settings, **kw):
    """Path mode with the gateway collapsed onto the panel's own host (merged layout)."""
    _path_settings(settings, **kw)
    settings.gateway_host = settings.panel_host
    return settings


def test_render_nginx_path_emits_one_server_block_for_the_gateway(db, settings, edge):
    _path_settings(settings)
    rendered = render_nginx(load_routes(db), settings)
    assert rendered.count("server {") == 1
    assert "server_name gate.panel.test;" in rendered
    # No per-router vhost may survive: that is the whole point of the mode.
    assert "edge-one.panel.test" not in rendered
    assert "map $http_upgrade $tg_connection_upgrade {" in rendered


def test_render_nginx_path_scopes_each_router_to_its_own_prefix(db, settings, edge):
    _path_settings(settings)
    rendered = render_nginx(load_routes(db), settings)
    assert "location /edge-one/ {" in rendered
    assert f"proxy_pass http://127.0.0.1:{edge.remote_port}/;" in rendered
    assert "auth_request /__tg/auth;" in rendered
    assert "error_page 401 = @tg_login;" in rendered
    assert f"set $tg_router '{edge.id}';" in rendered
    assert "set $tg_slug 'edge-one';" in rendered


def test_render_nginx_path_rewrites_root_absolute_urls(db, settings, edge):
    """LuCI emits /luci-static/... and /cgi-bin/luci/... - under a prefix those 404."""
    _path_settings(settings)
    block = render_nginx(load_routes(db), settings)
    assert 'proxy_set_header Accept-Encoding "";' in block
    assert "sub_filter_once off;" in block
    assert """sub_filter 'href="/' 'href="/edge-one/';""" in block
    assert """sub_filter 'src="/'  'src="/edge-one/';""" in block
    assert """sub_filter 'action="/' 'action="/edge-one/';""" in block
    # A redirect out of LuCI must come back inside the prefix too: the captured group
    # already starts with "/", so the replacement is /edge-one + /cgi-bin/luci.
    assert "proxy_redirect ~^(/[^/].*)$ /edge-one$1;" in block


def test_render_nginx_path_rewrites_luci_own_url_builder(db, settings, edge):
    """The rules that decide whether path mode works are the ones LuCI's env needs.

    Real LuCI builds its page environment as JSON with every slash escaped, so the page
    carries a backslash before each slash inside the value. luci.js then derives EVERY url
    it emits - menu links, the view and class loader, rpc and ubus endpoints - from those
    values. Rewriting only href/src/action therefore leaves the application generating
    root-absolute urls that resolve to the gateway root, so the menus 404 and the loader asks
    for /luci-static/resources/<name>.js. These assertions pin the four rules that fix it.
    """
    _path_settings(settings)
    block = render_nginx(load_routes(db), settings)

    # nginx unescapes quoted strings, so the doubled backslash in the file is what the page
    # itself has once. Built through chr() to keep this file free of literal backslashes.
    esc = chr(92) * 2 + "/"
    dq = chr(34)
    prefix = "edge-one"
    for key in ("scriptname", "resource", "media", "ubuspath"):
        assert "        sub_filter '" + dq + key + dq + ":" + dq + esc + "'" in block
        assert "'" + dq + key + dq + ":" + dq + esc + prefix + esc + "'" in block

    # The rule must not pin the router-specific tail either: the same template has to work
    # for whatever path the router answers under.
    assert "cgi-bin" not in block.split("_luci_env_rules")[0].split("router LuCI")[0]

    # A byte-level check on the rendered text: the doubled backslash really is there, so the
    # config nginx reads and the page LuCI serves agree on what to search for.
    assert chr(92) * 2 + "/" + prefix in block


def test_render_nginx_path_scopes_the_router_cookie_to_the_prefix(db, settings, edge):
    """Every router shares the host, so an unscoped cookie would reach its neighbours."""
    _path_settings(settings)
    block = render_nginx(load_routes(db), settings)
    assert "proxy_cookie_path / /edge-one/;" in block


def test_render_nginx_path_keeps_the_enter_location_outside_the_gate(db, settings, edge):
    _path_settings(settings)
    block = render_nginx(load_routes(db), settings)
    assert "location = /edge-one/__tg/enter {" in block
    enter = block[block.index("location = /edge-one/__tg/enter {") :]
    enter = enter[: enter.index("location /edge-one/ {")]
    # The comment above says "No auth_request here"; the directive must not be there either.
    directives = [line for line in enter.splitlines() if not line.strip().startswith("#")]
    assert all("auth_request" not in line for line in directives)
    assert "/__tg/enter?router=$tg_slug&t=$arg_t&next=$arg_next;" in enter


def test_render_nginx_path_answers_a_bare_prefix_with_a_redirect(db, settings, edge):
    _path_settings(settings)
    block = render_nginx(load_routes(db), settings)
    assert "location = /edge-one {" in block
    assert "return 308 /edge-one/;" in block


def test_render_nginx_path_keeps_the_root_closed(db, settings, edge):
    """The gateway root belongs to no router; the panel is on another host."""
    _path_settings(settings)
    block = render_nginx(load_routes(db), settings)
    assert "location / {" in block
    assert "return 404;" in block


# ---------------------------------------------- path mode, merged onto the panel host
def _directives(block: str) -> list[str]:
    """The lines that are config, not commentary.

    Merged mode's header explains the layout in prose - including an example server{} -
    so counting "server {" over the raw text measures the comment, not the config.
    """
    return [line for line in block.splitlines() if not line.strip().startswith("#")]


def test_merged_layout_renders_locations_only(db, settings, edge):
    """A second server block for the panel's name would be served first and 404 the panel.

    nginx takes the FIRST server block matching a name, and an included one is first, so a
    full gateway block would claim the host: every panel page becomes 404 while nginx -t
    keeps passing. The merged renderer therefore emits no server{} and no map at all.
    """
    _merged_path_settings(settings)
    block = render_nginx(load_routes(db), settings)
    config = "\n".join(_directives(block))

    assert "server {" not in config
    assert "server_name" not in config
    # map is illegal inside a server block, so it cannot live in an included file either.
    assert "map $http_upgrade" not in config
    # ... but the routers are all there, as locations.
    assert "location /edge-one/ {" in block
    assert "location = /__tg/auth {" in block


def test_merged_layout_tells_the_operator_where_to_include_it(db, settings, edge):
    """The include context is the one part of this layout that fails silently."""
    _merged_path_settings(settings)
    block = render_nginx(load_routes(db), settings)
    assert "LOCATIONS ONLY" in block
    assert "INSIDE the panel server block" in block
    assert "include " + str(settings.proxy_routes_path) + ";" in block


def test_merged_layout_reuses_the_connection_upgrade_map_of_the_panel_vhost(db, settings, edge):
    """nginx allows one map per target variable, and the panel vhost already owns it."""
    _merged_path_settings(settings)
    block = render_nginx(load_routes(db), settings)
    assert "proxy_set_header Connection $connection_upgrade;" in block
    assert "$tg_connection_upgrade" not in block


def test_merged_layout_keeps_the_router_cookie_scoping(db, settings, edge):
    """Same host, so scoping matters MORE here: the panel cookie lives on this origin too."""
    _merged_path_settings(settings)
    block = render_nginx(load_routes(db), settings)
    assert "proxy_cookie_path / /edge-one/;" in block
    assert 'proxy_set_header Cookie "";' in block


def test_merged_layout_renders_an_empty_file_without_routes(db, settings):
    _merged_path_settings(settings)
    rendered = render_nginx([], settings)
    config = "\n".join(_directives(rendered))
    assert "No routers currently have an allocated tunnel port." in rendered
    assert "location / {" not in config
    assert "server {" not in config


def test_merged_layout_indents_locations_for_a_server_block(db, settings, edge):
    """These lines land inside someone else's server block; 4 spaces keeps it readable."""
    _merged_path_settings(settings)
    block = render_nginx(load_routes(db), settings)
    lines = _directives(block)
    auth = next(line for line in lines if line.strip().startswith("location = /__tg/auth"))
    assert auth == "    location = /__tg/auth {"
    router = next(line for line in lines if line.strip().startswith("location /edge-one/ {"))
    assert router == "    location /edge-one/ {"


def test_a_gateway_that_only_differs_by_case_is_still_merged(settings):
    """Host names are case-insensitive; TCPGATEWAY_HOST == panel.example.COM must merge."""
    _path_settings(settings, gateway_host=settings.panel_host.upper())
    assert settings.gateway_merged is True


def test_merged_is_false_outside_path_mode(settings):
    settings.route_mode = "subdomain"
    settings.gateway_host = settings.panel_host
    assert settings.gateway_merged is False


def test_render_nginx_path_forwards_exactly_one_cookie_to_the_gate(db, settings, edge):
    _path_settings(settings)
    header = cookie_header_name(settings.router_cookie_name)
    block = render_nginx(load_routes(db), settings)
    assert f"proxy_set_header {header} $cookie_{settings.router_cookie_name};" in block
    # The router upstream must never see a browser cookie: the gate already authorised it.
    assert 'proxy_set_header Cookie "";' in block


def test_render_nginx_path_renders_an_empty_file_without_routes(db, settings):
    """No routers is a normal state on a fresh install; the gateway still has to be valid."""
    _path_settings(settings)
    rendered = render_nginx([], settings)
    assert "No routers currently have an allocated tunnel port." in rendered
    assert "location / {" in rendered
    assert "/__tg/enter" not in rendered


def test_render_nginx_auth_snippet_explains_itself_in_path_mode(settings):
    _path_settings(settings)
    snippet = render_nginx_auth_snippet(settings)
    assert proxy_module.GENERATED_MARKER in snippet
    assert "/__tg/auth" in snippet
    assert "routes.conf" in snippet


def test_caddy_refuses_path_mode_instead_of_half_implementing_it(db, settings, edge):
    _path_settings(settings, proxy_driver="caddy")
    with pytest.raises(ProxyError) as excinfo:
        render_caddy_route(load_routes(db)[0], settings)
    message = str(excinfo.value)
    assert "nginx" in message
    assert "path" in message


# ---------------------------------------------- real nginx: what a fresh install parses
# The generated file is only useful if nginx accepts it BEFORE the first router exists.
# These tests run a real nginx binary when the host has one; the string tests elsewhere
# cannot catch a parse failure like 'unknown "tg_router" variable'.
NGINX = shutil.which("nginx") or ("/usr/sbin/nginx" if Path("/usr/sbin/nginx").exists() else None)
requires_nginx = pytest.mark.skipif(NGINX is None, reason="needs a real nginx binary")


def _self_signed_cert(directory: Path) -> tuple[Path, Path]:
    """A throwaway certificate, so a TLS server block can be parsed offline."""
    directory.mkdir(parents=True, exist_ok=True)
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=panel.test",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


def _nginx_accepts(
    tmp_path: Path,
    include_text: str,
    *,
    inside_server: bool,
    cert: Path | None = None,
    key: Path | None = None,
) -> tuple[int, str]:
    """Run 'nginx -t' over a config that pulls include_text in from the layout's context."""
    prefix = tmp_path / "prefix"
    (prefix / "logs").mkdir(parents=True, exist_ok=True)
    included = prefix / "routes.conf"
    included.write_text(include_text)
    if inside_server:
        # Merged layout: locations only, included inside the panel server block, which is
        # the operator's block in production - this driver stands in for it.
        if cert is None or key is None:
            cert, key = _self_signed_cert(prefix / "tls")
        body = (
            "events {}\n"
            "http {\n"
            "    map $http_upgrade $connection_upgrade { default upgrade; '' close; }\n"
            "    server {\n"
            "        listen 127.0.0.1:8443 ssl;\n"
            f"        ssl_certificate {cert};\n"
            f"        ssl_certificate_key {key};\n"
            "        server_name panel.test;\n"
            f"        include {included};\n"
            '        location / { return 200 "panel"; }\n'
            "    }\n"
            "}\n"
        )
    else:
        # Separate layout: the file declares its own server{} block.
        body = f"events {{}}\nhttp {{\n    include {included};\n}}\n"
    conf = prefix / "nginx.conf"
    conf.write_text(body)
    proc = subprocess.run(
        [NGINX, "-t", "-c", str(conf), "-p", str(prefix)], capture_output=True, text=True
    )
    return proc.returncode, proc.stdout + proc.stderr


def _tls_for_render(tmp_path: Path, monkeypatch) -> tuple[Path, Path]:
    """Point the renderer at a throwaway certificate.

    The separate-layout render hardcodes ssl_certificate, and Settings rejects unknown
    attribute assignment (pydantic), so the override has to come from the environment that
    _tls_cert_path() / _tls_key_path() consult.
    """
    cert, key = _self_signed_cert(tmp_path / "tls")
    monkeypatch.setenv("TUNNELGATE_TLS_CERT", str(cert))
    monkeypatch.setenv("TUNNELGATE_TLS_KEY", str(key))
    return cert, key


@pytest.mark.parametrize("merged", [False, True], ids=["separate", "merged"])
@requires_nginx
def test_a_zero_router_path_mode_config_is_accepted_by_nginx(
    tmp_path, settings, merged, monkeypatch
):
    """A fresh install has no routers yet, and nginx must still load its gateway.

    The first version of this renderer emitted the /__tg/auth and @tg_login locations and
    nothing else, and both USE $tg_router / $tg_slug while only the (absent) per-router
    locations declared them. nginx therefore refused the whole config with
    'unknown "tg_router" variable' - and because the installer validates before reloading,
    the panel could not be brought up at all until an operator added a router by hand.
    """
    _path_settings(settings)
    if merged:
        _merged_path_settings(settings)
    cert, key = _tls_for_render(tmp_path, monkeypatch)
    rendered = render_nginx([], settings)
    assert "/__tg/enter" not in rendered, "this really is the empty fleet"
    code, output = _nginx_accepts(tmp_path, rendered, inside_server=merged, cert=cert, key=key)
    assert code == 0, output


@requires_nginx
def test_a_one_router_path_mode_config_is_accepted_by_nginx(
    tmp_path, settings, edge, db, monkeypatch
):
    """The populated case keeps parsing, so the fix did not merely move the failure."""
    _path_settings(settings)
    cert, key = _tls_for_render(tmp_path, monkeypatch)
    rendered = render_nginx(load_routes(db), settings)
    code, output = _nginx_accepts(tmp_path, rendered, inside_server=False, cert=cert, key=key)
    assert code == 0, output


def test_path_mode_declares_the_gate_variables_for_an_empty_fleet(settings):
    """The declaration must be a location, not a server-level set.

    A 'set' directly in the server block silences the parser too, but nginx re-evaluates it
    when the 401 is internally redirected to @tg_login, so the login bounce loses the slug
    ('/login?router=&next=...') and the hand-off to the router breaks. A 'map' cannot be
    used either: it is illegal inside a server block, and this file lives inside one.
    """
    _path_settings(settings)
    lines = _directives(render_nginx([], settings))
    declared = [
        line.strip() for line in lines if line.strip() in {"set $tg_router '';", "set $tg_slug '';"}
    ]
    assert declared == ["set $tg_router '';", "set $tg_slug '';"], "exactly one declaration each"
    marker = next(i for i, line in enumerate(lines) if "location = /__tg/vars {" in line)
    assert lines[marker + 1].strip() == "internal;"
    auth = next(i for i, line in enumerate(lines) if "location = /__tg/auth {" in line)
    assert marker < auth, "the declaration has to precede the locations that use it"
    for offset, line in enumerate(lines):
        if line.strip() in {"set $tg_router '';", "set $tg_slug '';"}:
            assert marker < offset < auth, line


# ------------------------------------------- the scheme a published URL must name
def test_public_scheme_stays_https_without_an_explicit_origin(settings):
    """A panel behind a TLS terminator that forgot PUBLIC_URL must not downgrade itself."""
    settings.public_url = None
    settings.panel_url = "http://127.0.0.1:8080"
    assert proxy_module.public_scheme(settings) == "https"


def test_public_scheme_follows_an_http_public_origin(settings):
    settings.public_url = "http://panel.example.com"
    assert proxy_module.public_scheme(settings) == "http"


def test_router_url_uses_the_public_scheme(settings):
    """An install that only answers http must not advertise https links.

    quick-install.sh publishes the panel on plain HTTP and leaves TLS to the operator's own
    proxy; with the scheme hardcoded every "Open LuCI" click and every provisioned
    launch_url named https://<host>/<slug>/ and could not connect.
    """
    settings.route_mode = "path"
    settings.gateway_host = "panel.example.com"
    settings.panel_host = "panel.example.com"
    settings.public_url = "http://panel.example.com"
    assert proxy_module.router_url(settings, "edge-one") == "http://panel.example.com/edge-one/"
    assert launch_url(settings, "edge-one") == "http://panel.example.com/edge-one/__tg/enter"


def test_subdomain_router_url_also_follows_the_public_scheme(settings):
    settings.public_url = "http://routers.example.com"
    settings.subdomain_suffix = "routers.example.com"
    assert proxy_module.router_url(settings, "edge-one") == "http://edge-one.routers.example.com"


def test_a_merged_gateway_keeps_the_public_port(settings):
    """The merged layout shares the panel origin, so the port browsers use is also the router's."""
    settings.route_mode = "path"
    settings.panel_host = "panel.example.com"
    settings.gateway_host = "panel.example.com"
    settings.panel_url = "http://127.0.0.1:8080"
    settings.public_url = "http://panel.example.com:8095"
    assert (
        proxy_module.router_url(settings, "edge-one") == "http://panel.example.com:8095/edge-one/"
    )


def test_a_separate_gateway_never_borrows_the_panel_port(settings):
    """A gateway on its own name is not on the panel's port; nothing names one, so use the default."""
    settings.route_mode = "path"
    settings.panel_host = "panel.example.com"
    settings.gateway_host = "gate.example.com"
    settings.public_url = "https://panel.example.com:8443"
    assert proxy_module.router_url(settings, "edge-one") == "https://gate.example.com/edge-one/"


def test_the_settings_copy_of_router_url_agrees_with_the_renderer(settings):
    """Two implementations used to exist and they drifted; there is now one decision."""
    settings.route_mode = "path"
    settings.panel_host = "panel.example.com"
    settings.gateway_host = "panel.example.com"
    settings.public_url = "http://panel.example.com:8095"
    assert settings.router_url("edge-one") == proxy_module.router_url(settings, "edge-one")
