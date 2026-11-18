"""Tests for the reverse-proxy renderer and manager.

Two things are being protected here. First, the generated nginx include is a config file
built by string interpolation from database values, so the escaping/validation rules get
their own tests. Second, deploy/nginx/router-vhost.conf.template is the human-readable copy
of the same server block, and it silently rots unless a test keeps the two in step.
"""

from __future__ import annotations

import json
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
    route = render_caddy_route(load_routes(db)[0], settings)
    auth_headers = route["handle"][0]["headers"]["request"]
    router_headers = route["handle"][1]["headers"]["request"]
    assert "delete" not in auth_headers
    assert router_headers["delete"] == ["Cookie"]


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
    for placeholder in ("<slug>", "<suffix>", "<router_id>", "<tunnel_port>", "<bind>"):
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


def test_render_caddy_route_matches_the_host_and_hides_the_tunnel(settings):
    spec = RouteSpec(router_id="rid-1", slug="edge-one", port=20001, bind_address="127.0.0.1")
    route = render_caddy_route(spec, settings)

    assert route["@id"] == CADDY_ROUTE_PREFIX + "rid-1"
    assert route["match"] == [{"host": ["edge-one.panel.test"]}]
    handlers = [item["handler"] for item in route["handle"]]
    assert handlers == ["reverse_proxy", "reverse_proxy"]
    auth, upstream = route["handle"]
    auth_uri = auth["rewrite"]["uri"]
    assert auth_uri == "/__tg/auth?router_id=rid-1&uri={http.request.uri}"
    assert upstream["upstreams"] == [{"dial": "127.0.0.1:20001"}]


def test_render_caddy_route_redirects_an_unauthenticated_browser(settings):
    spec = RouteSpec(router_id="rid-1", slug="edge-one", port=20001, bind_address="127.0.0.1")
    auth = render_caddy_route(spec, settings)["handle"][0]
    handlers = [item for entry in auth["handle_response"] for item in entry["routes"]]
    assert any(
        handler["handle"][0].get("status_code") == 302 for handler in handlers if handler["handle"]
    )


def test_render_caddy_route_only_forwards_the_identity_header_on_success(settings):
    spec = RouteSpec(router_id="rid-1", slug="edge-one", port=20001, bind_address="127.0.0.1")
    auth = render_caddy_route(spec, settings)["handle"][0]
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
