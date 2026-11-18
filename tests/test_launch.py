"""The launch hand-off: panel ticket -> router-host cookie -> gate.

This is the module that replaces "widen the session cookie to the whole domain". The tests
below pin the properties that make that trade safe: the ticket is single use, bound to one
router, and the cookie the router host receives authorises that router only.
"""

from __future__ import annotations

import time

import pytest

from app.db import session_scope
from app.models import AuditLog, Router, User
from app.security import hash_password
from app.services.launch import (
    TICKETS,
    LaunchTicketStore,
    cookie_header_name,
    host_router_slug,
    issue_router_cookie,
    launch_url,
    panel_login_url,
    router_cookie_names,
    safe_target,
    ticket_from_uri,
    verify_router_cookie,
)


def _user(username: str = "launch-user", role: str = "operator") -> int:
    with session_scope() as s:
        u = User(username=username, role=role, password_hash=hash_password("user-t3st-pass"))
        s.add(u)
        s.flush()
        return u.id


def _login(client, username: str = "launch-user", password: str = "user-t3st-pass") -> str:
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["csrf_token"]


# --------------------------------------------------------------------------- pure helpers
@pytest.mark.parametrize(
    "raw, expected",
    [
        (None, "/"),
        ("", "/"),
        ("/cgi-bin/luci", "/cgi-bin/luci"),
        ("/cgi-bin/luci?x=1", "/cgi-bin/luci?x=1"),
        # Everything below would turn the launch endpoint into an open redirect.
        ("https://evil.example/", "/"),
        ("//evil.example/", "/"),
        ("/\\evil.example/", "/"),
        ("javascript:alert(1)", "/"),
        ("cgi-bin/luci", "/"),
    ],
)
def test_safe_target_only_accepts_a_path_on_this_host(raw, expected):
    assert safe_target(raw) == expected


def test_safe_target_caps_the_length():
    assert len(safe_target("/" + "a" * 5000)) == 512


def test_launch_url_points_at_the_router_host_enter_endpoint(settings):
    assert launch_url(settings, "edge-one") == "https://edge-one.panel.test/__tg/enter"
    assert launch_url(settings, "edge-one", "abc") == "https://edge-one.panel.test/__tg/enter?t=abc"


def test_panel_login_url_carries_the_router_and_the_target(settings):
    url = panel_login_url(settings, "edge-one", "/cgi-bin/luci")
    assert url == "http://panel.test/login?next=%2Fcgi-bin%2Fluci&router=edge-one"


def test_host_router_slug_reads_the_slug_out_of_a_router_host(settings):
    assert host_router_slug(settings, "edge-one.panel.test") == "edge-one"
    assert host_router_slug(settings, "edge-one.panel.test:443") == "edge-one"
    assert host_router_slug(settings, "EDGE-ONE.PANEL.TEST") == "edge-one"
    # Not ours: the panel itself, an unrelated domain, a bare suffix.
    assert host_router_slug(settings, "panel.test") is None
    assert host_router_slug(settings, "edge-one.example.com") is None
    assert host_router_slug(settings, None) is None


def test_ticket_from_uri_reads_the_proxy_handoff(settings):
    assert ticket_from_uri("/__tg/enter?router=edge-one&t=abc123") == "abc123"
    assert ticket_from_uri("/__tg/enter?router=edge-one") is None
    assert ticket_from_uri(None) is None


def test_cookie_header_name_is_derived_from_the_cookie_name():
    assert cookie_header_name("tg_luci") == "X-Tg-Luci-Cookie"
    assert router_cookie_names.__name__ == "router_cookie_names"


# --------------------------------------------------------------------------- ticket store
def test_a_ticket_is_single_use():
    store = LaunchTicketStore(ttl=60)
    ticket = store.issue("rid", 7, "/cgi-bin/luci")
    record = store.consume(ticket)
    assert record is not None
    assert (record.router_id, record.user_id, record.target) == ("rid", 7, "/cgi-bin/luci")
    assert store.consume(ticket) is None, "a redeemed ticket must never work twice"


def test_a_ticket_expires():
    store = LaunchTicketStore(ttl=0.05)
    ticket = store.issue("rid", 7)
    time.sleep(0.08)
    assert store.consume(ticket) is None
    assert len(store) == 0


def test_an_unknown_ticket_is_not_a_crash():
    store = LaunchTicketStore()
    assert store.consume(None) is None
    assert store.consume("nope") is None


# --------------------------------------------------------------------------- router cookie
def test_a_router_cookie_round_trips(settings):
    value, max_age = issue_router_cookie(settings, "rid-1", 7)
    assert max_age == settings.router_session_ttl_minutes * 60
    assert verify_router_cookie(settings, "rid-1", value) == 7


def test_a_router_cookie_does_not_transfer_to_another_router(settings):
    value, _ = issue_router_cookie(settings, "rid-1", 7)
    assert verify_router_cookie(settings, "rid-2", value) is None


def test_a_router_cookie_is_signed_with_the_panel_secret(settings, tmp_path):
    """A router that edits its own cookie gains nothing: the signature is not its to make."""
    value, _ = issue_router_cookie(settings, "rid-1", 7)
    router_id, user_id, expiry, _signature = value.split(".")
    forged = f"{router_id}.{user_id}.{expiry}." + "0" * 64
    assert verify_router_cookie(settings, "rid-1", forged) is None


def test_a_router_cookie_for_a_different_secret_is_rejected(settings):
    value, _ = issue_router_cookie(settings, "rid-1", 7)
    other = settings.model_copy(update={"secret_key": "a-completely-different-secret"})
    assert verify_router_cookie(other, "rid-1", value) is None


def test_an_expired_router_cookie_is_rejected(settings):
    from app.services.launch import _cookie_signature

    expiry = int(time.time()) - 5
    signature = _cookie_signature(settings, "rid-1", 7, expiry)
    assert verify_router_cookie(settings, "rid-1", f"rid-1.7.{expiry}.{signature}") is None


# --------------------------------------------------------------------------- /__tg/launch
def test_launch_requires_a_session(client, api):
    created = api.create_router("Launch Anonymous")
    client.cookies.clear()
    r = client.get("/__tg/launch", params={"router": created["slug"]})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"


def test_launch_sends_a_signed_out_browser_to_the_login_form(client, api):
    """A fresh browser clicking "Open LuCI" must see the login form, not a JSON 401.

    The redirect carries the router and the wanted path, so the login screen can resume the
    hand-off instead of dropping the operator on the dashboard.
    """
    created = api.create_router("Launch Browser")
    client.cookies.clear()
    r = client.get(
        "/__tg/launch",
        params={"router": created["slug"], "next": "/cgi-bin/luci"},
        headers={"accept": "text/html,application/xhtml+xml"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["cache-control"] == "no-store"
    location = r.headers["location"]
    assert "/login?" in location
    assert f"router={created['slug']}" in location
    assert "next=%2Fcgi-bin%2Fluci" in location


def test_launch_keeps_the_json_401_for_api_clients(client, api):
    created = api.create_router("Launch Api")
    client.cookies.clear()
    r = client.get(
        "/__tg/launch",
        params={"router": created["slug"]},
        headers={"accept": "application/json"},
        follow_redirects=False,
    )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"


def test_launch_mints_a_ticket_and_redirects_to_the_router_host(client, api, settings):
    created = api.create_router("Launch Mint")
    _user()
    _login(client)

    r = client.get(
        "/__tg/launch",
        params={"router": created["slug"], "next": "/cgi-bin/luci"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["cache-control"] == "no-store"
    location = r.headers["location"]
    assert location.startswith(f"https://{created['slug']}.panel.test/__tg/enter?t=")

    ticket = location.split("t=", 1)[1]
    record = TICKETS.consume(ticket)
    assert record is not None
    assert record.router_id == created["id"]
    assert record.target == "/cgi-bin/luci"


def test_launch_audits_the_handoff(client, api):
    created = api.create_router("Launch Audit")
    _user("launch-auditor")
    _login(client, "launch-auditor")

    client.get(
        "/__tg/launch",
        params={"router": created["slug"], "next": "/cgi-bin/luci"},
        follow_redirects=False,
    )

    with session_scope() as s:
        row = s.query(AuditLog).filter(AuditLog.action == "luci.launch").one()
    assert row.router_id == created["id"]
    import json

    assert json.loads(row.detail)["next"] == "/cgi-bin/luci"


def test_launch_refuses_an_unknown_router(client, api):
    _user()
    _login(client)
    r = client.get("/__tg/launch", params={"router": "does-not-exist"})
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "router_not_found"


def test_launch_refuses_a_revoked_router(client, api):
    created = api.create_router("Launch Revoked")
    with session_scope() as s:
        router = s.get(Router, created["id"])
        router.status = "revoked"
        s.flush()
    _user()
    _login(client)
    r = client.get("/__tg/launch", params={"router": created["slug"]})
    assert r.status_code == 404


# --------------------------------------------------------------------------- /__tg/enter
def test_enter_redeems_a_ticket_and_sets_a_router_scoped_cookie(client, api, settings):
    created = api.create_router("Enter Happy")
    owner = _user()
    ticket = TICKETS.issue(created["id"], owner, "/cgi-bin/luci")
    client.cookies.clear()

    r = client.get(
        "/__tg/enter",
        params={"router": created["slug"], "t": ticket},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/cgi-bin/luci"
    assert r.headers["cache-control"] == "no-store"

    cookie_name, _header = router_cookie_names(settings)
    value = client.cookies.get(cookie_name)
    assert value is not None, "the response must install the router cookie"
    assert verify_router_cookie(settings, created["id"], value) == owner


def test_enter_consumes_the_ticket_so_a_replay_falls_back_to_login(client, api, settings):
    created = api.create_router("Enter Replay")
    owner = _user()
    ticket = TICKETS.issue(created["id"], owner)
    client.cookies.clear()

    first = client.get(
        "/__tg/enter", params={"router": created["slug"], "t": ticket}, follow_redirects=False
    )
    assert first.status_code == 303 and first.headers["location"] == "/"

    client.cookies.clear()  # a different browser replaying the captured URL
    second = client.get(
        "/__tg/enter", params={"router": created["slug"], "t": ticket}, follow_redirects=False
    )
    assert second.status_code == 303
    assert "/login?" in second.headers["location"]


def test_enter_rejects_a_ticket_minted_for_another_router(client, api):
    first = api.create_router("Enter First")
    second = api.create_router("Enter Second")
    owner = _user()
    ticket = TICKETS.issue(first["id"], owner)
    client.cookies.clear()

    r = client.get(
        "/__tg/enter", params={"router": second["slug"], "t": ticket}, follow_redirects=False
    )
    assert r.status_code == 303
    assert "/login?" in r.headers["location"]
    assert second["slug"] in r.headers["location"]


def test_enter_keeps_working_for_a_browser_that_already_has_the_cookie(client, api, settings):
    """No ticket needed once the cookie exists - a bookmark to the plain URL keeps working."""
    created = api.create_router("Enter Bookmark")
    owner = _user()
    value, _ = issue_router_cookie(settings, created["id"], owner)
    cookie_name, _header = router_cookie_names(settings)
    client.cookies.clear()
    client.cookies.set(cookie_name, value)

    r = client.get(
        "/__tg/enter", params={"router": created["slug"], "next": "/luci"}, follow_redirects=False
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/luci"


def test_enter_sends_an_anonymous_browser_to_the_login_with_the_launch_path(client, api):
    created = api.create_router("Enter Anonymous")
    client.cookies.clear()

    r = client.get("/__tg/enter", params={"router": created["slug"]}, follow_redirects=False)
    assert r.status_code == 303
    location = r.headers["location"]
    assert location.startswith("http://panel.test/login?")
    assert f"router={created['slug']}" in location


def test_enter_refuses_a_host_that_does_not_match_the_router(client, api):
    """A router cannot widen its own authority by rewriting the Host header."""
    first = api.create_router("Host First")
    api.create_router("Host Second")
    owner = _user()
    ticket = TICKETS.issue(first["id"], owner)
    client.cookies.clear()

    r = client.get(
        "/__tg/enter",
        params={"router": first["slug"], "t": ticket},
        headers={"host": "host-second.panel.test"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "/login?" in r.headers["location"]


def test_enter_with_an_unknown_router_reaches_the_login_instead_of_raising(client, api):
    """An unauthenticated endpoint must not 500 on a reference it cannot resolve.

    The landing default is router-dependent, so an early cut computed
    default_target(settings, item.slug) before checking that item existed and answered
    HTTP 500 for any unknown slug. The endpoint is unauthenticated by design (the ticket
    is the credential), so garbage input is expected traffic, not an internal error.
    """
    client.cookies.clear()

    r = client.get("/__tg/enter", params={"router": "no-such-router"}, follow_redirects=False)
    assert r.status_code == 303
    assert "/login?" in r.headers["location"]


def test_enter_status_reports_whether_the_cookie_still_works(client, api, settings):
    created = api.create_router("Enter Status")
    owner = _user()
    client.cookies.clear()

    before = client.get("/__tg/enter/status", params={"router": created["slug"]})
    assert before.json()["authorized"] is False

    value, _ = issue_router_cookie(settings, created["id"], owner)
    cookie_name, _header = router_cookie_names(settings)
    client.cookies.set(cookie_name, value)
    after = client.get("/__tg/enter/status", params={"router": created["slug"]})
    assert after.json()["authorized"] is True
    assert after.json()["user"] == "launch-user"


# --------------------------------------------------------------------------- the contract
def test_a_router_is_advertised_with_a_launch_url(client, api):
    created = api.create_router("Advertising")
    assert created["url"] == f"https://{created['slug']}.panel.test"
    assert created["launch_url"] == f"https://{created['slug']}.panel.test/__tg/enter"


# --------------------------------------------------------------------- path routing mode
def _path_mode(settings, **kw):
    params = {"route_mode": "path", "gateway_host": "gate.panel.test"}
    params.update(kw)
    for key, value in params.items():
        setattr(settings, key, value)
    return settings


def test_path_mode_advertises_one_gateway_host_and_a_prefix(settings):
    _path_mode(settings)
    assert settings.path_routing is True
    assert settings.gateway == "gate.panel.test"
    assert settings.router_prefix("edge-one") == "/edge-one"
    assert settings.router_url("edge-one") == "https://gate.panel.test/edge-one/"
    assert launch_url(settings, "edge-one") == "https://gate.panel.test/edge-one/__tg/enter"
    assert (
        launch_url(settings, "edge-one", "abc")
        == "https://gate.panel.test/edge-one/__tg/enter?t=abc"
    )


def test_path_mode_defaults_the_gateway_to_gate_dot_suffix(settings):
    settings.route_mode = "path"
    settings.gateway_host = None
    settings.subdomain_suffix = "routers.example.com"
    assert settings.gateway == "gate.routers.example.com"


def test_an_unknown_route_mode_falls_back_to_subdomains(settings):
    """A typo must not stop the panel from booting (doctor reports it instead)."""
    settings.route_mode = "pth"
    assert settings.route_mode_normalized == "subdomain"
    assert settings.path_routing is False


def test_path_mode_scopes_the_router_cookie_to_the_prefix(settings):
    from app.services.launch import router_cookie_path

    assert router_cookie_path(settings, "edge-one") == "/"
    _path_mode(settings)
    assert router_cookie_path(settings, "edge-one") == "/edge-one/"


def test_path_mode_has_no_single_router_host(settings):
    """One host serves every router, so a slug cannot be read out of it."""
    _path_mode(settings)
    assert host_router_slug(settings, "gate.panel.test") is None
    assert host_router_slug(settings, "panel.test") is None


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("/edge-one/cgi-bin/luci", "edge-one"),
        ("/edge-one/", "edge-one"),
        ("/edge-one", "edge-one"),
        ("/edge-one/cgi-bin/luci?x=1", "edge-one"),
        ("/edge-one/__tg/enter?t=abc", "edge-one"),
        # A request that lost its prefix must not be guessed at.
        ("/", None),
        ("", None),
        (None, None),
        ("/cgi-bin/luci", "cgi-bin"),
    ],
)
def test_slug_from_path_reads_only_the_first_segment(raw, expected):
    from app.services.launch import slug_from_path

    assert slug_from_path(raw) == expected


def test_path_mode_default_target_is_the_router_prefix(settings):
    from app.services.launch import default_target

    assert default_target(settings, "edge-one") == "/"
    _path_mode(settings)
    assert default_target(settings, "edge-one") == "/edge-one/"


def test_enter_in_path_mode_resolves_the_router_from_the_original_uri(client, api, settings):
    """nginx sends X-Original-URI; the slug is its first segment, not the Host header."""
    _path_mode(settings)
    created = api.create_router("Path Enter")
    owner = _user()
    ticket = TICKETS.issue(created["id"], owner, f"/{created['slug']}/cgi-bin/luci")
    client.cookies.clear()

    r = client.get(
        "/__tg/enter",
        params={"t": ticket},
        headers={"host": "gate.panel.test", "x-original-uri": f"/{created['slug']}/__tg/enter"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == f"/{created['slug']}/cgi-bin/luci"
    cookie_name, _header = router_cookie_names(settings)
    assert verify_router_cookie(settings, created["id"], client.cookies.get(cookie_name)) == owner


def test_enter_in_path_mode_scopes_its_cookie_to_the_prefix(client, api, settings):
    """One host, many routers: an unscoped cookie would be sent to the neighbours."""
    _path_mode(settings)
    created = api.create_router("Path Cookie")
    owner = _user()
    ticket = TICKETS.issue(created["id"], owner)
    client.cookies.clear()

    r = client.get(
        "/__tg/enter",
        params={"t": ticket},
        headers={"host": "gate.panel.test", "x-original-uri": f"/{created['slug']}/__tg/enter"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    header = r.headers["set-cookie"].lower()
    assert f"path=/{created['slug']}/;" in header or header.endswith(f"path=/{created['slug']}/")


def test_enter_in_path_mode_defaults_to_the_router_prefix_not_the_gateway_root(
    client, api, settings
):
    """A launch with no next= must land on the router, and "/" on the gateway is a 404."""
    _path_mode(settings)
    created = api.create_router("Path Landing")
    owner = _user()
    ticket = TICKETS.issue(created["id"], owner)
    client.cookies.clear()

    r = client.get(
        "/__tg/enter",
        params={"t": ticket},
        headers={"host": "gate.panel.test", "x-original-uri": f"/{created['slug']}/__tg/enter"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == f"/{created['slug']}/"


def test_enter_in_path_mode_ignores_a_prefix_that_names_another_router(client, api, settings):
    """A router cannot widen its authority by rewriting the prefix it is reached under."""
    _path_mode(settings)
    first = api.create_router("Path First")
    second = api.create_router("Path Second")
    owner = _user()
    ticket = TICKETS.issue(second["id"], owner)
    client.cookies.clear()

    r = client.get(
        "/__tg/enter",
        params={"t": ticket},
        headers={"host": "gate.panel.test", "x-original-uri": f"/{first['slug']}/__tg/enter"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "/login?" in r.headers["location"]


def test_the_router_api_advertises_path_urls(client, api, settings):
    _path_mode(settings)
    created = api.create_router("Path Advertising")
    assert created["url"] == f"https://gate.panel.test/{created['slug']}/"
    assert created["launch_url"] == f"https://gate.panel.test/{created['slug']}/__tg/enter"
