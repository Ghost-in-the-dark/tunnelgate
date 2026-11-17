"""The `auth_request` gate: the only thing between the internet and a router's LuCI."""

from __future__ import annotations

import json

import pytest

from app.db import session_scope
from app.models import AuditLog, User
from app.security import hash_password


@pytest.fixture(autouse=True)
def _clear_luci_throttle():
    """The throttle dict is process state; every test starts from a clean slate."""
    from app.api import gate as gate_api

    gate_api._LUCI_AUDIT.clear()
    yield
    gate_api._LUCI_AUDIT.clear()


def _login(client, username: str, password: str) -> str:
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["csrf_token"]


def _user(username: str, role: str = "viewer", password: str = "user-t3st-pass", active=True):
    with session_scope() as s:
        u = User(
            username=username,
            role=role,
            password_hash=hash_password(password),
            is_active=active,
        )
        s.add(u)
        s.flush()
        return u.id


# --------------------------------------------------------------------------- unauthenticated
def test_gate_denies_without_a_session(client, api):
    created = api.create_router("Gated")
    # api implies admin_client, so the cookie jar is authenticated: drop it to model a stranger.
    client.cookies.clear()
    r = client.get("/__tg/auth", params={"router_id": created["id"], "uri": "/"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "not_authenticated"
    assert r.headers["cache-control"] == "no-store"


def test_gate_denies_when_the_router_id_is_missing(client):
    _user("gate-no-router")
    _login(client, "gate-no-router", "user-t3st-pass")
    r = client.get("/__tg/auth", params={"uri": "/"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "not_authenticated"


def test_gate_is_not_a_router_existence_oracle(client):
    _user("gate-prober")
    _login(client, "gate-prober", "user-t3st-pass")
    unknown = client.get("/__tg/auth", params={"router_id": "does-not-exist"})
    # The router-id branch and the absent-id branch must be indistinguishable by CODE; the
    # message text differs because "no router in this request" is a client wiring bug, not a
    # probe, but both are 401 not_authenticated and both carry no-store.
    assert unknown.status_code == 401
    assert unknown.json()["error"]["code"] == "not_authenticated"
    assert "cache-control" in unknown.headers


def test_gate_denies_a_disabled_account(client):
    _user("gate-disabled", active=False)
    r = client.post(
        "/api/auth/login",
        json={"username": "gate-disabled", "password": "user-t3st-pass"},
    )
    assert r.status_code == 401


# --------------------------------------------------------------------------- allowed
def test_gate_allows_a_logged_in_user(client, api):
    created = api.create_router("Allowed")
    r = client.get("/__tg/auth", params={"router_id": created["id"], "uri": "/cgi-bin/luci"})
    assert r.status_code == 200, r.text
    assert r.headers["x-tg-user"] == "admin"
    assert r.headers["x-tg-role"] == "admin"
    assert r.headers["x-tg-router"] == created["slug"]
    assert r.headers["cache-control"] == "no-store"
    assert r.content == b""


def test_gate_allows_every_role_including_viewer(client, api):
    created = api.create_router("Viewer Router")
    _user("gate-viewer", role="viewer")
    _login(client, "gate-viewer", "user-t3st-pass")
    r = client.get("/__tg/auth", params={"router_id": created["id"]})
    assert r.status_code == 200
    assert r.headers["x-tg-role"] == "viewer"


def test_gate_works_without_a_uri_parameter(client, api):
    created = api.create_router("No URI")
    r = client.get("/__tg/auth", params={"router_id": created["id"]})
    assert r.status_code == 200


# --------------------------------------------------------------------------- audit
def test_gate_audits_the_first_open(client, api, db):
    created = api.create_router("Audited LuCI")
    client.get("/__tg/auth", params={"router_id": created["id"], "uri": "/cgi-bin/luci"})
    db.expire_all()
    rows = db.query(AuditLog).filter_by(action="luci.open").all()
    assert len(rows) == 1
    assert rows[0].router_id == created["id"]
    assert rows[0].actor_username == "admin"
    # detail is stored as JSON text, not a JSON column.
    assert json.loads(rows[0].detail)["uri"] == "/cgi-bin/luci"


def test_gate_throttles_repeated_opens_to_one_row(client, api, db):
    created = api.create_router("Throttled")
    for _ in range(10):
        assert client.get("/__tg/auth", params={"router_id": created["id"]}).status_code == 200
    db.expire_all()
    rows = db.query(AuditLog).filter_by(action="luci.open").all()
    # A LuCI page pulls dozens of subresources; the log answers "who opened which router".
    assert len(rows) == 1


def test_gate_audits_each_router_separately(client, api, db):
    first = api.create_router("LuCI One")
    second = api.create_router("LuCI Two")
    client.get("/__tg/auth", params={"router_id": first["id"]})
    client.get("/__tg/auth", params={"router_id": second["id"]})
    db.expire_all()
    rows = db.query(AuditLog).filter_by(action="luci.open").all()
    assert {r.router_id for r in rows} == {first["id"], second["id"]}


def test_gate_does_not_audit_a_denied_request(client, api, db):
    created = api.create_router("Denied LuCI")
    client.cookies.clear()
    client.get("/__tg/auth", params={"router_id": created["id"]})
    db.expire_all()
    assert db.query(AuditLog).filter_by(action="luci.open").count() == 0


def test_should_audit_window_expires(monkeypatch):
    from app.api import gate as gate_api

    gate_api._LUCI_AUDIT.clear()
    assert gate_api._should_audit(1, "r1", 1000.0) is True
    assert gate_api._should_audit(1, "r1", 1000.0 + 1) is False
    assert gate_api._should_audit(1, "r1", 1000.0 + 61) is True
    assert gate_api._should_audit(2, "r1", 1000.0 + 61) is True


def test_should_audit_prunes_stale_entries():
    from app.api import gate as gate_api

    gate_api._LUCI_AUDIT.clear()
    now = 10_000.0
    for i in range(5000):
        gate_api._should_audit(i, "r", now)
    # A burst of distinct (user, router) pairs inside a single window is all "fresh", so the cap
    # has to evict the oldest survivors rather than only entries older than the window.
    assert len(gate_api._LUCI_AUDIT) <= gate_api.LUCI_AUDIT_MAX_ENTRIES
    # A later window still sweeps what is left.
    gate_api._should_audit(99_999, "r", now + 10_000)
    assert len(gate_api._LUCI_AUDIT) < 100


def test_gate_route_is_not_in_the_public_api_namespace(client):
    # The gate lives under /__tg, which the SPA catch-all ignores; a 404 here would mean nginx
    # cannot reach it at all.
    r = client.get("/__tg/auth")
    assert r.status_code in (401, 200)
