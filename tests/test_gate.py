"""The `auth_request` gate: the only thing between the internet and a router's LuCI."""

from __future__ import annotations

import json

import pytest

from app.config import get_settings
from app.db import session_scope
from app.models import AuditLog, RouterGrant, User
from app.security import hash_password


@pytest.fixture(autouse=True)
def _clear_luci_throttle():
    """The throttle dict is process state; every test starts from a clean slate."""
    from app.api import gate as gate_api

    gate_api._LUCI_AUDIT.clear()
    yield
    gate_api._LUCI_AUDIT.clear()


def _login(client, username: str, password: str) -> str:
    """Log in and return the CSRF token, which now lives in the csrf cookie, not the body.

    The panel moved the token out of the login body because a same-origin router page could
    fetch it back out of /api/auth/me; it is delivered as a cookie the SPA reads instead
    (app/api/auth.py::_set_csrf_cookie). TestClient keeps the Set-Cookie, so the value the
    browser would hold is exactly r.cookies[csrf_cookie_name]. The body field is still read as
    a fallback so this suite does not depend on which of the two shapes is deployed.
    """
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    token = r.cookies.get(get_settings().csrf_cookie_name) or r.json().get("csrf_token")
    assert token, "login returned no CSRF token in the cookie or the body"
    client.headers[get_settings().csrf_header] = token
    return token


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


def _grant(user_id: int, router_id: str) -> None:
    """One router_grants row - the whole permission for a viewer."""
    with session_scope() as s:
        s.add(RouterGrant(user_id=user_id, router_id=router_id))
        s.flush()


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


def test_gate_allows_a_viewer_only_on_a_granted_router(client, api):
    """The rule that replaced "every authenticated user reaches every router".

    A viewer is authenticated, but authentication is no longer authorization: without a grant
    row the gate answers with the same 401 it gives a stranger (below), and WITH one it answers
    200 and names the router in the audit trail (test_gate_audits_a_granted_viewer_open).
    Admin and operator skip the grant entirely - see test_gate_allows_every_role_including_viewer
    for that half, which still holds for the roles that manage routers.
    """
    granted = api.create_router("Granted Router")
    other = api.create_router("Ungranted Router")
    viewer_id = _user("gate-viewer", role="viewer")
    _grant(viewer_id, granted["id"])
    _login(client, "gate-viewer", "user-t3st-pass")

    allowed = client.get("/__tg/auth", params={"router_id": granted["id"], "uri": "/"})
    assert allowed.status_code == 200, allowed.text
    assert allowed.headers["x-tg-role"] == "viewer"
    assert allowed.headers["x-tg-router"] == granted["slug"]

    denied = client.get("/__tg/auth", params={"router_id": other["id"], "uri": "/"})
    assert denied.status_code == 401
    assert denied.json()["error"]["code"] == "not_authenticated"


def test_gate_denies_a_viewer_without_a_grant_with_the_unauthenticated_body(client, api):
    """A refused viewer must not learn whether the router exists.

    Both calls below are made by the SAME logged-in viewer and differ only in whether the router
    id is real. If the gate answered 403 for "exists but not granted" and 401 for "no such
    router", that difference would be a working router-id enumerator for anyone holding a
    viewer account.
    """
    created = api.create_router("Someone Else's Router")
    _user("gate-ungranted", role="viewer")
    _login(client, "gate-ungranted", "user-t3st-pass")

    real = client.get("/__tg/auth", params={"router_id": created["id"], "uri": "/"})
    fake = client.get("/__tg/auth", params={"router_id": "does-not-exist", "uri": "/"})
    assert real.status_code == fake.status_code == 401
    assert real.json() == fake.json()
    assert real.headers["cache-control"] == "no-store"


def test_gate_allows_every_role_including_viewer(client, api):
    """Admin and operator reach a router with no grant row; only the viewer needs one.

    Kept under its old name on purpose: the name states the half of the rule that did NOT
    change, so a reader looking for "every role" finds the roles that still have blanket
    access, and the two tests above/below carry the viewer's new condition.
    """
    created = api.create_router("Role Router")
    for username, role in (("gate-operator", "operator"), ("gate-admin", "admin")):
        _user(username, role=role)
        _login(client, username, "user-t3st-pass")
        r = client.get("/__tg/auth", params={"router_id": created["id"]})
        assert r.status_code == 200, (role, r.text)
        assert r.headers["x-tg-role"] == role


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


def test_gate_audits_a_granted_viewer_open(client, api, db):
    """A viewer's LuCI open is logged like anyone else's, with the router named.

    The grant is what makes the row exist at all: the same call from the same viewer without it
    is refused before the audit block, so a row here also proves the check runs before the
    write rather than after it.
    """
    created = api.create_router("Viewer Audited")
    viewer_id = _user("gate-viewer-audited", role="viewer")
    _grant(viewer_id, created["id"])
    _login(client, "gate-viewer-audited", "user-t3st-pass")
    assert (
        client.get("/__tg/auth", params={"router_id": created["id"], "uri": "/"}).status_code == 200
    )
    db.expire_all()
    rows = db.query(AuditLog).filter_by(action="luci.open").all()
    assert len(rows) == 1
    assert rows[0].router_id == created["id"]
    assert rows[0].router_name == "Viewer Audited"
    assert rows[0].actor_username == "gate-viewer-audited"


def test_gate_does_not_audit_a_refused_viewer(client, api, db):
    """A denial writes no luci.open row: it would otherwise record an open that never happened."""
    created = api.create_router("Not Audited")
    _user("gate-viewer-refused", role="viewer")
    _login(client, "gate-viewer-refused", "user-t3st-pass")
    assert client.get("/__tg/auth", params={"router_id": created["id"]}).status_code == 401
    db.expire_all()
    assert db.query(AuditLog).filter_by(action="luci.open").count() == 0


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


# --------------------------------------------------------------------------- router cookie
def _router_cookie(settings, router_id: str, user_id: int) -> str:
    from app.services.launch import issue_router_cookie

    value, _max_age = issue_router_cookie(settings, router_id, user_id)
    return value


def _cookie_header(settings) -> str:
    from app.services.launch import router_cookie_names

    return router_cookie_names(settings)[1]


def test_gate_accepts_the_router_cookie_without_a_panel_session(client, api, settings):
    """The whole point of the launch flow: a credential scoped to THIS router host is enough.

    A browser on https://<slug>.<suffix> has no panel session (that cookie is host-only by
    design), so the gate has to accept the router-scoped cookie the launch endpoint installed.
    """
    created = api.create_router("Launched")
    owner = _user("gate-launch-owner")
    # The cookie proves WHICH router host the browser reached; the grant proves the viewer may
    # reach that router. Both are required now, which is the point: a viewer who mints a router
    # cookie through /__tg/launch must still be refused a router nobody granted them.
    _grant(owner, created["id"])
    client.cookies.clear()

    r = client.get(
        "/__tg/auth",
        params={"router_id": created["id"], "uri": "/cgi-bin/luci"},
        headers={_cookie_header(settings): _router_cookie(settings, created["id"], owner)},
    )
    assert r.status_code == 200, r.text
    assert r.headers["x-tg-user"] == "gate-launch-owner"
    assert r.headers["x-tg-router"] == created["slug"]
    assert r.headers["cache-control"] == "no-store"


def test_gate_audits_a_router_cookie_open_as_such(client, api, settings):
    """The log has to say which credential was used: they have different blast radii."""
    created = api.create_router("Launched Audit")
    owner = _user("gate-launch-auditor")
    _grant(owner, created["id"])
    client.cookies.clear()

    client.get(
        "/__tg/auth",
        params={"router_id": created["id"], "uri": "/cgi-bin/luci"},
        headers={_cookie_header(settings): _router_cookie(settings, created["id"], owner)},
    )

    with session_scope() as s:
        rows = s.query(AuditLog).filter(AuditLog.action == "luci.open").all()
    assert len(rows) == 1
    assert rows[0].actor_username == "gate-launch-auditor"
    assert json.loads(rows[0].detail)["credential"] == "router-cookie"


def test_gate_refuses_a_router_cookie_for_an_ungranted_router(client, api, settings):
    """A valid cookie is a credential, not a permission.

    /__tg/launch mints a router cookie for any authenticated user (it cannot know which routers
    that user was granted), so the gate is where the grant has to be enforced. Without this the
    viewer could mint a cookie for a neighbour's router id and walk straight into its LuCI - the
    same hole in a different shape.
    """
    created = api.create_router("Ungranted Launched")
    viewer = _user("gate-launch-ungranted")
    client.cookies.clear()

    r = client.get(
        "/__tg/auth",
        params={"router_id": created["id"], "uri": "/cgi-bin/luci"},
        headers={_cookie_header(settings): _router_cookie(settings, created["id"], viewer)},
    )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "not_authenticated"


def test_gate_rejects_a_router_cookie_minted_for_another_router(client, api, settings):
    """A cookie is bound to one router id; holding one must never open a neighbour."""
    first = api.create_router("First")
    second = api.create_router("Second")
    owner = _user("gate-cross-router")
    client.cookies.clear()

    r = client.get(
        "/__tg/auth",
        params={"router_id": second["id"], "uri": "/"},
        headers={_cookie_header(settings): _router_cookie(settings, first["id"], owner)},
    )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "not_authenticated"


def test_gate_rejects_a_tampered_router_cookie(client, api, settings):
    created = api.create_router("Tampered")
    owner = _user("gate-tamper")
    value = _router_cookie(settings, created["id"], owner)
    forged = value.rsplit(".", 1)[0] + "." + "0" * 64
    client.cookies.clear()

    r = client.get(
        "/__tg/auth",
        params={"router_id": created["id"], "uri": "/"},
        headers={_cookie_header(settings): forged},
    )
    assert r.status_code == 401


def test_gate_rejects_a_router_cookie_for_a_disabled_account(client, api, settings):
    created = api.create_router("Disabled")
    owner = _user("gate-disabled", active=False)
    client.cookies.clear()

    r = client.get(
        "/__tg/auth",
        params={"router_id": created["id"], "uri": "/"},
        headers={_cookie_header(settings): _router_cookie(settings, created["id"], owner)},
    )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "not_authenticated"


def test_gate_prefers_the_panel_session_when_both_are_present(client, api, settings):
    """Both cookies at once is not an error: the session wins and is audited as such."""
    created = api.create_router("Both")
    owner = _user("gate-both")
    _grant(owner, created["id"])
    _login(client, "gate-both", "user-t3st-pass")

    r = client.get(
        "/__tg/auth",
        params={"router_id": created["id"], "uri": "/"},
        headers={_cookie_header(settings): _router_cookie(settings, created["id"], owner)},
    )
    assert r.status_code == 200
    with session_scope() as s:
        row = s.query(AuditLog).filter(AuditLog.action == "luci.open").one()
    assert json.loads(row.detail)["credential"] == "panel-session"
