"""Per-router authorization: the grant table, the access rule and every endpoint that enforces it.

The rule under test (app/services/access.py) is deliberately small:

    admin, operator -> every router, no grant row needed
    viewer          -> only the routers in router_grants for that user

The tests are grouped the way the failure would appear: the service itself, the LuCI gate (see
also tests/test_gate.py), the router REST surface, the console surface, and the admin routes
that hand a grant out.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.config import get_settings
from app.db import session_scope
from app.errors import ApiError
from app.models import Router, RouterGrant, User
from app.security import hash_password
from app.services.access import accessible_router_ids, can_access_router, require_router_access


def _login(client, username: str, password: str = "user-t3st-pass") -> str:
    """Log in and install the CSRF header the mutating routes require.

    Read from the csrf cookie, not the response body: the panel moved the token out of the JSON
    answer because a same-origin router page could fetch it back out of /api/auth/me. The body
    field stays as a fallback so the suite does not pin the transport.
    """
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    token = r.cookies.get(get_settings().csrf_cookie_name) or r.json().get("csrf_token")
    assert token, "login returned no CSRF token in the cookie or the body"
    client.headers[get_settings().csrf_header] = token
    return token


def _user(db, username: str, role: str = "viewer", password: str = "user-t3st-pass") -> User:
    """Create a user in its own transaction and return it attached to `db`."""
    with session_scope() as s:
        item = User(username=username, role=role, password_hash=hash_password(password))
        s.add(item)
        s.flush()
        user_id = item.id
    return db.get(User, user_id)


def _grant(user_id: int, router_id: str) -> None:
    with session_scope() as s:
        s.add(RouterGrant(user_id=user_id, router_id=router_id))


def _grant_ids(db, user_id: int) -> set[str]:
    rows = db.execute(select(RouterGrant.router_id).where(RouterGrant.user_id == user_id))
    return set(rows.scalars().all())


# --------------------------------------------------------------------------- the rule itself
def test_admin_and_operator_reach_every_router_without_a_grant(db, api, make_user):
    """The roles that rotate keys and read install scripts already hold a credential.

    They also have to reach routers that nobody granted them, otherwise rotating the key of a
    freshly installed router - the only way to recover a device whose token was lost - would be
    impossible until an admin granted it, and an admin granting themselves routers is noise.
    """
    created = api.create_router("Role Router")
    for role in ("admin", "operator"):
        user = _user(db, f"role-{role}", role=role)
        assert can_access_router(db, user, created["id"]) is True
        assert can_access_router(db, user, db.get(Router, created["id"])) is True
        assert accessible_router_ids(db, user) is None  # None means "all", not "none"
        require_router_access(db, user, created["id"])  # must not raise


def test_a_viewer_reaches_only_granted_routers(db, api, make_user):
    """The concrete accident: before this table, every authenticated user could read everything."""
    granted = api.create_router("Granted")
    other = api.create_router("Not Granted")
    viewer = _user(db, "grant-viewer", role="viewer")
    assert can_access_router(db, viewer, granted["id"]) is False
    assert accessible_router_ids(db, viewer) == set()
    _grant(viewer.id, granted["id"])
    db.expire_all()
    assert can_access_router(db, viewer, granted["id"]) is True
    assert can_access_router(db, viewer, other["id"]) is False
    assert accessible_router_ids(db, viewer) == {granted["id"]}
    require_router_access(db, viewer, granted["id"])
    with pytest.raises(ApiError) as excinfo:
        require_router_access(db, viewer, other["id"])
    assert excinfo.value.status == 403
    assert excinfo.value.code == "forbidden"


def test_an_unknown_router_is_forbidden_for_a_viewer_and_free_for_an_admin(db, make_user):
    """403 for both "not granted" and "does not exist": the difference is an existence oracle."""
    viewer = _user(db, "oracle-viewer", role="viewer")
    admin = _user(db, "oracle-admin", role="admin")
    assert can_access_router(db, viewer, "0" * 32) is False
    with pytest.raises(ApiError) as excinfo:
        require_router_access(db, viewer, "0" * 32)
    assert excinfo.value.status == 403
    assert can_access_router(db, admin, "0" * 32) is True  # the rule is about grants, not rows
    require_router_access(db, admin, "0" * 32)


def test_removing_the_grant_revokes_access_immediately(db, api):
    """No cached permission: the row is the permission, so deleting it is the revocation."""
    created = api.create_router("Revoked")
    user_id = None
    with session_scope() as s:
        viewer = User(username="revoked-viewer", role="viewer", password_hash=hash_password("x"))
        s.add(viewer)
        s.flush()
        user_id = viewer.id
        s.add(RouterGrant(user_id=user_id, router_id=created["id"]))
    viewer = db.get(User, user_id)
    assert can_access_router(db, viewer, created["id"]) is True
    with session_scope() as s:
        row = s.query(RouterGrant).filter_by(user_id=user_id).one()
        s.delete(row)
    db.expire_all()
    assert can_access_router(db, db.get(User, user_id), created["id"]) is False


# --------------------------------------------------------------------------- router REST
def test_list_routers_for_a_viewer_contains_only_grants_and_matches_the_counters(
    app, api, admin_client, client, db, make_user
):
    visible = api.create_router("Visible")
    hidden = api.create_router("Hidden")
    viewer_id = make_user("list-viewer", role="viewer")
    _grant(viewer_id, visible["id"])
    row = db.get(Router, visible["id"])
    row.status = "online"
    db.get(Router, hidden["id"]).status = "offline"
    db.commit()
    _login(client, "list-viewer")

    body = client.get("/api/v1/routers").json()
    assert [i["id"] for i in body["items"]] == [visible["id"]]
    # The counters describe the filtered set - the docstring's promise. Counting the hidden
    # router would tell a viewer how many devices the panel holds and in which state.
    assert body["total"] == 1
    assert body["online"] == 1
    assert body["offline"] == 0
    assert body["pending"] == 0

    # ... and an admin still sees both through the same endpoint. A second client is required:
    # admin_client IS client (the fixture logs in over the shared TestClient), so reusing it
    # here would silently assert against the viewer's own session.
    with TestClient(app) as admin_view:
        login = admin_view.post(
            "/api/auth/login", json={"username": "admin", "password": "admin-t3st-pass"}
        )
        assert login.status_code == 200
        assert admin_view.get("/api/v1/routers").json()["total"] == 2


def test_read_endpoints_are_forbidden_for_an_ungranted_viewer(api, client, db, make_user):
    """GET and status are the two read endpoints a viewer's role already allows."""
    created = api.create_router("Read Protected")
    make_user("read-viewer", role="viewer")
    _login(client, "read-viewer")
    for path in (
        f"/api/v1/routers/{created['id']}",
        f"/api/v1/routers/{created['id']}/status",
    ):
        r = client.get(path)
        assert r.status_code == 403, (path, r.text)
        assert r.json()["error"]["code"] == "forbidden"
        # No router data leaks in the refusal: the message is the generic one.
        assert created["slug"] not in r.text


def test_write_endpoints_are_refused_for_a_viewer_on_an_ungranted_router(
    api, client, db, make_user
):
    """patch/delete/rotate/script are operator-only today; the grant check must not be the only
    thing standing between a role change and every router, so each of them is exercised."""
    created = api.create_router("Write Protected")
    make_user("write-viewer", role="viewer")
    _login(client, "write-viewer")
    for method, path in (
        ("patch", f"/api/v1/routers/{created['id']}"),
        ("delete", f"/api/v1/routers/{created['id']}"),
        ("post", f"/api/v1/routers/{created['id']}/rotate-key"),
        ("get", f"/api/v1/routers/{created['id']}/script"),
    ):
        kwargs = {"json": {"name": "Renamed"}} if method == "patch" else {}
        r = getattr(client, method)(path, **kwargs)
        assert r.status_code == 403, (method, path, r.text)
        assert r.json()["error"]["code"] == "forbidden"


def test_an_unknown_router_is_403_for_a_viewer_and_404_for_an_admin(client, api, make_user):
    """The rule a caller may not see a router must not be able to tell it apart from a typo."""
    make_user("oracle2-viewer", role="viewer")
    _login(client, "oracle2-viewer")
    unknown = "0" * 32
    r = client.get(f"/api/v1/routers/{unknown}")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "forbidden"

    admin_login = client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin-t3st-pass"}
    )
    assert admin_login.status_code == 200
    r = client.get(f"/api/v1/routers/{unknown}")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"


def test_a_granted_viewer_can_read_and_the_gate_audits_the_open(api, client, db, make_user):
    """End to end for the one thing a viewer is for: looking at a router they were given."""
    created = api.create_router("Audited Router")
    viewer_id = make_user("audited-viewer", role="viewer")
    _grant(viewer_id, created["id"])
    _login(client, "audited-viewer")
    assert client.get(f"/api/v1/routers/{created['id']}").status_code == 200
    assert client.get(f"/api/v1/routers/{created['id']}/status").status_code == 200
    r = client.get("/__tg/auth", params={"router_id": created["id"], "uri": "/"})
    assert r.status_code == 200
    assert r.headers["x-tg-role"] == "viewer"
    from app.models import AuditLog

    with session_scope() as s:
        rows = s.query(AuditLog).filter_by(action="luci.open", router_id=created["id"]).all()
        assert len(rows) == 1
        assert rows[0].router_name == "Audited Router"


# --------------------------------------------------------------------------- console surface
def test_console_endpoints_are_forbidden_for_an_ungranted_viewer(api, client, db, make_user):
    """Console state is per-router data (ports, fingerprints, live session count)."""
    created = api.create_router("Console Protected")
    make_user("console-viewer", role="viewer")
    _login(client, "console-viewer")
    for path in (
        f"/api/v1/routers/{created['id']}/console",
        f"/api/v1/routers/{created['id']}/console/sessions",
    ):
        r = client.get(path)
        assert r.status_code == 403, (path, r.text)
        assert r.json()["error"]["code"] == "forbidden"


def test_console_start_denies_a_viewer_even_with_a_grant(app, client, api, db, make_user):
    """The role check stays the blocker: a grant does not buy a shell."""
    created = api.create_router("Console Role")
    viewer_id = make_user("console-granted", role="viewer")
    _grant(viewer_id, created["id"])
    _login(client, "console-granted")
    r = client.post(f"/api/v1/routers/{created['id']}/console/start")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "console_forbidden"


# --------------------------------------------------------------------------- grant management
def test_grant_put_replaces_the_whole_set(api, admin_client, db, make_user):
    first = api.create_router("Grant A")
    second = api.create_router("Grant B")
    third = api.create_router("Grant C")
    user_id = make_user("replace-viewer", role="viewer")

    r = admin_client.put(
        f"/api/v1/users/{user_id}/routers", json={"router_ids": [first["id"], second["id"]]}
    )
    assert r.status_code == 200, r.text
    assert {i["id"] for i in r.json()["items"]} == {first["id"], second["id"]}
    assert _grant_ids(db, user_id) == {first["id"], second["id"]}

    listed = admin_client.get(f"/api/v1/users/{user_id}/routers").json()
    assert listed["total"] == 2
    assert {i["id"] for i in listed["items"]} == {first["id"], second["id"]}

    # Replace: second stays, first goes, third arrives. A merge would leave first behind.
    r = admin_client.put(
        f"/api/v1/users/{user_id}/routers", json={"router_ids": [second["id"], third["id"]]}
    )
    assert r.status_code == 200, r.text
    assert _grant_ids(db, user_id) == {second["id"], third["id"]}

    # The same set twice is a no-op, not an error: that is the point of a PUT.
    r = admin_client.put(
        f"/api/v1/users/{user_id}/routers", json={"router_ids": [second["id"], third["id"]]}
    )
    assert r.status_code == 200
    assert _grant_ids(db, user_id) == {second["id"], third["id"]}

    # An empty list revokes everything.
    assert (
        admin_client.put(f"/api/v1/users/{user_id}/routers", json={"router_ids": []}).status_code
        == 200
    )
    assert _grant_ids(db, user_id) == set()


def test_grant_put_rejects_an_unknown_router_id_and_writes_nothing(
    api, admin_client, db, make_user
):
    created = api.create_router("Known")
    user_id = make_user("unknown-id-viewer", role="viewer")
    admin_client.put(f"/api/v1/users/{user_id}/routers", json={"router_ids": [created["id"]]})
    missing = "f" * 32
    r = admin_client.put(
        f"/api/v1/users/{user_id}/routers", json={"router_ids": [created["id"], missing]}
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "validation_error"
    assert missing in r.json()["error"]["message"]
    # The whole body is rejected: the previous set is untouched, so a UI that retries after a
    # typo does not silently lose access it had already granted.
    assert _grant_ids(db, user_id) == {created["id"]}


def test_grant_routes_are_admin_only(api, client, db, make_user):
    """An operator who could grant themselves routers would make the access rule pointless."""
    created = api.create_router("Admin Only")
    user_id = make_user("grant-target", role="viewer")
    make_user("grant-operator", role="operator")
    _login(client, "grant-operator")
    assert client.get(f"/api/v1/users/{user_id}/routers").status_code == 403
    assert (
        client.put(
            f"/api/v1/users/{user_id}/routers", json={"router_ids": [created["id"]]}
        ).status_code
        == 403
    )
    assert client.delete(f"/api/v1/users/{user_id}/routers/{created['id']}").status_code == 403
    assert _grant_ids(db, user_id) == set()


def test_grant_put_needs_the_csrf_header(api, admin_client, settings, db, make_user):
    """Granting a router is a privilege change; a cross-site form post must not be able to do it."""
    created = api.create_router("CSRF Guarded")
    user_id = make_user("csrf-viewer", role="viewer")
    saved = admin_client.headers.pop(settings.csrf_header, None)
    try:
        r = admin_client.put(
            f"/api/v1/users/{user_id}/routers", json={"router_ids": [created["id"]]}
        )
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "csrf_failed"
        assert _grant_ids(db, user_id) == set()
    finally:
        if saved is not None:
            admin_client.headers[settings.csrf_header] = saved


def test_grant_delete_removes_one_row_and_404s_when_there_is_none(api, admin_client, db, make_user):
    created = api.create_router("Delete Grant")
    user_id = make_user("delete-grant-viewer", role="viewer")
    admin_client.put(f"/api/v1/users/{user_id}/routers", json={"router_ids": [created["id"]]})
    r = admin_client.delete(f"/api/v1/users/{user_id}/routers/{created['id']}")
    assert r.status_code == 204
    assert _grant_ids(db, user_id) == set()
    # Deleting nothing is a 404, not a quiet success that makes the caller believe it revoked.
    again = admin_client.delete(f"/api/v1/users/{user_id}/routers/{created['id']}")
    assert again.status_code == 404
    assert again.json()["error"]["code"] == "not_found"


def test_grant_changes_are_audited(api, admin_client, db, make_user):
    """The audit log has to answer "who could see this router, and when did that change"."""
    from app.models import AuditLog

    first = api.create_router("Audit A")
    second = api.create_router("Audit B")
    user_id = make_user("audit-grant-viewer", role="viewer")
    admin_client.put(f"/api/v1/users/{user_id}/routers", json={"router_ids": [first["id"]]})
    admin_client.put(
        f"/api/v1/users/{user_id}/routers", json={"router_ids": [first["id"], second["id"]]}
    )
    admin_client.delete(f"/api/v1/users/{user_id}/routers/{first['id']}")
    with session_scope() as s:
        updates = s.query(AuditLog).filter_by(action="user.grants.update").all()
        revokes = s.query(AuditLog).filter_by(action="user.grants.revoke").all()
    assert len(updates) == 2
    assert len(revokes) == 1
    assert "audit-grant-viewer" in updates[0].detail
    assert sorted([first["id"], second["id"]]) == sorted(
        json.loads(updates[1].detail)["router_ids"]
    )
    assert '"router_ids"' in revokes[0].detail or first["id"] in revokes[0].detail


def test_deleting_a_router_cascades_its_grants_away(api, admin_client, db, make_user):
    """A grant row must never outlive its router: an id that gets reused would be a live grant."""
    created = api.create_router("Cascade Router")
    user_id = make_user("cascade-viewer", role="viewer")
    admin_client.put(f"/api/v1/users/{user_id}/routers", json={"router_ids": [created["id"]]})
    assert _grant_ids(db, user_id) == {created["id"]}
    assert admin_client.delete(f"/api/v1/routers/{created['id']}").status_code == 204
    db.expire_all()
    with session_scope() as s:
        assert s.query(RouterGrant).filter_by(router_id=created["id"]).count() == 0


def test_deleting_a_user_cascades_their_grants_away(api, admin_client, db, make_user):
    created = api.create_router("Cascade User Router")
    user_id = make_user("cascade-user", role="viewer")
    admin_client.put(f"/api/v1/users/{user_id}/routers", json={"router_ids": [created["id"]]})
    assert admin_client.delete(f"/api/v1/users/{user_id}").status_code == 204
    with session_scope() as s:
        assert s.query(RouterGrant).filter_by(user_id=user_id).count() == 0


def test_a_router_created_by_a_non_viewer_gets_no_grant_row(api, db):
    """The creator self-grant is conditional; an admin's routers are reached by role."""
    created = api.create_router("No Grant Needed")
    with session_scope() as s:
        assert s.query(RouterGrant).filter_by(router_id=created["id"]).count() == 0


def test_grant_routes_404_for_an_unknown_user(admin_client):
    unknown_user = 999999
    assert admin_client.get(f"/api/v1/users/{unknown_user}/routers").status_code == 404
    assert (
        admin_client.put(
            f"/api/v1/users/{unknown_user}/routers", json={"router_ids": []}
        ).status_code
        == 404
    )
