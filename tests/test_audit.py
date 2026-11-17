"""Audit log read API: who did what, readable by every authenticated role."""

from __future__ import annotations

import json

from app.db import session_scope
from app.models import User
from app.security import hash_password


def _login(client, username: str, password: str) -> str:
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["csrf_token"]


def _viewer(username: str = "audit-viewer") -> int:
    with session_scope() as s:
        u = User(username=username, role="viewer", password_hash=hash_password("user-t3st-pass"))
        s.add(u)
        s.flush()
        return u.id


# --------------------------------------------------------------------------- access
def test_audit_requires_authentication(client):
    r = client.get("/api/v1/audit")
    assert r.status_code == 401
    # deps.require_session raises "unauthorized"; docs/API.md:42 documents "not_authenticated".
    # Reported to the lead as contract drift in a file I do not own (app/deps.py).
    assert r.json()["error"]["code"] == "unauthorized"


def test_audit_is_readable_by_a_viewer(api, client):
    api.create_router("Audited Router")
    _viewer()
    _login(client, "audit-viewer", "user-t3st-pass")
    r = client.get("/api/v1/audit")
    assert r.status_code == 200, r.text
    body = r.json()
    # Seeing who did what is not a privilege escalation: it is why the log exists.
    assert any(item["action"] == "router.create" for item in body["items"])


def test_audit_has_no_write_endpoints(admin_client):
    assert admin_client.post("/api/v1/audit", json={}).status_code == 405
    assert admin_client.patch("/api/v1/audit").status_code == 405
    assert admin_client.delete("/api/v1/audit").status_code == 405


# --------------------------------------------------------------------------- shape
def test_audit_rows_expose_the_documented_fields(api, db):
    created = api.create_router("Field Router")
    body = api.c.get("/api/v1/audit").json()
    row = next(item for item in body["items"] if item["action"] == "router.create")
    assert set(row) == {
        "id",
        "ts",
        "actor_username",
        "action",
        "outcome",
        "router_id",
        "router_name",
        "ip",
        "detail",
    }
    assert row["actor_username"] == "admin"
    assert row["outcome"] == "ok"
    assert row["router_id"] == created["id"]
    assert row["router_name"] == "Field Router"
    assert row["ts"].endswith("Z")


def test_audit_detail_is_stored_json_text(api):
    api.create_router("Detail Router")
    items = api.c.get("/api/v1/audit").json()["items"]
    row = next(item for item in items if item["action"] == "router.create")
    # The column is Text holding json.dumps(...) with sorted keys; the SPA type is `string`.
    assert isinstance(row["detail"], str)
    assert json.loads(row["detail"])["slug"]


def test_audit_records_the_actor_ip(admin_client):
    items = admin_client.get("/api/v1/audit").json()["items"]
    login_rows = [i for i in items if i["action"] == "auth.login"]
    assert login_rows
    assert login_rows[0]["ip"]


# --------------------------------------------------------------------------- ordering and paging
def test_audit_is_newest_first(api):
    for i in range(5):
        api.create_router(f"Ordered {i}")
    items = api.c.get("/api/v1/audit").json()["items"]
    ids = [item["id"] for item in items]
    assert ids == sorted(ids, reverse=True)


def test_audit_total_counts_the_whole_filtered_set(admin_client):
    for i in range(4):
        admin_client.post("/api/v1/routers", json={"name": f"Paged {i}"})
    body = admin_client.get("/api/v1/audit", params={"limit": 2}).json()
    assert len(body["items"]) == 2
    assert body["total"] >= 4


def test_audit_offset_pages_through_results(admin_client):
    for i in range(4):
        admin_client.post("/api/v1/routers", json={"name": f"Offset {i}"})
    first = admin_client.get("/api/v1/audit", params={"limit": 2, "offset": 0}).json()
    second = admin_client.get("/api/v1/audit", params={"limit": 2, "offset": 2}).json()
    assert {i["id"] for i in first["items"]}.isdisjoint({i["id"] for i in second["items"]})
    assert first["total"] == second["total"]


def test_audit_rejects_a_bad_limit(admin_client):
    assert admin_client.get("/api/v1/audit", params={"limit": 0}).status_code == 422
    assert admin_client.get("/api/v1/audit", params={"limit": 1001}).status_code == 422
    assert admin_client.get("/api/v1/audit", params={"offset": -1}).status_code == 422


def test_audit_default_limit_is_a_hundred(admin_client):
    for i in range(105):
        admin_client.post("/api/v1/routers", json={"name": f"Many {i}"})
    body = admin_client.get("/api/v1/audit").json()
    assert len(body["items"]) == 100
    assert body["total"] > 100


# --------------------------------------------------------------------------- filters
def test_audit_filters_by_action(api):
    api.create_router("Action Filtered")
    body = api.c.get("/api/v1/audit", params={"action": "router.create"}).json()
    assert body["items"]
    assert {i["action"] for i in body["items"]} == {"router.create"}


def test_audit_filters_by_router_id(api):
    first = api.create_router("Filter One")
    api.create_router("Filter Two")
    body = api.c.get("/api/v1/audit", params={"router_id": first["id"]}).json()
    assert body["items"]
    assert {i["router_id"] for i in body["items"]} == {first["id"]}


def test_audit_filters_by_actor(api):
    _viewer("actor-viewer")
    body = api.c.get("/api/v1/audit", params={"actor": "admin"}).json()
    assert body["items"]
    assert {i["actor_username"] for i in body["items"]} == {"admin"}
    assert api.c.get("/api/v1/audit", params={"actor": "nobody"}).json()["total"] == 0


def test_audit_filters_by_outcome(api):
    api.c.post("/api/v1/routers", json={"name": ""})  # 422, not audited as a failure
    api.c.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    # Outcomes are ok / denied / error: a refused action is "denied", not "fail".
    body = api.c.get("/api/v1/audit", params={"outcome": "denied"}).json()
    assert body["items"]
    assert {i["outcome"] for i in body["items"]} == {"denied"}
    assert {i["action"] for i in body["items"]} == {"auth.login_failed"}


def test_audit_filters_combine(api):
    created = api.create_router("Combined")
    body = api.c.get(
        "/api/v1/audit",
        params={"router_id": created["id"], "action": "router.create", "outcome": "ok"},
    ).json()
    assert len(body["items"]) == 1
    assert body["items"][0]["router_id"] == created["id"]


# --------------------------------------------------------------------------- durability
def test_audit_row_survives_deleting_the_router(api, db):
    created = api.create_router("Deleted Later")
    assert api.c.delete(f"/api/v1/routers/{created['id']}").status_code == 204
    body = api.c.get("/api/v1/audit", params={"router_id": created["id"]}).json()
    actions = {item["action"] for item in body["items"]}
    assert {"router.create", "router.delete"} <= actions
    # The name is snapshotted into the row, so history stays readable after the router is gone.
    assert all(item["router_name"] == "Deleted Later" for item in body["items"])


def test_failed_login_is_recorded_without_the_password(api, db):
    api.c.post("/api/auth/login", json={"username": "admin", "password": "hunter2-wrong"})
    body = api.c.get("/api/v1/audit", params={"action": "auth.login_failed"}).json()
    assert body["items"]
    blob = json.dumps(body["items"])
    assert "hunter2-wrong" not in blob
