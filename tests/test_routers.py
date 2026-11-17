"""Router CRUD, install script issuance, status derivation and the wizard endpoints."""

from __future__ import annotations

import pytest

from app.config import utcnow
from app.models import AuditLog, BootstrapToken, Router, RouterRuntime


def _stable(c: Router) -> dict:
    return c


# --------------------------------------------------------------------------- create
def test_create_router_returns_install_material_once(api):
    body = api.create_router("Kitchen AP", group_name="home", integrations=["luci"])
    assert body["name"] == "Kitchen AP"
    assert body["slug"] == "kitchen-ap"
    assert body["status"] == "pending"
    assert body["bootstrap_token"].startswith("tgbt_") or len(body["bootstrap_token"]) > 20
    assert body["install_command"].startswith("curl -fsSL")
    assert body["install_script_url"].endswith("/api/v1/routers/install?os=linux")
    assert body["install_script_url"].startswith("http://testserver")
    assert body["url"] == "https://kitchen-ap.panel.test"
    assert body["remote_port"] is None  # no port is burned before the router shows up
    assert body["has_key"] is False
    assert body["bootstrap_expires_at"].endswith("Z")


def test_create_router_slugifies_and_deduplicates(api):
    first = api.create_router("Office Router!!")
    second = api.create_router("Office Router!!")
    assert first["slug"] == "office-router"
    assert second["slug"] == "office-router-2"
    assert first["id"] != second["id"]


def test_create_router_honours_an_explicit_slug(api):
    body = api.create_router("Whatever", slug="my-slug")
    assert body["slug"] == "my-slug"


def test_create_router_rejects_a_bad_slug(api):
    r = api.c.post("/api/v1/routers", json={"name": "X", "slug": "Not A Slug"})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "validation_error"


def test_create_router_requires_csrf(api, settings):
    saved = api.c.headers.pop(settings.csrf_header)
    try:
        r = api.c.post("/api/v1/routers", json={"name": "No CSRF"})
    finally:
        api.c.headers[settings.csrf_header] = saved
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"


def test_create_router_requires_authentication(client):
    r = client.post("/api/v1/routers", json={"name": "Anon"})
    assert r.status_code == 401


def test_viewer_cannot_create_or_delete(client, settings, make_user):
    make_user("viewer1", role="viewer")
    login = client.post(
        "/api/auth/login", json={"username": "viewer1", "password": "user-t3st-pass"}
    )
    assert login.status_code == 200
    client.headers[settings.csrf_header] = login.json()["csrf_token"]
    r = client.post("/api/v1/routers", json={"name": "Nope"})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "forbidden"
    # but a viewer may read the list
    assert client.get("/api/v1/routers").status_code == 200


def test_operator_can_create(api, db, settings, make_user, client):
    make_user("operator1", role="operator")
    login = client.post(
        "/api/auth/login", json={"username": "operator1", "password": "user-t3st-pass"}
    )
    client.headers[settings.csrf_header] = login.json()["csrf_token"]
    r = client.post("/api/v1/routers", json={"name": "Operator Router"})
    assert r.status_code == 201, r.text


# --------------------------------------------------------------------------- list
def test_list_is_empty_initially(admin_client):
    body = admin_client.get("/api/v1/routers").json()
    assert body == {
        "items": [],
        "total": 0,
        "online": 0,
        "offline": 0,
        "pending": 0,
    }


def test_list_counts_and_filters(api, admin_client, db):
    first = api.create_router("One")
    second = api.create_router("Two")
    router = db.get(Router, second["id"])
    router.status = "online"
    db.commit()
    body = admin_client.get("/api/v1/routers").json()
    assert body["total"] == 2
    assert body["online"] == 1
    assert body["pending"] == 1
    filtered = admin_client.get("/api/v1/routers?status=online").json()
    assert filtered["total"] == 1
    assert filtered["items"][0]["id"] == second["id"]
    assert first["id"] != second["id"]


def test_list_rejects_an_unknown_status(admin_client):
    r = admin_client.get("/api/v1/routers?status=bogus")
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "validation_error"


def test_list_searches_by_name_and_hostname(api, admin_client, db):
    api.create_router("Garage Unit")
    other = api.create_router("Attic Unit")
    row = db.get(Router, other["id"])
    row.hostname = "attic-openwrt"
    db.commit()
    assert admin_client.get("/api/v1/routers?q=garage").json()["total"] == 1
    assert admin_client.get("/api/v1/routers?q=attic-openwrt").json()["total"] == 1
    assert admin_client.get("/api/v1/routers?q=zzz").json()["total"] == 0


def test_list_pagination(api, admin_client):
    for i in range(5):
        api.create_router(f"R{i}")
    page = admin_client.get("/api/v1/routers?limit=2&offset=0").json()
    assert len(page["items"]) == 2
    assert page["total"] == 5
    tail = admin_client.get("/api/v1/routers?limit=2&offset=4").json()
    assert len(tail["items"]) == 1


# --------------------------------------------------------------------------- get/update
def test_get_returns_404_for_unknown(admin_client):
    r = admin_client.get("/api/v1/routers/nope")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"


def test_get_round_trips(api, admin_client):
    created = api.create_router("Round Trip", notes="hello")
    body = admin_client.get(f"/api/v1/routers/{created['id']}").json()
    assert body["id"] == created["id"]
    assert body["notes"] == "hello"
    # the plaintext token is only echoed by create, never again
    assert "bootstrap_token" not in body


def test_get_exposes_the_pending_token_expiry_but_not_the_token(api, admin_client):
    created = api.create_router("Pending One")
    body = admin_client.get(f"/api/v1/routers/{created['id']}").json()
    assert body["bootstrap_expires_at"].endswith("Z")
    assert "install_command" not in body


def test_update_patches_display_fields(api, admin_client):
    created = api.create_router("Before")
    r = admin_client.patch(
        f"/api/v1/routers/{created['id']}",
        json={"name": "After", "group_name": "lab", "notes": "n", "http_port": 8080},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "After"
    assert body["group_name"] == "lab"
    assert body["notes"] == "n"
    assert body["http_port"] == 8080
    assert body["slug"] == created["slug"]  # slug is immutable


def test_update_rejects_a_bad_http_port(api, admin_client):
    created = api.create_router("Port Test")
    r = admin_client.patch(f"/api/v1/routers/{created['id']}", json={"http_port": 0})
    assert r.status_code == 422


# --------------------------------------------------------------------------- delete
def test_delete_router_removes_row_and_token(api, admin_client, db):
    created = api.create_router("Doomed")
    r = admin_client.delete(f"/api/v1/routers/{created['id']}")
    assert r.status_code == 204
    assert admin_client.get(f"/api/v1/routers/{created['id']}").status_code == 404
    assert db.query(BootstrapToken).filter_by(router_id=created["id"]).count() == 0


def test_delete_router_releases_the_ports(api, admin_client, db, settings):
    created = api.create_router("Ports")
    row = db.get(Router, created["id"])
    row.remote_port = settings.port_min
    row.console_port = settings.console_port_min
    db.commit()
    assert admin_client.delete(f"/api/v1/routers/{created['id']}").status_code == 204
    from app.services import ports as ports_service

    assert ports_service.free_port_count() == settings.port_max - settings.port_min + 1


def test_delete_unknown_is_404(admin_client):
    assert admin_client.delete("/api/v1/routers/nope").status_code == 404


# --------------------------------------------------------------------------- script / rotate
def test_script_is_refused_once_a_key_exists(api, admin_client, db):
    created = api.create_router("Scripted")
    row = db.get(Router, created["id"])
    row.public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake tunnelgate:x"
    db.commit()
    r = admin_client.get(f"/api/v1/routers/{created['id']}/script")
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "already_installed"


def test_script_returns_a_fresh_command_before_install(api, admin_client):
    created = api.create_router("Scripted")
    r = admin_client.get(f"/api/v1/routers/{created['id']}/script")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {
        "bootstrap_token",
        "bootstrap_expires_at",
        "install_command",
        "install_script_url",
    }
    assert body["bootstrap_token"] != created["bootstrap_token"]


def test_script_reissue_on_an_installed_router_needs_admin(api, client, settings, db, make_user):
    created = api.create_router("Locked")
    row = db.get(Router, created["id"])
    row.public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake tunnelgate:x"
    row.revoked_at = None
    db.commit()
    make_user("operator2", role="operator")
    login = client.post(
        "/api/auth/login", json={"username": "operator2", "password": "user-t3st-pass"}
    )
    client.headers[settings.csrf_header] = login.json()["csrf_token"]
    r = client.get(f"/api/v1/routers/{created['id']}/script?reissue=true")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "forbidden"


def test_rotate_key_revokes_and_reissues(api, admin_client, db, settings):
    created = api.create_router("Rotating")
    row = db.get(Router, created["id"])
    row.public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOld tunnelgate:x"
    row.remote_port = settings.port_min
    row.status = "online"
    db.commit()
    r = admin_client.post(f"/api/v1/routers/{created['id']}/rotate-key")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["bootstrap_token"]
    assert "note" in body
    db.expire_all()
    row = db.get(Router, created["id"])
    assert row.status == "pending"
    assert row.public_key is None
    assert row.revoked_at is not None
    assert row.remote_port == settings.port_min  # ports survive a rotation


# --------------------------------------------------------------------------- status / phase
def test_status_of_a_fresh_router_is_waiting(api, admin_client):
    created = api.create_router("Fresh")
    body = admin_client.get(f"/api/v1/routers/{created['id']}/status").json()
    assert body["phase"] == "waiting"
    assert body["online"] is False
    assert body["tunnel_present"] is False
    assert body["health_ok"] is None
    assert body["message"]


def test_status_reports_connected_when_the_tunnel_is_up(api, admin_client, db):
    created = api.create_router("Tunnelled")
    row = db.get(Router, created["id"])
    row.public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey tunnelgate:x"
    row.status = "awaiting"
    db.add(RouterRuntime(router_id=row.id, tunnel_present=True, health_ok=None))
    db.commit()
    body = admin_client.get(f"/api/v1/routers/{created['id']}/status").json()
    assert body["phase"] in ("connected", "reporting")
    assert body["tunnel_present"] is True


def test_status_reports_done_when_health_is_ok(api, admin_client, db):
    created = api.create_router("Healthy")
    row = db.get(Router, created["id"])
    row.public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey tunnelgate:x"
    row.status = "online"
    row.last_heartbeat_at = utcnow()
    db.add(RouterRuntime(router_id=row.id, tunnel_present=True, health_ok=True))
    db.commit()
    body = admin_client.get(f"/api/v1/routers/{created['id']}/status").json()
    assert body["phase"] == "done"
    assert body["health_ok"] is True
    assert body["online"] is True


def test_status_of_an_unreachable_keyed_router_is_offline(api, admin_client, db):
    created = api.create_router("Dark")
    row = db.get(Router, created["id"])
    row.public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey tunnelgate:x"
    row.status = "offline"
    db.add(RouterRuntime(router_id=row.id, tunnel_present=False, health_ok=None))
    db.commit()
    body = admin_client.get(f"/api/v1/routers/{created['id']}/status").json()
    assert body["phase"] == "offline"
    assert body["online"] is False


def test_status_404s_for_unknown_router(admin_client):
    assert admin_client.get("/api/v1/routers/nope/status").status_code == 404


# --------------------------------------------------------------------------- audit trail
def test_crud_writes_audit_rows(api, admin_client, db):
    created = api.create_router("Audited")
    admin_client.patch(f"/api/v1/routers/{created['id']}", json={"notes": "x"})
    admin_client.post(f"/api/v1/routers/{created['id']}/rotate-key")
    admin_client.delete(f"/api/v1/routers/{created['id']}")
    actions = [r.action for r in db.query(AuditLog).order_by(AuditLog.id).all()]
    for expected in ("router.create", "router.update", "router.rotate", "router.delete"):
        assert expected in actions


def test_router_out_exposes_console_readiness(api, admin_client, db):
    created = api.create_router("Console-ish")
    row = db.get(Router, created["id"])
    row.console_port = 25001
    db.commit()
    body = admin_client.get(f"/api/v1/routers/{created['id']}").json()
    assert body["console_port"] == 25001
    assert body["console_ready"] is False  # no console key yet
    # reverse_port is a deprecated alias for remote_port; it must never disagree with it.
    assert body["reverse_port"] == body["remote_port"]


def test_reverse_port_mirrors_remote_port_once_installed(api):
    created = api.create_router("Aliased Port")
    body = api.exchange(created["bootstrap_token"]).json()
    detail = api.c.get(f"/api/v1/routers/{created['id']}").json()
    assert detail["remote_port"] == body["tunnel"]["remote_port"]
    assert detail["reverse_port"] == detail["remote_port"]


@pytest.mark.parametrize("name", ["A", "Router With Spaces", "Ünïcode"])
def test_create_accepts_a_range_of_names(api, name):
    body = api.create_router(name)
    assert body["name"] == name.strip()
    assert body["slug"]
