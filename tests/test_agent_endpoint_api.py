"""The three settings endpoints: who may call them, what they validate, what they persist.

The agent endpoint decides where freshly installed routers send their bootstrap token, so the
permissions here are the interesting part: admin-only, CSRF-guarded, audited, and the test route
must never persist what it probes.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.db import session_scope
from app.services import agent_endpoint

URL = "/api/v1/settings/agent-endpoint"


def csrf(client: TestClient) -> str:
    return client.headers[get_settings().csrf_header]


def login(client: TestClient, username: str, password: str) -> None:
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    data = r.json()
    client.headers[get_settings().csrf_header] = data["csrf_token"]


def stored_value():
    from app.models import PanelSetting

    with session_scope() as db:
        row = db.get(PanelSetting, agent_endpoint.AGENT_ENDPOINT_KEY)
        return row.value if row else None


# ------------------------------------------------------------------ reading
def test_get_reports_the_environment_value_and_its_source(admin_client) -> None:
    r = admin_client.get(URL)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["agent_url"] == "http://testserver"
    assert body["agent_endpoint"] == {
        "scheme": "http",
        "host": "testserver",
        "port": None,
        "source": "environment",
    }


def test_get_requires_a_session(client: TestClient) -> None:
    assert client.get(URL).status_code == 401


def test_get_is_admin_only(client: TestClient, make_user) -> None:
    make_user("viewer1", role="viewer")
    login(client, "viewer1", "user-t3st-pass")
    assert client.get(URL).status_code == 403


def test_config_endpoint_exposes_the_agent_url(admin_client) -> None:
    body = admin_client.get("/api/v1/config").json()
    assert body["agent_url"] == "http://testserver"
    assert body["agent_endpoint"]["source"] == "environment"
    assert body["agent_endpoint_testable"] is True


# ------------------------------------------------------------------ writing
def test_put_stores_an_override_and_reports_database(admin_client) -> None:
    r = admin_client.put(URL, json={"scheme": "https", "host": "panel.example.com", "port": 8443})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["agent_url"] == "https://panel.example.com:8443"
    assert body["agent_endpoint"]["source"] == "database"
    assert stored_value() is not None
    # And the value the SPA reads back on the next page load is the same one.
    assert admin_client.get(URL).json()["agent_endpoint"]["source"] == "database"


def test_put_requires_csrf(admin_client) -> None:
    admin_client.headers.pop(get_settings().csrf_header)
    r = admin_client.put(URL, json={"scheme": "https", "host": "panel.example.com", "port": None})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"


@pytest.mark.parametrize(
    ("payload", "field"),
    [
        ({"scheme": "https", "host": "bad host", "port": None}, "host"),
        ({"scheme": "ftp", "host": "panel.example.com", "port": None}, "scheme"),
        ({"scheme": "https", "host": "panel.example.com", "port": 70000}, "port"),
    ],
)
def test_put_returns_field_level_errors_the_spa_can_map(admin_client, payload, field) -> None:
    r = admin_client.put(URL, json=payload)
    assert r.status_code == 422, r.text
    body = r.json()
    assert body["error"]["code"] == "validation_error"
    locs = [f["loc"] for f in body["error"]["details"]["fields"]]
    # fieldErrors() in web/src/lib/api.ts keys by the first entry after "body".
    assert ["body", field] in locs
    assert stored_value() is None


def test_put_is_admin_only(client: TestClient, make_user) -> None:
    make_user("op1", role="operator")
    login(client, "op1", "user-t3st-pass")
    r = client.put(URL, json={"scheme": "https", "host": "panel.example.com", "port": None})
    assert r.status_code == 403


def test_delete_restores_the_environment_value(admin_client) -> None:
    admin_client.put(URL, json={"scheme": "https", "host": "moved.example.com", "port": None})
    r = admin_client.delete(URL)
    assert r.status_code == 200, r.text
    assert r.json()["agent_endpoint"]["source"] == "environment"
    assert stored_value() is None
    # Idempotent: a second reset is not an error.
    assert admin_client.delete(URL).status_code == 200


def test_delete_requires_csrf(admin_client) -> None:
    admin_client.headers.pop(get_settings().csrf_header)
    assert admin_client.delete(URL).status_code == 403


def test_writes_are_audited(admin_client) -> None:
    admin_client.put(URL, json={"scheme": "https", "host": "panel.example.com", "port": None})
    admin_client.delete(URL)
    body = admin_client.get("/api/v1/audit?limit=50").json()
    actions = [row["action"] for row in body["items"]]
    assert "settings.agent_endpoint.save" in actions
    assert "settings.agent_endpoint.reset" in actions


# ------------------------------------------------------------------ probing
def test_test_route_probes_and_persists_nothing(admin_client, monkeypatch) -> None:
    calls: list[str] = []

    def fake_probe(url, timeout=5.0):
        calls.append(url)
        return {
            "ok": True,
            "checked_url": url + "/api/v1/health",
            "status_code": 200,
            "latency_ms": 12,
            "error": None,
        }

    monkeypatch.setattr(agent_endpoint, "probe", fake_probe)
    r = admin_client.post(
        "/api/v1/settings/agent-endpoint/test",
        json={"scheme": "https", "host": "candidate.example.com", "port": None},
    )
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
    assert r.json()["checked_url"] == "https://candidate.example.com/api/v1/health"
    assert calls == ["https://candidate.example.com"]
    assert stored_value() is None
    # The effective endpoint did not move either.
    assert admin_client.get(URL).json()["agent_endpoint"]["source"] == "environment"


def test_test_route_reports_a_failure_without_a_500(admin_client, monkeypatch) -> None:
    def fake_probe(url, timeout=5.0):
        return {
            "ok": False,
            "checked_url": url + "/api/v1/health",
            "status_code": None,
            "latency_ms": None,
            "error": "connection refused",
        }

    monkeypatch.setattr(agent_endpoint, "probe", fake_probe)
    r = admin_client.post(
        "/api/v1/settings/agent-endpoint/test",
        json={"scheme": "https", "host": "nope.example.com", "port": None},
    )
    assert r.status_code == 200
    assert r.json()["ok"] is False
    assert r.json()["error"] == "connection refused"


def test_test_route_validates_before_probing(admin_client, monkeypatch) -> None:
    called = []
    monkeypatch.setattr(agent_endpoint, "probe", lambda *a, **k: called.append(a))
    r = admin_client.post(
        "/api/v1/settings/agent-endpoint/test",
        json={"scheme": "https", "host": "bad host", "port": None},
    )
    assert r.status_code == 422
    assert called == []


def test_test_route_is_admin_only(client: TestClient, make_user) -> None:
    make_user("viewer2", role="viewer")
    login(client, "viewer2", "user-t3st-pass")
    r = client.post(
        "/api/v1/settings/agent-endpoint/test",
        json={"scheme": "https", "host": "panel.example.com", "port": None},
    )
    assert r.status_code == 403
