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
    # The token is no longer in the body; login writes it to the csrf cookie and mutating
    # routes need it back in the header as well (double submit).
    client.headers[get_settings().csrf_header] = r.cookies[get_settings().csrf_cookie_name]


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
        "verify_tls": True,
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

    def fake_probe(url, timeout=5.0, *, verify_tls=True):
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
    def fake_probe(url, timeout=5.0, *, verify_tls=True):
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


# ------------------------------------------------------------------ TLS trust over the API
def test_get_reports_verification_on_by_default(admin_client) -> None:
    """The environment value has no TLS knob, so it reports the safe default."""
    body = admin_client.get(URL).json()
    assert body["agent_endpoint"]["verify_tls"] is True
    assert body["agent_endpoint"]["source"] == "environment"


def test_config_endpoint_exposes_the_tls_policy(admin_client) -> None:
    """The SPA reads /api/v1/config to render its banner, so the flag has to be there too."""
    body = admin_client.get("/api/v1/config").json()
    assert body["agent_endpoint"]["verify_tls"] is True


def test_put_stores_a_self_signed_acceptance_and_echoes_it(admin_client) -> None:
    r = admin_client.put(
        URL,
        json={
            "scheme": "https",
            "host": "self.example.com",
            "port": None,
            "verify_tls": False,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["agent_endpoint"]["verify_tls"] is False
    assert body["agent_endpoint"]["source"] == "database"
    # The URL is untouched by the policy: still a plain, pasteable address.
    assert body["agent_url"] == "https://self.example.com"
    # And it is what the SPA reads back on the next page load.
    assert admin_client.get(URL).json()["agent_endpoint"]["verify_tls"] is False


def test_put_defaults_to_verifying_when_the_field_is_omitted(admin_client) -> None:
    """A client that never learned about this field must not disable certificate checks."""
    r = admin_client.put(URL, json={"scheme": "https", "host": "plain.example.com", "port": None})
    assert r.status_code == 200, r.text
    assert r.json()["agent_endpoint"]["verify_tls"] is True


def test_http_overrides_a_submitted_false_rather_than_rejecting_it(admin_client) -> None:
    """Normalisation, not validation: the save succeeds and reports verification on.

    An http endpoint has no certificate to verify, so accepting the flag and reporting true is
    the honest answer; a 422 would reject a request that asked for nothing impossible.
    """
    r = admin_client.put(
        URL,
        json={
            "scheme": "http",
            "host": "plain.example.com",
            "port": None,
            "verify_tls": False,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["agent_endpoint"]["verify_tls"] is True


def test_an_http_stint_does_not_pin_verification_on_forever(admin_client) -> None:
    """The reported true for http is a report, not a one-way latch on the setting.

    An operator who temporarily switches to http (say, while nginx is being reconfigured) and
    then returns to https must be able to get back to the self-signed acceptance they chose.
    The row is normalised while it is http, so the SPA shows true there; re-submitting the
    choice restores it. This pins that the round trip is possible - if http silently wrote a
    permanent true, the operator would have no way back except clearing the row.
    """
    admin_client.put(
        URL,
        json={"scheme": "https", "host": "self.example.com", "port": None, "verify_tls": False},
    )
    admin_client.put(
        URL,
        json={"scheme": "http", "host": "self.example.com", "port": None, "verify_tls": False},
    )
    assert admin_client.get(URL).json()["agent_endpoint"]["verify_tls"] is True
    body = admin_client.put(
        URL,
        json={"scheme": "https", "host": "self.example.com", "port": None, "verify_tls": False},
    ).json()
    assert body["agent_endpoint"]["verify_tls"] is False


def test_delete_restores_verification(admin_client) -> None:
    admin_client.put(
        URL,
        json={"scheme": "https", "host": "self.example.com", "port": None, "verify_tls": False},
    )
    assert admin_client.get(URL).json()["agent_endpoint"]["verify_tls"] is False
    body = admin_client.delete(URL).json()
    assert body["agent_endpoint"]["source"] == "environment"
    assert body["agent_endpoint"]["verify_tls"] is True


def test_the_tls_decision_is_audited(admin_client) -> None:
    """Turning verification off is a security-relevant change and must leave a trace.

    While it is off, the router cannot tell this panel from an impostor, and the bootstrap and
    API tokens ride on that connection, so the audit row has to say what was decided.
    """
    import json

    from sqlalchemy import select

    from app.models import AuditLog

    admin_client.put(
        URL,
        json={"scheme": "https", "host": "self.example.com", "port": None, "verify_tls": False},
    )
    with session_scope() as db:
        row = (
            db.execute(
                select(AuditLog)
                .where(AuditLog.action == "settings.agent_endpoint.save")
                .order_by(AuditLog.id.desc())
            )
            .scalars()
            .first()
        )
        assert row is not None
        detail = json.loads(row.detail)
        assert detail["verify_tls"] is False


def test_the_test_route_probes_with_the_submitted_policy(admin_client, monkeypatch) -> None:
    """The probe must test what the operator is about to save."""
    seen: dict = {}

    def fake_probe(url, timeout=5.0, *, verify_tls=True):
        seen["url"] = url
        seen["verify_tls"] = verify_tls
        return {
            "ok": True,
            "checked_url": url + "/api/v1/health",
            "status_code": 200,
            "latency_ms": 8,
            "error": None,
        }

    monkeypatch.setattr(agent_endpoint, "probe", fake_probe)
    r = admin_client.post(
        "/api/v1/settings/agent-endpoint/test",
        json={
            "scheme": "https",
            "host": "self.example.com",
            "port": None,
            "verify_tls": False,
        },
    )
    assert r.status_code == 200, r.text
    assert seen["verify_tls"] is False
    # Nothing was persisted by a probe.
    assert stored_value() is None


def test_the_test_route_forces_verification_on_for_http(admin_client, monkeypatch) -> None:
    """An http candidate cannot be probed with verification off, because there is nothing to skip."""
    seen: dict = {}

    def fake_probe(url, timeout=5.0, *, verify_tls=True):
        seen["verify_tls"] = verify_tls
        return {
            "ok": True,
            "checked_url": url + "/api/v1/health",
            "status_code": 200,
            "latency_ms": 4,
            "error": None,
        }

    monkeypatch.setattr(agent_endpoint, "probe", fake_probe)
    r = admin_client.post(
        "/api/v1/settings/agent-endpoint/test",
        json={"scheme": "http", "host": "plain.example.com", "port": None, "verify_tls": False},
    )
    assert r.status_code == 200, r.text
    assert seen["verify_tls"] is True
