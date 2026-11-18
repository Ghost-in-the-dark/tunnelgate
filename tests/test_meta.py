"""Meta endpoints, and the hardening that applies to the whole app (F3 CORS, F7 docs)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


# --------------------------------------------------------------------------- health
def test_health_needs_no_auth_and_reports_a_version(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"]
    assert body["time"].endswith("Z")


def test_config_requires_a_session(client):
    assert client.get("/api/v1/config").status_code == 401


def test_stats_requires_a_session(client):
    assert client.get("/api/v1/stats").status_code == 401


# --------------------------------------------------------------------------- docs gating (F7)
def _client_for(settings, monkeypatch, **overrides):
    for key, value in overrides.items():
        monkeypatch.setattr(settings, key, value)
    app = create_app(settings, use_monitor=False)
    return TestClient(app)


def test_docs_are_served_outside_production(settings, monkeypatch):
    monkeypatch.setattr(settings, "env", "test")
    monkeypatch.setattr(settings, "docs_enabled", None)
    with _client_for(settings, monkeypatch) as c:
        assert c.get("/api/docs").status_code == 200
        assert c.get("/api/openapi.json").status_code == 200


@pytest.mark.parametrize("env_name", ["production", "prod", "PRODUCTION"])
def test_docs_are_closed_in_production(settings, monkeypatch, env_name):
    """An unauthenticated schema advertises every route and field: recon for free."""
    monkeypatch.setattr(settings, "env", env_name)
    monkeypatch.setattr(settings, "docs_enabled", None)
    with _client_for(settings, monkeypatch) as c:
        # FastAPI stops routing these paths at all, so the request falls through to the error
        # handler: a 404 envelope, not a schema. (The SPA catch-all never sees /api/.)
        schema = c.get("/api/openapi.json")
        assert schema.status_code == 404, schema.text
        assert "openapi" not in schema.json()
        assert schema.json()["error"]["code"] == "not_found"
        assert c.get("/api/docs").status_code == 404


def test_docs_enabled_forces_the_schema_off(settings, monkeypatch):
    monkeypatch.setattr(settings, "env", "test")
    monkeypatch.setattr(settings, "docs_enabled", False)
    with _client_for(settings, monkeypatch) as c:
        assert c.get("/api/openapi.json").status_code == 404
        assert c.get("/api/docs").status_code == 404


def test_docs_enabled_forces_the_schema_on_in_production(settings, monkeypatch):
    """The explicit override wins both ways, so operators can diagnose a live deployment."""
    monkeypatch.setattr(settings, "env", "production")
    monkeypatch.setattr(settings, "docs_enabled", True)
    with _client_for(settings, monkeypatch) as c:
        assert c.get("/api/docs").status_code == 200
        assert c.get("/api/openapi.json").status_code == 200


# --------------------------------------------------------------------------- CORS (F3)
def test_wildcard_origin_with_credentials_is_refused_at_startup(settings, monkeypatch):
    """allow_credentials=True + "*" lets any site read authenticated responses."""
    monkeypatch.setattr(settings, "cors_origins", ["*"])
    with pytest.raises(ValueError, match="explicit origins"):
        create_app(settings, use_monitor=False)


def test_no_cors_middleware_without_configured_origins(settings, monkeypatch):
    monkeypatch.setattr(settings, "cors_origins", [])
    with _client_for(settings, monkeypatch) as c:
        r = c.get("/api/v1/health", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in r.headers


def test_explicit_origin_gets_credentialed_cors(settings, monkeypatch):
    monkeypatch.setattr(settings, "cors_origins", ["https://panel.example"])
    with _client_for(settings, monkeypatch) as c:
        r = c.get("/api/v1/health", headers={"Origin": "https://panel.example"})
        assert r.headers["access-control-allow-origin"] == "https://panel.example"
        assert r.headers["access-control-allow-credentials"] == "true"


def test_unlisted_origin_is_not_reflected(settings, monkeypatch):
    monkeypatch.setattr(settings, "cors_origins", ["https://panel.example"])
    with _client_for(settings, monkeypatch) as c:
        r = c.get("/api/v1/health", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in r.headers


def test_preflight_does_not_allow_a_wildcard_method(settings, monkeypatch):
    monkeypatch.setattr(settings, "cors_origins", ["https://panel.example"])
    with _client_for(settings, monkeypatch) as c:
        r = c.options(
            "/api/v1/routers",
            headers={
                "Origin": "https://panel.example",
                "Access-Control-Request-Method": "TRACE",
            },
        )
        allowed = r.headers.get("access-control-allow-methods", "")
        assert "TRACE" not in allowed
        assert "*" not in allowed


def test_preflight_allows_the_csrf_header(settings, monkeypatch):
    """The browser must be able to preflight X-CSRF-Token or every mutation is blocked."""
    monkeypatch.setattr(settings, "cors_origins", ["https://panel.example"])
    with _client_for(settings, monkeypatch) as c:
        r = c.options(
            "/api/v1/routers",
            headers={
                "Origin": "https://panel.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "X-CSRF-Token",
            },
        )
        assert "x-csrf-token" in r.headers.get("access-control-allow-headers", "").lower()


@pytest.mark.parametrize("raw_origin", ["*", " * ", "\t*\n"])
def test_padded_wildcard_origin_is_also_refused(settings, monkeypatch, raw_origin):
    """The guard must run on the stripped list, or " * " reaches CORSMiddleware as "*"."""
    monkeypatch.setattr(settings, "cors_origins", [raw_origin])
    with pytest.raises(ValueError, match="explicit origins"):
        create_app(settings, use_monitor=False)


def test_wildcard_among_explicit_origins_is_refused(settings, monkeypatch):
    monkeypatch.setattr(settings, "cors_origins", ["https://panel.example", " *"])
    with pytest.raises(ValueError, match="explicit origins"):
        create_app(settings, use_monitor=False)


def test_blank_origins_do_not_add_cors(settings, monkeypatch):
    """A list of empty strings must not be treated as "cors configured"."""
    monkeypatch.setattr(settings, "cors_origins", ["", "   "])
    with _client_for(settings, monkeypatch) as c:
        r = c.get("/api/v1/health", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in r.headers
