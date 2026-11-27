"""Shared pytest fixtures: isolated temp DB + settings, TestClient, logged-in clients."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

# Keep tests hermetic: never inherit a developer's .env.
os.environ.setdefault("TUNNELGATE_ENV_FILE", "/nonexistent/.env")

from fastapi.testclient import TestClient

from app.config import Settings, get_settings, set_settings_override
from app.db import init_db, reset_for_tests, session_scope
from app.main import create_app
from app.security import hash_password

ADMIN_PASSWORD = "admin-t3st-pass"


def make_settings(tmp_path: Path, **overrides) -> Settings:
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    params = {
        "env": "test",
        "db_url": "sqlite:///" + str(tmp_path / "test.db"),
        "data_dir": data,
        "authorized_keys_path": data / "authorized_keys",
        "proxy_routes_path": data / "tunnelgate.routes.conf",
        "panel_url": "http://testserver",
        "panel_host": "panel.test",
        "cookie_secure": False,
        "admin_password": ADMIN_PASSWORD,
        "login_rate_limit": 1000,
        "cookie_name": "tg_session",
        "port_min": 20000,
        "port_max": 20050,
        "console_port_min": 25000,
        "console_port_max": 25050,
        "console_enabled": True,
        "secret_key": "test-secret-key",
        "proxy_driver": "none",
        "ssh_host": "127.0.0.1",
        "ssh_port": 22,
        "ssh_user": "tunnelgate",
        "bootstrap_ttl_minutes": 15,
        "tunnel_poll_seconds": 3600,
        "require_health_for_online": False,
    }
    params.update(overrides)
    return Settings(**params)


@pytest.fixture()
def settings(tmp_path: Path) -> Iterator[Settings]:
    s = make_settings(tmp_path)
    set_settings_override(s)
    reset_for_tests()
    init_db(s.db_url)
    _reset_runtime_state()
    yield s
    reset_for_tests()
    set_settings_override(None)


@pytest.fixture()
def app(settings: Settings):
    return create_app(settings, use_monitor=False)


@pytest.fixture()
def client(app) -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def db(settings: Settings):
    with session_scope() as session:
        yield session


@pytest.fixture()
def admin_client(client: TestClient) -> TestClient:
    r = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    # The token is no longer in the JSON body: login puts it in the csrf cookie beside the
    # session cookie, and a mutating request has to carry both the cookie and the header.
    # TestClient persists set-cookie on the login response, so this is the same value the
    # browser would have; copying it into the header here is what the SPA does in api.ts.
    # TestClient already stored both cookies from the login response, so they carry the real
    # domain and path; setting them again here would add a second, domainless copy of the same
    # name and make cookies[...] raise CookieConflict on the next read.
    token = r.cookies[get_settings().csrf_cookie_name]
    client.headers[settings_csrf_header()] = token
    client.csrf_token = token  # type: ignore[attr-defined]
    client.user = r.json()["user"]  # type: ignore[attr-defined]
    return client


def _reset_runtime_state() -> None:
    """Clear module-level state (rate limiters, ticket stores) between tests."""
    import importlib

    for mod_name, attrs in (
        ("app.api.auth", ("LOGIN_LIMITER", "_LIMITER")),
        ("app.api.bootstrap", ("EXCHANGE_LIMITER",)),
        ("app.services.console", ("TICKETS", "SESSIONS")),
        ("app.services.launch", ("TICKETS",)),
    ):
        try:
            mod = importlib.import_module(mod_name)
        except Exception:  # pragma: no cover - module may not exist yet
            continue
        for attr in attrs:
            obj = getattr(mod, attr, None)
            if obj is not None and hasattr(obj, "clear"):
                obj.clear()
            elif obj is not None and hasattr(obj, "reset"):
                obj.reset()


def settings_csrf_header() -> str:
    from app.config import get_settings

    return get_settings().csrf_header


@pytest.fixture()
def api(admin_client: TestClient):
    """Thin helper around the admin client for creating routers in tests."""

    class Helper:
        def __init__(self, c: TestClient) -> None:
            self.c = c

        def create_router(self, name: str = "Router One", **kw):
            payload = {"name": name, **kw}
            r = self.c.post("/api/v1/routers", json=payload)
            assert r.status_code == 201, r.text
            return r.json()

        def exchange(self, token: str, report: dict | None = None):
            return self.c.post(
                "/api/v1/routers/bootstrap/exchange",
                headers={"X-Bootstrap-Token": token},
                json=report or {"hostname": "test-router", "openwrt_version": "23.05.5"},
            )

    return Helper(admin_client)


@pytest.fixture()
def make_user(settings: Settings):
    def _make(username: str, role: str = "viewer", password: str = "user-t3st-pass"):
        from app.models import User

        with session_scope() as s:
            u = User(username=username, role=role, password_hash=hash_password(password))
            s.add(u)
            s.flush()
            return u.id

    return _make


@pytest.fixture()
def tmp_authorized_keys(settings: Settings) -> Path:
    return Path(settings.authorized_keys_path)
