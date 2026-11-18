"""Bootstrap contract: the install script endpoint and the one-shot token exchange."""

from __future__ import annotations

from app.models import AuditLog, Router, RouterRuntime
from app.services import keys as keys_service


def _exchange(client, token, report=None):
    return client.post(
        "/api/v1/routers/bootstrap/exchange",
        headers={"X-Bootstrap-Token": token},
        json=report or {"hostname": "test-router", "openwrt_version": "23.05.5"},
    )


# --------------------------------------------------------------------------- install script
def test_install_requires_the_token_header(client):
    r = client.get("/api/v1/routers/install?os=linux")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_token"


def test_install_rejects_an_unknown_token(client):
    r = client.get("/api/v1/routers/install", headers={"X-Bootstrap-Token": "nope"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_token"


def test_install_serves_the_script_with_the_token_inlined(api, client, settings):
    created = api.create_router("Installable")
    r = client.get(
        "/api/v1/routers/install?os=linux",
        headers={"X-Bootstrap-Token": created["bootstrap_token"]},
    )
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/x-shellscript")
    assert r.headers["cache-control"] == "no-store"
    body = r.text
    assert "TG_PANEL_URL=" in body
    assert "TG_BOOTSTRAP_TOKEN=" in body
    assert "TG_OS_TYPE=" in body
    assert "http://testserver" in body
    # The token is embedded in the body, not in a URL the browser would log.
    assert created["bootstrap_token"] not in r.headers.get("location", "")


def test_install_rejects_an_unknown_os(api, client):
    created = api.create_router("OS Test")
    r = client.get(
        "/api/v1/routers/install?os=plan9",
        headers={"X-Bootstrap-Token": created["bootstrap_token"]},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "validation_error"


def test_install_token_works_until_it_is_exchanged(api, client):
    created = api.create_router("Reusable")
    for _ in range(3):
        r = client.get(
            "/api/v1/routers/install",
            headers={"X-Bootstrap-Token": created["bootstrap_token"]},
        )
        assert r.status_code == 200


# --------------------------------------------------------------------------- exchange
def test_exchange_hands_out_the_private_key_once(api, client, db):
    created = api.create_router("Exchanging")
    r = api.exchange(created["bootstrap_token"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["private_key"].startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert body["router_id"] == created["id"]
    assert body["slug"] == created["slug"]
    assert body["api_token"].startswith("tg_")
    assert body["heartbeat_url"].endswith(f"/api/v1/routers/{created['id']}/heartbeat")
    assert body["key_fingerprint"].startswith("SHA256:")
    assert body["server_time"].endswith("Z")
    # A second attempt with the same token must fail: it is single use.
    again = _exchange(client, created["bootstrap_token"])
    assert again.status_code == 401
    assert again.json()["error"]["code"] == "invalid_token"


def test_exchange_returns_ssh_tunnel_and_console_specs(api):
    created = api.create_router("Specified")
    body = api.exchange(created["bootstrap_token"]).json()
    assert body["ssh"]["host"] == "127.0.0.1"
    assert body["ssh"]["port"] == 22
    assert body["ssh"]["username"] == "tunnelgate"
    tunnel = body["tunnel"]
    assert 20000 <= tunnel["remote_port"] <= 20050
    assert tunnel["bind_address"] == "127.0.0.1"
    assert tunnel["router_http_port"] == 80
    assert tunnel["local_target"] == "127.0.0.1:80"
    assert tunnel["url"] == f"https://{created['slug']}.panel.test"
    console = body["console"]
    assert console["enabled"] is True
    assert console["ssh_user"] == "root"
    assert console["allowed_from"] == "127.0.0.1"
    assert 25000 <= console["console_port"] <= 25050
    assert console["target_port"] == 22
    assert console["authorized_keys_path"] == "/etc/dropbear/authorized_keys"
    assert console["shell"] == "/bin/ash"


def test_exchange_records_the_reported_metadata(api, db):
    created = api.create_router("Reported")
    report = {
        "hostname": "openwrt-lab",
        "model": "GL-MT3000",
        "openwrt_version": "23.05.5",
        "mac": "aa:bb:cc:dd:ee:ff",
        "uptime_seconds": 1234,
        "client_version": "1.0.0",
    }
    assert api.exchange(created["bootstrap_token"], report).status_code == 200
    db.expire_all()
    row = db.get(Router, created["id"])
    assert row.hostname == "openwrt-lab"
    assert row.model == "GL-MT3000"
    assert row.openwrt_version == "23.05.5"
    assert row.mac == "aa:bb:cc:dd:ee:ff"
    assert row.uptime_seconds == 1234
    assert row.client_version == "1.0.0"
    assert row.client_ip
    assert row.status == "awaiting"
    assert row.key_serial == 1


def test_exchange_api_token_authenticates_the_heartbeat(api, client, db):
    created = api.create_router("Heartbeatable")
    body = api.exchange(created["bootstrap_token"]).json()
    r = client.post(
        f"/api/v1/routers/{created['id']}/heartbeat",
        headers={"X-Api-Token": body["api_token"]},
        json={"hostname": "beating"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True


def test_exchange_writes_the_authorized_keys_line(api, db, settings, tmp_authorized_keys):
    created = api.create_router("On Disk")
    body = api.exchange(created["bootstrap_token"]).json()
    content = tmp_authorized_keys.read_text()
    assert "permitlisten" in content
    assert f'permitlisten="127.0.0.1:{body["tunnel"]["remote_port"]}"' in content
    assert f'permitlisten="127.0.0.1:{body["console"]["console_port"]}"' in content
    assert body["key_fingerprint"] in content or "ssh-ed25519" in content


def test_exchange_invalidates_older_tokens(api, admin_client, client, db):
    created = api.create_router("Twice")
    first_token = created["bootstrap_token"]
    # Asking for the script again issues a new token and retires the previous one.
    second = admin_client.get(f"/api/v1/routers/{created['id']}/script").json()
    assert second["bootstrap_token"] != first_token
    assert _exchange(client, first_token).status_code == 401
    assert _exchange(client, second["bootstrap_token"]).status_code == 200


def test_exchange_rejects_a_missing_header(client):
    r = client.post("/api/v1/routers/bootstrap/exchange", json={})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_token"


def test_expired_token_is_rejected_like_an_unknown_one(api, client, db, settings):
    created = api.create_router("Expiring")
    from app.config import utcnow
    from app.models import BootstrapToken

    row = db.query(BootstrapToken).filter_by(router_id=created["id"]).one()
    from datetime import timedelta

    row.expires_at = utcnow() - timedelta(minutes=1)
    db.commit()
    r = _exchange(client, created["bootstrap_token"])
    assert r.status_code == 401
    # Same code as unknown/used: the response must not distinguish the reason.
    assert r.json()["error"]["code"] == "invalid_token"


def test_exchange_is_audited(api, client, db):
    created = api.create_router("Audited Exchange")
    api.exchange(created["bootstrap_token"])
    db.expire_all()
    rows = db.query(AuditLog).filter_by(action="router.exchange").all()
    assert len(rows) == 1
    assert rows[0].router_id == created["id"]
    assert rows[0].outcome == "ok"


def test_exchange_throttles_repeated_failures(client, settings):
    # The limiter is module level and conftest clears it per test.
    from app.api import bootstrap as bootstrap_api

    bootstrap_api.EXCHANGE_LIMITER.clear()
    codes = []
    for _ in range(70):
        codes.append(_exchange(client, "bogus").status_code)
    assert 429 in codes
    # Everything before the limit is a 401, never a 200.
    assert 200 not in codes


def test_partial_report_is_accepted(api):
    created = api.create_router("Quiet")
    r = _exchange(api.c, created["bootstrap_token"], report={})
    assert r.status_code == 200


def test_exchange_without_a_report_body(api):
    created = api.create_router("No Body")
    r = api.c.post(
        "/api/v1/routers/bootstrap/exchange",
        headers={"X-Bootstrap-Token": created["bootstrap_token"]},
    )
    assert r.status_code == 200


def test_rotating_an_installed_router_keeps_its_ports(api, admin_client, db, settings):
    created = api.create_router("Keeps Ports")
    first = api.exchange(created["bootstrap_token"]).json()
    port = first["tunnel"]["remote_port"]
    console_port = first["console"]["console_port"]
    rotate = admin_client.post(f"/api/v1/routers/{created['id']}/rotate-key").json()
    second = api.exchange(rotate["bootstrap_token"]).json()
    assert second["tunnel"]["remote_port"] == port
    assert second["console"]["console_port"] == console_port
    db.expire_all()
    row = db.get(Router, created["id"])
    assert row.key_serial == 2
    assert row.revoked_at is None


def test_console_spec_port_is_zero_when_console_is_disabled(api, client, settings, db):
    settings.console_enabled = False
    created = api.create_router("No Console")
    body = api.exchange(created["bootstrap_token"]).json()
    assert body["console"]["enabled"] is False
    db.expire_all()
    row = db.get(Router, created["id"])
    assert row.console_port is None
    assert body["tunnel"]["remote_port"] is not None


def test_exchange_does_not_fabricate_a_runtime_row(api, db):
    created = api.create_router("Runtime")
    api.exchange(created["bootstrap_token"])
    db.expire_all()
    # RouterRuntime is owned by the monitor: it records what was OBSERVED. An exchange only
    # proves the router installed itself, so inventing tunnel_present=False here would be a lie
    # the monitor then has to correct on its first cycle.
    assert db.get(RouterRuntime, created["id"]) is None


def test_api_token_is_derived_from_the_public_key(api, db):
    created = api.create_router("Derived")
    body = api.exchange(created["bootstrap_token"]).json()
    db.expire_all()
    row = db.get(Router, created["id"])
    assert body["api_token"] == keys_service.api_token(row.public_key)


def test_exchange_rejects_a_used_token_even_for_the_same_router(api, client):
    created = api.create_router("Single Use")
    assert api.exchange(created["bootstrap_token"]).status_code == 200
    for _ in range(2):
        assert _exchange(client, created["bootstrap_token"]).status_code == 401


def test_install_returns_503_when_the_agent_script_is_missing(api, client, monkeypatch):
    from app.services import bootstrap as bootstrap_service

    monkeypatch.setattr(
        bootstrap_service,
        "load_install_script",
        lambda: (_ for _ in ()).throw(
            __import__("app.errors", fromlist=["ApiError"]).ApiError(
                503, "install_script_missing", "missing"
            )
        ),
    )
    created = api.create_router("No Script")
    r = client.get(
        "/api/v1/routers/install",
        headers={"X-Bootstrap-Token": created["bootstrap_token"]},
    )
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "install_script_missing"


# --------------------------------------------------------------------------- per-token limit (F6)
def _fetch_script(client, token, os_name="linux"):
    return client.get(
        "/api/v1/routers/install?os=" + os_name,
        headers={"X-Bootstrap-Token": token},
    )


def test_install_script_renders_are_capped_per_token(api, client):
    """A token may be rendered a handful of times, then it is throttled.

    The per-address limiter is not enough: the install endpoint re-renders for the whole life of
    the token and every render echoes the live single-use credential, so an attacker rotating
    source addresses could keep pulling it.
    """
    from app.api import bootstrap as bootstrap_api

    bootstrap_api.SCRIPT_LIMITER.clear()
    created = api.create_router("Renderable")
    token = created["bootstrap_token"]

    for attempt in range(bootstrap_api.SCRIPT_LIMIT):
        r = _fetch_script(client, token)
        assert r.status_code == 200, (attempt, r.text)

    blocked = _fetch_script(client, token)
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "rate_limited"
    assert int(blocked.headers["Retry-After"]) > 0
    assert blocked.json()["error"]["details"]["retry_after_seconds"] > 0


def test_install_script_limit_is_per_token_not_global(api, client):
    """Burning one token quota must not lock out a different router token."""
    from app.api import bootstrap as bootstrap_api

    bootstrap_api.SCRIPT_LIMITER.clear()
    first = api.create_router("First")
    second = api.create_router("Second")

    for _ in range(bootstrap_api.SCRIPT_LIMIT):
        assert _fetch_script(client, first["bootstrap_token"]).status_code == 200
    assert _fetch_script(client, first["bootstrap_token"]).status_code == 429

    other = _fetch_script(client, second["bootstrap_token"])
    assert other.status_code == 200, other.text


def test_unknown_token_does_not_burn_a_real_token_budget(api, client):
    """The limiter is keyed by the token, so a bogus one can only throttle itself."""
    from app.api import bootstrap as bootstrap_api

    bootstrap_api.SCRIPT_LIMITER.clear()
    created = api.create_router("Untouched")
    token = created["bootstrap_token"]

    for _ in range(bootstrap_api.SCRIPT_LIMIT + 2):
        assert _fetch_script(client, "not-a-real-token").status_code == 401

    assert _fetch_script(client, token).status_code == 200


def test_exchange_is_not_affected_by_the_script_limiter(api, client):
    """The two limiters are separate; exhausting renders must not block the exchange."""
    from app.api import bootstrap as bootstrap_api

    bootstrap_api.SCRIPT_LIMITER.clear()
    created = api.create_router("Exchanger")
    token = created["bootstrap_token"]

    for _ in range(bootstrap_api.SCRIPT_LIMIT):
        assert _fetch_script(client, token).status_code == 200
    assert _fetch_script(client, token).status_code == 429

    r = _exchange(client, token)
    assert r.status_code == 200, r.text
