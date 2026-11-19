"""Bootstrap contract: the install script endpoint and the one-shot token exchange."""

from __future__ import annotations

import base64
import json
from pathlib import Path

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


# ------------------------------------------------- token channels (contract sections 1-2)
def _basic(token: str) -> dict[str, str]:
    """The credential uclient-fetch sends for --user=TOKEN --password=""."""
    encoded = base64.b64encode(f"{token}:".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def test_install_accepts_the_token_as_the_basic_username(api, client):
    """Stock OpenWrt has no curl and no --header before 24.10, so Basic is the only channel."""
    created = api.create_router("Basic Install")
    r = client.get("/api/v1/routers/install?os=linux", headers=_basic(created["bootstrap_token"]))
    assert r.status_code == 200, r.text
    assert "TG_BOOTSTRAP_TOKEN=" in r.text


def test_install_ignores_the_password_half_of_basic_auth(api, client):
    """The protocol is user=token; the password is a placeholder a device may fill with anything."""
    created = api.create_router("Basic Password")
    encoded = base64.b64encode(f"{created['bootstrap_token']}:hunter2".encode()).decode()
    r = client.get("/api/v1/routers/install", headers={"Authorization": f"Basic {encoded}"})
    assert r.status_code == 200, r.text


def test_basic_and_header_share_one_render_quota(api, client):
    """Switching channels must not reset the per-token budget."""
    from app.api import bootstrap as bootstrap_api

    bootstrap_api.SCRIPT_LIMITER.clear()
    created = api.create_router("Channel Swap")
    token = created["bootstrap_token"]

    for _ in range(bootstrap_api.SCRIPT_LIMIT):
        assert _fetch_script(client, token).status_code == 200
    # Same token, different channel: still exhausted.
    assert client.get("/api/v1/routers/install", headers=_basic(token)).status_code == 429


def test_malformed_authorization_is_a_401_not_a_server_error(client):
    """A garbage header runs before authentication, so it must never raise."""
    for header in (
        "Basic !!!not-base64",
        "Basic bm9jb2xvbg==",  # "nocolon"
        "Digest username=admin",
        "Basic",
        "Basic ",
        "",
    ):
        r = client.get("/api/v1/routers/install", headers={"Authorization": header})
        assert r.status_code == 401, (header, r.status_code, r.text)


def test_install_401_carries_the_basic_challenge(client):
    """Without the challenge uclient-fetch never retries with the credentials it was given."""
    r = client.get("/api/v1/routers/install")
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == 'Basic realm="tunnelgate"'


def test_install_unknown_token_401_also_carries_the_challenge(client):
    r = client.get("/api/v1/routers/install", headers=_basic("not-a-real-token"))
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == 'Basic realm="tunnelgate"'


# ------------------------------------------------- exchange: three channels, lenient body
def test_exchange_accepts_the_token_as_the_basic_username(api, client):
    created = api.create_router("Basic Exchange")
    r = client.post(
        "/api/v1/routers/bootstrap/exchange",
        headers=_basic(created["bootstrap_token"]),
        json={"hostname": "openwrt-lab"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["api_token"].startswith("tg_")


def test_exchange_accepts_the_token_in_the_body(api, client):
    created = api.create_router("Body Token")
    r = client.post(
        "/api/v1/routers/bootstrap/exchange",
        json={"bootstrap_token": created["bootstrap_token"], "hostname": "openwrt-lab"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["router_id"] == created["id"]


def test_exchange_reports_fields_sent_alongside_the_body_token(api, client, db):
    created = api.create_router("Body Report")
    r = client.post(
        "/api/v1/routers/bootstrap/exchange",
        json={
            "bootstrap_token": created["bootstrap_token"],
            "hostname": "from-body",
            "openwrt_version": "23.05.5",
        },
    )
    assert r.status_code == 200, r.text
    db.expire_all()
    assert db.get(Router, created["id"]).hostname == "from-body"


def test_exchange_accepts_a_form_content_type(api, client):
    """uclient-fetch always sends this content type with unchanged JSON body bytes."""
    created = api.create_router("Form Typed")
    r = client.post(
        "/api/v1/routers/bootstrap/exchange",
        content=json.dumps({"hostname": "openwrt-lab"}).encode(),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            **_basic(created["bootstrap_token"]),
        },
    )
    assert r.status_code == 200, r.text


def test_exchange_accepts_a_chunked_form_post(api, client):
    """uclient-fetch also always uses chunked transfer encoding."""
    created = api.create_router("Chunked")
    r = client.post(
        "/api/v1/routers/bootstrap/exchange",
        content=json.dumps({"hostname": "openwrt-lab"}).encode(),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Transfer-Encoding": "chunked",
            **_basic(created["bootstrap_token"]),
        },
    )
    assert r.status_code == 200, r.text


def test_exchange_treats_an_unparsable_body_as_no_report(api, client):
    """A body that does not parse is "the router told us nothing", never a 422."""
    created = api.create_router("Garbage Body")
    r = client.post(
        "/api/v1/routers/bootstrap/exchange",
        content=b"\x00\xff this is not json",
        headers=_basic(created["bootstrap_token"]),
    )
    assert r.status_code == 200, r.text


def test_exchange_treats_a_non_object_body_as_no_report(api, client):
    created = api.create_router("Array Body")
    r = client.post(
        "/api/v1/routers/bootstrap/exchange",
        content=b'["not", "an", "object"]',
        headers=_basic(created["bootstrap_token"]),
    )
    assert r.status_code == 200, r.text


def test_exchange_degrades_an_invalid_field_instead_of_rejecting(api, client, db):
    """One out-of-range field must not burn the token: keep the fields that fit."""
    created = api.create_router("Partial Report")
    r = client.post(
        "/api/v1/routers/bootstrap/exchange",
        content=json.dumps({"hostname": "kept", "uptime_seconds": -5}).encode(),
        headers=_basic(created["bootstrap_token"]),
    )
    assert r.status_code == 200, r.text
    db.expire_all()
    row = db.get(Router, created["id"])
    assert row.hostname == "kept"
    assert row.uptime_seconds in (None, 0)


def test_exchange_401_carries_the_basic_challenge(api, client):
    r = client.post("/api/v1/routers/bootstrap/exchange", json={})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == 'Basic realm="tunnelgate"'

    created = api.create_router("Used Token")
    api.exchange(created["bootstrap_token"])
    again = client.post(
        "/api/v1/routers/bootstrap/exchange",
        headers=_basic(created["bootstrap_token"]),
        json={},
    )
    assert again.status_code == 401
    assert again.headers["www-authenticate"] == 'Basic realm="tunnelgate"'


# ------------------------------------------------- body token must be a string
def test_exchange_ignores_a_non_string_body_token(api, client):
    """A JSON object in the token field is malformed input, not a credential to stringify."""
    api.create_router("Object Token")
    r = client.post(
        "/api/v1/routers/bootstrap/exchange",
        json={"bootstrap_token": {"$ne": None}, "hostname": "x"},
    )
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == 'Basic realm="tunnelgate"'


# ------------------------------------- wire shapes measured on stock OpenWrt (Lead's capture)
def _basic_raw(payload: str) -> dict[str, str]:
    """A Basic header from a raw payload, colon or not - exactly what the device put on the wire."""
    return {"Authorization": "Basic " + base64.b64encode(payload.encode()).decode()}


def test_install_accepts_the_colon_less_basic_payload(api, client):
    """The real shape uclient-fetch sends: base64(TOKEN) with NO colon.

    Captured from OpenWrt 19.07.10/22.03.7/23.05.5/24.10.1. Before this was accepted the
    parser discarded the payload as "no token" and every stock device got 401 forever.
    """
    created = api.create_router("Colonless Install")
    r = client.get("/api/v1/routers/install", headers=_basic_raw(created["bootstrap_token"]))
    assert r.status_code == 200, r.text
    assert "TG_BOOTSTRAP_TOKEN=" in r.text


def test_exchange_accepts_the_colon_less_basic_payload(api, client):
    created = api.create_router("Colonless Exchange")
    r = client.post(
        "/api/v1/routers/bootstrap/exchange",
        headers=_basic_raw(created["bootstrap_token"]),
        json={"hostname": "openwrt-lab"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["api_token"].startswith("tg_")


def test_install_rejects_a_basic_payload_with_only_a_password(client):
    """:pass" has an empty username - a device authenticating as nobody."""
    r = client.get("/api/v1/routers/install", headers=_basic_raw(":tunnelgate"))
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == 'Basic realm="tunnelgate"'


# ------------------------------------------------------- the TLS policy in the installer header
def _rendered_header(verify_tls: bool, settings) -> str:
    """Render the installer with a chosen TLS policy, without touching the database.

    The policy is read from the effective endpoint, so patching that resolver is the narrowest
    way to drive the branch: no row to write and no HTTP involved.
    """
    from app.services import agent_endpoint as agent_endpoint_service
    from app.services import bootstrap as bootstrap_service
    from app.services.agent_endpoint import AgentEndpoint

    original = agent_endpoint_service.effective
    agent_endpoint_service.effective = lambda db=None, s=None: AgentEndpoint(
        "https", "panel.example.com", None, "database", verify_tls
    )
    try:
        script = bootstrap_service.render_install_script("tok-abc", "linux", settings)
    finally:
        agent_endpoint_service.effective = original
    return script.split("# ------------------------------")[0]


def test_the_installer_header_carries_tg_tls_verify_1(settings) -> None:
    """Always emitted, never omitted when it is 1.

    The agent reads TG_TLS_VERIFY unconditionally, so a missing line would be indistinguishable
    from "the panel predates this field" and the agent would have to guess.
    """
    header = _rendered_header(True, settings)
    assert "TG_TLS_VERIFY='1'" in header


def test_the_installer_header_carries_tg_tls_verify_0(settings) -> None:
    header = _rendered_header(False, settings)
    assert "TG_TLS_VERIFY='0'" in header


def test_the_tls_line_is_a_shell_assignment_next_to_the_others(settings) -> None:
    """Same shape as the other three injected values: quoted, one word, inside the header block."""
    header = _rendered_header(False, settings)
    lines = header.splitlines()
    tls_lines = [ln for ln in lines if ln.startswith("TG_TLS_VERIFY=")]
    assert len(tls_lines) == 1
    assert tls_lines[0].startswith("TG_TLS_VERIFY='")
    assert "TG_PANEL_URL=" in header
    assert "TG_BOOTSTRAP_TOKEN=" in header
    assert "TG_OS_TYPE=" in header


def test_the_served_script_starts_with_the_shebang_then_the_sentinel(settings) -> None:
    """Line 1 must be the shebang and line 2 the installer's own identifying comment.

    Order matters mechanically, not cosmetically. The kernel only honours a shebang at offset 0,
    so a served script whose first line is the injected comment block is not executable as a
    file: the caller's shell interprets it instead, which is why `sh -n` and every
    "does it parse" test kept passing while the real install was broken. Keeping the sentinel on
    line 2 matters for the same reason one level down - the installer's own head-check
    (agent/install.sh::check_self) greps a bounded window for it, and a header that grows must not
    be able to push it out of that window.
    """
    from app.services.bootstrap import render_install_script

    script = render_install_script("tok-abc", "linux", settings)
    lines = script.splitlines()
    assert lines[0] == "#!/bin/sh", (
        "line 1 must be the shebang: a shebang anywhere else is a comment"
    )
    assert "TunnelGate router agent installer" in lines[1], (
        "line 2 must be the installer's sentinel comment, ahead of the injected block"
    )
    # And the injected block really did land after those two lines, not instead of them.
    assert lines[2] == "# --- injected by the panel ---"
    assert any(ln.startswith("TG_PANEL_URL=") for ln in lines[2:9])


def test_the_served_script_is_executable_directly_not_just_under_sh(
    settings, tmp_path: Path
) -> None:
    """The check that would have caught the shipped bug: exec the file, do not hand it to sh.

    Under `sh <file>` the shebang is irrelevant - the shell is already chosen. Only a direct
    exec proves the kernel found the interpreter, which is the thing an operator gets when they
    download the script and run it. The host is not OpenWrt, so the expected failure is the
    OpenWrt guard; "Exec format error" or the install-self-check error both mean the ordering
    regressed.
    """
    import subprocess

    from app.services.bootstrap import render_install_script

    script = render_install_script("tok-abc", "linux", settings)
    path = tmp_path / "install.sh"
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)
    try:
        result = subprocess.run([str(path)], capture_output=True, text=True, timeout=120)
    except OSError as exc:
        raise AssertionError(
            f"the served script cannot be executed as a file ({exc}): the shebang is not on line 1"
        ) from exc
    combined = result.stdout + result.stderr
    assert "Exec format error" not in combined, f"the shebang is not on line 1: {combined!r}"
    assert "does not look like the TunnelGate installer" not in combined, (
        f"the installer rejected its own served copy: {combined!r}"
    )
    # Which guard speaks first depends on who is running: check_root precedes check_openwrt, so
    # a CI runner (non-root) gets the root objection and a root shell gets the OpenWrt one. Both
    # prove the same thing - the kernel found the interpreter and the script ran - so accept
    # either rather than pinning the order of two independent guards.
    assert "not look like OpenWrt" in combined or "must run as root" in combined, (
        f"executing the served file directly never reached a TunnelGate guard: {combined!r}"
    )


def test_the_rendered_installer_still_parses_in_both_modes(settings) -> None:
    """A new header line must not break busybox ash, and the body after it must stay intact."""
    import shutil
    import subprocess
    import tempfile

    from app.services import agent_endpoint as agent_endpoint_service
    from app.services import bootstrap as bootstrap_service
    from app.services.agent_endpoint import AgentEndpoint

    shell = shutil.which("sh")
    assert shell
    original = agent_endpoint_service.effective
    try:
        for verify_tls in (True, False):
            agent_endpoint_service.effective = lambda db=None, s=None, v=verify_tls: AgentEndpoint(
                "https", "panel.example.com", None, "database", v
            )
            script = bootstrap_service.render_install_script("tok-abc", "linux", settings)
            with tempfile.TemporaryDirectory() as tmpdir:
                path = tmpdir + "/install.sh"
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(script)
                result = subprocess.run([shell, "-n", path], capture_output=True, text=True)
            assert result.returncode == 0, (verify_tls, result.stderr)
    finally:
        agent_endpoint_service.effective = original


def test_install_serves_the_tls_policy_it_rendered(api, client) -> None:
    """End to end: a fresh install with verification on announces 1, not 0 or nothing."""
    created = api.create_router("TLS Header")
    r = client.get(
        "/api/v1/routers/install?os=linux",
        headers={"X-Bootstrap-Token": created["bootstrap_token"]},
    )
    assert r.status_code == 200, r.text
    assert "TG_TLS_VERIFY='1'" in r.text
    assert "TG_TLS_VERIFY='0'" not in r.text
