"""Heartbeat contract: three token channels, a lenient body, and what a heartbeat may not do.

The endpoint is router-facing, so it is exercised the way a stock OpenWrt device would call it:
no curl, no custom headers, credentials in the URL userinfo or in an HTTP Basic header.
"""

from __future__ import annotations

import base64
import json

from app.models import Router, RouterRuntime


def _basic(token: str) -> dict[str, str]:
    encoded = base64.b64encode(f"{token}:".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def _install(api, client, name: str = "Beating") -> dict:
    """Create a router and take it through the exchange, returning the exchange payload."""
    created = api.create_router(name)
    r = api.exchange(created["bootstrap_token"])
    assert r.status_code == 200, r.text
    return {"id": created["id"], **r.json()}


def _beat(client, router_id: str, headers=None, body=None, **kw):
    return client.post(
        f"/api/v1/routers/{router_id}/heartbeat",
        headers=headers or {},
        json=body if body is not None else {"hostname": "beating"},
        **kw,
    )


# --------------------------------------------------------------------------- token channels
def test_heartbeat_accepts_the_header_token(api, client):
    installed = _install(api, client)
    r = _beat(client, installed["id"], headers={"X-Api-Token": installed["api_token"]})
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True


def test_heartbeat_accepts_the_token_as_the_basic_username(api, client):
    """The channel a stock OpenWrt device actually has."""
    installed = _install(api, client)
    r = _beat(client, installed["id"], headers=_basic(installed["api_token"]))
    assert r.status_code == 200, r.text


def test_heartbeat_accepts_the_token_in_the_body(api, client):
    installed = _install(api, client)
    r = _beat(
        client,
        installed["id"],
        body={"api_token": installed["api_token"], "hostname": "from-body"},
    )
    assert r.status_code == 200, r.text


def test_heartbeat_ignores_the_password_half_of_basic_auth(api, client):
    installed = _install(api, client)
    encoded = base64.b64encode(f"{installed['api_token']}:ignored".encode()).decode()
    r = _beat(client, installed["id"], headers={"Authorization": f"Basic {encoded}"})
    assert r.status_code == 200, r.text


def test_heartbeat_header_wins_over_body_token(api, client):
    """A body token must not be able to override a header that already authenticated."""
    installed = _install(api, client)
    r = _beat(
        client,
        installed["id"],
        headers={"X-Api-Token": installed["api_token"]},
        body={"api_token": "tg_not-a-real-token"},
    )
    assert r.status_code == 200, r.text


def test_heartbeat_rejects_a_wrong_token(api, client):
    installed = _install(api, client)
    r = _beat(client, installed["id"], headers={"X-Api-Token": "tg_wrong"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_api_token"


def test_heartbeat_401_carries_the_basic_challenge(api, client):
    """Without the challenge uclient-fetch never retries with the credentials it has."""
    installed = _install(api, client)
    r = _beat(client, installed["id"], headers={"X-Api-Token": "tg_wrong"})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == 'Basic realm="tunnelgate"'


def test_heartbeat_unknown_router_also_challenges(client):
    r = _beat(client, "no-such-router", headers={"X-Api-Token": "tg_anything"})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == 'Basic realm="tunnelgate"'


def test_heartbeat_rejects_a_malformed_authorization_header(api, client):
    installed = _install(api, client)
    for header in ("Basic !!!not-base64", "Basic bm9jb2xvbg==", "Bearer abc", "Basic", ""):
        r = _beat(client, installed["id"], headers={"Authorization": header})
        assert r.status_code == 401, (header, r.status_code)


# --------------------------------------------------------------------------- lenient bodies
def test_heartbeat_accepts_a_form_content_type(api, client):
    installed = _install(api, client)
    r = client.post(
        f"/api/v1/routers/{installed['id']}/heartbeat",
        content=json.dumps({"hostname": "openwrt-lab"}).encode(),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            **_basic(installed["api_token"]),
        },
    )
    assert r.status_code == 200, r.text


def test_heartbeat_accepts_a_chunked_form_post(api, client):
    installed = _install(api, client)
    r = client.post(
        f"/api/v1/routers/{installed['id']}/heartbeat",
        content=json.dumps({"hostname": "openwrt-lab"}).encode(),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Transfer-Encoding": "chunked",
            **_basic(installed["api_token"]),
        },
    )
    assert r.status_code == 200, r.text


def test_heartbeat_treats_an_unparsable_body_as_no_report(api, client, db):
    installed = _install(api, client)
    r = client.post(
        f"/api/v1/routers/{installed['id']}/heartbeat",
        content=b"not json at all",
        headers=_basic(installed["api_token"]),
    )
    assert r.status_code == 200, r.text
    # The beat still counts: last_heartbeat_at moved even though nothing was reported.
    db.expire_all()
    assert db.get(Router, installed["id"]).last_heartbeat_at is not None


def test_heartbeat_degrades_an_invalid_field(api, client, db):
    installed = _install(api, client)
    r = client.post(
        f"/api/v1/routers/{installed['id']}/heartbeat",
        content=json.dumps({"hostname": "kept", "uptime_seconds": -5}).encode(),
        headers=_basic(installed["api_token"]),
    )
    assert r.status_code == 200, r.text
    db.expire_all()
    assert db.get(Router, installed["id"]).hostname == "kept"


def test_heartbeat_copies_reported_metadata(api, client, db):
    installed = _install(api, client)
    r = _beat(
        client,
        installed["id"],
        headers=_basic(installed["api_token"]),
        body={
            "hostname": "openwrt-lab",
            "model": "GL-MT3000",
            "openwrt_version": "23.05.5",
            "mac": "aa:bb:cc:dd:ee:ff",
            "uptime_seconds": 4321,
            "client_version": "1.0.0",
        },
    )
    assert r.status_code == 200, r.text
    db.expire_all()
    row = db.get(Router, installed["id"])
    assert row.hostname == "openwrt-lab"
    assert row.model == "GL-MT3000"
    assert row.uptime_seconds == 4321


# --------------------------------------------------------------------------- what it may not do
def test_heartbeat_cannot_mark_a_router_online(api, client, db):
    """The contract's hardest rule: "online" means an observed listener, not a claim."""
    installed = _install(api, client)
    db.expire_all()
    assert db.get(Router, installed["id"]).status == "awaiting"

    r = _beat(client, installed["id"], headers=_basic(installed["api_token"]))
    assert r.status_code == 200, r.text

    db.expire_all()
    assert db.get(Router, installed["id"]).status == "awaiting"
    assert r.json()["status"] == "awaiting"


def test_heartbeat_promotes_awaiting_when_a_listener_is_observed(api, client, db):
    installed = _install(api, client)
    db.expire_all()
    row = db.get(Router, installed["id"])
    row.runtime = RouterRuntime(router_id=row.id, tunnel_present=True)
    db.commit()

    r = _beat(client, installed["id"], headers=_basic(installed["api_token"]))
    assert r.status_code == 200, r.text
    db.expire_all()
    assert db.get(Router, installed["id"]).status == "online"


def _issue_console_key(db, router_id: str) -> None:
    """Mint the panel's console key the way opening a console does, without the HTTP dance."""
    from app.services import keys as keys_service

    db.expire_all()
    keys_service.issue_console_key(db, db.get(Router, router_id))
    db.commit()


def test_heartbeat_delivers_the_console_registration_once(api, client, db):
    """The registration is advertised until the router says it wrote the key."""
    installed = _install(api, client)
    _issue_console_key(db, installed["id"])

    first = _beat(client, installed["id"], headers=_basic(installed["api_token"]))
    assert first.status_code == 200, first.text
    registration = first.json()["console"]
    assert registration is not None
    assert registration["serial"] >= 1
    assert registration["public_key"].startswith("ssh-ed25519 ")


def test_heartbeat_records_the_console_installed_claim(api, client, db):
    installed = _install(api, client)
    _issue_console_key(db, installed["id"])
    _beat(client, installed["id"], headers=_basic(installed["api_token"]))

    second = _beat(
        client,
        installed["id"],
        headers=_basic(installed["api_token"]),
        body={"hostname": "beating", "console_installed": True},
    )
    assert second.status_code == 200, second.text
    assert second.json()["console"] is None
    db.expire_all()
    assert db.get(Router, installed["id"]).console_installed_at is not None


def test_heartbeat_without_the_claim_keeps_advertising_the_registration(api, client, db):
    installed = _install(api, client)
    _issue_console_key(db, installed["id"])

    r = _beat(client, installed["id"], headers=_basic(installed["api_token"]))
    assert r.status_code == 200, r.text
    assert r.json()["console"] is not None
    db.expire_all()
    assert db.get(Router, installed["id"]).console_installed_at is None


def test_heartbeat_returns_the_desired_heartbeat_url(api, client):
    installed = _install(api, client)
    r = _beat(client, installed["id"], headers=_basic(installed["api_token"]))
    assert r.status_code == 200, r.text
    desired = r.json()["desired"]
    assert desired["heartbeat_url"].endswith(f"/api/v1/routers/{installed['id']}/heartbeat")


def test_revoked_router_loses_heartbeat_access(api, admin_client, client, db):
    installed = _install(api, client)
    assert admin_client.delete(f"/api/v1/routers/{installed['id']}").status_code == 204

    r = _beat(client, installed["id"], headers=_basic(installed["api_token"]))
    assert r.status_code == 401


def test_heartbeat_ignores_a_non_string_body_token(api, client):
    """Only a string can be a token; a JSON object in that field is malformed, not a credential."""
    installed = _install(api, client)
    r = _beat(client, installed["id"], body={"api_token": {"$ne": None}})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == 'Basic realm="tunnelgate"'


def test_heartbeat_accepts_the_colon_less_basic_payload(api, client):
    """base64(TOKEN) with no colon, the shape a stock OpenWrt device puts on the wire."""
    installed = _install(api, client)
    encoded = base64.b64encode(installed["api_token"].encode()).decode()
    r = _beat(client, installed["id"], headers={"Authorization": f"Basic {encoded}"})
    assert r.status_code == 200, r.text
