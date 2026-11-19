"""Router CRUD, install script issuance, status derivation and the wizard endpoints."""

from __future__ import annotations

import re

import pytest

from app.config import RESERVED_SLUGS, SLUG_RE, utcnow
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
    # The command must work on a stock OpenWrt, where curl does not exist: it probes for a
    # fetcher instead of assuming curl (details in the install-command tests at the end of
    # this file).
    assert body["install_command"].startswith("TK='")
    assert "command -v curl" in body["install_command"]
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


@pytest.mark.parametrize("slug", sorted(RESERVED_SLUGS))
def test_create_router_rejects_a_reserved_slug(api, slug):
    """The panel owns these first path segments.

    In path mode a router is published at <gateway>/<slug>/, so "api" or "assets" makes nginx
    reject the whole config ("duplicate location"), and "login" shadows the login page with a
    redirect loop that locks the operator out. Nothing in the UI could undo either.
    """
    r = api.c.post("/api/v1/routers", json={"name": "X", "slug": slug})
    assert r.status_code == 422, r.text
    assert r.json()["error"]["code"] == "validation_error"
    if re.match(SLUG_RE, slug):
        # "__tg" is already outside the character class; the rest are rejected BY the
        # reserved list, which is the guard worth naming in the message.
        assert "reserved" in r.text


def test_a_name_that_slugifies_into_a_reserved_word_gets_a_free_one(api):
    """A router called "Login" must not become "login": the derived slug is bumped, so the
    operator does not have to understand why the obvious name was refused."""
    first = api.create_router("Login")
    assert first["slug"] == "login-2"
    second = api.create_router("Login")
    assert second["slug"] == "login-3"


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


# --------------------------------------------------------------------------- install command
# The command is the ONLY thing an operator runs on the router, and it has to work on a stock
# OpenWrt: no curl on any generation, and /usr/bin/wget is uclient-fetch, which had no --header
# before 24.10. These tests pin the wire shape rather than the wording, because the failure mode
# (a command that "works" on the developer's laptop and nowhere else) is invisible until a
# customer tries it.


def _install_command(settings=None) -> str:
    from app.config import Settings as _Settings
    from app.services import bootstrap as bootstrap_service

    s = settings or _Settings(panel_url="https://panel.example.com")
    return bootstrap_service.build_install_command("Q1rZ9x-Kk3mNp7vB2sT4", s)


def test_install_command_sends_the_token_as_a_basic_auth_username():
    """The token rides as the basic-auth username, which is the one channel a stock router has.

    Measured on real OpenWrt containers through a logging proxy: uclient-fetch sends no
    Authorization on its first request and retries only after our 401 challenge, so the channel
    has to be basic auth. A header is impossible (--header arrived in uclient-fetch 24.10) and
    URL userinfo is worse than useless (GNU wget 1.25 refuses it outright), so both fetchers are
    handed the same credential explicitly.
    """
    command = _install_command()
    assert '-u "$TK:"' in command, "curl must send the token preemptively via -u"
    assert '--user="$TK"' in command, "wget must send the token as --user"
    # Neither of the channels that cannot work may survive.
    assert "X-Bootstrap-Token" not in command
    assert "--header" not in command
    assert "-H " not in command


def test_install_command_gives_wget_a_non_empty_password():
    """The placeholder password is load-bearing, not decoration.

    uclient-fetch joins user and password with a colon and DROPS the colon when the password is
    empty or absent: an empty one sends base64(TOKEN), which is not a legal RFC 7617 payload and
    is rejected. With any non-empty password it sends base64(TOKEN:x) and the panel answers 200.
    This was measured on 19.07.10 / 22.03.7 / 23.05.5 / 24.10.1; without it every stock router
    fails to install, which is exactly the bug this command exists to fix.
    """
    from app.services import bootstrap as bootstrap_service

    assert bootstrap_service.INSTALL_AUTH_PASSWORD, "the placeholder must be non-empty"
    command = _install_command()
    assert f"--password={bootstrap_service.INSTALL_AUTH_PASSWORD}" in command
    for empty_shape in ("--password= ", '--password=""', "--password=''", "--password= "):
        assert empty_shape not in command, empty_shape
    # --user without a --password would also drop the colon, so both must appear together.
    wget_line = next(ln for ln in command.splitlines() if "--user=" in ln)
    assert "--password=" in wget_line
    # The password is a formality the panel never reads; it must not look like one we keep.
    assert "tunnelgate" not in bootstrap_service.INSTALL_AUTH_PASSWORD.lower()


def test_install_command_keeps_the_token_out_of_the_url():
    """No userinfo in the URL at all now.

    GNU wget 1.25 rejects a userinfo URL with exit 6, and both fetchers already accept --user,
    so keeping the token in the URL would buy nothing and break the one client that is easy to
    test on a laptop. The URL must also stay free of the token in its path and query, where
    every proxy in the chain would log it.
    """
    command = _install_command()
    url = re.search(r"U='([^']+)'", command).group(1)
    assert url == "https://panel.example.com/api/v1/routers/install?os=linux"
    assert "@" not in url
    assert "Q1rZ9x-Kk3mNp7vB2sT4" not in url
    assert "token" not in url.lower()


def test_install_command_probes_the_fetcher_with_if_elif():
    """One probe, one request. "curl ... || wget ..." would fire a second request on failure.

    Every render of the installer burns the same per-token quota (SCRIPT_LIMIT in
    app/api/bootstrap.py), so a fallback chain turns one operator retry into two burned slots.
    """
    command = _install_command()
    assert "if command -v curl" in command
    assert 'then curl -fsSL -o "$F" -u "$TK:" "$U"' in command
    assert "elif command -v wget" in command
    assert 'then wget -q -O "$F"' in command
    # No command-alternative chaining between the two fetchers at all.
    assert "|| wget" not in command
    assert "|| curl" not in command
    # And the fetches never run as separate unconditional statements.
    fetch_lines = [ln for ln in command.splitlines() if "curl -fsSL" in ln or "wget -q -O" in ln]
    assert len(fetch_lines) == 2


def test_install_command_explains_itself_when_no_fetcher_exists():
    command = _install_command()
    assert "neither curl nor wget is installed" in command
    assert "exit 1" in command


def test_install_command_never_pipes_the_download_into_sh():
    """A 401 answers an empty body, and "| sh" on an empty body exits 0 doing nothing.

    The operator then sees no error at all and a router that never dials in. The body is
    fetched to a file, checked, and only then run.
    """
    command = _install_command()
    assert "| sh" not in command
    assert 'sh "$F"' in command
    # The fetch writes to a file, and that file is what gets executed.
    assert '-o "$F"' in command


def test_install_command_verifies_the_sentinel_before_running_anything():
    command = _install_command()
    assert "grep -q 'TunnelGate router agent installer' \"$F\"" in command
    # The sentinel check must fail closed: complain, delete the bad body, and do not run it.
    check_line = next(ln for ln in command.splitlines() if "grep -q 'TunnelGate" in ln)
    assert "exit 1" in check_line
    assert 'rm -f "$F"' in check_line
    # The only execution of $F comes after the check, never before it.
    lines = command.splitlines()
    check_at = next(i for i, ln in enumerate(lines) if "grep -q 'TunnelGate" in ln)
    run_at = next(i for i, ln in enumerate(lines) if ln.strip() == 'sh "$F"')
    assert run_at > check_at


def test_install_command_uses_a_pid_unique_temp_file():
    """ "$$" keeps two installs on one router from clobbering each other's download."""
    assert "/tmp/tg-install.$$.sh" in _install_command()


def test_the_sentinel_is_really_the_installers_own_line():
    """The command greps for a line the shipped installer must actually contain.

    This is a cross-file contract: build_install_command (app/services/bootstrap.py) greps a
    constant, and agent/install.sh is the file that has to carry it. Pinning both sides here
    means a change to either one fails a test instead of bricking onboarding.
    """
    from app.services import bootstrap as bootstrap_service

    script = bootstrap_service.load_install_script()
    first_lines = script.splitlines()[:2]
    assert any(bootstrap_service.INSTALL_SENTINEL in line for line in first_lines), first_lines
    assert bootstrap_service.INSTALL_SENTINEL in _install_command()


def test_install_command_shell_quotes_the_token():
    """The token is now a shell word of its own, so it must be quoted as one.

    It no longer has to survive a URL, but it does have to survive the shell: a token containing
    a quote, a space or a "$" would otherwise split the assignment or run a substitution. Tokens
    are url-safe today, so this pins the encoding that a future alphabet change would need.
    """
    import os
    import shutil
    import subprocess
    import tempfile

    from app.config import Settings as _Settings
    from app.services import bootstrap as bootstrap_service

    shell = shutil.which("sh")
    assert shell, "no /bin/sh to check the quoting with"
    settings = _Settings(panel_url="https://panel.example.com")
    hostile = "ab/cd+ef'g h$i"
    command = bootstrap_service.build_install_command(hostile, settings)
    assert command.startswith("TK='")
    # The proof is a round trip through a real POSIX shell, not a string comparison: the bytes
    # the shell reconstructs must be the token itself, with no split and no substitution.
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "verify.sh")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(command.splitlines()[0] + '\nprintf %s "$TK"\n')
        result = subprocess.run([shell, path], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout == hostile


def test_the_bootstrap_token_alphabet_is_urlsafe():
    """Prove the alphabet, do not assume it.

    The token travels as a basic-auth username, which is base64-encoded by the fetcher, so
    almost any alphabet would survive the wire. It is still asserted that tokens come from
    secrets.token_urlsafe: a token with a newline or a NUL would break the Authorization header
    itself, and this is the one place that assumption is checked rather than believed.
    """
    import string

    from app.security import new_token

    urlsafe_b64 = set(string.ascii_letters + string.digits + "-_")
    for _ in range(200):
        token = new_token()
        assert set(token) <= urlsafe_b64, token


def test_install_script_url_stays_bare_and_tokenless(api, admin_client):
    """The manual path hands out the endpoint, not a credential."""
    created = api.create_router("Manual Path")
    assert created["install_script_url"] == "http://testserver/api/v1/routers/install?os=linux"
    assert created["bootstrap_token"] not in created["install_script_url"]
    assert "@" not in created["install_script_url"]
    # Asking for the script again returns the same bare URL and a NEW token, neither in it.
    again = admin_client.get(f"/api/v1/routers/{created['id']}/script").json()
    assert again["install_script_url"] == created["install_script_url"]
    assert again["bootstrap_token"] not in again["install_script_url"]


def test_install_command_is_reachable_in_every_issuing_response(api, admin_client):
    """Every endpoint that issues a token must hand out a command that carries THAT token.

    Three call sites build this string (create, script, rotate); a drift between the command and
    the token it carries would only show up on a customer's router.
    """
    created = api.create_router("Consistent")
    assert created["bootstrap_token"] in created["install_command"]

    script_body = admin_client.get(f"/api/v1/routers/{created['id']}/script").json()
    assert script_body["bootstrap_token"] in script_body["install_command"]

    rotate = admin_client.post(f"/api/v1/routers/{created['id']}/rotate-key").json()
    assert rotate["bootstrap_token"] in rotate["install_command"]


def test_install_command_is_valid_posix_shell():
    """Busybox ash is the only shell on an OpenWrt router, so the block must be parseable.

    "sh -n" parses without executing: it catches an unbalanced quote or an empty if-branch,
    which would otherwise reach the router as a syntax error from a command the panel printed.
    """
    import os
    import shutil
    import subprocess
    import tempfile

    from app.services import bootstrap as bootstrap_service

    shell = shutil.which("sh")
    assert shell, "no /bin/sh to validate the generated command with"
    with tempfile.TemporaryDirectory() as tmpdir:
        script_path = os.path.join(tmpdir, "install.sh")
        with open(script_path, "w", encoding="utf-8") as handle:
            handle.write(bootstrap_service.build_install_command("tok-123", None))
        result = subprocess.run([shell, "-n", script_path], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


# ---------------------------------------------------------------- TLS trust in the command
def _install_command_for_tls(verify_tls: bool, settings=None) -> str:
    """Render the command as if the stored endpoint had this TLS policy.

    The policy lives in the panel_settings row, so the cheapest honest way to drive it here is
    to patch the resolver that reads it: no database, no HTTP, just the branch under test.
    """
    from app.services import agent_endpoint as agent_endpoint_service
    from app.services import bootstrap as bootstrap_service
    from app.services.agent_endpoint import AgentEndpoint

    def fake_effective(db=None, settings=None):
        return AgentEndpoint("https", "panel.example.com", None, "database", verify_tls)

    original = agent_endpoint_service.effective
    agent_endpoint_service.effective = fake_effective
    try:
        return bootstrap_service.build_install_command("Q1rZ9x-Kk3mNp7vB2sT4", settings)
    finally:
        agent_endpoint_service.effective = original


def test_install_command_verifies_by_default() -> None:
    """The strict shape is byte-for-byte what shipped before this field existed.

    An operator who changes nothing must get the same command they got in 1.1.0: no -k, no
    --no-check-certificate, and no comment line explaining a policy they never opted into.
    """
    command = _install_command()
    assert " -k " not in command
    assert "--no-check-certificate" not in command
    assert not command.startswith("#")
    assert "TLS certificate verification is OFF" not in command


def test_install_command_disables_curl_verification_when_asked() -> None:
    """-k is written as its own flag, not folded into -fsSLk.

    The operator has to be able to see the certificate check being switched off in the command
    they paste, and to copy back exactly what they ran when they ask for help.
    """
    command = _install_command_for_tls(False)
    curl_line = next(ln for ln in command.splitlines() if "command -v curl" in ln)
    assert "curl -fsSL -k -o " in curl_line
    assert "-fsSLk" not in command
    assert "--no-check-certificate" not in curl_line


def test_install_command_disables_wget_verification_when_asked() -> None:
    """uclient-fetch has the long form on all four stock images; use the one it documents."""
    command = _install_command_for_tls(False)
    wget_line = next(ln for ln in command.splitlines() if "command -v wget" in ln)
    assert "wget -q --no-check-certificate -O " in wget_line
    assert " -k" not in wget_line


def test_install_command_explains_the_insecure_choice_exactly_once() -> None:
    """One leading comment line, when and only when verification is off.

    It has to be a comment rather than an echo: the command is pasted into a router shell and
    an echo would add noise to every install, while a comment vanishes.
    """
    insecure = _install_command_for_tls(False)
    first = insecure.splitlines()[0]
    assert first == (
        "# TLS certificate verification is OFF for this panel (Settings > Agent endpoint)."
    )
    assert insecure.count("TLS certificate verification is OFF") == 1


def test_the_insecure_command_still_keeps_every_other_guard() -> None:
    """Turning off certificate checking must not weaken the token, sentinel or if/elif shape."""
    insecure = _install_command_for_tls(False)
    assert '-u "$TK:"' in insecure
    assert '--user="$TK"' in insecure
    assert "--password=x" in insecure
    assert "--header" not in insecure
    assert "X-Bootstrap-Token" not in insecure
    assert "| sh" not in insecure
    assert "if command -v curl" in insecure
    assert "elif command -v wget" in insecure
    assert _install_sentinel() in insecure


def _install_sentinel() -> str:
    from app.services import bootstrap as bootstrap_service

    return bootstrap_service.INSTALL_SENTINEL


@pytest.mark.parametrize("verify_tls", [True, False])
def test_the_install_command_stays_valid_posix_shell_in_both_modes(verify_tls) -> None:
    """sh -n both ways: a comment line or an extra flag must not break busybox ash."""
    import shutil
    import subprocess
    import tempfile

    shell = shutil.which("sh")
    assert shell
    with tempfile.TemporaryDirectory() as tmpdir:
        path = tmpdir + "/install.sh"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(_install_command_for_tls(verify_tls))
        result = subprocess.run([shell, "-n", path], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_a_stored_tls_policy_reaches_the_issued_install_command(api, admin_client) -> None:
    """End to end: the row the operator saved decides the command the panel hands out.

    Every intermediate step is covered by a unit test, but the wiring is what ships: a stored
    verify_tls=false that never reaches build_install_command would leave the operator with a
    command that cannot install anything, and no test above would notice.
    """
    from app.db import session_scope
    from app.services import agent_endpoint

    with session_scope() as db:
        agent_endpoint.save(db, "https", "self.example.com", None, verify_tls=False)
        db.commit()

    created = api.create_router("Self Signed")
    command = created["install_command"]
    assert command.startswith("# TLS certificate verification is OFF")
    assert "curl -fsSL -k -o" in command
    assert "wget -q --no-check-certificate -O" in command
    # The URL now points at the stored endpoint, and still carries no token.
    assert "https://self.example.com/api/v1/routers/install?os=linux" in command
    assert created["bootstrap_token"] not in command.split("U=")[1].split(";")[0]


def test_clearing_the_row_restores_the_strict_command(api, admin_client) -> None:
    """And the reverse: resetting the endpoint must not leave an insecure command behind."""
    from app.db import session_scope
    from app.services import agent_endpoint

    with session_scope() as db:
        agent_endpoint.save(db, "https", "self.example.com", None, verify_tls=False)
        db.commit()
    assert "-k" in api.create_router("Before Reset")["install_command"]

    admin_client.delete("/api/v1/settings/agent-endpoint")

    command = api.create_router("After Reset")["install_command"]
    assert "-k" not in command
    assert "--no-check-certificate" not in command
    assert not command.startswith("#")
