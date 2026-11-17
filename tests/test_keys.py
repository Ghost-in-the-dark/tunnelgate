"""Tunnel key handling: authorized_keys rendering, api tokens, rotation and the on-disk file."""

from __future__ import annotations

import stat

from app.config import utcnow
from app.models import Router
from app.security import authorized_key_line, encrypt_secret, key_fingerprint
from app.services import keys as keys_service


def _router(db, settings, **kw) -> Router:
    defaults = {
        "name": "Edge One",
        "slug": "edge-one",
        "status": "awaiting",
        "http_port": 20001,
        "remote_port": 20002,
        "bind_address": settings.bind_address,
        "ssh_user": settings.ssh_user,
    }
    defaults.update(kw)
    item = Router(**defaults)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


# --------------------------------------------------------------------------- api tokens
def test_api_token_is_derived_and_prefixed():
    public = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake tunnelgate:edge-one"
    token = keys_service.api_token(public)
    assert token.startswith("tg_")
    assert len(token) == len("tg_") + 40
    assert keys_service.api_token(public) == token  # deterministic
    assert keys_service.api_token(public + " ") == token  # stripped before hashing


def test_api_token_is_none_without_a_key():
    assert keys_service.api_token(None) is None
    assert keys_service.api_token("") is None


def test_api_token_matches_only_the_right_token(db, settings):
    item = _router(db, settings)
    keys_service.issue_key(db, item)
    db.commit()
    token = keys_service.api_token(item.public_key)
    assert keys_service.api_token_matches(item, token) is True
    assert keys_service.api_token_matches(item, "tg_wrong") is False
    assert keys_service.api_token_matches(item, None) is False


def test_api_token_stops_matching_after_revocation(db, settings):
    item = _router(db, settings)
    keys_service.issue_key(db, item)
    db.commit()
    token = keys_service.api_token(item.public_key)
    keys_service.revoke_router_key(db, item)
    db.commit()
    assert keys_service.api_token_matches(item, token) is False


# --------------------------------------------------------------------------- key issuing
def test_issue_key_stores_only_the_public_half(db, settings):
    item = _router(db, settings)
    pair = keys_service.issue_key(db, item)
    db.commit()
    assert pair.private_openssh.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert item.public_key == pair.public_line
    assert item.key_fingerprint == pair.fingerprint == key_fingerprint(pair.public_line)
    assert item.key_serial == 1
    assert pair.private_openssh not in (item.public_key or "")
    # Nothing anywhere in the row holds the private half.
    for column in (item.console_key_sealed, item.notes, item.public_key):
        assert "PRIVATE KEY" not in (column or "")


def test_issue_key_bumps_the_serial_and_clears_revocation(db, settings):
    item = _router(db, settings, revoked_at=utcnow())
    keys_service.issue_key(db, item)
    keys_service.issue_key(db, item)
    db.commit()
    assert item.key_serial == 2
    assert item.revoked_at is None


def test_tunnel_comment_names_the_router(db, settings):
    item = _router(db, settings, slug="kitchen-ap")
    assert keys_service.tunnel_comment(item) == "tunnelgate:kitchen-ap"
    pair = keys_service.issue_key(db, item)
    assert pair.public_line.endswith("tunnelgate:kitchen-ap")


# --------------------------------------------------------------------------- authorized_keys rendering
def test_render_is_empty_without_routers(db, settings):
    assert keys_service.render_authorized_keys(db, settings).strip() == ""


def test_authorized_keys_line_carries_both_listeners(db, settings):
    item = _router(db, settings, console_port=25001)
    keys_service.issue_key(db, item)
    db.commit()
    body = keys_service.render_authorized_keys(db, settings)
    assert f'permitlisten="{settings.bind_address}:20002"' in body
    assert f'permitlisten="{settings.bind_address}:25001"' in body
    assert "no-pty" in body
    assert "no-port-forwarding" not in body  # deliberate: permitlisten needs forwarding on
    assert 'command="/bin/false"' in body
    assert 'permitopen="none"' in body
    # "restrict" would disable forwarding and silently break the reverse listener.
    assert "restrict" not in body
    assert body.count("ssh-ed25519") == 1


def test_console_listener_is_omitted_when_the_console_is_disabled(db, settings):
    settings.console_enabled = False
    item = _router(db, settings, console_port=25001)
    keys_service.issue_key(db, item)
    db.commit()
    body = keys_service.render_authorized_keys(db, settings)
    assert "25001" not in body
    assert "20002" in body


def test_render_skips_routers_without_a_port_or_key(db, settings):
    _router(db, settings, slug="no-port", remote_port=None, public_key="ssh-ed25519 AAAA x")
    _router(db, settings, slug="no-key", remote_port=20050)
    assert keys_service.render_authorized_keys(db, settings).strip() == ""


def test_render_skips_revoked_routers(db, settings):
    item = _router(db, settings, status="revoked")
    keys_service.issue_key(db, item)
    item.revoked_at = utcnow()
    db.commit()
    assert keys_service.render_authorized_keys(db, settings).strip() == ""


def test_render_handles_many_routers(db, settings):
    for i in range(5):
        item = _router(db, settings, slug=f"r{i}", remote_port=20010 + i)
        keys_service.issue_key(db, item)
    db.commit()
    body = keys_service.render_authorized_keys(db, settings)
    assert body.count("ssh-ed25519") == 5
    assert body.endswith("\n")


# --------------------------------------------------------------------------- on-disk file
def test_write_authorized_keys_creates_a_private_file(db, settings, tmp_authorized_keys):
    item = _router(db, settings)
    keys_service.issue_key(db, item)
    db.commit()
    written = keys_service.write_authorized_keys(db, settings)
    assert written == 1
    assert tmp_authorized_keys.exists()
    mode = stat.S_IMODE(tmp_authorized_keys.stat().st_mode)
    assert mode == settings.authorized_keys_mode
    assert "permitlisten" in tmp_authorized_keys.read_text()


def test_write_is_atomic_and_leaves_no_temp_file(db, settings, tmp_authorized_keys):
    item = _router(db, settings)
    keys_service.issue_key(db, item)
    db.commit()
    keys_service.write_authorized_keys(db, settings)
    leftovers = [
        p.name for p in tmp_authorized_keys.parent.iterdir() if p.name != "authorized_keys"
    ]
    assert leftovers == []


def test_write_replaces_stale_content(db, settings, tmp_authorized_keys):
    tmp_authorized_keys.write_text("stale-line\n")
    item = _router(db, settings)
    keys_service.issue_key(db, item)
    db.commit()
    keys_service.write_authorized_keys(db, settings)
    body = tmp_authorized_keys.read_text()
    assert "stale-line" not in body
    assert body.count("ssh-ed25519") == 1


def test_revoke_removes_the_line_from_disk(db, settings, tmp_authorized_keys):
    item = _router(db, settings)
    keys_service.issue_key(db, item)
    db.commit()
    keys_service.write_authorized_keys(db, settings)
    assert tmp_authorized_keys.read_text().strip() != ""
    keys_service.revoke_router_key(db, item)
    db.commit()
    assert tmp_authorized_keys.read_text().strip() == ""
    assert item.public_key is None
    assert item.key_fingerprint is None
    assert item.revoked_at is not None


def test_sync_authorized_keys_is_idempotent(db, settings, tmp_authorized_keys):
    item = _router(db, settings)
    keys_service.issue_key(db, item)
    db.commit()
    first = keys_service.sync_authorized_keys(db, item)
    second = keys_service.sync_authorized_keys(db, item)
    assert first == second == 1


# --------------------------------------------------------------------------- console key
def test_issue_console_key_seals_the_private_half(db, settings):
    item = _router(db, settings)
    pair = keys_service.issue_console_key(db, item)
    db.commit()
    assert item.console_public_key == pair.public_line
    assert item.console_key_fingerprint == pair.fingerprint
    assert item.console_key_serial == 1
    assert item.console_key_sealed
    assert item.console_key_sealed.startswith("v1.")
    assert "PRIVATE KEY" not in item.console_key_sealed
    assert item.console_port is not None


def test_issue_console_key_allocates_a_port_once(db, settings):
    item = _router(db, settings)
    keys_service.issue_console_key(db, item)
    db.commit()
    port = item.console_port
    assert port is not None
    item.console_installed_at = utcnow()
    keys_service.issue_console_key(db, item)
    db.commit()
    assert item.console_port == port  # rotating the key must not move the listener
    assert item.console_key_serial == 2
    assert item.console_installed_at is None


def test_console_registration_is_delivered_once_per_serial(db, settings):
    item = _router(db, settings)
    keys_service.issue_console_key(db, item)
    db.commit()
    registration = keys_service.console_key_registration(item)
    assert registration is not None
    assert registration.serial == 1
    assert registration.user == keys_service.CONSOLE_REMOTE_USER
    assert registration.public_key == item.console_public_key
    assert registration.authorized_keys_path == keys_service.ROUTER_AUTHORIZED_KEYS_PATH
    item.console_installed_at = utcnow()
    assert keys_service.console_key_registration(item) is None


def test_console_registration_is_absent_without_a_key(db, settings):
    item = _router(db, settings)
    assert keys_service.console_key_registration(item) is None


def test_install_console_key_snippet_targets_dropbear(db, settings):
    item = _router(db, settings)
    keys_service.issue_console_key(db, item)
    db.commit()
    snippet = keys_service.install_console_key_on_router(item)
    assert keys_service.ROUTER_AUTHORIZED_KEYS_PATH in snippet
    assert "mkdir -p" in snippet
    assert "chmod 600" in snippet
    assert item.console_public_key is not None
    assert item.console_public_key.split()[1] in snippet


def test_console_key_is_not_rendered_into_the_panel_authorized_keys(db, settings):
    item = _router(db, settings)
    keys_service.issue_key(db, item)
    keys_service.issue_console_key(db, item)
    db.commit()
    body = keys_service.render_authorized_keys(db, settings)
    # The console key is addressed to the ROUTER, never to the panel authorized_keys file.
    assert item.console_public_key.split()[1] not in body


def test_shell_quote_wraps_in_single_quotes():
    assert keys_service.shell_quote("abc") == "'abc'"
    assert keys_service.shell_quote("a b") == "'a b'"
    # POSIX-correct escaping: close the quote, emit an escaped quote, reopen.
    assert keys_service.shell_quote("it's") == "'it'\\''s'"


def test_authorized_key_line_helper_matches_the_service_output(db, settings):
    item = _router(db, settings, console_port=25001)
    pair = keys_service.issue_key(db, item)
    db.commit()
    expected = authorized_key_line(
        pair.public_line,
        bind_address=settings.bind_address,
        ports=item.remote_port,
        comment=keys_service.tunnel_comment(item),
        extra_options=f'permitlisten="{settings.bind_address}:25001"',
    )
    assert expected in keys_service.render_authorized_keys(db, settings)


def test_sealed_console_key_round_trips_through_the_same_secret():
    sealed = encrypt_secret("hello")
    from app.security import decrypt_secret

    assert decrypt_secret(sealed) == "hello"
