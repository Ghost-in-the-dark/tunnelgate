"""Tests for the console service layer: tickets, registry, SSH dial-out, lifecycle states."""

from __future__ import annotations

import time
from typing import ClassVar

import paramiko
import pytest

from app.config import get_settings, utcnow
from app.models import AuditLog, ConsoleSession, PanelSession, Router, User
from app.security import encrypt_secret, generate_ed25519_keypair
from app.services import console as console_service
from app.services import keys as keys_service
from app.services.console import (
    STATE_DISABLED,
    STATE_NO_KEY,
    STATE_NOT_INSTALLED,
    STATE_OFFLINE,
    STATE_READY,
    ConsoleError,
    ConsoleSessionRegistry,
    ConsoleTicket,
    ConsoleTicketStore,
    console_ssh_user,
    console_state,
)
from app.services.keys import console_remote_user
from tests.conftest import settings_csrf_header


# --------------------------------------------------------------------------- fixtures
def _make_router(db, settings, **kw) -> Router:
    defaults = {
        "name": "Edge One",
        "slug": "edge-one",
        "status": "online",
        "http_port": 20001,
        "remote_port": 20002,
        "console_port": 25001,
        "console_ssh_port": 22,
        "ssh_user": "tunnelgate",
        "console_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake console",
        "console_key_sealed": encrypt_secret("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n"),
        "console_key_fingerprint": "SHA256:abc",
        "console_key_serial": 1,
        "console_installed_at": utcnow(),
    }
    defaults.update(kw)
    item = Router(**defaults)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@pytest.fixture()
def router(db, settings) -> Router:
    return _make_router(db, settings)


# --------------------------------------------------------------------------- tickets
def test_ticket_is_single_use():
    store = ConsoleTicketStore(ttl=30)
    token = store.ticket("rtr-1", 7, "10.0.0.9")
    granted = store.consume(token)
    assert isinstance(granted, ConsoleTicket)
    assert granted.router_id == "rtr-1"
    assert granted.user_id == 7
    assert granted.client_ip == "10.0.0.9"
    # second redemption must fail: this is the replay guarantee
    assert store.consume(token) is None


def test_ticket_is_stored_hashed():
    store = ConsoleTicketStore(ttl=30)
    token = store.ticket("rtr-1", 1)
    assert token not in store._tickets
    assert len(store) == 1
    assert store.consume(token) is not None


def test_ticket_rejects_unknown_and_empty():
    store = ConsoleTicketStore(ttl=30)
    assert store.consume("nope") is None
    assert store.consume("") is None
    assert store.consume(None) is None


def test_ticket_expires():
    store = ConsoleTicketStore(ttl=0.01)
    token = store.ticket("rtr-1", 1)
    time.sleep(0.05)
    assert store.consume(token) is None
    assert len(store) == 0


def test_ticket_clear_and_reset():
    store = ConsoleTicketStore()
    store.ticket("a", 1)
    store.ticket("b", 2)
    assert len(store) == 2
    store.reset()
    assert len(store) == 0


# --------------------------------------------------------------------------- registry
class _FakeLoop:
    def call_soon_threadsafe(self, fn, *args):
        fn(*args)


def _fake_session(session_id="s1", router_id="rtr-1", user_id=1, username="alice"):
    import asyncio

    return console_service.ActiveConsoleSession(
        session_id=session_id,
        router_id=router_id,
        user_id=user_id,
        username=username,
        client_ip="10.0.0.1",
        started_at=time.monotonic(),
        loop=_FakeLoop(),  # type: ignore[arg-type]
        stop=asyncio.Event(),
    )


def test_registry_counts_per_user_and_router():
    reg = ConsoleSessionRegistry()
    reg.add(_fake_session("s1", "rtr-1", 1))
    reg.add(_fake_session("s2", "rtr-1", 2))
    reg.add(_fake_session("s3", "rtr-2", 1))

    assert reg.active_count() == 3
    assert reg.count_for_user(1) == 2
    assert reg.count_for_user(2) == 1
    assert reg.count_for_user(99) == 0
    assert reg.count_for_router("rtr-1") == 2
    assert reg.count_for_router("nope") == 0

    reg.remove("s1")
    assert reg.count_for_user(1) == 1


def test_registry_close_all_marks_sessions():
    reg = ConsoleSessionRegistry()
    first = _fake_session("s1", "rtr-1", 1)
    second = _fake_session("s2", "rtr-2", 1)
    reg.add(first)
    reg.add(second)

    assert reg.close_all("rtr-1", "killed") == 1
    assert first.stop.is_set() and first.close_reason == "killed"
    assert not second.stop.is_set()


def test_registry_reset():
    reg = ConsoleSessionRegistry()
    reg.add(_fake_session())
    assert len(reg) == 1
    reg.clear()
    assert len(reg) == 0


# --------------------------------------------------------------------------- ssh user
# The console login is NOT Router.ssh_user: that column holds the panel-side tunnel login
# ("tunnelgate"), an account the router does not have. The console must dial the account the
# console key was actually installed for, or every real router fails authentication while
# console_state() still says ready.
def test_console_ssh_user_is_the_account_the_key_was_installed_for(db, settings):
    item = _make_router(db, settings, name="A", slug="a", ssh_user="tunnelgate")
    assert console_ssh_user(item) == console_remote_user()
    assert console_ssh_user(item) != item.ssh_user


def test_console_ssh_user_ignores_the_tunnel_login(db, settings):
    """A router whose tunnel login looks plausible must not change the console login."""
    item = _make_router(db, settings, name="B", slug="b", ssh_user="root")
    assert console_ssh_user(item) == console_remote_user()


def test_console_ssh_user_matches_the_registration_delivered_to_the_router(db, settings):
    """End-to-end guard: the dialled login and the advertised one cannot drift apart."""
    item = _make_router(db, settings, name="C", slug="c", ssh_user="tunnelgate")
    item.console_installed_at = None  # still pending, so a registration is advertised
    registration = keys_service.console_key_registration(item)
    assert registration is not None
    assert registration.user == console_ssh_user(item)


# --------------------------------------------------------------------------- states
def test_state_disabled(db, settings):
    settings.console_enabled = False
    item = _make_router(db, settings, name="D", slug="d")
    assert console_state(db, item, settings) == STATE_DISABLED
    status, code, _msg = console_service.state_error(STATE_DISABLED)
    assert (status, code) == (403, "console_disabled")


def test_state_no_key(db, settings):
    item = _make_router(
        db, settings, name="E", slug="e", console_public_key=None, console_key_sealed=None
    )
    assert console_state(db, item, settings) == STATE_NO_KEY
    status, code, _msg = console_service.state_error(STATE_NO_KEY)
    assert (status, code) == (409, "console_no_key")


def test_state_not_installed(db, settings):
    item = _make_router(db, settings, name="F", slug="f", console_installed_at=None)
    assert console_state(db, item, settings) == STATE_NOT_INSTALLED


def test_state_not_installed_without_port(db, settings):
    item = _make_router(db, settings, name="G", slug="g", console_port=None)
    assert console_state(db, item, settings) == STATE_NOT_INSTALLED


def test_state_offline(db, settings):
    item = _make_router(db, settings, name="H", slug="h", status="offline")
    assert console_state(db, item, settings) == STATE_OFFLINE
    status, code, _msg = console_service.state_error(STATE_OFFLINE)
    assert (status, code) == (409, "console_offline")


def test_state_ready(db, settings, router):
    assert console_state(db, router, settings) == STATE_READY


def test_state_error_unknown_state_is_generic():
    status, code, _msg = console_service.state_error("bogus")
    assert status == 409
    assert code == "console_unavailable"


# --------------------------------------------------------------------------- open_ssh
def _sealed_keypair(settings) -> str:
    pair = generate_ed25519_keypair("test-console")
    return encrypt_secret(pair.private_openssh, settings)


class _StubSSHClient:
    """Minimal SSHClient stand-in: records the connect() kwargs and never touches the network."""

    instances: ClassVar[list[_StubSSHClient]] = []
    # The host key the fake router presents. paramiko calls the missing-host-key policy during
    # connect() with whatever key the server sent; the stub does the same, so the pin/refuse
    # logic runs exactly as it does against a real device. A class attribute because the client
    # is constructed inside open_ssh(): a test that wants a different key sets it on the fixture.
    host_key_bytes: ClassVar[bytes] = b"stub-host-key-bytes"

    def __init__(self) -> None:
        self.policy = None
        self.connect_kwargs: dict | None = None
        self.closed = False
        self.shell_kwargs: dict | None = None
        _StubSSHClient.instances.append(self)

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, **kwargs):
        self.connect_kwargs = kwargs

        class _PresentedKey:
            def __init__(self, blob: bytes) -> None:
                self._blob = blob

            def asbytes(self) -> bytes:
                return self._blob

        if self.policy is not None:
            self.policy.missing_host_key(
                self, kwargs.get("hostname", "?"), _PresentedKey(self.host_key_bytes)
            )

    def get_transport(self):
        return None

    def invoke_shell(self, **kwargs):
        self.shell_kwargs = kwargs
        return self

    def close(self):
        self.closed = True


@pytest.fixture()
def stub_ssh(monkeypatch):
    _StubSSHClient.instances = []
    _StubSSHClient.host_key_bytes = b"stub-host-key-bytes"
    monkeypatch.setattr(console_service, "SSHClient", _StubSSHClient)
    return _StubSSHClient


@pytest.mark.asyncio
async def test_open_ssh_uses_sealed_key_and_loopback(db, settings, stub_ssh):
    item = _make_router(
        db,
        settings,
        name="I",
        slug="i",
        console_port=25011,
        console_key_sealed=_sealed_keypair(settings),
        ssh_user="tunnelgate",
    )

    client = await console_service.open_ssh(item, settings)
    assert isinstance(client, _StubSSHClient)

    kwargs = client.connect_kwargs
    assert kwargs is not None
    assert kwargs["hostname"] == "127.0.0.1"  # settings.console_bind_address
    assert kwargs["port"] == 25011
    # The dial must use the account the console key was installed for, not Router.ssh_user.
    assert kwargs["username"] == console_remote_user()
    assert kwargs["username"] == "root"
    assert kwargs["allow_agent"] is False
    assert kwargs["look_for_keys"] is False
    assert isinstance(kwargs["pkey"], paramiko.Ed25519Key)

    # the private key must never be echoed back through its own repr
    assert "PRIVATE KEY" not in repr(kwargs["pkey"].asbytes())


@pytest.mark.asyncio
async def test_open_ssh_refuses_unsealable_key(db, settings, stub_ssh):
    item = _make_router(
        db, settings, name="J", slug="j", console_key_sealed="v1.not-a-real-sealed-blob"
    )
    with pytest.raises(ConsoleError) as excinfo:
        await console_service.open_ssh(item, settings)
    assert excinfo.value.code == "console_no_key"
    assert excinfo.value.status == 409


@pytest.mark.asyncio
async def test_open_ssh_refuses_missing_key(db, settings, stub_ssh):
    item = _make_router(
        db, settings, name="K", slug="k", console_port=None, console_key_sealed=None
    )
    with pytest.raises(ConsoleError) as excinfo:
        await console_service.open_ssh(item, settings)
    assert excinfo.value.code == "console_no_key"


@pytest.mark.asyncio
async def test_open_ssh_maps_auth_failure(db, settings, stub_ssh):
    item = _make_router(
        db, settings, name="L", slug="l", console_key_sealed=_sealed_keypair(settings)
    )

    def boom(**kwargs):
        raise paramiko.AuthenticationException("bad key")

    monkeypatch_client = _StubSSHClient()
    monkeypatch_client.connect = boom  # type: ignore[method-assign]
    console_service.SSHClient = lambda: monkeypatch_client  # type: ignore[assignment]

    with pytest.raises(ConsoleError) as excinfo:
        await console_service.open_ssh(item, settings)
    assert excinfo.value.code == "console_auth_failed"
    assert excinfo.value.status == 502
    assert monkeypatch_client.closed is True


@pytest.mark.asyncio
async def test_open_ssh_maps_unreachable(db, settings, stub_ssh):
    item = _make_router(
        db, settings, name="M", slug="m", console_key_sealed=_sealed_keypair(settings)
    )

    client = _StubSSHClient()

    def boom(**kwargs):
        raise paramiko.SSHException("no route")

    client.connect = boom  # type: ignore[method-assign]
    console_service.SSHClient = lambda: client  # type: ignore[assignment]

    with pytest.raises(ConsoleError) as excinfo:
        await console_service.open_ssh(item, settings)
    assert excinfo.value.code == "console_unreachable"
    assert client.closed is True


@pytest.mark.asyncio
async def test_open_ssh_rejects_when_disabled(db, settings):
    settings.console_enabled = False
    item = _make_router(db, settings, name="N", slug="n")
    with pytest.raises(ConsoleError) as excinfo:
        await console_service.open_ssh(item, settings)
    assert excinfo.value.status == 403


@pytest.mark.asyncio
async def test_open_shell_requests_xterm_pty(db, settings, stub_ssh):
    item = _make_router(
        db, settings, name="O", slug="o", console_key_sealed=_sealed_keypair(settings)
    )
    connection = await console_service.open_shell(item, settings, cols=120, rows=40)
    channel = connection.channel
    assert channel.shell_kwargs == {"term": "xterm-256color", "width": 120, "height": 40}
    connection.close()
    assert connection.client.closed is True


@pytest.mark.asyncio
async def test_host_key_policy_pins_known_fingerprint(db, settings, stub_ssh):
    item = _make_router(db, settings, name="P", slug="p")
    policy = console_service.ConsoleHostKeyPolicy(item)

    class _Key:
        def asbytes(self):
            return b"host-key-bytes"

    policy.missing_host_key(None, "127.0.0.1", _Key())
    assert policy.observed and policy.observed.startswith("SHA256:")

    # now pin a *different* fingerprint: the policy must refuse
    item.console_host_key_fingerprint = "SHA256:definitely-not-matching"
    strict = console_service.ConsoleHostKeyPolicy(item)
    with pytest.raises(ConsoleError) as excinfo:
        strict.missing_host_key(None, "127.0.0.1", _Key())
    assert excinfo.value.code == "console_auth_failed"


def test_console_session_row_roundtrip(db, settings):
    """The WS handler writes rows through session_scope(); prove the helpers do that."""
    from app.db import session_scope
    from app.services.console_ws import create_session_row, finish_session_row

    item = _make_router(db, settings, name="Q", slug="q")
    user = User(username="carol", role="operator", password_hash="x")
    db.add(user)
    db.commit()
    db.refresh(user)

    info = create_session_row(item, user, "10.1.1.1", "pytest-agent")
    assert info["id"]
    assert info["username"] == "carol"

    with session_scope() as s:
        row = s.get(ConsoleSession, info["id"])
        assert row is not None
        assert row.router_id == item.id
        assert row.username == "carol"
        assert row.closed_at is None

    finish_session_row(info["id"], close_reason="client_closed", bytes_in=12, bytes_out=34)
    with session_scope() as s:
        row = s.get(ConsoleSession, info["id"])
        assert row.closed_at is not None
        assert row.close_reason == "client_closed"
        assert (row.bytes_in, row.bytes_out) == (12, 34)


def test_orphaned_console_rows_are_closed_on_startup(db, settings):
    """A restart strands open rows; the sweep must close them and leave a trail.

    Nothing but the bridge closes a ConsoleSession row, so a panel that dies mid-session leaves
    closed_at IS NULL forever - and /api/v1/stats counts that as a live shell.
    """
    from app.db import session_scope
    from app.services.console_ws import close_orphaned_session_rows, create_session_row

    item = _make_router(db, settings, name="S", slug="s")
    user = User(username="dave", role="operator", password_hash="x")
    db.add(user)
    db.commit()
    db.refresh(user)

    stranded = create_session_row(item, user, "10.2.2.2", "pytest-agent")
    finished = create_session_row(item, user, "10.2.2.3", "pytest-agent")
    from app.services.console_ws import finish_session_row

    finish_session_row(finished["id"], close_reason="client_closed", bytes_in=5, bytes_out=6)

    assert close_orphaned_session_rows() == 1

    with session_scope() as s:
        row = s.get(ConsoleSession, stranded["id"])
        assert row.closed_at is not None
        assert row.close_reason == "panel_restart"
        # the sweep cannot know the traffic, so it must not overwrite the counters
        assert (row.bytes_in, row.bytes_out) == (0, 0)
        # an already-closed row is untouched: its reason survives
        done = s.get(ConsoleSession, finished["id"])
        assert done.close_reason == "client_closed"

    # a second sweep is a no-op rather than re-stamping the same rows
    assert close_orphaned_session_rows() == 0


def test_private_key_is_not_stored_in_plaintext(db, settings):
    """encrypt_secret must be what lands in the row: the raw PEM must not appear."""
    pair = generate_ed25519_keypair("leak-check")
    item = _make_router(
        db,
        settings,
        name="R",
        slug="r",
        console_key_sealed=encrypt_secret(pair.private_openssh, settings),
    )
    assert item.console_key_sealed.startswith("v1.")
    assert "PRIVATE KEY" not in item.console_key_sealed
    assert pair.private_openssh not in item.console_key_sealed
    del pair


def test_channel_send_and_resize_are_used(monkeypatch):
    """resize must call paramiko's resize_pty(cols, rows) positional form."""
    calls = []

    class _Chan:
        def resize_pty(self, *args, **kwargs):
            calls.append((args, kwargs))

    chan = _Chan()
    chan.resize_pty(100, 30)
    assert calls == [((100, 30), {})]


# --------------------------------------------------------------------------- host key pinning
# The bug this covers: _pinned_host_key_fingerprint() probed attribute names the Router model
# never had, so it always answered None and ConsoleHostKeyPolicy accepted ANY host key. A router
# that had been taken over (or an impostor inside the tunnel) could therefore terminate the
# panel's SSH session with a key of its own choosing and read everything typed into the console.
# The pin is what makes that detectable; these tests are what keep the pin honest.
def _expected_fingerprint(blob: bytes) -> str:
    """The same form app.security.key_fingerprint and console._fingerprint_of_key produce."""
    import base64
    import hashlib

    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


@pytest.mark.asyncio
async def test_first_use_pins_the_host_key_and_persists_it(db, settings, stub_ssh):
    """First open: accept, record the fingerprint plus when it was seen, keep the session."""
    item = _make_router(
        db, settings, name="HK1", slug="hk1", console_key_sealed=_sealed_keypair(settings)
    )
    assert item.console_host_key_fingerprint is None

    client = await console_service.open_ssh(item, settings, db=db)
    expected = _expected_fingerprint(_StubSSHClient.instances[0].host_key_bytes)

    assert _StubSSHClient.instances[0].closed is False
    # the fingerprint travels on the client so the WS handler can audit it
    assert client._tg_console_host_key_fingerprint == expected
    # and it is on the row, with a timestamp, not only on the in-memory object
    db.expire_all()
    row = db.get(Router, item.id)
    assert row.console_host_key_fingerprint == expected
    assert row.console_host_key_seen_at is not None


@pytest.mark.asyncio
async def test_a_matching_pin_opens_the_console_and_leaves_the_row_alone(db, settings, stub_ssh):
    """A router that still presents the pinned key must open, and must not rewrite the pin.

    The seen-at timestamp is deliberately NOT refreshed by a matching handshake: it answers
    "when was this key first learned", and bumping it on every open would quietly erase the only
    evidence of how long the device has been trusted.
    """
    pinned_blob = b"the-pinned-host-key"
    stub_ssh.host_key_bytes = pinned_blob
    pinned_at = utcnow().replace(year=2026, month=1, day=2, hour=3, minute=4, second=5)
    item = _make_router(
        db,
        settings,
        name="HK2",
        slug="hk2",
        console_key_sealed=_sealed_keypair(settings),
        console_host_key_fingerprint=_expected_fingerprint(pinned_blob),
        console_host_key_seen_at=pinned_at,
    )

    client = await console_service.open_ssh(item, settings, db=db)
    assert _StubSSHClient.instances[0].closed is False
    assert client.connect_kwargs is not None

    db.expire_all()
    row = db.get(Router, item.id)
    assert row.console_host_key_fingerprint == _expected_fingerprint(pinned_blob)
    assert row.console_host_key_seen_at == pinned_at


@pytest.mark.asyncio
async def test_a_mismatched_pin_refuses_the_console_and_closes_the_client(db, settings, stub_ssh):
    """A changed host key is a 502 console_auth_failed, and nothing is left connected.

    This is the whole point of the pin: the handshake must stop BEFORE a shell exists, and the
    message has to tell an operator what changed and that an admin clears the pin only after
    verifying the device out of band - "host key changed" alone invites a blind retry.
    """
    item = _make_router(
        db,
        settings,
        name="HK3",
        slug="hk3",
        console_key_sealed=_sealed_keypair(settings),
        console_host_key_fingerprint="SHA256:this-is-not-the-key-on-the-device",
        console_host_key_seen_at=utcnow(),
    )

    with pytest.raises(ConsoleError) as excinfo:
        await console_service.open_ssh(item, settings, db=db)

    error = excinfo.value
    assert error.code == "console_auth_failed"
    assert error.status == 502
    # the message must name the cause and the remedy, not just say "unexpected key"
    assert "host key changed" in error.message
    assert "clear the pin" in error.message
    assert "console/host-key" in error.message
    assert "tampered" in error.message
    assert _StubSSHClient.instances[0].closed is True
    # a refusal must never touch the stored pin: the panel has no reason to believe the new key
    db.expire_all()
    row = db.get(Router, item.id)
    assert row.console_host_key_fingerprint == "SHA256:this-is-not-the-key-on-the-device"


@pytest.mark.asyncio
async def test_the_console_dial_still_forbids_agents_and_key_lookup(db, settings, stub_ssh):
    """Pin or no pin, the panel must never offer an agent or a local key as a candidate."""
    item = _make_router(
        db, settings, name="HK4", slug="hk4", console_key_sealed=_sealed_keypair(settings)
    )
    await console_service.open_ssh(item, settings, db=db)
    kwargs = _StubSSHClient.instances[0].connect_kwargs
    assert kwargs is not None
    assert kwargs["allow_agent"] is False
    assert kwargs["look_for_keys"] is False


@pytest.mark.asyncio
async def test_a_failed_pin_commit_does_not_break_the_console(
    db, settings, stub_ssh, monkeypatch, caplog
):
    """A pin that cannot be saved is a warning, not a 502.

    The commit happens inside the handshake worker; letting it raise would turn a database blip
    into "the console is broken" for every router at once, and the cost of NOT saving is merely
    that the pin is relearned next time.
    """
    item = _make_router(
        db, settings, name="HK5", slug="hk5", console_key_sealed=_sealed_keypair(settings)
    )

    def boom(*args, **kwargs):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(db, "commit", boom)
    with caplog.at_level("WARNING", logger="tunnelgate.console"):
        client = await console_service.open_ssh(item, settings, db=db)

    assert _StubSSHClient.instances[0].closed is False
    assert client.connect_kwargs is not None
    assert "could not persist the console host key pin" in caplog.text
    # the rollback expunges the uncommitted pin, so the row stays unpinned: the next open learns
    # it again, which is the documented consequence and much better than a console that cannot
    # be opened at all.
    assert db.get(Router, item.id).console_host_key_fingerprint is None


@pytest.mark.asyncio
async def test_opening_without_a_session_records_the_pin_in_memory(db, settings, stub_ssh):
    """open_ssh(..., db=None) has to stay usable: record the pin, just do not persist it."""
    item = _make_router(
        db, settings, name="HK6", slug="hk6", console_key_sealed=_sealed_keypair(settings)
    )
    await console_service.open_ssh(item, settings)

    assert item.console_host_key_fingerprint == _expected_fingerprint(
        _StubSSHClient.instances[0].host_key_bytes
    )
    assert item.console_host_key_seen_at is not None
    db.rollback()
    assert db.get(Router, item.id).console_host_key_fingerprint is None


# --------------------------------------------------------------------------- host key API
def _pinned_router_id(api, fingerprint: str | None = "SHA256:pinnedhostkey") -> str:
    """Create a router through the API and give it everything console_state() needs."""
    from app.db import session_scope

    created = api.create_router("Console Pinned")
    with session_scope() as s:
        row = s.get(Router, created["id"])
        row.status = "online"
        row.console_port = 25001
        row.console_ssh_port = 22
        row.console_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake console"
        row.console_key_sealed = encrypt_secret("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n")
        row.console_key_fingerprint = "SHA256:consolekey"
        row.console_key_serial = 1
        row.console_installed_at = utcnow()
        row.console_host_key_fingerprint = fingerprint
        row.console_host_key_seen_at = utcnow() if fingerprint else None
    return created["id"]


def test_console_read_exposes_the_host_key_pin(admin_client, api):
    """The read endpoint is where an operator sees why a console refuses to open."""
    router_id = _pinned_router_id(api)
    body = admin_client.get(f"/api/v1/routers/{router_id}/console").json()

    assert body["host_key_fingerprint"] == "SHA256:pinnedhostkey"
    assert body["host_key_pinned_at"].endswith("Z")
    # the console KEY fingerprint keeps its own field; the two must not be confused
    assert body["fingerprint"] == "SHA256:consolekey"


def test_console_read_reports_a_null_pin_before_the_first_open(api):
    """A router that has never been opened has no pin, and both fields say so explicitly."""
    created = api.create_router("Never Opened")
    body = api.c.get(f"/api/v1/routers/{created['id']}/console").json()
    assert body["host_key_fingerprint"] is None
    assert body["host_key_pinned_at"] is None


def _login_as(client, user_id: int, username: str, csrf_token: str):
    """Point the client at an already-created user with its own panel session cookie.

    A second username/password login would rotate state the shared TestClient cookie jar cannot
    cleanly undo; minting the session row directly is what tests/test_console_ws.py does, and it
    keeps each role's client independent.
    """
    from app.db import session_scope
    from app.security import hash_token, new_token

    token = new_token()
    with session_scope() as s:
        s.add(
            PanelSession(
                user_id=user_id,
                token_hash=hash_token(token),
                csrf_token=csrf_token,
                expires_at=utcnow().replace(year=utcnow().year + 1),
            )
        )
    client.cookies.set(get_settings().cookie_name, token)
    # CSRF is a double submit now: the header and the tg_csrf cookie must agree and both must
    # match the session row, so a role test that only set the header would fail on csrf_failed
    # instead of reaching the role check it is about.
    client.cookies.set(get_settings().csrf_cookie_name, csrf_token)
    client.headers[settings_csrf_header()] = csrf_token
    return client


def test_clearing_the_host_key_pin_needs_admin(api, client, db, make_user):
    """operator 403, viewer 403: clearing a pin disarms the check that catches a swapped router."""
    router_id = _pinned_router_id(api)

    from app.security import new_token

    for username, role in (("op-hk", "operator"), ("view-hk", "viewer")):
        user_id = make_user(username, role=role)
        _login_as(client, user_id, username, new_token(16))
        r = client.delete(f"/api/v1/routers/{router_id}/console/host-key")
        assert r.status_code == 403, (username, r.text)
        assert r.json()["error"]["code"] == "forbidden"

    # the pin survives both refusals
    db.expire_all()
    assert db.get(Router, router_id).console_host_key_fingerprint == "SHA256:pinnedhostkey"


def test_clearing_the_host_key_pin_requires_csrf(admin_client, api, db, settings):
    router_id = _pinned_router_id(api)
    saved = admin_client.headers.pop(settings.csrf_header)
    try:
        r = admin_client.delete(f"/api/v1/routers/{router_id}/console/host-key")
    finally:
        admin_client.headers[settings.csrf_header] = saved

    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"
    db.expire_all()
    assert db.get(Router, router_id).console_host_key_fingerprint == "SHA256:pinnedhostkey"


def test_clearing_the_host_key_pin_clears_both_columns_and_audits(admin_client, api, db):
    """204, both columns gone, and a row naming the fingerprint that was discarded.

    The audit detail is the point: the next open re-pins whatever the device presents, so the
    discarded value is the only remaining record of the key an admin decided to stop trusting -
    and who made that call.
    """
    router_id = _pinned_router_id(api)

    r = admin_client.delete(f"/api/v1/routers/{router_id}/console/host-key")
    assert r.status_code == 204
    assert r.content == b""

    db.expire_all()
    row = db.get(Router, router_id)
    assert row.console_host_key_fingerprint is None
    assert row.console_host_key_seen_at is None

    entry = (
        db.query(AuditLog)
        .filter(AuditLog.action == "console.host_key.cleared")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert entry is not None
    assert entry.router_id == router_id
    assert entry.actor_username == "admin"
    assert entry.outcome == "ok"
    assert "SHA256:pinnedhostkey" in (entry.detail or "")


def test_clearing_an_absent_pin_is_still_204(admin_client, api):
    """Idempotent: a router that was never opened has no pin, and pressing the button is fine."""
    created = api.create_router("Unpinned")
    r = admin_client.delete(f"/api/v1/routers/{created['id']}/console/host-key")
    assert r.status_code == 204


def test_clearing_the_host_key_pin_404s_for_an_unknown_router(admin_client):
    r = admin_client.delete("/api/v1/routers/does-not-exist/console/host-key")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "router_not_found"


@pytest.mark.asyncio
async def test_clearing_the_pin_lets_the_next_open_learn_a_new_key(db, settings, stub_ssh):
    """End to end: pin -> cleared -> the next handshake records the NEW key instead of refusing.

    Without this the route would only be cosmetic: the reason it exists is that a reflashed
    router presents a key the panel has never seen, and that has to be accepted exactly once.
    """
    item = _make_router(
        db,
        settings,
        name="HK7",
        slug="hk7",
        console_key_sealed=_sealed_keypair(settings),
        console_host_key_fingerprint="SHA256:the-old-device",
        console_host_key_seen_at=utcnow(),
    )

    # refused while the old pin stands
    with pytest.raises(ConsoleError) as excinfo:
        await console_service.open_ssh(item, settings, db=db)
    assert excinfo.value.code == "console_auth_failed"

    # an admin clears it ...
    item.console_host_key_fingerprint = None
    item.console_host_key_seen_at = None
    db.commit()

    # ... and the next open learns the key the router now presents
    await console_service.open_ssh(item, settings, db=db)
    observed = _expected_fingerprint(_StubSSHClient.instances[-1].host_key_bytes)
    db.expire_all()
    row = db.get(Router, item.id)
    assert row.console_host_key_fingerprint == observed
    assert row.console_host_key_seen_at is not None
