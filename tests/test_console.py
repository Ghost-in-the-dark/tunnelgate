"""Tests for the console service layer: tickets, registry, SSH dial-out, lifecycle states."""

from __future__ import annotations

import time
from typing import ClassVar

import paramiko
import pytest

from app.config import utcnow
from app.models import ConsoleSession, Router, User
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
