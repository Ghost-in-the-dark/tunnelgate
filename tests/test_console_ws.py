"""Tests for the console WebSocket bridge, exercised through the real ASGI endpoint."""

from __future__ import annotations

import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from app.config import utcnow
from app.db import session_scope
from app.models import AuditLog, ConsoleSession, PanelSession, Router, User
from app.security import (
    encrypt_secret,
    generate_ed25519_keypair,
    hash_password,
    hash_token,
    new_token,
)
from app.services import console as console_service
from app.services import console_ws as bridge_service

COOKIE = "tg_session"


# --------------------------------------------------------------------------- fakes
class FakeChannel:
    """Stand-in for a paramiko Channel: a bounded inbox for stdin, records resizes."""

    def __init__(self) -> None:
        self.inbox: list[bytes] = []
        self.resizes: list[tuple[int, int]] = []
        self.sent = bytearray()
        self.closed = False
        self._outbox: list[bytes] = []
        self._lock = threading.Lock()
        self._eof = False

    # --- server -> browser side
    def push_output(self, data: bytes) -> None:
        with self._lock:
            self._outbox.append(data)

    def push_eof(self) -> None:
        with self._lock:
            self._eof = True

    def recv(self, nbytes: int) -> bytes:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            with self._lock:
                if self._outbox:
                    return self._outbox.pop(0)
                if self._eof:
                    return b""
            time.sleep(0.005)
        raise TimeoutError("no output produced")

    # --- browser -> server side
    def send(self, data: bytes) -> int:
        self.sent.extend(data)
        with self._lock:
            self.inbox.append(bytes(data))
        return len(data)

    def resize_pty(self, cols, rows, *args, **kwargs) -> None:
        self.resizes.append((cols, rows))

    def close(self) -> None:
        self.closed = True
        self.push_eof()


class FakeConnection:
    def __init__(self) -> None:
        self.channel = FakeChannel()
        self.host_key_fingerprint = "SHA256:fake"
        self.closed = False

    def close(self) -> None:
        self.closed = True
        self.channel.close()


@pytest.fixture()
def fake_connection(monkeypatch):
    """Replace the SSH dial-out with an in-memory connection."""
    made: list[FakeConnection] = []

    async def fake_open_shell(router, settings=None, *, cols=80, rows=24):
        conn = FakeConnection()
        made.append(conn)
        return conn

    monkeypatch.setattr(console_service, "open_shell", fake_open_shell)
    return made


@pytest.fixture()
def failing_connection(monkeypatch):
    async def boom(router, settings=None, *, cols=80, rows=24):
        raise console_service.ConsoleError("console_auth_failed", "router said no", 502)

    monkeypatch.setattr(console_service, "open_shell", boom)


# --------------------------------------------------------------------------- helpers
def _login(client: TestClient, settings, username="admin") -> tuple[TestClient, User, PanelSession]:
    """Create a user + panel session row and put the cookie on the client."""
    token = new_token()
    with session_scope() as s:
        user = s.query(User).filter(User.username == username).one_or_none()
        if user is None:
            user = User(
                username=username,
                role="admin" if username == "admin" else "operator",
                password_hash=hash_password("x"),
            )
            s.add(user)
            s.flush()
        sess = PanelSession(
            user_id=user.id,
            token_hash=hash_token(token),
            csrf_token=new_token(16),
            expires_at=utcnow().replace(year=utcnow().year + 1),
        )
        s.add(sess)
        s.flush()
        s.expunge(user)
        s.expunge(sess)
    client.cookies.set(COOKIE, token)
    return client, user, sess


def _make_router(settings, **kw) -> Router:
    pair = generate_ed25519_keypair("ws-test")
    defaults = {
        "name": "WS Router",
        "slug": "ws-router",
        "status": "online",
        "http_port": 20011,
        "remote_port": kw.pop("remote_port", 20012),
        "console_port": 25021,
        "console_ssh_port": 22,
        "ssh_user": "tunnelgate",
        "console_public_key": pair.public_line,
        "console_key_sealed": encrypt_secret(pair.private_openssh, settings),
        "console_key_fingerprint": pair.fingerprint,
        "console_key_serial": 1,
        "console_installed_at": utcnow(),
    }
    defaults.update(kw)
    with session_scope() as s:
        item = Router(**defaults)
        s.add(item)
        s.flush()
        s.refresh(item)
        s.expunge(item)
    return item


def _ticket(router: Router, user: User, ip: str = "10.0.0.5") -> str:
    return console_service.TICKETS.issue(router.id, user.id, ip)


def _ws_url(router: Router, ticket: str) -> str:
    return f"/api/v1/routers/{router.id}/console/ws?ticket={ticket}"


# --------------------------------------------------------------------------- auth gates
def _drain_until_close(ws) -> int | None:
    """Read frames until the peer closes; return the close code.

    ws.receive() hands back raw ASGI messages and does NOT raise on close - calling it
    again after the close frame blocks forever, which is what hung the whole test file.
    Inspect the message type instead of catching an exception.
    """
    while True:
        message = ws.receive()
        if message["type"] == "websocket.close":
            return message.get("code")


def _expect_refusal(client, url) -> tuple[dict, int | None]:
    """A refused upgrade sends one {"type":"error"} frame, then closes with a contract code."""
    with client.websocket_connect(url) as ws:
        frame = json.loads(ws.receive_text())
        assert frame["type"] == "error", frame
        return frame, _drain_until_close(ws)


def test_ws_requires_cookie(client, settings):
    item = _make_router(settings)
    user_id = 1
    ticket = console_service.TICKETS.issue(item.id, user_id)
    frame, code = _expect_refusal(client, _ws_url(item, ticket))
    assert frame["code"] == "unauthorized"
    assert code == 4401


def test_ws_rejects_bad_ticket(client, settings):
    _client, _user, _sess = _login(client, settings)
    item = _make_router(settings)
    frame, code = _expect_refusal(client, _ws_url(item, "not-a-ticket"))
    assert frame["code"] == "invalid_ticket"
    assert code == 4001


def test_ws_ticket_is_single_use(client, settings, fake_connection):
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        ws.receive_json()  # status
        ws.send_json({"type": "close", "reason": "done"})

    # replaying the same ticket must be refused
    frame, code = _expect_refusal(client, _ws_url(item, ticket))
    assert frame["code"] == "invalid_ticket"
    assert code == 4001


def test_ws_ticket_bound_to_router(client, settings, fake_connection):
    _c, user, _s = _login(client, settings)
    item_a = _make_router(
        settings, name="A", slug="a", console_port=25031, http_port=20031, remote_port=20041
    )
    item_b = _make_router(
        settings, name="B", slug="b", console_port=25032, http_port=20032, remote_port=20042
    )
    ticket_for_a = _ticket(item_a, user)

    frame, code = _expect_refusal(client, _ws_url(item_b, ticket_for_a))
    assert frame["code"] == "ticket_mismatch"
    assert code == 4403
    # the ticket must be burned even though it was refused: no retry against router A
    frame, code = _expect_refusal(client, _ws_url(item_a, ticket_for_a))
    assert frame["code"] == "invalid_ticket"


def test_ws_ticket_bound_to_user(client, settings, fake_connection):
    _c, _user, _s = _login(client, settings, "admin")
    with session_scope() as s:
        other = User(username="intruder", role="operator", password_hash=hash_password("x"))
        s.add(other)
        s.flush()
        other_id = other.id
    item = _make_router(settings)
    stolen = console_service.TICKETS.issue(item.id, other_id)

    frame, code = _expect_refusal(client, _ws_url(item, stolen))
    assert frame["code"] == "ticket_mismatch"
    assert code == 4403


def test_ws_rejects_viewer(client, settings):
    client, _user, _s = _login(client, settings, "watcher")
    with session_scope() as s:
        u = s.query(User).filter(User.username == "watcher").one()
        u.role = "viewer"
        viewer_id = u.id
    item = _make_router(settings)
    ticket = console_service.TICKETS.issue(item.id, viewer_id)

    frame, code = _expect_refusal(client, _ws_url(item, ticket))
    assert frame["code"] == "console_forbidden"
    assert code == 4403


# --------------------------------------------------------------------------- bridge
def test_ws_bridge_transfers_bytes_both_ways(client, settings, fake_connection):
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        status = ws.receive_json()
        assert status["type"] == "status"
        assert status["state"] == "ready"
        assert status["session_id"]
        assert status["cols"] == 80 and status["rows"] == 24

        conn = fake_connection[0]
        conn.channel.push_output(b"root@router:~# ")
        assert ws.receive_bytes() == b"root@router:~# "

        ws.send_bytes(b"uname -a\n")
        # wait for the fake channel to see the keystrokes
        deadline = time.monotonic() + 5
        while not conn.channel.inbox and time.monotonic() < deadline:
            time.sleep(0.01)
        assert conn.channel.inbox[0] == b"uname -a\n"

        conn.channel.push_output(b"Linux router 5.15\r\n")
        assert ws.receive_bytes() == b"Linux router 5.15\r\n"

        ws.send_json({"type": "close", "reason": "test_done"})


def test_ws_resize_control_frame(client, settings, fake_connection):
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        ws.receive_json()
        ws.send_json({"type": "resize", "cols": 132, "rows": 43})
        conn = fake_connection[0]
        deadline = time.monotonic() + 5
        while not conn.channel.resizes and time.monotonic() < deadline:
            time.sleep(0.01)
        assert conn.channel.resizes == [(132, 43)]
        ws.send_json({"type": "close"})


def test_ws_resize_is_clamped(client, settings, fake_connection):
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        ws.receive_json()
        ws.send_json({"type": "resize", "cols": 99999, "rows": -5})
        conn = fake_connection[0]
        deadline = time.monotonic() + 5
        while not conn.channel.resizes and time.monotonic() < deadline:
            time.sleep(0.01)
        assert conn.channel.resizes == [(1000, 1)]
        ws.send_json({"type": "close"})


def test_ws_ping_pong(client, settings, fake_connection):
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        ws.receive_json()
        ws.send_json({"type": "ping", "ts": 12345})
        pong = ws.receive_json()
        assert pong == {"type": "pong", "ts": 12345}
        ws.send_json({"type": "close"})


def test_ws_non_json_text_is_shell_input(client, settings, fake_connection):
    """A text frame that is not a control frame must reach the shell untouched."""
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        ws.receive_json()
        ws.send_text("ls -la\n")
        conn = fake_connection[0]
        deadline = time.monotonic() + 5
        while not conn.channel.inbox and time.monotonic() < deadline:
            time.sleep(0.01)
        assert conn.channel.inbox[0] == b"ls -la\n"
        ws.send_json({"type": "close"})


def test_ws_failed_ssh_closes_with_4502(client, settings, failing_connection):
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    frame, code = _expect_refusal(client, _ws_url(item, ticket))
    assert frame["code"] == "console_auth_failed"
    assert code == 4502


# --------------------------------------------------------------------------- persistence
def test_session_row_and_audit_are_written(client, settings, fake_connection):
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        ws.receive_json()
        conn = fake_connection[0]
        conn.channel.push_output(b"hello")
        assert ws.receive_bytes() == b"hello"
        ws.send_bytes(b"abc")
        ws.send_json({"type": "close", "reason": "operator_done"})

    deadline = time.monotonic() + 5
    row = None
    while time.monotonic() < deadline:
        with session_scope() as s:
            row = s.query(ConsoleSession).filter(ConsoleSession.router_id == item.id).one_or_none()
        if row is not None and row.closed_at is not None:
            break
        time.sleep(0.02)

    assert row is not None
    assert row.router_id == item.id
    assert row.username == "admin"
    assert row.closed_at is not None
    assert row.close_reason == "operator_done"
    assert row.bytes_in == 3
    assert row.bytes_out == 5

    with session_scope() as s:
        actions = [a.action for a in s.query(AuditLog).all()]
    assert "console.open" in actions
    assert "console.close" in actions


def test_session_row_closed_on_eof(client, settings, fake_connection):
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        ws.receive_json()
        fake_connection[0].channel.push_eof()
        # server side ends the session; the socket closes
        _drain_until_close(ws)

    deadline = time.monotonic() + 5
    row = None
    while time.monotonic() < deadline:
        with session_scope() as s:
            row = s.query(ConsoleSession).filter(ConsoleSession.router_id == item.id).one_or_none()
        if row is not None and row.closed_at is not None:
            break
        time.sleep(0.02)
    assert row is not None and row.closed_at is not None
    assert row.close_reason == "eof"


# --------------------------------------------------------------------------- limits
def test_idle_timeout_closes_session(client, settings, fake_connection, monkeypatch):
    settings.console_idle_timeout_seconds = 0.2
    monkeypatch.setattr(bridge_service, "WATCHDOG_TICK", 0.05)
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        ws.receive_json()
        exit_frame = ws.receive_json()
        assert exit_frame["type"] == "exit"
        assert exit_frame["reason"] == "idle_timeout"

    deadline = time.monotonic() + 5
    row = None
    while time.monotonic() < deadline:
        with session_scope() as s:
            row = s.query(ConsoleSession).filter(ConsoleSession.router_id == item.id).one_or_none()
        if row is not None and row.closed_at is not None:
            break
        time.sleep(0.02)
    assert row is not None and row.close_reason == "idle_timeout"


def test_max_duration_closes_session(client, settings, fake_connection, monkeypatch):
    settings.console_max_session_seconds = 0.2
    monkeypatch.setattr(bridge_service, "WATCHDOG_TICK", 0.05)
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        ws.receive_json()
        exit_frame = ws.receive_json()
        assert exit_frame["type"] == "exit"
        assert exit_frame["reason"] == "max_duration"


def test_kill_console_signal_ends_session(client, settings, fake_connection):
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        ws.receive_json()
        assert console_service.SESSIONS.count_for_router(item.id) == 1
        console_service.SESSIONS.close_all(item.id, "admin_killed")
        exit_frame = ws.receive_json()
        assert exit_frame["type"] == "exit"
        assert exit_frame["reason"] == "admin_killed"


def test_session_limit_blocks_second_console(client, settings, fake_connection):
    settings.console_max_sessions_per_user = 1
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)

    first = _ticket(item, user)
    with client.websocket_connect(_ws_url(item, first)) as ws:
        ws.receive_json()
        second = _ticket(item, user)
        frame, code = _expect_refusal(client, _ws_url(item, second))
        assert frame["code"] == "console_session_limit"
        assert code == 4403
        ws.send_json({"type": "close"})


def test_disabled_console_refuses_ws(client, settings, fake_connection):
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)
    settings.console_enabled = False

    frame, code = _expect_refusal(client, _ws_url(item, ticket))
    assert frame["code"] == "console_disabled"
    assert code == 4403


def test_handler_release_on_disconnect(client, settings, fake_connection):
    """A client that simply vanishes must not leave the registry or the channel open."""
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        ws.receive_json()
        assert console_service.SESSIONS.count_for_router(item.id) == 1

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if console_service.SESSIONS.count_for_router(item.id) == 0:
            break
        time.sleep(0.02)
    assert console_service.SESSIONS.count_for_router(item.id) == 0
    assert fake_connection[0].closed is True
