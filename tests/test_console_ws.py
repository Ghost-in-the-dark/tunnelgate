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


# The Starlette TestClient dials in from the literal peer "testclient" (see
# starlette/testclient.py: scope client is ("testclient", 50000)). Tickets are bound to the
# client ip, so the helper must mint them for the address the socket will actually use;
# tests that care about a mismatch pass their own ip.
TESTCLIENT_PEER = "testclient"


def _ticket(router: Router, user: User, ip: str = TESTCLIENT_PEER) -> str:
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

    # Teardown drops the session from the registry BEFORE it closes the SSH channel
    # (_teardown: SESSIONS.remove -> persist -> connection.close), so waiting on the
    # registry alone would let the poll win the race and read "closed" too early. Wait
    # for both facts; the assertions then state the invariant instead of the timing.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if console_service.SESSIONS.count_for_router(item.id) == 0 and fake_connection[0].closed:
            break
        time.sleep(0.02)
    assert console_service.SESSIONS.count_for_router(item.id) == 0
    assert fake_connection[0].closed is True


class _FakeRequest:
    """Minimal stand-in for an ASGI connection with a chosen peer and headers."""

    def __init__(self, client_ip: str, xff: str | None = None):
        self.client = type("C", (), {"host": client_ip})()
        self.headers = {} if xff is None else {"x-forwarded-for": xff}


# --------------------------------------------------------------------------- ticket ip binding (F8-a)
def test_ticket_from_another_address_is_refused(client, settings, fake_connection):
    """docs/API.md promises the ticket is bound to (router, user, client ip); enforce it.

    A ws_path leaks easily - server logs, a Referer, a screenshot - and until this check it was
    replayable from anywhere for its whole TTL. The ticket is consumed before the comparison, so
    a stolen one buys exactly one failing attempt.
    """
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user, ip="203.0.113.7")

    from app.api import console_ws as console_api

    frame, code = _expect_refusal(client, _ws_url(item, ticket))
    assert frame["code"] == "ticket_foreign_ip"
    assert code == console_api.CLOSE_TICKET_FOREIGN_IP
    assert code != bridge_service.CLOSE_FORBIDDEN


def test_refused_foreign_ticket_is_still_consumed(client, settings, fake_connection):
    """One attempt only: the refusal must not leave the ticket replayable."""
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user, ip="203.0.113.7")

    _expect_refusal(client, _ws_url(item, ticket))
    # Same url, same address as the ticket now: it must not resolve any more.
    with session_scope():
        assert console_service.TICKETS.consume(ticket) is None


def test_ticket_bound_to_the_real_peer_opens_the_console(client, settings, fake_connection):
    """The matching case must still connect, or the check would break the console."""
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        greeting = ws.receive_json()
        assert greeting["type"] == "status", greeting
        assert greeting["state"] == "ready", greeting
        ws.send_json({"type": "close"})


def test_ticket_without_a_bound_address_is_not_pinned(client, settings, fake_connection):
    """An empty stored ip means "unknown", which must not be treated as a mismatch."""
    _c, user, _s = _login(client, settings)
    item = _make_router(settings)
    ticket = _ticket(item, user, ip="")

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        greeting = ws.receive_json()
        assert greeting["type"] == "status", greeting
        assert greeting["state"] == "ready", greeting
        ws.send_json({"type": "close"})


def test_ipv4_mapped_ticket_address_still_matches(client, settings, fake_connection):
    """::ffff:127.0.0.1 and 127.0.0.1 are the same peer; normalization must not split them."""
    from app import forwarded
    from app.api import console_ws as console_api

    assert forwarded.normalize_ip("::ffff:127.0.0.1") == "127.0.0.1"
    assert console_api._ticket_ip_matches("::ffff:10.0.0.9", "10.0.0.9") is True
    assert console_api._ticket_ip_matches("10.0.0.9", "10.0.0.10") is False
    assert console_api._ticket_ip_matches("", "10.0.0.9") is True
    assert console_api._ticket_ip_matches("unknown", "10.0.0.9") is True


def test_forwarded_header_from_an_untrusted_peer_is_ignored(client, settings):
    """F1 in the console path: a spoofed X-Forwarded-For must not move the bound address."""
    from app import forwarded

    # An arbitrary peer is not one of our proxies, so whatever it claims is its own assertion.
    assert forwarded.is_trusted_proxy("203.0.113.50", settings) is False
    assert (
        forwarded.client_ip(_FakeRequest(client_ip="203.0.113.50", xff="1.2.3.4"), settings)
        == "203.0.113.50"
    )

    # A trusted peer IS believed, and the client is the hop our own proxy appended: rightmost.
    spoofed = _FakeRequest(client_ip="127.0.0.1", xff="1.2.3.4, 198.51.100.9")
    assert forwarded.client_ip(spoofed, settings) == "198.51.100.9"

    # Rotating the attacker-supplied leftmost entries changes nothing.
    rotated = _FakeRequest(client_ip="127.0.0.1", xff="9.9.9.9, 198.51.100.9")
    assert forwarded.client_ip(rotated, settings) == "198.51.100.9"


def test_non_ip_peer_still_binds_the_console_ticket(client, settings, fake_connection):
    """A transport whose peer is not an IP must not silently disable the binding.

    forwarded.client_ip answers "unknown" for a non-IP peer; the console path then falls back to
    the literal peer string so two different transports still cannot share a ticket.
    """
    from app.api import console_ws as console_api

    assert console_api._ticket_ip_matches("testclient", "othertransport") is False
    assert console_api._ticket_ip_matches("testclient", "testclient") is True


# --------------------------------------------------------------------------- admin terminate
def _csrf(client: TestClient, session) -> None:
    """Put the CSRF header on the client; mutating routes require it."""
    from app.config import get_settings

    client.headers[get_settings().csrf_header] = session.csrf_token


def test_admin_can_terminate_a_live_session(client, settings, fake_connection):
    """DELETE signals the owning handler; the handler tears down and stamps the row itself."""
    _c, user, session = _login(client, settings)
    _csrf(client, session)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        status = ws.receive_json()
        session_id = status["session_id"]

        r = client.delete(f"/api/v1/console/sessions/{session_id}")
        assert r.status_code == 204, r.text

        exit_frame = ws.receive_json()
        assert exit_frame["type"] == "exit"
        assert exit_frame["reason"] == "admin_terminated"

    # The row is closed by the bridge teardown, not by the DELETE: same single-writer rule the
    # rest of the console follows.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        with session_scope() as s:
            row = s.get(ConsoleSession, session_id)
            if row is not None and row.closed_at is not None:
                break
        time.sleep(0.01)
    with session_scope() as s:
        row = s.get(ConsoleSession, session_id)
        assert row.close_reason == "admin_terminated"


def test_terminate_is_audited(client, settings, fake_connection):
    _c, user, session = _login(client, settings)
    _csrf(client, session)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        session_id = ws.receive_json()["session_id"]
        assert client.delete(f"/api/v1/console/sessions/{session_id}").status_code == 204
        ws.receive_json()

    with session_scope() as s:
        rows = (
            s.query(AuditLog)
            .filter(AuditLog.action == "console.terminate")
            .order_by(AuditLog.id.desc())
            .all()
        )
        assert rows, "the kill must leave an audit trail"
        assert rows[0].router_id == item.id
        assert session_id in (rows[0].detail or "")


def test_terminate_unknown_session_is_404(client, settings):
    _c, _user, session = _login(client, settings)
    _csrf(client, session)

    r = client.delete("/api/v1/console/sessions/does-not-exist")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "console_session_not_found"


def test_terminate_a_closed_session_is_409(client, settings):
    _c, _user, session = _login(client, settings)
    _csrf(client, session)
    item = _make_router(settings)
    with session_scope() as s:
        row = ConsoleSession(
            router_id=item.id,
            router_name=item.name,
            username="alice",
            started_at=utcnow(),
            closed_at=utcnow(),
            close_reason="client_closed",
        )
        s.add(row)
        s.flush()
        session_id = row.id

    r = client.delete(f"/api/v1/console/sessions/{session_id}")
    assert r.status_code == 409
    body = r.json()["error"]
    assert body["code"] == "console_session_closed"
    # The reason is echoed so the admin understands it was not their kill that ended it.
    assert body["details"]["close_reason"] == "client_closed"


def test_terminate_an_open_row_without_a_live_handle_is_409(client, settings):
    """A row with no live handle cannot be killed; claiming 204 would lie to the admin."""
    _c, _user, session = _login(client, settings)
    _csrf(client, session)
    item = _make_router(settings)
    with session_scope() as s:
        row = ConsoleSession(
            router_id=item.id, router_name=item.name, username="alice", started_at=utcnow()
        )
        s.add(row)
        s.flush()
        session_id = row.id

    r = client.delete(f"/api/v1/console/sessions/{session_id}")
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "console_session_not_live"


def test_terminate_requires_admin(client, settings, make_user, fake_connection):
    """An operator may open shells but may not kill other people's."""
    make_user("op1", role="operator")
    login = client.post("/api/auth/login", json={"username": "op1", "password": "user-t3st-pass"})
    client.headers[settings.csrf_header] = login.json()["csrf_token"]
    item = _make_router(settings)
    with session_scope() as s:
        row = ConsoleSession(
            router_id=item.id, router_name=item.name, username="alice", started_at=utcnow()
        )
        s.add(row)
        s.flush()
        session_id = row.id

    r = client.delete(f"/api/v1/console/sessions/{session_id}")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "forbidden"


def test_terminate_requires_csrf(client, settings):
    _c, _user, _session = _login(client, settings)
    item = _make_router(settings)
    with session_scope() as s:
        row = ConsoleSession(
            router_id=item.id, router_name=item.name, username="alice", started_at=utcnow()
        )
        s.add(row)
        s.flush()
        session_id = row.id

    r = client.delete(f"/api/v1/console/sessions/{session_id}")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"


def test_deleting_a_router_ends_its_live_shells(client, settings, fake_connection):
    """A shell on a router the panel no longer knows would be unreachable forever."""
    _c, user, session = _login(client, settings)
    _csrf(client, session)
    item = _make_router(settings)
    ticket = _ticket(item, user)

    with client.websocket_connect(_ws_url(item, ticket)) as ws:
        ws.receive_json()
        assert client.delete(f"/api/v1/routers/{item.id}").status_code == 204
        exit_frame = ws.receive_json()
        assert exit_frame["type"] == "exit"
        assert exit_frame["reason"] == "router_disconnected"

    assert console_service.SESSIONS.count_for_router(item.id) == 0
