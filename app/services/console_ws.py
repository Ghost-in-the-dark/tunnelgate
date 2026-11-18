"""WebSocket <-> SSH channel bridge for the interactive router console.

Protocol (CONTRACT.md ADDENDUM 1, frozen)
-----------------------------------------
client -> server
    * **binary** frame                raw keystrokes, written to the shell channel untouched
    * **text** frame, JSON object     control message:
        {"type":"resize","cols":N,"rows":N}   resize the remote pty
        {"type":"ping","ts":...}              liveness probe (answered with a pong)
        {"type":"close","reason":"..."}       close the session deliberately
    * any other text frame            written to the shell channel verbatim (utf-8)

server -> client
    * **binary** frame                raw shell output (exact bytes from the pty)
    * **text** frame, JSON object
        {"type":"status","state":"ready","session_id":..,"idle_timeout_seconds":..,
         "max_session_seconds":..,"cols":..,"rows":..}      sent once, right after connect
        {"type":"pong","ts":..}                            answer to a client ping
        {"type":"error","code":..,"message":..}            sent before a failure close
        {"type":"exit","reason":..,"bytes_in":..,"bytes_out":..}   sent before a normal close

Close codes
    4001  missing / invalid / expired / already-used ticket
    4401  no authenticated panel session
    4403  forbidden (role, ticket bound to another router or user, session limit)
    4502  the SSH side failed (no key, key not installed, router offline, auth rejected)

The handler never logs keystrokes or shell output - only open/close events and byte counts.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from typing import Any

from sqlalchemy import select

from ..config import Settings, get_settings, utcnow
from ..db import session_scope
from ..models import ConsoleSession, Router, User
from . import console as console_service
from .audit import record as audit_record

log = logging.getLogger("tunnelgate.console.ws")

CLOSE_INVALID_TICKET = 4001
CLOSE_UNAUTHORIZED = 4401
CLOSE_FORBIDDEN = 4403
CLOSE_UPSTREAM = 4502

MAX_CONTROL_FRAME_BYTES = 8192
# How often the watchdog wakes up to check idle/absolute deadlines (seconds).
WATCHDOG_TICK = 0.5


def _now_iso() -> str:
    from ..schemas import iso

    return iso(utcnow())


# --------------------------------------------------------------------------- DB helpers
def create_session_row(
    router: Router,
    user: User | None,
    client_ip: str | None,
    user_agent: str | None,
) -> dict[str, Any]:
    """Insert the ConsoleSession row. Returns a small dict so the caller holds no ORM object."""
    row = ConsoleSession(
        router_id=router.id,
        router_name=router.name,
        user_id=user.id if user else None,
        username=user.username if user else None,
        client_ip=client_ip,
        user_agent=(user_agent or "")[:255] or None,
        started_at=utcnow(),
    )
    with session_scope() as db:
        db.add(row)
        db.flush()
        return {
            "id": row.id,
            "router_id": router.id,
            "user_id": row.user_id,
            "username": row.username,
        }


def finish_session_row(
    session_id: str,
    *,
    close_reason: str,
    bytes_in: int,
    bytes_out: int,
    audit_action: str | None = None,
    router: Router | None = None,
    user: User | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    audit_detail: dict[str, Any] | None = None,
) -> None:
    """Close the row: stamp closed_at, the reason and the byte counters.

    When audit_action is given the closing audit record is written in the SAME
    transaction: a reader must never observe a closed session without a matching
    close event, and two commits would leave exactly that window.
    """
    with session_scope() as db:
        row = db.get(ConsoleSession, session_id)
        if row is None:
            # The router was deleted while this shell was being torn down: its ConsoleSession
            # rows go with it through ON DELETE CASCADE (app/models.py), so there is nothing left
            # to stamp. Reproduced by tests/test_console_ws.py::test_deleting_a_router_ends_its_live_shells.
            return
        row.closed_at = utcnow()
        row.close_reason = (close_reason or "unknown")[:32]
        row.bytes_in = int(bytes_in)
        row.bytes_out = int(bytes_out)
        if audit_action and router is not None:
            audit_record(
                db,
                audit_action,
                actor=user,
                router=router,
                ip=ip,
                user_agent=user_agent,
                detail=audit_detail,
            )


def audit_event(
    action: str,
    *,
    router: Router,
    user: User | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    detail: dict[str, Any] | None = None,
    outcome: str = "ok",
) -> None:
    with session_scope() as db:
        audit_record(
            db,
            action,
            actor=user,
            outcome=outcome,
            router=router,
            ip=ip,
            user_agent=user_agent,
            detail=detail,
        )


def close_orphaned_session_rows() -> int:
    """Close console rows a previous panel process left open, and return how many.

    A ConsoleSession row is opened when the shell opens and closed in the bridge's teardown.
    Nothing else can close it: the row has no "still alive" reference outside this process, so
    a panel that is restarted (an upgrade, a crash, systemd's Restart=) leaves every session it
    was serving stamped closed_at IS NULL forever. That is not cosmetic - /api/v1/stats counts
    open rows as "console_sessions_active", so the dashboard and any alert on that metric show
    phantom live shells that no user can end, and a concurrent-session limit silently eats into
    its budget.

    Called once from the lifespan startup, before the app serves a request, so the sweep cannot
    race a live session: at that instant this process serves none. The close reason is its own
    value ("panel_restart") so an audit reader can tell a sweep from a real disconnect, and the
    byte counters stay as they were written - the sweep has no idea what the shell transferred
    and must not invent zeroes that would read as "nothing happened".
    """
    with session_scope() as db:
        rows = (
            db.execute(select(ConsoleSession).where(ConsoleSession.closed_at.is_(None)))
            .scalars()
            .all()
        )
        if not rows:
            return 0
        now = utcnow()
        for row in rows:
            row.closed_at = now
            row.close_reason = "panel_restart"
            audit_record(
                db,
                "console.close",
                actor_username=row.username,
                router_id=row.router_id,
                router_name=row.router_name,
                detail={
                    "session_id": row.id,
                    "reason": "panel_restart",
                    "started_at": row.started_at.isoformat() if row.started_at else None,
                },
            )
        return len(rows)


# --------------------------------------------------------------------------- frame helpers
def _as_control_frame(text: str) -> dict[str, Any] | None:
    """Parse a text frame as a control message, or return None if it is shell input."""
    if not text or len(text) > MAX_CONTROL_FRAME_BYTES or not text.lstrip().startswith("{"):
        return None
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    kind = payload.get("type")
    if kind not in ("resize", "ping", "close"):
        return None
    return payload


def _int_or(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


class ConsoleWebSocketHandler:
    """Bridges one WebSocket to one interactive SSH shell and keeps the audit trail honest."""

    def __init__(
        self,
        websocket: Any,
        *,
        router: Router,
        user: User | None,
        client_ip: str | None = None,
        user_agent: str | None = None,
        settings: Settings | None = None,
        cols: int = console_service.DEFAULT_CONSOLE_COLS,
        rows: int = console_service.DEFAULT_CONSOLE_ROWS,
    ) -> None:
        self.websocket = websocket
        self.router = router
        self.user = user
        self.client_ip = client_ip
        self.user_agent = user_agent
        self.settings = settings or get_settings()
        self.cols = cols
        self.rows = rows

        self.connection: console_service.ConsoleConnection | None = None
        self.session_id: str | None = None
        self.live: console_service.ActiveConsoleSession | None = None
        self.bytes_in = 0
        self.bytes_out = 0
        self.close_reason = "unknown"
        self._last_activity = time.monotonic()
        self._started = time.monotonic()

    # ------------------------------------------------------------------ lifecycle
    async def run(self) -> None:
        """Connect, bridge until one side stops, then always clean up."""
        try:
            self.connection = await console_service.open_shell(
                self.router, self.settings, cols=self.cols, rows=self.rows
            )
        except console_service.ConsoleError as exc:
            await self._refuse(exc.code, exc.message, CLOSE_UPSTREAM)
            await self._audit_failed_open(exc.code)
            return
        except Exception:
            log.exception("console ssh setup failed for router %s", self.router.id)
            await self._refuse("console_unreachable", "Console connection failed", CLOSE_UPSTREAM)
            await self._audit_failed_open("console_unreachable")
            return

        try:
            await self._start_tracking()
            await self._send_json(
                {
                    "type": "status",
                    "state": "ready",
                    "session_id": self.session_id,
                    "idle_timeout_seconds": int(self.settings.console_idle_timeout_seconds),
                    "max_session_seconds": int(self.settings.console_max_session_seconds),
                    "cols": self.cols,
                    "rows": self.rows,
                }
            )
            await self._bridge()
        except asyncio.CancelledError:
            raise
        except Exception:
            # Record the failure BEFORE _teardown persists the row, otherwise the client
            # close_reason stays "unknown" and the audit trail cannot tell a crash from a
            # clean client disconnect.
            if self.close_reason in ("unknown", ""):
                self.close_reason = "error"
            log.debug("console bridge failed router=%s", self.router.id, exc_info=True)
        finally:
            await self._teardown()

    async def _start_tracking(self) -> None:
        info = await asyncio.to_thread(
            create_session_row, self.router, self.user, self.client_ip, self.user_agent
        )
        self.session_id = info["id"]
        await asyncio.to_thread(
            audit_event,
            "console.open",
            router=self.router,
            user=self.user,
            ip=self.client_ip,
            user_agent=self.user_agent,
            detail={
                "session_id": self.session_id,
                "term": self.settings.console_term,
                "cols": self.cols,
                "rows": self.rows,
                "host_key_fingerprint": (
                    self.connection.host_key_fingerprint if self.connection else None
                ),
            },
        )
        loop = asyncio.get_running_loop()
        self.live = console_service.ActiveConsoleSession(
            session_id=self.session_id,
            router_id=self.router.id,
            user_id=self.user.id if self.user else None,
            username=self.user.username if self.user else None,
            client_ip=self.client_ip,
            started_at=self._started,
            loop=loop,
            stop=asyncio.Event(),
        )
        console_service.SESSIONS.add(self.live)
        log.info(
            "console open router=%s user=%s session=%s ip=%s",
            self.router.id,
            self.user.username if self.user else "-",
            self.session_id,
            self.client_ip,
        )

    async def _teardown(self) -> None:
        if self.live is not None:
            console_service.SESSIONS.remove(self.live.session_id)
            if self.live.close_reason and self.close_reason in ("unknown", ""):
                self.close_reason = self.live.close_reason
        # Persist BEFORE the closing awaits: asyncio.CancelledError can land on any
        # suspension point, and a cancellation between "client went away" and this write
        # would leave the ConsoleSession row open forever (a permanent ghost session in
        # the UI and in every active-session count). close_reason is already decided here.
        self._persist_close()
        if self.connection is not None:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(self.connection.close)
            self.connection = None

    def _persist_close(self) -> None:
        """Close the row + write console.close in one transaction, shielded from cancellation."""
        if not self.session_id:
            return
        with contextlib.suppress(Exception):
            finish_session_row(
                self.session_id,
                close_reason=self.close_reason,
                bytes_in=self.bytes_in,
                bytes_out=self.bytes_out,
                audit_action="console.close",
                router=self.router,
                user=self.user,
                ip=self.client_ip,
                user_agent=self.user_agent,
                audit_detail={
                    "session_id": self.session_id,
                    "reason": self.close_reason,
                    "bytes_in": self.bytes_in,
                    "bytes_out": self.bytes_out,
                    "duration_seconds": round(time.monotonic() - self._started, 3),
                },
            )
        log.info(
            "console closed router=%s session=%s reason=%s in=%d out=%d",
            self.router.id,
            self.session_id,
            self.close_reason,
            self.bytes_in,
            self.bytes_out,
        )
        self.session_id = None

    async def _audit_failed_open(self, code: str) -> None:
        with contextlib.suppress(Exception):
            await asyncio.to_thread(
                audit_event,
                "console.open",
                router=self.router,
                user=self.user,
                ip=self.client_ip,
                user_agent=self.user_agent,
                detail={"error": code},
                outcome="error",
            )

    # ------------------------------------------------------------------ bridging
    async def _bridge(self) -> None:
        assert self.connection is not None
        tasks = {
            asyncio.create_task(self._pump_inbound(), name="console-in"),
            asyncio.create_task(self._pump_outbound(), name="console-out"),
            asyncio.create_task(self._watchdog(), name="console-watch"),
        }
        try:
            done, _pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        for task in done:
            exc = task.exception()
            if exc is not None and not isinstance(exc, asyncio.CancelledError | TimeoutError):
                log.debug("console task %s ended: %r", task.get_name(), exc, exc_info=False)
                if self.close_reason == "unknown":
                    self.close_reason = "error"

    async def _pump_inbound(self) -> None:
        """WebSocket -> SSH channel (keystrokes and control frames)."""
        assert self.connection is not None and self.live is not None
        while True:
            message = await self.websocket.receive()
            kind = message.get("type")
            if kind == "websocket.disconnect":
                if self.close_reason == "unknown":
                    self.close_reason = "client_closed"
                return

            data = message.get("bytes")
            if data is not None:
                if not data:
                    continue
                await self._write(data)
                continue

            text = message.get("text")
            if text is None:
                continue

            control = _as_control_frame(text)
            if control is None:
                await self._write(text.encode("utf-8"), count=len(text.encode("utf-8")))
                continue

            frame_type = control.get("type")
            if frame_type == "resize":
                cols = _int_or(control.get("cols"), self.cols, 1, 1000)
                rows = _int_or(control.get("rows"), self.rows, 1, 500)
                self.cols, self.rows = cols, rows
                self._last_activity = time.monotonic()
                await self._resize(cols, rows)
            elif frame_type == "ping":
                self._last_activity = time.monotonic()
                await self._send_json({"type": "pong", "ts": control.get("ts")})
            elif frame_type == "close":
                reason = str(control.get("reason") or "client_closed")[:32]
                if self.close_reason == "unknown":
                    self.close_reason = reason or "client_closed"
                return

    async def _pump_outbound(self) -> None:
        """SSH channel -> WebSocket (shell output)."""
        assert self.connection is not None
        channel = self.connection.channel
        while True:
            try:
                data = await asyncio.to_thread(channel.recv, console_service.CONSOLE_READ_CHUNK)
            except asyncio.CancelledError:
                raise
            except Exception:
                if self.close_reason == "unknown":
                    self.close_reason = "error"
                return
            if not data:
                if self.close_reason == "unknown":
                    self.close_reason = "eof"
                return
            self.bytes_out += len(data)
            self._last_activity = time.monotonic()
            try:
                await self.websocket.send_bytes(data)
            except Exception:
                if self.close_reason == "unknown":
                    self.close_reason = "client_closed"
                return

    async def _watchdog(self) -> None:
        """Enforce the idle and absolute session limits and honour 'kill console'."""
        assert self.live is not None
        idle_limit = float(self.settings.console_idle_timeout_seconds)
        max_limit = float(self.settings.console_max_session_seconds)
        while True:
            await asyncio.sleep(WATCHDOG_TICK)
            now = time.monotonic()
            if self.live.stop.is_set():
                self.close_reason = self.live.close_reason or "killed"
                await self._send_json({"type": "exit", "reason": self.close_reason})
                return
            if idle_limit > 0 and now - self._last_activity >= idle_limit:
                self.close_reason = "idle_timeout"
                await self._send_json({"type": "exit", "reason": "idle_timeout"})
                return
            if max_limit > 0 and now - self._started >= max_limit:
                self.close_reason = "max_duration"
                await self._send_json({"type": "exit", "reason": "max_duration"})
                return

    # ------------------------------------------------------------------ io helpers
    async def _write(self, data: bytes, count: int | None = None) -> None:
        assert self.connection is not None
        await asyncio.to_thread(self.connection.channel.send, data)
        self.bytes_in += count if count is not None else len(data)
        self._last_activity = time.monotonic()

    async def _resize(self, cols: int, rows: int) -> None:
        assert self.connection is not None
        channel = self.connection.channel
        # paramiko signature: resize_pty(width=, height=)
        await asyncio.to_thread(channel.resize_pty, cols, rows)

    async def _send_json(self, payload: dict[str, Any]) -> None:
        with contextlib.suppress(Exception):
            await self.websocket.send_text(json.dumps(payload, separators=(",", ":")))

    async def _refuse(self, code: str, message: str, close_code: int) -> None:
        """Accept (so a frame can be delivered), explain, close."""
        self.close_reason = code
        with contextlib.suppress(Exception):
            await self.websocket.accept()
        await self._send_json({"type": "error", "code": code, "message": message})
        with contextlib.suppress(Exception):
            await self.websocket.close(code=close_code, reason=code)


async def bridge(
    websocket: Any,
    *,
    router: Router,
    user: User | None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    settings: Settings | None = None,
    cols: int = console_service.DEFAULT_CONSOLE_COLS,
    rows: int = console_service.DEFAULT_CONSOLE_ROWS,
) -> None:
    """Convenience wrapper used by the API layer."""
    handler = ConsoleWebSocketHandler(
        websocket,
        router=router,
        user=user,
        client_ip=client_ip,
        user_agent=user_agent,
        settings=settings,
        cols=cols,
        rows=rows,
    )
    await handler.run()
