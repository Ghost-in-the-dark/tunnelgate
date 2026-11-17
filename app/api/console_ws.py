"""WebSocket endpoint for the interactive console.

The browser cannot set headers on a WebSocket upgrade, so authentication is split:

* the **panel session cookie** (same `tg_session` cookie as the REST API) proves *who* is
  connecting; a missing/expired/revoked session is closed with 4401;
* the **one-time ticket** in the query string proves *what* is being connected to and is the
  CSRF equivalent for the upgrade: it is bound to this router *and* this user at issuance and is
  consumed exactly once, so a leaked URL cannot be replayed and a ticket minted for one router
  cannot open another.

Everything after the handshake is raw bytes plus the JSON control frames documented in
`app/services/console_ws.py`.
"""

from __future__ import annotations

import contextlib
import json
import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from ..config import get_settings, utcnow
from ..db import session_scope
from ..models import PanelSession, Router, User
from ..security import hash_token
from ..services import console as console_service
from ..services import console_ws as bridge_service

log = logging.getLogger("tunnelgate.api.console_ws")

router = APIRouter(prefix="/api/v1", tags=["console"])

CONSOLE_ROLES = ("admin", "operator")


async def _resolve_identity(websocket: WebSocket) -> tuple[User, PanelSession] | None:
    """Cookie -> hashed token -> PanelSession -> User. Mirrors app.deps without the DI layer."""
    settings = get_settings()
    token = websocket.cookies.get(settings.cookie_name)
    if not token:
        return None
    with session_scope() as db:
        sess = db.execute(
            select(PanelSession).where(PanelSession.token_hash == hash_token(token))
        ).scalar_one_or_none()
        if sess is None or sess.revoked_at is not None or sess.expires_at <= utcnow():
            return None
        user = db.get(User, sess.user_id)
        if user is None or not user.is_active:
            return None
        db.expunge(user)
        return user, sess


def _load_router(router_id: str) -> Router | None:
    with session_scope() as db:
        item = db.get(Router, router_id)
        if item is not None:
            db.expunge(item)
        return item


async def _reject(websocket: WebSocket, close_code: int, code: str, message: str) -> None:
    """Accept just long enough to explain why, then close with the contract code."""
    with contextlib.suppress(Exception):
        await websocket.accept()
        await websocket.send_text(json.dumps({"type": "error", "code": code, "message": message}))
        await websocket.close(code=close_code, reason=code)


def _client_ip(websocket: WebSocket) -> str:
    settings = get_settings()
    if settings.trust_proxy_headers:
        xff = websocket.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        real = websocket.headers.get("x-real-ip")
        if real:
            return real.strip()
    client = websocket.client
    return client.host if client else "unknown"


@router.websocket("/routers/{router_id}/console/ws")
async def console_websocket(
    websocket: WebSocket,
    router_id: str,
    ticket: str | None = Query(default=None, max_length=128),
) -> None:
    settings = get_settings()

    identity = await _resolve_identity(websocket)
    if identity is None:
        await _reject(
            websocket, bridge_service.CLOSE_UNAUTHORIZED, "unauthorized", "Authentication required"
        )
        return
    user, _session = identity

    if user.role not in CONSOLE_ROLES:
        await _reject(
            websocket,
            bridge_service.CLOSE_FORBIDDEN,
            "console_forbidden",
            "The interactive console requires the operator or admin role",
        )
        return

    if not settings.console_enabled:
        await _reject(
            websocket,
            bridge_service.CLOSE_FORBIDDEN,
            "console_disabled",
            "The web console is disabled",
        )
        return

    # Consume the ticket before anything else that can fail: a ticket must never be retryable.
    granted = console_service.TICKETS.consume(ticket)
    if granted is None:
        await _reject(
            websocket,
            bridge_service.CLOSE_INVALID_TICKET,
            "invalid_ticket",
            "The console ticket is missing, expired or already used",
        )
        return
    if granted.router_id != router_id or granted.user_id != user.id:
        await _reject(
            websocket,
            bridge_service.CLOSE_FORBIDDEN,
            "ticket_mismatch",
            "This console ticket was issued for a different router or user",
        )
        return

    item = _load_router(router_id)
    if item is None:
        await _reject(
            websocket, bridge_service.CLOSE_FORBIDDEN, "router_not_found", "Router not found"
        )
        return

    state = console_service.console_state(None, item, settings)
    if state != console_service.STATE_READY:
        _status, code, message = console_service.state_error(state)
        await _reject(websocket, bridge_service.CLOSE_UPSTREAM, code, message)
        return

    limit = int(settings.console_max_sessions_per_user)
    if limit > 0 and console_service.SESSIONS.count_for_user(user.id) >= limit:
        await _reject(
            websocket,
            bridge_service.CLOSE_FORBIDDEN,
            "console_session_limit",
            "Too many live console sessions",
        )
        return

    with contextlib.suppress(Exception):
        await websocket.accept()

    handler = bridge_service.ConsoleWebSocketHandler(
        websocket,
        router=item,
        user=user,
        client_ip=_client_ip(websocket),
        user_agent=websocket.headers.get("user-agent"),
        settings=settings,
    )
    try:
        await handler.run()
    except WebSocketDisconnect:
        handler.close_reason = handler.close_reason or "client_closed"
    except Exception:
        log.exception("console websocket failed for router %s", router_id)
        handler.close_reason = handler.close_reason or "error"
    finally:
        with contextlib.suppress(Exception):
            await websocket.close(code=1000)
