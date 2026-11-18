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
import hmac
import json
import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from .. import forwarded
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


# Close code for "the ticket is real, but it is being redeemed from a different address".
# Deliberately not CLOSE_FORBIDDEN (a role problem) and not CLOSE_INVALID_TICKET (the ticket
# itself was fine), so a client can tell a stolen or replayed ticket apart from the others.
CLOSE_TICKET_FOREIGN_IP = 4003

# Placeholder when the peer address cannot be resolved to an IP at all.
UNKNOWN_IP = "unknown"


def _client_ip(websocket: WebSocket) -> str:
    """The address this socket is coming from, for ticket binding.

    Delegated to app.forwarded so the console pins tickets against exactly the same notion of
    client address the REST API writes into audit rows and rate-limit buckets: if the two
    drifted apart, a ticket issued behind a proxy would never match the socket redeeming it.

    forwarded answers "unknown" when the peer is not an IP at all, which really only happens for
    a unix socket or a test transport. Falling back to the literal peer keeps the binding tight
    there too, instead of silently disabling the check for anyone who can arrange a non-IP peer.
    """
    address = forwarded.client_ip(websocket, get_settings())
    if address == UNKNOWN_IP:
        peer = websocket.client.host if websocket.client else None
        if peer:
            return str(peer)
    return address


def _ticket_ip_matches(ticket_ip: str, peer_ip: str) -> bool:
    """Whether a ticket minted from one address may be redeemed from another.

    An empty or unroutable side is not pinned. "unknown" means the server genuinely cannot see
    the peer (a unix socket, a test transport, a stripped client scope) - refusing those would
    break the console without protecting anything, because an attacker who can make the server
    forget its own peer address is already past this check.
    """
    ticket_ip = forwarded.normalize_ip(ticket_ip) or (ticket_ip or "")
    peer_ip = forwarded.normalize_ip(peer_ip) or (peer_ip or "")
    if not ticket_ip or ticket_ip == UNKNOWN_IP:
        return True
    if not peer_ip or peer_ip == UNKNOWN_IP:
        return True
    return hmac.compare_digest(ticket_ip, peer_ip)


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

    # docs/API.md promised the ticket is bound to the client ip; without this check the promise
    # was fiction, and a leaked ws_path in a log or a Referer was replayable from anywhere for
    # the ticket's whole TTL. The ticket is already consumed at this point, so a refusal burns
    # it: an attacker holding a stolen ticket gets exactly one attempt, and it fails.
    peer_ip = _client_ip(websocket)
    if not _ticket_ip_matches(granted.client_ip, peer_ip):
        log.warning(
            "console ticket for router %s redeemed from %s, issued to %s",
            router_id,
            peer_ip,
            granted.client_ip,
        )
        await _reject(
            websocket,
            CLOSE_TICKET_FOREIGN_IP,
            "ticket_foreign_ip",
            "This console ticket was issued to a different client address",
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
        client_ip=peer_ip,
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
