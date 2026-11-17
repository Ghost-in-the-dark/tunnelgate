"""Console REST API: open a ticket, inspect console state, list sessions.

The browser never receives SSH credentials: the only thing `start` returns is a one-time,
short-lived, router+user-bound ticket that the WebSocket handler redeems.

Authorization model
* `viewer` may not open a console (403 `console_forbidden`) but may read the state endpoint.
* `operator` / `admin` may open one, subject to a per-user rate limit and the live-session cap.
* `start` is CSRF-protected and fully audited (`console.start`); a failed attempt is audited as
  `console.start` with `outcome="error"` so an operator cannot probe routers silently.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select

from ..config import utcnow
from ..deps import CurrentUser, DbSession, SettingsDep, client_ip, csrf_protect
from ..errors import ApiError
from ..models import ConsoleSession, Router
from ..schemas import ConsoleSessionListOut, ConsoleSessionOut, ConsoleStartOut, iso
from ..security import RateLimiter
from ..services import console as console_service
from ..services.audit import record as audit_record

log = logging.getLogger("tunnelgate.api.console")

router = APIRouter(prefix="/api/v1", tags=["console"])

# 10 console opens per minute per user. Separate from the login limiter: opening a console is
# cheap for the panel but is an audited, privileged action on the router.
CONSOLE_START_LIMIT = 10
CONSOLE_START_WINDOW = 60
START_LIMITER = RateLimiter(limit=CONSOLE_START_LIMIT, window_seconds=CONSOLE_START_WINDOW)

CONSOLE_ROLES = ("admin", "operator")


# --------------------------------------------------------------------------- helpers
def _require_console_role(user) -> None:
    if user.role not in CONSOLE_ROLES:
        raise ApiError(
            403, "console_forbidden", "The interactive console requires the operator or admin role"
        )


def _get_router(db, router_id: str) -> Router:
    item = db.get(Router, router_id)
    if item is None:
        raise ApiError(404, "router_not_found", "Router not found")
    return item


def _state_error(state: str) -> ApiError:
    status, code, message = console_service.state_error(state)
    return ApiError(status, code, message, {"state": state})


def _issue_console_key(db, item: Router) -> None:
    """Provision the console key pair lazily, on the first console request for this router.

    `keys.issue_console_key` belongs to api-core and may not be deployed yet, so it is imported
    lazily: a missing implementation leaves the router in `no_key` (an honest, actionable
    state) instead of turning every console request into a 500.
    """
    try:
        from ..services.keys import issue_console_key
    except ImportError:  # pragma: no cover - depends on sibling module landing first
        log.warning("console key issuance is unavailable: app.services.keys is missing")
        return
    try:
        issue_console_key(db, item)
        db.commit()
    except Exception as exc:
        db.rollback()
        log.warning("console key issuance failed for router %s: %r", item.id, exc)
        raise ApiError(
            409, "console_no_key", "Could not provision a console key for this router"
        ) from exc
    db.refresh(item)


def _audit_start(
    db,
    item: Router,
    user,
    *,
    ip: str | None,
    user_agent: str | None,
    outcome: str = "ok",
    detail: dict | None = None,
) -> None:
    audit_record(
        db,
        "console.start",
        actor=user,
        outcome=outcome,
        router=item,
        ip=ip,
        user_agent=user_agent,
        detail=detail or {},
    )


def _console_read_out(db, item: Router, settings) -> dict:
    state = console_service.console_state(db, item, settings)
    return {
        "state": state,
        "console_port": item.console_port,
        "console_ssh_port": item.console_ssh_port,
        "ssh_user": console_service.console_ssh_user(item),
        "installed_at": iso(item.console_installed_at),
        "fingerprint": item.console_key_fingerprint,
        "active_sessions": console_service.SESSIONS.count_for_router(item.id),
        "idle_timeout_seconds": int(settings.console_idle_timeout_seconds),
        "max_session_seconds": int(settings.console_max_session_seconds),
        "max_sessions_per_user": int(settings.console_max_sessions_per_user),
    }


def _ws_path(router_id: str, ticket: str) -> str:
    return f"/api/v1/routers/{router_id}/console/ws?ticket={ticket}"


# --------------------------------------------------------------------------- endpoints
@router.post("/routers/{router_id}/console/start", response_model=ConsoleStartOut)
async def start_console(
    router_id: str,
    request: Request,
    db: DbSession,
    user: CurrentUser,
    settings: SettingsDep,
    _csrf: None = Depends(csrf_protect),
) -> ConsoleStartOut:
    """Prove the router is reachable, hand out a ticket, audit the attempt."""
    ip = client_ip(request)
    user_agent = request.headers.get("user-agent")
    _require_console_role(user)

    item = _get_router(db, router_id)

    if not settings.console_enabled:
        _audit_start(
            db,
            item,
            user,
            ip=ip,
            user_agent=user_agent,
            outcome="denied",
            detail={"error": console_service.STATE_DISABLED},
        )
        db.commit()
        raise _state_error(console_service.STATE_DISABLED)

    allowed, retry_after = START_LIMITER.check(f"console-start:{user.id}")
    if not allowed:
        _audit_start(
            db,
            item,
            user,
            ip=ip,
            user_agent=user_agent,
            outcome="denied",
            detail={"error": "rate_limited"},
        )
        db.commit()
        raise ApiError(
            429,
            "rate_limited",
            "Too many console sessions requested; slow down",
            {"retry_after_seconds": retry_after},
            headers={"Retry-After": str(retry_after)},
        )

    state = console_service.console_state(db, item, settings)
    if state == console_service.STATE_NO_KEY:
        _issue_console_key(db, item)
        state = console_service.console_state(db, item, settings)

    if state != console_service.STATE_READY:
        code = console_service.state_error(state)[1]
        _audit_start(
            db,
            item,
            user,
            ip=ip,
            user_agent=user_agent,
            outcome="denied",
            detail={"error": code, "state": state},
        )
        db.commit()
        raise _state_error(state)

    limit = int(settings.console_max_sessions_per_user)
    if limit > 0 and console_service.SESSIONS.count_for_user(user.id) >= limit:
        _audit_start(
            db,
            item,
            user,
            ip=ip,
            user_agent=user_agent,
            outcome="denied",
            detail={"error": "session_limit", "limit": limit},
        )
        db.commit()
        raise ApiError(
            409,
            "console_session_limit",
            f"You already have {limit} live console session(s); close one first",
            {"limit": limit},
        )

    START_LIMITER.hit(f"console-start:{user.id}")

    # Reachability probe: dial, then hang up. This turns "ticket issued but the socket fails"
    # into a clean 502 with the real reason, and it validates the sealed key end to end.
    connection = None
    try:
        connection = await console_service.open_ssh(item, settings)
    except console_service.ConsoleError as exc:
        _audit_start(
            db,
            item,
            user,
            ip=ip,
            user_agent=user_agent,
            outcome="error",
            detail={"error": exc.code},
        )
        db.commit()
        raise ApiError(exc.status, exc.code, exc.message) from exc
    finally:
        if connection is not None:
            with contextlib.suppress(Exception):
                connection.close()

    ticket = console_service.TICKETS.issue(item.id, user.id, ip)
    expires_at = utcnow()
    _audit_start(
        db,
        item,
        user,
        ip=ip,
        user_agent=user_agent,
        detail={
            "console_port": item.console_port,
            "ssh_user": console_service.console_ssh_user(item),
        },
    )
    db.commit()

    return ConsoleStartOut(
        router_id=item.id,
        ticket=ticket,
        ws_path=_ws_path(item.id, ticket),
        expires_at=iso(expires_at + timedelta(seconds=console_service.CONSOLE_TICKET_TTL_SECONDS))
        or "",
        console_port=int(item.console_port or 0),
    )


@router.get("/routers/{router_id}/console")
def console_info(
    router_id: str,
    db: DbSession,
    user: CurrentUser,
    settings: SettingsDep,
) -> dict:
    """Read-only console state. Available to every authenticated user (viewers included)."""
    item = _get_router(db, router_id)
    return _console_read_out(db, item, settings)


@router.get("/console/sessions", response_model=ConsoleSessionListOut)
def list_console_sessions(
    db: DbSession,
    user: CurrentUser,
    router_id: Annotated[str | None, Query(max_length=32)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ConsoleSessionListOut:
    """Recent console sessions. Admins see everyone's, operators only their own."""
    stmt = select(ConsoleSession)
    count_stmt = select(func.count(ConsoleSession.id))
    if user.role != "admin":
        stmt = stmt.where(ConsoleSession.user_id == user.id)
        count_stmt = count_stmt.where(ConsoleSession.user_id == user.id)
    if router_id:
        stmt = stmt.where(ConsoleSession.router_id == router_id)
        count_stmt = count_stmt.where(ConsoleSession.router_id == router_id)

    total = int(db.execute(count_stmt).scalar_one() or 0)
    rows = (
        db.execute(
            stmt.order_by(ConsoleSession.started_at.desc(), ConsoleSession.id.desc())
            .limit(limit)
            .offset(offset)
        )
        .scalars()
        .all()
    )
    items = [
        ConsoleSessionOut(
            id=row.id,
            router_id=row.router_id,
            router_name=row.router_name,
            username=row.username,
            client_ip=row.client_ip,
            started_at=iso(row.started_at),
            closed_at=iso(row.closed_at),
            close_reason=row.close_reason,
            bytes_in=row.bytes_in or 0,
            bytes_out=row.bytes_out or 0,
        )
        for row in rows
    ]
    return ConsoleSessionListOut(items=items, total=total)


@router.get("/routers/{router_id}/console/sessions", response_model=ConsoleSessionListOut)
def list_router_console_sessions(
    router_id: str,
    db: DbSession,
    user: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ConsoleSessionListOut:
    """Per-router convenience view of the same audit rows (used by the router detail page)."""
    _get_router(db, router_id)
    return list_console_sessions(db=db, user=user, router_id=router_id, limit=limit, offset=offset)
