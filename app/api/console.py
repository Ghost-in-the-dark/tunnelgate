"""Console REST API: open a ticket, inspect console state, list sessions.

The browser never receives SSH credentials: the only thing `start` returns is a one-time,
short-lived, router+user-bound ticket that the WebSocket handler redeems.

Authorization model
* `viewer` may not open a console (403 `console_forbidden`) but may read the state endpoint -
  for a router they were granted: console state is per-router data like any other, so
  app/services/access.py::require_router_access runs on it as well.
* the role check is not the only gate. Every console surface below also requires access to THAT
  router, so a later change to CONSOLE_ROLES cannot widen the reach of a role by accident -
  which is exactly the accident that let viewers see every router before grants existed.
* `operator` / `admin` may open one, subject to a per-user rate limit and the live-session cap.
* `start` is CSRF-protected and fully audited (`console.start`); a failed attempt is audited as
  `console.start` with `outcome="error"` so an operator cannot probe routers silently.
* `terminate` (DELETE /console/sessions/{id}) is admin-only and CSRF-protected: it signals the
  handler that owns the shell rather than writing the row itself, so the teardown stays the only
  writer of `closed_at`. Admins are audited as `console.terminate`.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import func, select

from ..config import utcnow
from ..deps import (
    AdminUser,
    CsrfGuard,
    CurrentUser,
    DbSession,
    SettingsDep,
    client_ip,
    csrf_protect,
)
from ..errors import ApiError
from ..models import ConsoleSession, Router
from ..schemas import ConsoleInfoOut, ConsoleSessionListOut, ConsoleSessionOut, ConsoleStartOut, iso
from ..security import RateLimiter
from ..services import console as console_service
from ..services.access import require_router_access
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


def _get_router(db, router_id: str, user=None) -> Router:
    """Load a router, checking per-router access first when a caller user is supplied.

    The access check runs BEFORE the row load on purpose: if the lookup went first, a viewer
    could tell an existing router from a missing one by the difference between 403 and 404,
    which is the existence oracle app/api/gate.py goes out of its way to avoid. With the
    check first, a viewer without a grant gets the same 403 whether or not the id is real.

    `user=None` is for the internal callers (websocket teardown, the audit list) that have
    already resolved who owns the session; every HTTP route below passes the current user.
    """
    if user is not None:
        require_router_access(db, user, router_id)
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


def _console_read_out(db, item: Router, settings) -> ConsoleInfoOut:
    state = console_service.console_state(db, item, settings)
    return ConsoleInfoOut(
        state=state,
        console_port=item.console_port,
        console_ssh_port=item.console_ssh_port,
        ssh_user=console_service.console_ssh_user(item),
        installed_at=iso(item.console_installed_at),
        # The console KEY fingerprint (the panel's own key, as the router sees it). Distinct
        # from the host key fields below, which are about who the router claims to be.
        fingerprint=item.console_key_fingerprint,
        # What the panel trusts about the router's identity, so an admin can see WHY a console
        # refuses to open after a reflash, and what an out-of-band check should be compared to.
        host_key_fingerprint=item.console_host_key_fingerprint,
        host_key_pinned_at=iso(item.console_host_key_seen_at),
        active_sessions=console_service.SESSIONS.count_for_router(item.id),
        idle_timeout_seconds=int(settings.console_idle_timeout_seconds),
        max_session_seconds=int(settings.console_max_session_seconds),
        max_sessions_per_user=int(settings.console_max_sessions_per_user),
    )


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

    # Role first, then per-router access: a viewer keeps getting console_forbidden even for a
    # router they were granted, because the role is the real blocker. The second check exists so
    # that a future CONSOLE_ROLES widening cannot hand an operator-role change access to every
    # router on its own - the grant table stays the only thing that says WHICH routers.
    item = _get_router(db, router_id, user)

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
        # db is passed so a host key met for the first time is pinned here, on the reachability
        # probe, rather than only on the WebSocket that follows it: an operator who gets a
        # ticket must be able to redeems it without the second handshake learning a new pin.
        connection = await console_service.open_ssh(item, settings, db=db)
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


@router.get("/routers/{router_id}/console", response_model=ConsoleInfoOut)
def console_info(
    router_id: str,
    db: DbSession,
    user: CurrentUser,
    settings: SettingsDep,
) -> ConsoleInfoOut:
    """Read-only console state. Available to every authenticated user - for a granted router.

    Console state is per-router data (ports, key fingerprints, live session count), so a viewer
    without a grant must not read it: that is the same leak the router list used to have. The
    check happens inside _get_router and returns 403 for an ungranted id and for an unknown one
    alike, so this endpoint is not a router-id oracle either.
    """
    item = _get_router(db, router_id, user)
    return _console_read_out(db, item, settings)


@router.delete("/routers/{router_id}/console/host-key", status_code=204)
async def clear_console_host_key(
    router_id: str,
    request: Request,
    db: DbSession,
    admin: AdminUser,
    _csrf: Annotated[None, CsrfGuard],
) -> Response:
    """Forget the router's pinned SSH host key so the next console open learns a new one.

    This is the counterpart of the trust-on-first-use pin in app/services/console.py. A pin is
    what stops a compromised or replaced router from presenting its own host key, so it must
    never be relearned silently - but a router that was legitimately reflashed or swapped DOES
    come back with a new host key, and without this route every console open on that device
    fails with console_auth_failed and the operator has no way out except editing the database.

    Deliberately admin-only and audited: clearing the pin is exactly the action an attacker who
    has taken a router would want a confused operator to perform, so it leaves a row naming who
    did it and the fingerprint they discarded.

    It terminates nothing. A live shell keeps running (the key was verified when it opened);
    the pin is simply relearned - and re-audited as a new pin - on the next open.
    """
    item = _get_router(db, router_id, admin)
    previous = item.console_host_key_fingerprint
    previous_seen_at = iso(item.console_host_key_seen_at)

    item.console_host_key_fingerprint = None
    item.console_host_key_seen_at = None
    audit_record(
        db,
        "console.host_key.cleared",
        actor=admin,
        router=item,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={
            "host_key_fingerprint": previous,
            "host_key_pinned_at": previous_seen_at,
        },
    )
    db.commit()
    log.info(
        "console host key pin cleared by admin=%s router=%s (was %s)",
        admin.username,
        item.id,
        previous,
    )
    return Response(status_code=204)


@router.delete("/console/sessions/{session_id}", status_code=204)
async def terminate_console_session(
    session_id: str,
    request: Request,
    db: DbSession,
    admin: AdminUser,
    _csrf: Annotated[None, CsrfGuard],
) -> Response:
    """Force-close one live console session (kill console).

    The panel does not touch the SSH channel here: it signals the handler that owns it, and the
    handler watchdog turns that into an exit frame and the usual teardown, which is also what
    stamps closed_at, the byte counters and the console.close audit row. Keeping a single writer
    of the session row matters: a DELETE that wrote closed_at itself could race the teardown and
    leave the shell running behind a row the UI already shows as finished.

    A session that is not live in THIS process cannot be killed: the row may belong to a panel
    that is still starting the shell (between the row insert and the registry add) or to a
    previous process that died without closing it. Both are 409, not 204 - reporting success for
    a shell that keeps running is worse than telling the admin to look again.
    """
    row = db.get(ConsoleSession, session_id)
    if row is None:
        raise ApiError(404, "console_session_not_found", "No such console session")

    if row.closed_at is not None:
        raise ApiError(
            409,
            "console_session_closed",
            "That console session has already ended",
            {"close_reason": row.close_reason, "closed_at": iso(row.closed_at)},
        )

    live = console_service.SESSIONS.get(session_id)
    if live is None:
        raise ApiError(
            409,
            "console_session_not_live",
            "That console session is not running in this panel process, so there is nothing to "
            "close; it is either still starting or was left open by a previous run",
        )

    live.request_close(console_service.CLOSE_REASON_ADMIN_TERMINATED)
    audit_record(
        db,
        "console.terminate",
        actor=admin,
        router_id=row.router_id,
        router_name=row.router_name,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={
            "session_id": row.id,
            "target_username": row.username,
            "target_client_ip": row.client_ip,
            "reason": console_service.CLOSE_REASON_ADMIN_TERMINATED,
        },
    )
    db.commit()
    log.info(
        "console terminated by admin=%s router=%s session=%s",
        admin.username,
        row.router_id,
        row.id,
    )
    return Response(status_code=204)


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
    """Per-router convenience view of the same audit rows (used by the router detail page).

    The rows are session metadata for one router - who opened a shell and when - so the same
    per-router grant applies here as to the state read above.
    """
    _get_router(db, router_id, user)
    return list_console_sessions(db=db, user=user, router_id=router_id, limit=limit, offset=offset)
