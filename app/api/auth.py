"""Panel sessions: login, logout, whoami, password change.

Two things this module refuses to do, both on purpose:

* it never says whether a username exists (a wrong password and an unknown account produce the
  same 401 invalid_credentials), and
* it never tells an attacker that they hit the rate limit of a *valid* account: throttling is
  checked per client ip and per ip+username before the password is looked at.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Request, Response
from sqlalchemy import select

from ..config import get_settings, utcnow
from ..deps import CsrfGuard, CurrentSession, CurrentUser, DbSession, SettingsDep, client_ip
from ..errors import ApiError
from ..models import PanelSession, User
from ..schemas import ChangePasswordRequest, LoginRequest, SessionOut, UserOut, iso
from ..security import (
    RateLimiter,
    hash_password,
    hash_token,
    new_token,
    password_problem,
    verify_password,
)
from ..services.audit import record as audit_record

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Per-ip and per-ip+username, both sliding windows. The limits come from settings at call time
# so an operator can tighten them without a code change; the object is rebuilt only when the
# configured numbers move.
LOGIN_LIMITER = RateLimiter(
    limit=get_settings().login_rate_limit, window_seconds=get_settings().login_rate_window_seconds
)


def _limiter(settings) -> RateLimiter:
    """The module limiter, re-tuned when the settings changed (tests set a huge limit)."""
    if LOGIN_LIMITER.limit != int(settings.login_rate_limit) or LOGIN_LIMITER.window != int(
        settings.login_rate_window_seconds
    ):
        LOGIN_LIMITER.limit = int(settings.login_rate_limit)
        LOGIN_LIMITER.window = int(settings.login_rate_window_seconds)
        LOGIN_LIMITER.clear()
    return LOGIN_LIMITER


def _set_cookie(response: Response, token: str, settings) -> None:
    max_age = int(settings.session_ttl_minutes) * 60
    response.set_cookie(
        settings.cookie_name,
        token,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=bool(settings.cookie_secure),
        path="/",
        domain=settings.cookie_domain or None,
    )


def _clear_cookie(response: Response, settings) -> None:
    response.delete_cookie(
        settings.cookie_name,
        path="/",
        domain=settings.cookie_domain or None,
    )


def _create_session(db, user: User, request: Request, settings) -> tuple[str, PanelSession]:
    """Mint a session row plus the plaintext cookie token (only its hash is stored)."""
    plaintext = new_token()
    session = PanelSession(
        user_id=user.id,
        token_hash=hash_token(plaintext),
        csrf_token=new_token(24),
        expires_at=utcnow() + timedelta(minutes=int(settings.session_ttl_minutes)),
        ip=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:255] or None,
    )
    db.add(session)
    db.flush()
    return plaintext, session


@router.post("/login", response_model=SessionOut)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: DbSession,
    settings: SettingsDep,
) -> SessionOut:
    ip = client_ip(request)
    limiter = _limiter(settings)
    keys = (f"login-ip:{ip}", f"login-user:{ip}:{payload.username.lower()}")
    allowed, retry_after = limiter.check(*keys)
    if not allowed:
        audit_record(
            db,
            "auth.login_failed",
            actor_username=payload.username,
            outcome="denied",
            ip=ip,
            user_agent=request.headers.get("user-agent"),
            detail={"reason": "rate_limited"},
        )
        db.commit()
        raise ApiError(
            429,
            "rate_limited",
            "Too many login attempts; try again later",
            {"retry_after_seconds": retry_after},
            headers={"Retry-After": str(retry_after)},
        )

    user = db.execute(select(User).where(User.username == payload.username)).scalar_one_or_none()
    if user is None or not verify_password(payload.password, user.password_hash):
        # One code for "no such user" and "wrong password": the response must not be an
        # account-existence oracle. The audit row still records which username was tried.
        limiter.hit(*keys)
        audit_record(
            db,
            "auth.login_failed",
            actor_username=payload.username,
            outcome="denied",
            ip=ip,
            user_agent=request.headers.get("user-agent"),
            detail={"reason": "bad_credentials"},
        )
        db.commit()
        raise ApiError(401, "invalid_credentials", "Wrong username or password")

    if not user.is_active:
        limiter.hit(*keys)
        audit_record(
            db,
            "auth.login_failed",
            actor=user,
            outcome="denied",
            ip=ip,
            user_agent=request.headers.get("user-agent"),
            detail={"reason": "disabled"},
        )
        db.commit()
        raise ApiError(401, "invalid_credentials", "Wrong username or password")

    limiter.reset(*keys)
    plaintext, session = _create_session(db, user, request, settings)
    user.last_login_at = utcnow()
    audit_record(db, "auth.login", actor=user, ip=ip, user_agent=request.headers.get("user-agent"))
    db.commit()
    _set_cookie(response, plaintext, settings)
    return SessionOut(
        user=UserOut.model_validate(user),
        csrf_token=session.csrf_token,
        expires_at=iso(session.expires_at),
    )


@router.post("/logout", status_code=204)
async def logout(
    request: Request,
    response: Response,
    db: DbSession,
    session: CurrentSession,
    settings: SettingsDep,
) -> Response:
    session.revoked_at = utcnow()
    audit_record(
        db,
        "auth.logout",
        actor=db.get(User, session.user_id),
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()
    _clear_cookie(response, settings)
    response.status_code = 204
    return response


@router.get("/me", response_model=SessionOut)
async def me(
    session: CurrentSession,
    user: CurrentUser,
    db: DbSession,
) -> SessionOut:
    """Who the cookie belongs to, plus the CSRF token so a reload keeps working.

    The session token itself is never echoed - it lives in an HttpOnly cookie precisely so
    JavaScript cannot read it. The CSRF token is safe to hand out: it is useless without that
    cookie.
    """
    return SessionOut(
        user=UserOut.model_validate(user),
        csrf_token=session.csrf_token,
        expires_at=iso(session.expires_at),
    )


@router.post("/password", status_code=204)
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    response: Response,
    db: DbSession,
    user: CurrentUser,
    session: CurrentSession,
    _csrf: Annotated[None, CsrfGuard],
    settings: SettingsDep,
) -> Response:
    """Rehash the password and revoke every *other* session of that account.

    Revoking the others is the point: if the reason for the change is "somebody else may know
    my password", leaving their sessions alive would make the change cosmetic.
    """
    if not verify_password(payload.current_password, user.password_hash):
        audit_record(
            db,
            "auth.password",
            actor=user,
            outcome="denied",
            ip=client_ip(request),
            detail={"reason": "bad_current_password"},
        )
        db.commit()
        raise ApiError(403, "invalid_credentials", "The current password is not correct")

    problem = password_problem(payload.new_password)
    if problem:
        raise ApiError(400, "validation_error", problem)
    if payload.new_password == payload.current_password:
        raise ApiError(400, "validation_error", "The new password must differ from the old one")

    user.password_hash = hash_password(payload.new_password)
    revoked = 0
    others = (
        db.execute(
            select(PanelSession).where(
                PanelSession.user_id == user.id,
                PanelSession.id != session.id,
                PanelSession.revoked_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    for other in others:
        other.revoked_at = utcnow()
        revoked += 1
    audit_record(
        db, "auth.password", actor=user, ip=client_ip(request), detail={"sessions_revoked": revoked}
    )
    db.commit()
    response.status_code = 204
    return response
