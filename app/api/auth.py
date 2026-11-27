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

from .. import forwarded
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

# A throwaway scrypt hash, generated once at import, used only to keep the failed-login path
# flat. Returning early on "no such user" would skip a full scrypt (~85 ms) while an existing
# account with a wrong password pays for one, so the response time itself says whether the
# username exists. Verifying against this dummy costs exactly the same.
DUMMY_PASSWORD_HASH = hash_password(new_token())

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


def _cookie_secure(request: Request, settings) -> bool:
    """Whether the session cookie carries Secure.

    TUNNELGATE_COOKIE_SECURE=true forces it on. It is also set when the request itself arrived
    over HTTPS from a trusted TLS terminator, because a panel published as https://... and
    issuing a non-Secure session cookie is a downgrade the operator did not ask for - and one
    they cannot see. False is only ever returned for a request that is genuinely plain HTTP.
    """
    if bool(settings.cookie_secure):
        return True
    return forwarded.request_scheme(request, settings) == "https"


def _set_cookie(response: Response, token: str, settings, request: Request) -> None:
    max_age = int(settings.session_ttl_minutes) * 60
    response.set_cookie(
        settings.cookie_name,
        token,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(request, settings),
        path="/",
        domain=settings.cookie_domain or None,
    )


def _set_csrf_cookie(response: Response, csrf_token: str, settings, request: Request) -> None:
    """Write the double-submit CSRF cookie beside the session cookie.

    Why a cookie and not the JSON body it used to be in: the token was considered harmless
    because the session cookie is HttpOnly, and that reasoning fails in exactly one documented
    deployment - the merged path layout, where router pages are served from the panel's own
    origin. There a compromised router page runs same-origin script, calls GET /api/auth/me,
    reads the token out of the response and performs any authenticated mutation. Proven in a
    real browser (a router page created a second admin account). Serving it as a cookie that no
    response body ever contains removes that fetch-and-read step.

    HttpOnly is OFF on purpose, unlike the session cookie: the SPA has to read this value to
    build the X-CSRF-Token header, and a token that only the browser can send is a token the
    browser must be able to show to script. The session cookie is the credential; this cookie
    is only the second half of a proof that the request came from the same origin.

    Attributes mirror the session cookie (same max-age, path, domain, samesite, secure) so the
    two cannot drift apart under TUNNELGATE_COOKIE_DOMAIN or a TLS terminator: a session cookie
    this browser already dropped would otherwise leave a live CSRF cookie behind, and an
    operator who narrows the session scope must narrow this one with it. httpx.TestClient drops
    a cookie whose max-age is 0, so the test suite sees logout delete both.
    """
    response.set_cookie(
        settings.csrf_cookie_name,
        csrf_token,
        max_age=int(settings.session_ttl_minutes) * 60,
        httponly=False,
        samesite="lax",
        secure=_cookie_secure(request, settings),
        path="/",
        domain=settings.cookie_domain or None,
    )


def _clear_cookie(response: Response, settings) -> None:
    response.delete_cookie(
        settings.cookie_name,
        path="/",
        domain=settings.cookie_domain or None,
    )


def _clear_csrf_cookie(response: Response, settings) -> None:
    """Logout must take the CSRF cookie with it.

    Leaving it behind would keep a stale token in the browser past the session it belongs to;
    the next login would then have to overwrite it before the first mutation, and an operator
    reading their bank of cookies would see a live-looking CSRF token for a dead session.
    """
    response.delete_cookie(
        settings.csrf_cookie_name,
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
    # Always run a full scrypt verification, even when there is no row to check against: the
    # cost must not depend on whether the username exists, or the timing is an oracle.
    candidate_hash = (user.password_hash if user is not None else None) or DUMMY_PASSWORD_HASH
    password_ok = verify_password(payload.password, candidate_hash)
    if user is None or not password_ok:
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
    _set_cookie(response, plaintext, settings, request)
    _set_csrf_cookie(response, session.csrf_token, settings, request)
    return SessionOut(
        user=UserOut.model_validate(user),
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
    _clear_csrf_cookie(response, settings)
    response.status_code = 204
    return response


@router.get("/me", response_model=SessionOut)
async def me(
    session: CurrentSession,
    user: CurrentUser,
    db: DbSession,
) -> SessionOut:
    """Who the cookie belongs to. The CSRF token is NOT part of this answer any more.

    It is in the csrf cookie instead: login sets it next to the session cookie with the same
    lifetime, and logout deletes it. It used to be a field of this body, which was the whole
    vulnerability: in the merged path layout a router page is same-origin with the panel, so
    a compromised router could fetch this route with the operator's cookie and read the token
    straight out of the JSON - then mutate anything the operator could. Measured in a real
    browser, where a router page created a second admin account. This route does not touch the
    cookie: login writes it and logout deletes it, so a reloaded SPA reads the value the browser
    still holds and needs nothing from this answer.

    Serving it as a cookie does not make it secret from same-origin script - a script in the
    panel's origin can still read a non-HttpOnly cookie. What it removes is the cheap path: no
    response body carries the token, so no fetch, cache entry, log line, proxy trace or
    developer-tools response pane carries it either, and an attacker needs real script
    execution in the origin rather than merely a page served from it. See docs/SECURITY.md.

    The session token itself is still never echoed - it lives in an HttpOnly cookie precisely
    so JavaScript cannot read it.
    """
    return SessionOut(
        user=UserOut.model_validate(user),
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
