"""FastAPI dependencies: panel session auth, CSRF protection, role checks, client ip."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import forwarded
from .config import Settings, get_settings, utcnow
from .db import get_db
from .errors import ApiError
from .models import PanelSession, User
from .security import hash_token, tokens_equal

DbSession = Annotated[Session, Depends(get_db)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


def client_ip(request: Request) -> str:
    """The client address, or the socket peer when no trusted proxy vouched for it.

    The leftmost X-Forwarded-For entry is attacker-controlled: every proxy appends the address
    it saw, so the honest value is "forwarded_allow_hops" entries from the RIGHT, and only when
    the socket peer itself is a configured proxy. See app/forwarded.py for the full rule.
    """
    return forwarded.client_ip(request, get_settings())


def get_session_optional(request: Request, db: DbSession) -> PanelSession | None:
    token = request.cookies.get(get_settings().cookie_name)
    if not token:
        return None
    sess = db.execute(
        select(PanelSession).where(PanelSession.token_hash == hash_token(token))
    ).scalar_one_or_none()
    if sess is None or sess.revoked_at is not None or sess.expires_at <= utcnow():
        return None
    return sess


def get_current_session(request: Request, db: DbSession) -> PanelSession:
    sess = get_session_optional(request, db)
    if sess is None:
        raise ApiError(401, "unauthorized", "Authentication required")
    return sess


def get_current_user(
    session: Annotated[PanelSession, Depends(get_current_session)], db: DbSession
) -> User:
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise ApiError(401, "unauthorized", "Account is disabled")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentSession = Annotated[PanelSession, Depends(get_current_session)]
OptionalSession = Annotated[PanelSession | None, Depends(get_session_optional)]


def require_roles(*roles: str):
    """Dependency factory: the caller must hold one of the given roles."""

    def _dep(user: CurrentUser) -> User:
        if user.role not in roles:
            raise ApiError(403, "forbidden", "Role " + user.role + " may not perform this action")
        return user

    return _dep


AdminUser = Annotated[User, Depends(require_roles("admin"))]
OperatorUser = Annotated[User, Depends(require_roles("admin", "operator"))]


def csrf_protect(request: Request, session: CurrentSession) -> None:
    """Double-submit check: the header and the cookie must agree, and both must match the session.

    The token belongs to the server-side session row (PanelSession.csrf_token) and to nothing
    else. Login writes it into the csrf cookie as well, and every mutating panel request has to
    echo it in the header, so a request proves both that a browser script attached the header
    and that the cookie for this session travelled with it.

    Why both halves and not just the header: the header alone is satisfiable by anything that
    can read the token, and the token used to be readable by any same-origin script because it
    was a field of GET /api/auth/me. In the merged path layout router pages are same-origin with
    the panel, so a compromised router page could fetch that route with the operator's cookie,
    lift the token and mutate anything - proven in a real browser by creating a second admin
    account. Requiring the cookie too means the attacker needs the cookie jar as well, which a
    cross-origin page cannot read; combined with the token no longer appearing in any response
    body, the cheapest path is closed.

    Fail-closed by design, and deliberately strict about a missing cookie: no header, no cookie,
    a mismatch in either direction, or a session whose token differs all raise the same
    csrf_failed. An older client that still holds a token it obtained from the JSON body before
    this change is rejected on its next mutation and must sign in again - that is the intended
    cost, and it is one page reload, not a data loss. The SPA picks the token up from the cookie
    automatically; only a hand-written HTTP client has to be updated.

    Both comparisons go through tokens_equal, which is hmac.compare_digest, so neither the
    header nor the cookie is compared with == anywhere along this path: a length- or
    content-dependent early return would leak the token byte by byte.

    State-changing panel requests only. Bootstrap/heartbeat endpoints authenticate with their
    own bearer tokens and are exempt.
    """
    settings = get_settings()
    supplied = request.headers.get(settings.csrf_header)
    submitted = request.cookies.get(settings.csrf_cookie_name)
    if not supplied or not submitted:
        raise ApiError(403, "csrf_failed", "Missing or invalid CSRF token")
    # Header against cookie first, then cookie against the session: the cookie alone is not
    # enough (a page can be made to send it by simply being on the origin) and the header alone
    # is not enough (a script that can set it can also read it). Only the pair, plus the session
    # binding, is evidence of anything.
    if not tokens_equal(supplied, submitted) or not tokens_equal(submitted, session.csrf_token):
        raise ApiError(403, "csrf_failed", "Missing or invalid CSRF token")


CsrfGuard = Depends(csrf_protect)
