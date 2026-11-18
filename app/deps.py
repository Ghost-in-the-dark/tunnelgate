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
    """Double-submit style check: header must carry the token bound to this session.

    State-changing panel requests only. Bootstrap/heartbeat endpoints authenticate with
    their own bearer tokens and are exempt.
    """
    supplied = request.headers.get(get_settings().csrf_header)
    if not supplied or not tokens_equal(supplied, session.csrf_token):
        raise ApiError(403, "csrf_failed", "Missing or invalid CSRF token")


CsrfGuard = Depends(csrf_protect)
