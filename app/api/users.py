"""User administration. Every route here requires the admin role.

The last active admin is protected: demoting or deleting them would leave a panel with nobody
able to manage users, which is unrecoverable through the UI. The check runs inside the request
transaction so two concurrent demotions cannot both see "there are two admins".
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Request, Response
from sqlalchemy import func, select

from ..config import utcnow
from ..deps import AdminUser, CsrfGuard, DbSession, client_ip
from ..errors import ApiError
from ..models import PanelSession, User
from ..schemas import UserCreate, UserOut, UserUpdate
from ..security import hash_password, password_problem, verify_password
from ..services.audit import record as audit_record

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/users", tags=["users"])


def _get_user(db, user_id: int) -> User:
    item = db.get(User, user_id)
    if item is None:
        raise ApiError(404, "not_found", "User not found")
    return item


def _active_admins(db, *, exclude_id: int | None = None) -> int:
    """How many enabled admins exist, optionally ignoring one row (the one being changed)."""
    stmt = select(func.count(User.id)).where(User.role == "admin", User.is_active.is_(True))
    if exclude_id is not None:
        stmt = stmt.where(User.id != exclude_id)
    return int(db.execute(stmt).scalar_one())


def _guard_last_admin(db, item: User) -> None:
    """Refuse to leave the panel without an enabled admin."""
    if item.role == "admin" and item.is_active and _active_admins(db, exclude_id=item.id) == 0:
        raise ApiError(
            409,
            "last_admin",
            "This is the last active admin; create another admin first",
        )


def _check_password(password: str) -> None:
    problem = password_problem(password)
    if problem:
        raise ApiError(400, "validation_error", problem)


@router.get("", response_model=dict)
async def list_users(db: DbSession, admin: AdminUser) -> dict:
    """All users, oldest first. Returned as {items,total}; the SPA also tolerates a bare array."""
    rows = db.execute(select(User).order_by(User.id)).scalars().all()
    return {"items": [UserOut.model_validate(u) for u in rows], "total": len(rows)}


@router.post("", response_model=UserOut, status_code=201)
async def create_user(
    payload: UserCreate,
    request: Request,
    db: DbSession,
    admin: AdminUser,
    _csrf: Annotated[None, CsrfGuard],
) -> UserOut:
    """Create an account. Username uniqueness is a 422, not a 409: it is a field-level conflict."""
    _check_password(payload.password)
    existing = db.execute(
        select(User).where(User.username == payload.username)
    ).scalar_one_or_none()
    if existing is not None:
        raise ApiError(
            422,
            "validation_error",
            "That username is already taken",
            {"fields": [{"loc": ["body", "username"], "msg": "already taken"}]},
        )
    item = User(
        username=payload.username,
        display_name=payload.display_name,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(item)
    db.flush()
    audit_record(
        db,
        "user.create",
        actor=admin,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={"username": item.username, "role": item.role},
    )
    db.commit()
    db.refresh(item)
    return UserOut.model_validate(item)


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    db: DbSession,
    admin: AdminUser,
    _csrf: Annotated[None, CsrfGuard],
) -> UserOut:
    """Patch display name, role, active flag and/or password.

    A password change through the admin API revokes that user's live sessions: an admin resetting
    a password is usually responding to a compromise, so leaving the old sessions alive would
    defeat the point.
    """
    item = _get_user(db, user_id)
    changed = payload.model_dump(exclude_unset=True)
    demoting = changed.get("role") is not None and changed["role"] != "admin"
    disabling = changed.get("is_active") is False
    if demoting or disabling:
        _guard_last_admin(db, item)
    if "display_name" in changed:
        item.display_name = changed["display_name"]
    if changed.get("role") is not None:
        item.role = changed["role"]
    if changed.get("is_active") is not None:
        item.is_active = bool(changed["is_active"])
    revoked = 0
    if changed.get("password"):
        new_password = changed["password"]
        _check_password(new_password)
        if verify_password(new_password, item.password_hash):
            raise ApiError(400, "validation_error", "The new password must differ from the old")
        item.password_hash = hash_password(new_password)
        for other in (
            db.execute(
                select(PanelSession).where(
                    PanelSession.user_id == item.id, PanelSession.revoked_at.is_(None)
                )
            )
            .scalars()
            .all()
        ):
            other.revoked_at = utcnow()
            revoked += 1
    audit_record(
        db,
        "user.update",
        actor=admin,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={
            "username": item.username,
            "fields": sorted(k for k in changed if k != "password"),
            "sessions_revoked": revoked,
        },
    )
    db.commit()
    db.refresh(item)
    return UserOut.model_validate(item)


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: int,
    request: Request,
    db: DbSession,
    admin: AdminUser,
    _csrf: Annotated[None, CsrfGuard],
) -> Response:
    item = _get_user(db, user_id)
    _guard_last_admin(db, item)
    username = item.username
    audit_record(
        db,
        "user.delete",
        actor=admin,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={"username": username},
    )
    db.delete(item)
    db.commit()
    return Response(status_code=204)
