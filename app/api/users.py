"""User administration. Every route here requires the admin role.

The last active admin is protected: demoting or deleting them would leave a panel with nobody
able to manage users, which is unrecoverable through the UI. The check runs inside the request
transaction so two concurrent demotions cannot both see "there are two admins".

The per-router grant routes at the bottom live here rather than in app/api/routers.py because a
grant is a property of a USER, not of a router: an access review starts from "what may this
person reach", and the question "who can reach this router" is answered by the same table from
the audit trail. Everything under /api/v1/users is admin-only, which is also what a permission
change deserves - an operator who could grant themselves routers would make app/services/access.py
pointless.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Request, Response
from sqlalchemy import func, select

from ..config import utcnow
from ..deps import AdminUser, CsrfGuard, DbSession, SettingsDep, client_ip
from ..errors import ApiError
from ..models import PanelSession, Router, RouterGrant, User
from ..schemas import UserCreate, UserOut, UserRouterGrantsIn, UserUpdate
from ..security import hash_password, password_problem, verify_password
from ..services.audit import record as audit_record
from .routers import router_out

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


# --------------------------------------------------------------------------- router grants
# Per-router permissions. Admin and operator never need a row here - app/services/access.py
# says why - so these routes exist to hand a viewer one router at a time and to let an access
# review read back exactly what was handed out. Replacing the whole set (PUT) rather than
# adding/removing single rows is deliberate: a set operation is idempotent, so a UI retry after
# a timeout cannot double-grant, and the audit row then records the state that resulted instead
# of a delta nobody can replay against an unknown starting point.
def _granted_router_ids(db, user_id: int) -> set[str]:
    rows = db.execute(select(RouterGrant.router_id).where(RouterGrant.user_id == user_id))
    return set(rows.scalars().all())


@router.get("/{user_id}/routers", response_model=dict)
async def list_user_routers(
    user_id: int,
    db: DbSession,
    admin: AdminUser,
    settings: SettingsDep,
) -> dict:
    """The routers granted to one user, in the list shape the router screens already use."""
    item = _get_user(db, user_id)
    rows = (
        db.execute(
            select(Router)
            .join(RouterGrant, RouterGrant.router_id == Router.id)
            .where(RouterGrant.user_id == item.id)
            .order_by(Router.created_at.desc())
        )
        .scalars()
        .all()
    )
    return {
        "items": [router_out(row, settings=settings) for row in rows],
        "total": len(rows),
    }


@router.put("/{user_id}/routers", response_model=dict)
async def replace_user_routers(
    user_id: int,
    payload: UserRouterGrantsIn,
    request: Request,
    db: DbSession,
    admin: AdminUser,
    _csrf: Annotated[None, CsrfGuard],
    settings: SettingsDep,
) -> dict:
    """Replace the set of routers this user may reach. Unknown ids are a 400, not a silent skip.

    Silently ignoring an id that no longer exists would be the worst of both worlds: the caller
    believes a grant exists, no row was written, and nobody finds out until that person cannot
    open the router. Naming the ids in the error lets the UI show which one went stale.

    Role changes and grants are deliberately independent. Promoting a user to admin or operator
    leaves their grant rows in place - they are redundant then, harmless, and if the role falls
    back to viewer they become the whole permission again. Demoting an admin or operator to
    viewer does NOT create grants and does not delete anything: they simply stop reaching
    routers until an admin grants them, one at a time. Deleting a user or a router does cascade
    the rows away (ondelete CASCADE), so "no rows" always means "no grants", never an orphan.
    """
    item = _get_user(db, user_id)
    wanted = payload.router_ids
    if wanted:
        found = set(db.execute(select(Router.id).where(Router.id.in_(wanted))).scalars().all())
        missing = [router_id for router_id in wanted if router_id not in found]
        if missing:
            raise ApiError(
                400,
                "validation_error",
                "Unknown router id in router_ids: " + ", ".join(sorted(missing)),
                {
                    "fields": [
                        {"loc": ["body", "router_ids"], "msg": f"unknown router {i}"}
                        for i in missing
                    ]
                },
            )
    current = _granted_router_ids(db, item.id)
    target = set(wanted)
    removed = sorted(current - target)
    added = sorted(target - current)
    for router_id in removed:
        grant = db.execute(
            select(RouterGrant).where(
                RouterGrant.user_id == item.id, RouterGrant.router_id == router_id
            )
        ).scalar_one()
        db.delete(grant)
    for router_id in added:
        db.add(RouterGrant(user_id=item.id, router_id=router_id, created_by_id=admin.id))
    db.flush()
    audit_record(
        db,
        "user.grants.update",
        actor=admin,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={
            "username": item.username,
            "router_ids": sorted(target),
            "added": added,
            "removed": removed,
        },
    )
    db.commit()
    rows = (
        db.execute(
            select(Router).where(Router.id.in_(sorted(target))).order_by(Router.created_at.desc())
        )
        .scalars()
        .all()
        if target
        else []
    )
    return {
        "items": [router_out(row, settings=settings) for row in rows],
        "total": len(rows),
    }


@router.delete("/{user_id}/routers/{router_id}", status_code=204)
async def revoke_user_router(
    user_id: int,
    router_id: str,
    request: Request,
    db: DbSession,
    admin: AdminUser,
    _csrf: Annotated[None, CsrfGuard],
) -> Response:
    """Remove ONE grant. 404 when there was none: a delete that reports success while doing
    nothing teaches the caller that the router was protected when it was not."""
    item = _get_user(db, user_id)
    grant = db.execute(
        select(RouterGrant).where(
            RouterGrant.user_id == item.id, RouterGrant.router_id == router_id
        )
    ).scalar_one_or_none()
    if grant is None:
        raise ApiError(404, "not_found", "This user has no grant for that router")
    db.delete(grant)
    audit_record(
        db,
        "user.grants.revoke",
        actor=admin,
        router_id=router_id,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={"username": item.username, "router_ids": [router_id]},
    )
    db.commit()
    return Response(status_code=204)
