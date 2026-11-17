"""Audit log read API.

Read-only and available to every authenticated role: being able to see who did what is not a
privilege escalation, it is the reason the log exists. Only the panel writes rows (through
`app.services.audit.record`); nothing here can create, edit or delete an entry.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Query
from sqlalchemy import ColumnElement, func, select

from ..deps import CurrentUser, DbSession
from ..models import AuditLog
from ..schemas import AuditListOut, AuditOut, iso

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000


def _to_out(entry: AuditLog) -> AuditOut:
    return AuditOut(
        id=entry.id,
        ts=iso(entry.ts),
        actor_username=entry.actor_username,
        action=entry.action,
        outcome=entry.outcome,
        router_id=entry.router_id,
        router_name=entry.router_name,
        ip=entry.ip,
        detail=entry.detail,
    )


@router.get("", response_model=AuditListOut)
async def list_audit(
    db: DbSession,
    user: CurrentUser,
    router_id: str | None = Query(default=None),
    actor: str | None = Query(default=None),
    action: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> AuditListOut:
    """Newest first. `actor` matches the username exactly; `action` matches the dotted name."""
    filters: list[ColumnElement[bool]] = []
    if router_id:
        filters.append(AuditLog.router_id == router_id)
    if actor:
        filters.append(AuditLog.actor_username == actor)
    if action:
        filters.append(AuditLog.action == action)
    if outcome:
        filters.append(AuditLog.outcome == outcome)
    total = db.execute(select(func.count(AuditLog.id)).where(*filters)).scalar_one()
    rows = (
        db.execute(
            select(AuditLog)
            .where(*filters)
            .order_by(AuditLog.id.desc())
            .limit(limit)
            .offset(offset)
        )
        .scalars()
        .all()
    )
    return AuditListOut(items=[_to_out(r) for r in rows], total=int(total))
