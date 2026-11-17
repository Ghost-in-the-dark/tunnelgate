"""Audit trail helper. Every state-changing call and every LuCI access funnels through here."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from ..models import AuditLog, Router, User


def record(
    db: Session,
    action: str,
    *,
    actor: User | None = None,
    actor_username: str | None = None,
    outcome: str = "ok",
    router: Router | None = None,
    router_id: str | None = None,
    router_name: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    detail: dict[str, Any] | str | None = None,
) -> AuditLog:
    if isinstance(detail, dict):
        detail = json.dumps(detail, ensure_ascii=False, sort_keys=True)
    entry = AuditLog(
        action=action,
        outcome=outcome,
        actor_id=actor.id if actor else None,
        actor_username=actor.username if actor else actor_username,
        router_id=router.id if router else router_id,
        router_name=router.name if router else router_name,
        ip=ip,
        user_agent=(user_agent or "")[:255] or None,
        detail=detail,
    )
    db.add(entry)
    db.flush()
    return entry
