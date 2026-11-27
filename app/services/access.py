"""Per-router authorization. One place answers "may this user reach this router?".

The panel used to be single-tenant by accident: the nginx gate in app/api/gate.py only checked
that a session belonged to an active user, so any authenticated account - a viewer included -
could open ANY router's LuCI through the proxy, and the JSON API handed the same caller every
router row. Nothing in the code was wrong at the level of a single request; the missing piece
was a per-router decision, and that decision now lives here so the gate, the REST API and the
console all read the same rule instead of each growing its own copy of it.

The rule:

* admin and operator reach every router. They manage routers - create, re-key, rotate, delete -
  and rotating a key hands the panel a working credential anyway, so refusing them a router
  they can already take would be an inconsistency, not a control.
* viewer reaches a router only when a router_grants row says so. Row present, allowed; row
  absent, not allowed. There is deliberately no fallback to ownership, group or name matching:
  a grant is the only thing that can widen a viewer's reach, so an access review is one table
  scan rather than a reconstruction of implied rules.

Two shapes, because list endpoints and single-router endpoints want different things.
accessible_router_ids returns None for "all routers" rather than the full id set: a list query
then adds no predicate at all instead of shipping thousands of ids into an IN clause, and the
"all" case stays cheap as the table grows. can_access_router answers for one router and is
what a gate that only knows one router id can call.

Nothing here commits: these are reads, and the callers decide the transaction.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..errors import ApiError
from ..models import Router, RouterGrant, User

# Roles that are allowed on every router. Kept next to the rule it explains rather than in
# app/deps.py, because deps answers "may this ROLE call this endpoint" and this module answers
# "may this USER reach this ROUTER" - the second question is the one a viewer can fail.
FULL_ACCESS_ROLES = ("admin", "operator")

FORBIDDEN_MESSAGE = "You do not have access to this router"


def can_access_router(db: Session, user: User, router: Router | str) -> bool:
    """True when this user may see and use this router. Accepts a Router row or its id."""
    if user.role in FULL_ACCESS_ROLES:
        return True
    router_id = router.id if isinstance(router, Router) else router
    if not router_id:
        return False
    found = db.execute(
        select(RouterGrant.id)
        .where(RouterGrant.user_id == user.id, RouterGrant.router_id == router_id)
        .limit(1)
    ).first()
    return found is not None


def accessible_router_ids(db: Session, user: User) -> set[str] | None:
    """The routers this user may see, or None meaning "every router".

    None is the answer for admin and operator, and callers must treat it as "add no filter"
    rather than "no routers": an empty set is a real answer (a viewer with no grants) and the
    two must never be confused, or a viewer with no grants would start seeing everything the
    moment a caller wrote "if not ids: skip the filter".
    """
    if user.role in FULL_ACCESS_ROLES:
        return None
    rows = db.execute(select(RouterGrant.router_id).where(RouterGrant.user_id == user.id))
    return set(rows.scalars().all())


def require_router_access(db: Session, user: User, router_id: str) -> None:
    """Refuse a user who may not see this router.

    A viewer without a grant gets 403 - never 404 - even when the id does not exist at all.
    That is the point: if "not granted" and "no such router" answered differently, a viewer
    could enumerate router ids they are not allowed to see by watching which code came back.
    The row load that follows this check is what produces 404, and it only ever runs for a
    caller who is allowed to know the answer, so the two responses cannot leak existence to
    someone who was refused.

    Callers therefore use this BEFORE loading the row (app/api/routers.py::_get_router does)
    and get both halves of the rule from one place.
    """
    if can_access_router(db, user, router_id):
        return
    raise ApiError(403, "forbidden", FORBIDDEN_MESSAGE)
