"""Health, panel configuration and aggregate counters.

`/health` is deliberately unauthenticated and free of database access so an uptime probe can
tell "the process is alive" apart from "the database is reachable". Everything else here needs
a session.
"""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import func, select

from ..config import utcnow
from ..deps import CurrentUser, DbSession, SettingsDep
from ..models import STATUS_OFFLINE, STATUS_ONLINE, STATUS_PENDING, ConsoleSession, Router, User
from ..schemas import AgentEndpointOut, ConfigOut, StatsOut, iso
from ..services import ports as ports_service
from ..services.access import accessible_router_ids

router = APIRouter(prefix="/api/v1", tags=["meta"])

# The wizard polls the status endpoint at this cadence; the SPA uses it for its own polling.
WIZARD_POLL_SECONDS = 2


@router.get("/health")
async def health() -> dict:
    """Liveness only: no auth, no database, no settings that can raise."""
    from .. import __version__

    return {"status": "ok", "version": __version__, "time": iso(utcnow())}


@router.get("/config", response_model=ConfigOut)
async def panel_config(db: DbSession, user: CurrentUser, settings: SettingsDep) -> ConfigOut:
    """Everything the SPA needs to render hostnames and the install instructions.

    agent_url is what routers dial and can be overridden from the UI; panel_url stays the
    panel's own internal address (what the reverse proxy forwards to). They are usually the
    same string on a flat deployment and are allowed to differ behind a TLS terminator.
    """
    from .. import __version__
    from ..services import agent_endpoint

    endpoint = agent_endpoint.effective(db, settings)
    return ConfigOut(
        panel_url=settings.panel_url,
        subdomain_suffix=settings.host_suffix,
        route_mode=settings.route_mode_normalized,
        gateway_host=settings.gateway,
        bootstrap_ttl_minutes=int(settings.bootstrap_ttl_minutes),
        poll_interval_seconds=WIZARD_POLL_SECONDS,
        proxy_driver=settings.proxy_driver,
        version=__version__,
        agent_url=endpoint.url if endpoint else agent_endpoint.agent_url(db, settings),
        agent_endpoint=(AgentEndpointOut(**endpoint.as_dict()) if endpoint is not None else None),
        agent_endpoint_testable=endpoint is not None,
    )


@router.get("/stats", response_model=StatsOut)
async def stats(db: DbSession, user: CurrentUser) -> StatsOut:
    """Counters for the dashboard tiles. One query per number, all indexed.

    Counters are constrained exactly like the router list, because they answer the same
    question: "how many routers are there". A viewer granted two of twenty reading
    routers_total=20 is told about eighteen devices they cannot open - the fleet's size and
    health are information about routers they were not given. So the same predicate is
    applied here, and IP/ports/console numbers are all derived from the visible set rather
    than from the whole table. admin and operator see everything, so their counters are
    unchanged (accessible_router_ids returns None for them and no filter is added).
    """
    visible = accessible_router_ids(db, user)
    scope = [] if visible is None else [Router.id.in_(visible)]
    by_status = dict(
        db.execute(
            select(Router.status, func.count(Router.id)).where(*scope).group_by(Router.status)
        ).all()
    )
    total = sum(by_status.values())
    # Console sessions are per router, so the count follows the same scope. Counting them
    # globally would tell a viewer that somebody is inside a device they cannot see, and the
    # registry-backed count the console API returns is already per router.
    console_filters = [ConsoleSession.closed_at.is_(None)]
    if visible is not None:
        console_filters.append(ConsoleSession.router_id.in_(visible))
    console_active = db.execute(
        select(func.count(ConsoleSession.id)).where(*console_filters)
    ).scalar_one()
    # users_total is deliberately global: it counts panel accounts, not routers, there is no
    # per-user scoping rule for it, and the admin-only Users tab is where it is shown. The
    # stats endpoint answers a viewer too (the dashboard tiles render for every role), so it
    # stays a plain count rather than being invented into a permission.
    users_total = db.execute(select(func.count(User.id))).scalar_one()
    return StatsOut(
        routers_total=total,
        routers_online=int(by_status.get(STATUS_ONLINE, 0)),
        routers_offline=int(by_status.get(STATUS_OFFLINE, 0)),
        routers_pending=int(by_status.get(STATUS_PENDING, 0)),
        ports_free=ports_service.free_port_count(ports_service.KIND_TUNNEL),
        users_total=int(users_total),
        console_sessions_active=int(console_active),
    )
