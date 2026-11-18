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
    """Counters for the dashboard tiles. One query per number, all indexed."""
    by_status = dict(
        db.execute(select(Router.status, func.count(Router.id)).group_by(Router.status)).all()
    )
    total = sum(by_status.values())
    console_active = db.execute(
        select(func.count(ConsoleSession.id)).where(ConsoleSession.closed_at.is_(None))
    ).scalar_one()
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
