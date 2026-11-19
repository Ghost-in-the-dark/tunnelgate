"""Panel settings an admin can change from the UI.

Today this is one thing: the agent-facing endpoint (protocol, host, port) that install scripts
and heartbeats point routers at. It lives in the database rather than the env file because the
people who need to change it are reacting to a move - a new panel hostname, TLS terminating in
front, a non-default port - and editing env vars does not help the routers already installed.

Every route here is admin-only and CSRF-guarded, because this value decides where freshly
installed routers send their bootstrap token and their API token:

* GET    /api/v1/settings/agent-endpoint       - the effective endpoint and where it came from
* PUT    /api/v1/settings/agent-endpoint       - store an override
* DELETE /api/v1/settings/agent-endpoint       - drop it, back to TUNNELGATE_PANEL_URL
* POST   /api/v1/settings/agent-endpoint/test  - probe a candidate, persist nothing

Field-level validation comes back as the standard 422 envelope with "details.fields", which is
the shape web/src/lib/api.ts fieldErrors() maps onto the SPA's inputs.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated

from fastapi import APIRouter, Request

from ..deps import AdminUser, CsrfGuard, DbSession, SettingsDep, client_ip
from ..errors import ApiError
from ..schemas import (
    AgentEndpointIn,
    AgentEndpointOut,
    AgentEndpointOutEnvelope,
    AgentEndpointTestIn,
    AgentEndpointTestOut,
)
from ..services import agent_endpoint
from ..services.audit import record as audit_record

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])

AGENT_PATH = "/agent-endpoint"


def _envelope(endpoint: agent_endpoint.AgentEndpoint) -> AgentEndpointOutEnvelope:
    return AgentEndpointOutEnvelope(
        agent_url=endpoint.url,
        agent_endpoint=AgentEndpointOut(**endpoint.as_dict()),
    )


def _field_errors(problems: dict[str, str]) -> list[dict]:
    return [{"loc": ["body", field], "msg": msg} for field, msg in problems.items()]


def _effective_or_409(db, settings) -> agent_endpoint.AgentEndpoint:
    endpoint = agent_endpoint.effective(db, settings)
    if endpoint is None:
        raise ApiError(
            409,
            "agent_endpoint_unusable",
            "TUNNELGATE_PANEL_URL is not a usable http(s) URL; set the endpoint here instead",
        )
    return endpoint


@router.get(AGENT_PATH, response_model=AgentEndpointOutEnvelope)
async def get_agent_endpoint(
    db: DbSession, admin: AdminUser, settings: SettingsDep
) -> AgentEndpointOutEnvelope:
    """What routers are told to dial right now, and where that value came from.

    Admin-only like the rest of this router: the endpoint is public information, but the panel's
    own reachability details are not something a viewer account needs.
    """
    return _envelope(_effective_or_409(db, settings))


@router.put(AGENT_PATH, response_model=AgentEndpointOutEnvelope)
async def save_agent_endpoint(
    payload: AgentEndpointIn,
    request: Request,
    db: DbSession,
    admin: AdminUser,
    settings: SettingsDep,
    _csrf: Annotated[None, CsrfGuard],
) -> AgentEndpointOutEnvelope:
    """Store an override. From the next install script or heartbeat on, routers use it."""
    endpoint, problems = agent_endpoint.save(
        db, payload.scheme, payload.host, payload.port, verify_tls=payload.verify_tls, user=admin
    )
    if endpoint is None:
        raise ApiError(
            422,
            "validation_error",
            "That endpoint is not usable",
            {"fields": _field_errors(problems)},
        )
    audit_record(
        db,
        "settings.agent_endpoint.save",
        actor=admin,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        # verify_tls belongs in the audit row: turning it off means the router can no longer tell
        # this panel from an impostor, and the bootstrap/API tokens ride on that connection.
        detail={"agent_url": endpoint.url, "verify_tls": endpoint.verify_tls},
    )
    db.commit()
    return _envelope(endpoint)


@router.delete(AGENT_PATH, response_model=AgentEndpointOutEnvelope)
async def reset_agent_endpoint(
    request: Request,
    db: DbSession,
    admin: AdminUser,
    settings: SettingsDep,
    _csrf: Annotated[None, CsrfGuard],
) -> AgentEndpointOutEnvelope:
    """Drop the override so TUNNELGATE_PANEL_URL applies again.

    Idempotent: pressing "reset" when nothing is stored is not an error, it shows the operator
    the value that is now in effect.
    """
    removed = agent_endpoint.clear(db)
    endpoint = _effective_or_409(db, settings)
    audit_record(
        db,
        "settings.agent_endpoint.reset",
        actor=admin,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={
            "removed": removed,
            "agent_url": endpoint.url,
            "verify_tls": endpoint.verify_tls,
        },
    )
    db.commit()
    return _envelope(endpoint)


@router.post("/agent-endpoint/test", response_model=AgentEndpointTestOut)
async def test_agent_endpoint(
    payload: AgentEndpointTestIn,
    request: Request,
    db: DbSession,
    admin: AdminUser,
    _csrf: Annotated[None, CsrfGuard],
) -> AgentEndpointTestOut:
    """Probe a candidate endpoint from the panel and report what came back.

    This is the only way an operator can tell "the router will reach this address" apart from
    "my browser can": the probe runs here and asks the public URL for /api/v1/health. It never
    persists a candidate, so a bad one cannot break installs; it is admin-only because it makes
    the panel issue an outbound request to an operator-chosen address, and it is audited for the
    same reason.
    """
    endpoint, problems = agent_endpoint.normalize(
        payload.scheme, payload.host, payload.port, payload.verify_tls
    )
    if endpoint is None:
        raise ApiError(
            422,
            "validation_error",
            "That endpoint is not usable",
            {"fields": _field_errors(problems)},
        )
    # The probe is a blocking HTTP call; keep it off the event loop. It honours verify_tls so a
    # self-signed panel that the router would accept is not reported unreachable.
    result = await asyncio.to_thread(
        agent_endpoint.probe, endpoint.url, verify_tls=endpoint.verify_tls
    )
    audit_record(
        db,
        "settings.agent_endpoint.test",
        actor=admin,
        outcome="ok" if result["ok"] else "error",
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={
            "checked_url": result["checked_url"],
            "error": result["error"],
            "verify_tls": endpoint.verify_tls,
        },
    )
    db.commit()
    return AgentEndpointTestOut(**result)
