"""Router heartbeat: metadata refresh, tunnel status echo, console-key delivery.

This endpoint is authenticated with `X-Api-Token`, a value the router can compute from its own
public key and that the panel derives the same way. It is *not* a session and it carries no CSRF:
nothing here touches panel state beyond the router own row.

The important constraint from the contract: **a heartbeat can never mark a router online**. Only
an observed reverse listener can (the monitor owns that). A router that simply claims to be alive
must not turn green in the UI, or "online" would mean "the client said so".
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Header, Request

from ..config import utcnow
from ..deps import DbSession, SettingsDep, client_ip
from ..errors import ApiError
from ..models import STATUS_AWAITING, STATUS_OFFLINE, STATUS_ONLINE, Router
from ..schemas import HeartbeatIn, HeartbeatOut, iso
from ..services import keys as keys_service

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/routers", tags=["heartbeat"])


def _authenticate(db, router_id: str, supplied: str | None) -> Router:
    """Resolve the router and verify the derived token in constant time.

    A revoked router fails here too: its public key is gone, so no token can match it. That is
    the whole revocation mechanism for the heartbeat channel - no denylist needed.
    """
    item = db.get(Router, router_id)
    if item is None:
        raise ApiError(401, "invalid_api_token", "Unknown router or invalid api token")
    if not keys_service.api_token_matches(item, supplied):
        raise ApiError(401, "invalid_api_token", "Unknown router or invalid api token")
    return item


async def _console_installed_flag(request: Request) -> bool:
    """Read the router's "I installed the console key" flag off the raw body.

    `HeartbeatIn` is frozen and does not declare `console_installed`, so the flag is read from
    the cached request body instead of widening the shared schema. Anything unparsable simply
    means "no claim", which is the safe default: it just leaves the registration pending.
    """
    try:
        body = await request.json()
    except Exception:
        return False
    if not isinstance(body, dict):
        return False
    value = body.get("console_installed")
    return value is True


@router.post("/{router_id}/heartbeat", response_model=HeartbeatOut)
async def heartbeat(
    router_id: str,
    request: Request,
    db: DbSession,
    settings: SettingsDep,
    payload: HeartbeatIn | None = None,
    x_api_token: str | None = Header(default=None, alias="X-Api-Token"),
) -> HeartbeatOut:
    """Refresh metadata, echo the observed tunnel state, hand over the console key once."""
    item = _authenticate(db, router_id, x_api_token)
    now = utcnow()

    data = payload.model_dump(exclude_none=True) if payload else {}
    for field in ("hostname", "model", "openwrt_version", "mac", "client_version"):
        value = data.get(field)
        if value:
            setattr(item, field, str(value)[:128])
    if data.get("uptime_seconds") is not None:
        item.uptime_seconds = int(data["uptime_seconds"])
    item.last_heartbeat_at = now
    item.last_seen_at = now
    ip = client_ip(request)
    if ip:
        item.client_ip = ip

    runtime = item.runtime
    tunnel_present = bool(runtime.tunnel_present) if runtime else False
    reported_pid = data.get("tunnel_pid")
    if runtime is not None and reported_pid is not None:
        runtime.tunnel_pid = int(reported_pid)

    # The router sitting in "awaiting" and actually showing a live listener is worth promoting
    # immediately; everything else waits for the monitor. Never the other way round.
    if tunnel_present and item.status == STATUS_AWAITING:
        item.status = STATUS_ONLINE
        item.online_since = item.online_since or now
    elif not tunnel_present and item.status == STATUS_ONLINE:
        item.status = STATUS_OFFLINE

    console_installed = await _console_installed_flag(request)
    registration = keys_service.console_key_registration(item)
    if console_installed:
        # The router just told us it wrote the key; stop advertising it on the next poll.
        item.console_installed_at = now
        registration = None

    db.commit()
    db.refresh(item)
    return HeartbeatOut(
        ok=True,
        status=item.status,
        server_time=iso(now) or "",
        tunnel_present=tunnel_present,
        desired=None,
        console=registration,
    )
