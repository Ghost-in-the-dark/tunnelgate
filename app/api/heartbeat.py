"""Router heartbeat: metadata refresh, tunnel status echo, console-key delivery.

This endpoint is authenticated with `X-Api-Token`, a value the router can compute from its own
public key and that the panel derives the same way. It is *not* a session and it carries no CSRF:
nothing here touches panel state beyond the router own row.

The token is accepted on three channels, in this order: the `X-Api-Token` header, the HTTP Basic
username, and an `api_token` field in the JSON body. Only the first is available to curl; stock
OpenWrt has no curl and its uclient-fetch only learned `--header` in 24.10, so Basic is what
those devices actually use. Every 401 carries a Basic challenge, without which uclient-fetch never
retries with the credentials it was given.

The important constraint from the contract: **a heartbeat can never mark a router online**. Only
an observed reverse listener can (the monitor owns that). A router that simply claims to be alive
must not turn green in the UI, or "online" would mean "the client said so".
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Header, Request

from ..config import utcnow
from ..deps import DbSession, SettingsDep, client_ip
from ..errors import ApiError
from ..models import STATUS_AWAITING, STATUS_OFFLINE, STATUS_ONLINE, Router
from ..schemas import HeartbeatIn, HeartbeatOut, iso
from ..services import agent_endpoint
from ..services import keys as keys_service
from .bootstrap import json_object, token_from_request, validated_fields, with_challenge

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/routers", tags=["heartbeat"])


def _authenticate(db, router_id: str, supplied: str | None) -> Router:
    """Resolve the router and verify the derived token in constant time.

    A revoked router fails here too: its public key is gone, so no token can match it. That is
    the whole revocation mechanism for the heartbeat channel - no denylist needed.

    Both failure modes raise the same challenge-carrying 401: a caller must not be able to tell
    "no such router" from "wrong token", and the challenge is what makes a device retry.
    """
    item = db.get(Router, router_id)
    if item is not None and keys_service.api_token_matches(item, supplied):
        return item
    raise with_challenge(ApiError(401, "invalid_api_token", "Unknown router or invalid api token"))


def _heartbeat_url(item: Router, db, settings) -> str:
    """The address this router should POST to, derived from the effective agent endpoint."""
    base = agent_endpoint.agent_url(db, settings)
    return f"{base}/api/v1/routers/{item.id}/heartbeat"


@router.post("/{router_id}/heartbeat", response_model=HeartbeatOut)
async def heartbeat(
    router_id: str,
    request: Request,
    db: DbSession,
    settings: SettingsDep,
    x_api_token: Annotated[str | None, Header(alias="X-Api-Token")] = None,
) -> HeartbeatOut:
    """Refresh metadata, echo the observed tunnel state, hand over the console key once.

    The body is read once and parsed by hand, for two reasons: it may carry the token as a third
    authentication channel, and uclient-fetch always sends a form content type - a declared body
    model would answer 422 before this handler runs. A body that does not parse is simply "the
    router reported nothing", never an error.
    """
    body = json_object(await request.body())
    # Only a string can be a token: a JSON object or list in that field is a malformed request, and
    # str()-ing it would invent a credential out of its repr.
    body_token = body.get("api_token")
    token = token_from_request(x_api_token, request) or (
        body_token.strip() if isinstance(body_token, str) else None
    )
    item = _authenticate(db, router_id, token or None)
    now = utcnow()

    data = validated_fields(body, HeartbeatIn)
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

    console_installed = data.get("console_installed") is True
    registration = keys_service.console_key_registration(item)
    if console_installed:
        # The router just told us it wrote the key; stop advertising it on the next poll.
        item.console_installed_at = now
        registration = None

    # The ONLY channel that can re-point an already-installed router: the agent reads this and
    # rewrites its own heartbeat_url when it differs. It exists because an operator who moves the
    # panel (new hostname, TLS in front, another port) cannot re-run the installer on devices
    # that are already in the field - and without it they would silently rot on the old address.
    desired = {"heartbeat_url": _heartbeat_url(item, db, settings)}

    db.commit()
    db.refresh(item)
    return HeartbeatOut(
        ok=True,
        status=item.status,
        server_time=iso(now) or "",
        tunnel_present=tunnel_present,
        desired=desired,
        console=registration,
    )
