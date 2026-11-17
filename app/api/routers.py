"""Router CRUD, key rotation, install-script reissue and the wizard status poll.

`GET /{router_id}/status` is the hottest endpoint in the panel (polled every 2 seconds while the
install wizard is open), so it is assembled from the router row plus its RouterRuntime row only:
no port probing, no health check, no writes. The monitor owns observation; this endpoint reports
it. That split is what keeps a 2-second poll cheap and keeps the API from lying about a router.

Route order matters: `/install` is registered BEFORE `/{router_id}` because FastAPI matches in
registration order and the path parameter would otherwise swallow the literal path.
"""

from __future__ import annotations

import logging
import re
from typing import Annotated

from fastapi import APIRouter, Query, Request, Response
from sqlalchemy import ColumnElement, func, or_, select

from ..config import utcnow
from ..deps import (
    CsrfGuard,
    CurrentUser,
    DbSession,
    OperatorUser,
    SettingsDep,
    client_ip,
)
from ..errors import ApiError
from ..models import (
    STATUS_AWAITING,
    STATUS_OFFLINE,
    STATUS_ONLINE,
    STATUS_PENDING,
    STATUS_REVOKED,
    BootstrapToken,
    Router,
)
from ..schemas import (
    RotateKeyOut,
    RouterCreate,
    RouterCreatedOut,
    RouterListOut,
    RouterOut,
    RouterUpdate,
    StatusOut,
    iso,
)
from ..services import bootstrap as bootstrap_service
from ..services import keys as keys_service
from ..services import ports as ports_service
from ..services.audit import record as audit_record
from . import bootstrap as bootstrap_api

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/routers", tags=["routers"])

SLUG_CHARS_RE = re.compile(r"[^a-z0-9]+")
SLUG_MAX_LENGTH = 40

# Phase messages are user-facing: the wizard prints them verbatim next to the spinner.
PHASE_MESSAGES = {
    "waiting": "Waiting for connection",
    "connected": "Connected",
    "reporting": "Receiving initial report",
    "done": "LuCI responded",
    "offline": "Router is offline",
}


# --------------------------------------------------------------------------- helpers
def slugify(name: str) -> str:
    """Turn a display name into a DNS label - the slug is the router vhost label."""
    slug = SLUG_CHARS_RE.sub("-", name.strip().lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug[:SLUG_MAX_LENGTH].strip("-") or "router"


def _unique_slug(db, base: str) -> str:
    """First free slug: base, base-2, base-3... The slug is baked into DNS, so it never moves."""
    candidate = base
    counter = 1
    while db.execute(select(Router.id).where(Router.slug == candidate)).first() is not None:
        counter += 1
        suffix = f"-{counter}"
        candidate = base[: SLUG_MAX_LENGTH - len(suffix)].rstrip("-") + suffix
    return candidate


def _get_router(db, router_id: str) -> Router:
    item = db.get(Router, router_id)
    if item is None:
        raise ApiError(404, "not_found", "Router not found")
    return item


def _usable_token(db, router_id: str) -> BootstrapToken | None:
    """The newest still-unused bootstrap token of one router, if any."""
    return (
        db.execute(
            select(BootstrapToken)
            .where(BootstrapToken.router_id == router_id, BootstrapToken.used_at.is_(None))
            .order_by(BootstrapToken.created_at.desc())
        )
        .scalars()
        .first()
    )


def console_ready(item: Router) -> bool:
    """The console key exists AND the router has confirmed it installed it."""
    return bool(item.has_console_key and item.console_installed_at is not None)


def router_out(item: Router, *, token: BootstrapToken | None = None, settings=None) -> RouterOut:
    """Project a Router row (plus its runtime observation) onto the wire contract."""
    runtime = item.runtime
    return RouterOut(
        id=item.id,
        name=item.name,
        slug=item.slug,
        group_name=item.group_name,
        integrations=list(item.integrations or []),
        os_type=item.os_type,
        notes=item.notes,
        status=item.status,
        online=item.status == STATUS_ONLINE,
        http_port=int(item.http_port),
        remote_port=item.remote_port,
        # Deprecated alias kept for wire compatibility: the first draft of the contract called the
        # tunnel port "reverse_port", and an empty value made the UI report "no port allocated"
        # for a live router. It mirrors remote_port; drop it once no client reads it.
        reverse_port=item.remote_port,
        console_port=item.console_port,
        console_ready=console_ready(item),
        bind_address=item.bind_address,
        url=settings.router_url(item.slug) if settings is not None else None,
        hostname=item.hostname,
        model=item.model,
        openwrt_version=item.openwrt_version,
        mac=item.mac,
        client_ip=item.client_ip,
        client_version=item.client_version,
        uptime_seconds=item.uptime_seconds,
        key_fingerprint=item.key_fingerprint,
        has_key=item.has_key,
        installed=item.has_key,
        tunnel_present=bool(runtime.tunnel_present) if runtime else False,
        health_ok=runtime.health_ok if runtime else None,
        created_at=iso(item.created_at),
        updated_at=iso(item.updated_at),
        last_seen_at=iso(item.last_seen_at),
        last_heartbeat_at=iso(item.last_heartbeat_at),
        online_since=iso(item.online_since),
        bootstrap_expires_at=iso(token.expires_at) if token else None,
    )


def derive_phase(item: Router) -> tuple[str, str | None]:
    """(phase, message) for the wizard, derived from the row - never stored.

    The order tells the onboarding story: no key yet, key but no tunnel, tunnel but no report,
    report but no health, and finally "nothing observed" for a router that used to work. A
    heartbeat alone never reaches "done": only an observed tunnel plus a passing health check do.
    """
    runtime = item.runtime
    if item.status == STATUS_REVOKED or not item.has_key:
        return "waiting", PHASE_MESSAGES["waiting"]
    if not (runtime and runtime.tunnel_present):
        return "offline", PHASE_MESSAGES["offline"]
    if item.last_heartbeat_at is None:
        return "connected", PHASE_MESSAGES["connected"]
    if runtime.health_ok:
        return "done", PHASE_MESSAGES["done"]
    return "reporting", PHASE_MESSAGES["reporting"]


def _issue_token(db, item: Router, purpose: str, actor, settings) -> tuple[str, BootstrapToken]:
    return bootstrap_service.issue_bootstrap_token(db, item, purpose, actor, settings=settings)


def _created_response(item: Router, token_row: BootstrapToken, plaintext: str, settings):
    base = router_out(item, token=token_row, settings=settings)
    return RouterCreatedOut(
        **base.model_dump(),
        bootstrap_token=plaintext,
        install_command=bootstrap_service.build_install_command(plaintext, settings),
        install_script_url=bootstrap_service.install_script_url(settings),
    )


# --------------------------------------------------------------------------- endpoints
@router.post("", response_model=RouterCreatedOut, status_code=201)
async def create_router(
    payload: RouterCreate,
    request: Request,
    db: DbSession,
    user: OperatorUser,
    _csrf: Annotated[None, CsrfGuard],
    settings: SettingsDep,
) -> RouterCreatedOut:
    """Create the router and return the single-use install command.

    No port is allocated yet: the router only earns one when it actually exchanges a token, so a
    router that is never installed never consumes a pool entry.
    """
    base = payload.slug or slugify(payload.name)
    item = Router(
        name=payload.name.strip(),
        slug=_unique_slug(db, base),
        group_name=payload.group_name,
        integrations=list(payload.integrations or []),
        os_type=payload.os_type,
        notes=payload.notes,
        http_port=int(payload.http_port),
        status=STATUS_PENDING,
        bind_address=settings.bind_address,
        ssh_user=settings.ssh_user,
        created_by_id=user.id,
    )
    db.add(item)
    db.flush()
    plaintext, token_row = _issue_token(db, item, bootstrap_service.PURPOSE_INSTALL, user, settings)
    audit_record(
        db,
        "router.create",
        actor=user,
        router=item,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={"slug": item.slug, "os_type": item.os_type},
    )
    db.commit()
    db.refresh(item)
    return _created_response(item, token_row, plaintext, settings)


@router.get("", response_model=RouterListOut)
async def list_routers(
    db: DbSession,
    user: CurrentUser,
    settings: SettingsDep,
    status: str | None = Query(default=None),
    q: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> RouterListOut:
    """Filterable list. The counters describe the filtered set, not the whole table."""
    filters: list[ColumnElement[bool]] = []
    if status:
        if status not in (
            STATUS_PENDING,
            STATUS_AWAITING,
            STATUS_ONLINE,
            STATUS_OFFLINE,
            STATUS_REVOKED,
        ):
            raise ApiError(400, "validation_error", "Unknown router status filter")
        filters.append(Router.status == status)
    if q:
        needle = f"%{q.strip()}%"
        filters.append(
            or_(
                Router.name.ilike(needle),
                Router.slug.ilike(needle),
                Router.hostname.ilike(needle),
                Router.mac.ilike(needle),
                Router.client_ip.ilike(needle),
            )
        )
    total = db.execute(select(func.count(Router.id)).where(*filters)).scalar_one()
    counts = dict(
        db.execute(
            select(Router.status, func.count(Router.id)).where(*filters).group_by(Router.status)
        ).all()
    )
    items = (
        db.execute(
            select(Router)
            .where(*filters)
            .order_by(Router.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        .scalars()
        .all()
    )
    tokens: dict[str, BootstrapToken] = {}
    if items:
        for row in (
            db.execute(
                select(BootstrapToken)
                .where(
                    BootstrapToken.router_id.in_([i.id for i in items]),
                    BootstrapToken.used_at.is_(None),
                )
                .order_by(BootstrapToken.created_at.desc())
            )
            .scalars()
            .all()
        ):
            tokens.setdefault(row.router_id, row)
    return RouterListOut(
        items=[router_out(i, token=tokens.get(i.id), settings=settings) for i in items],
        total=int(total),
        online=int(counts.get(STATUS_ONLINE, 0)),
        offline=int(counts.get(STATUS_OFFLINE, 0)),
        pending=int(counts.get(STATUS_PENDING, 0) + counts.get(STATUS_AWAITING, 0)),
    )


# GET /install must come before GET /{router_id}: FastAPI matches in registration order.
router.add_api_route(
    "/install",
    bootstrap_api.install_script,
    methods=["GET"],
    include_in_schema=True,
    tags=["bootstrap"],
)


@router.get("/{router_id}", response_model=RouterOut)
async def get_router(
    router_id: str,
    db: DbSession,
    user: CurrentUser,
    settings: SettingsDep,
) -> RouterOut:
    item = _get_router(db, router_id)
    return router_out(item, token=_usable_token(db, item.id), settings=settings)


@router.patch("/{router_id}", response_model=RouterOut)
async def update_router(
    router_id: str,
    payload: RouterUpdate,
    request: Request,
    db: DbSession,
    user: OperatorUser,
    _csrf: Annotated[None, CsrfGuard],
    settings: SettingsDep,
) -> RouterOut:
    """Only mutable display fields. The slug never changes: it is baked into DNS and routers."""
    item = _get_router(db, router_id)
    changed = payload.model_dump(exclude_unset=True)
    if changed.get("name"):
        item.name = changed["name"].strip()
    for field in ("group_name", "notes"):
        if field in changed:
            setattr(item, field, changed[field])
    if changed.get("http_port") is not None:
        item.http_port = int(changed["http_port"])
    item.updated_at = utcnow()
    audit_record(
        db,
        "router.update",
        actor=user,
        router=item,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={"fields": sorted(changed)},
    )
    db.commit()
    db.refresh(item)
    return router_out(item, token=_usable_token(db, item.id), settings=settings)


@router.delete("/{router_id}", status_code=204)
async def delete_router(
    router_id: str,
    request: Request,
    db: DbSession,
    user: OperatorUser,
    _csrf: Annotated[None, CsrfGuard],
) -> Response:
    """Revoke the key first, then free the ports, then delete the row.

    That order is the whole point: a deleted row with a live authorized_keys line would leave a
    listener nobody can see or revoke from the panel.
    """
    item = _get_router(db, router_id)
    ports = [p for p in (item.remote_port, item.console_port) if p]
    keys_service.revoke_router_key(db, item)
    db.flush()
    audit_record(
        db,
        "router.delete",
        actor=user,
        router_id=item.id,
        router_name=item.name,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={"slug": item.slug, "ports": ports},
    )
    db.delete(item)
    db.commit()
    for port in ports:
        ports_service.release_port(db, port)
    db.commit()
    return Response(status_code=204)


@router.post("/{router_id}/rotate-key", response_model=RotateKeyOut)
async def rotate_key(
    router_id: str,
    request: Request,
    db: DbSession,
    user: OperatorUser,
    _csrf: Annotated[None, CsrfGuard],
    settings: SettingsDep,
) -> RotateKeyOut:
    """Revoke the old key immediately and hand out a fresh token.

    Ports are retained on purpose, so a reinstall lands on the same vhost and the same listener
    instead of breaking firewall rules and DNS that already point there.
    """
    item = _get_router(db, router_id)
    keys_service.revoke_router_key(db, item)
    item.status = STATUS_PENDING
    db.flush()
    plaintext, token_row = _issue_token(db, item, bootstrap_service.PURPOSE_ROTATE, user, settings)
    audit_record(
        db,
        "router.rotate",
        actor=user,
        router=item,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()
    db.refresh(item)
    return RotateKeyOut(
        bootstrap_token=plaintext,
        bootstrap_expires_at=iso(token_row.expires_at) or "",
        install_command=bootstrap_service.build_install_command(plaintext, settings),
        install_script_url=bootstrap_service.install_script_url(settings),
    )


@router.get("/{router_id}/script", response_model=None)
async def router_script(
    router_id: str,
    request: Request,
    db: DbSession,
    user: OperatorUser,
    settings: SettingsDep,
    reissue: bool = Query(default=False),
) -> dict:
    """Show the install command again for a router that has not been installed yet.

    `?reissue=true` is the admin-only escape hatch: on an installed router it is rotate-key,
    which is exactly why it is not the default and why the role requirement is stricter.
    """
    item = _get_router(db, router_id)
    if item.has_key and not reissue:
        raise ApiError(
            409,
            "already_installed",
            "This router already has a key; use reissue=true (admin) or rotate the key",
        )
    if reissue and item.has_key:
        if user.role != "admin":
            raise ApiError(403, "forbidden", "Re-issuing an installed router requires admin")
        keys_service.revoke_router_key(db, item)
        item.status = STATUS_PENDING
        db.flush()
    plaintext, token_row = _issue_token(db, item, bootstrap_service.PURPOSE_INSTALL, user, settings)
    audit_record(
        db,
        "router.script",
        actor=user,
        router=item,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={"reissue": bool(reissue)},
    )
    db.commit()
    return {
        "bootstrap_token": plaintext,
        "bootstrap_expires_at": iso(token_row.expires_at),
        "install_command": bootstrap_service.build_install_command(plaintext, settings),
        "install_script_url": bootstrap_service.install_script_url(settings),
    }


@router.get("/{router_id}/status", response_model=StatusOut)
async def router_status(router_id: str, db: DbSession, user: CurrentUser) -> StatusOut:
    """Cheap derived status for the wizard poll. Reads two rows, writes nothing."""
    item = _get_router(db, router_id)
    runtime = item.runtime
    phase, message = derive_phase(item)
    return StatusOut(
        id=item.id,
        status=item.status,
        phase=phase,
        online=item.status == STATUS_ONLINE,
        tunnel_present=bool(runtime.tunnel_present) if runtime else False,
        health_ok=runtime.health_ok if runtime else None,
        last_seen_at=iso(item.last_seen_at),
        last_heartbeat_at=iso(item.last_heartbeat_at),
        message=message,
    )
