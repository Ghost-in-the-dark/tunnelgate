"""Router-facing bootstrap endpoints: serve the installer, exchange the token.

Both endpoints authenticate with the X-Bootstrap-Token header and are exempt from the panel
CSRF check because there is no cookie involved: the token IS the credential, single-use and
short-lived.

The `install` route is registered on the routers router (app/api/routers.py) rather than here,
because FastAPI matches routes in registration order and `/{router_id}` would otherwise swallow
`/install` and answer 404. The handler lives here so the bootstrap contract stays in one file.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Header, Request, Response
from fastapi.responses import PlainTextResponse

from ..config import utcnow
from ..deps import DbSession, SettingsDep, client_ip
from ..errors import ApiError
from ..schemas import (
    BootstrapExchangeOut,
    BootstrapReport,
    ConsoleSpec,
    SshEndpoint,
    TunnelSpec,
    iso,
)
from ..security import RateLimiter, hash_token, key_fingerprint
from ..services import agent_endpoint
from ..services import bootstrap as bootstrap_service
from ..services import keys as keys_service
from ..services.audit import record as audit_record

log = logging.getLogger(__name__)

# Only the exchange is registered here: GET /install is attached to the routers router in
# app/api/routers.py, because main.py includes that router first and a GET /{router_id} route
# would otherwise capture the literal path "install".
router = APIRouter(prefix="/api/v1/routers", tags=["bootstrap"])

# A router may retry the install script a few times while the operator watches the console, and
# a failed exchange is retried by hand, so this window is generous but still bounded.
EXCHANGE_LIMIT = 60
EXCHANGE_WINDOW_SECONDS = 60
EXCHANGE_LIMITER = RateLimiter(limit=EXCHANGE_LIMIT, window_seconds=EXCHANGE_WINDOW_SECONDS)

# GET /install re-renders on every call for the whole life of the token, and each render echoes
# the live single-use credential into a response body. The per-ip limiter above is not enough: a
# caller who rotates source addresses can keep pulling the same token for its full TTL. Cap the
# renders *per token* as well, keyed by the digest so nothing secret sits in the limiter.
SCRIPT_LIMIT = 5
SCRIPT_WINDOW_SECONDS = 15 * 60
SCRIPT_LIMITER = RateLimiter(limit=SCRIPT_LIMIT, window_seconds=SCRIPT_WINDOW_SECONDS)

SCRIPT_MEDIA_TYPE = "text/x-shellscript"


def _throttle_token(token_hash: str) -> None:
    """Cap re-renders of the install script per token, independent of the caller's address."""
    allowed, retry_after = SCRIPT_LIMITER.check(f"script:{token_hash}")
    if not allowed:
        raise ApiError(
            429,
            "rate_limited",
            "This bootstrap token has been fetched too many times; wait or mint a new one",
            {"retry_after_seconds": retry_after},
            headers={"Retry-After": str(retry_after)},
        )
    SCRIPT_LIMITER.hit(f"script:{token_hash}")


def _throttle(ip: str, scope: str) -> None:
    allowed, retry_after = EXCHANGE_LIMITER.check(f"{scope}:{ip}")
    if not allowed:
        raise ApiError(
            429,
            "rate_limited",
            "Too many bootstrap requests from this address",
            {"retry_after_seconds": retry_after},
            headers={"Retry-After": str(retry_after)},
        )
    EXCHANGE_LIMITER.hit(f"{scope}:{ip}")


def _ssh_endpoint(settings) -> SshEndpoint:
    """The panel SSH coordinates, plus the host key fingerprint the router must pin.

    The fingerprint is read from the configured host key file. When it is unreadable the field
    stays None: a missing fingerprint is honest ("not configured"), a fabricated one would train
    the router to trust anything.
    """
    fingerprint = None
    key_type = None
    try:
        public_line = settings.ssh_host_key_path.read_text(encoding="utf-8").strip()
    except OSError:
        public_line = ""
    if public_line:
        key_type = public_line.split()[0] if public_line.split() else None
        try:
            fingerprint = key_fingerprint(public_line)
        except Exception:  # a malformed key file must not break onboarding
            log.warning("configured SSH host key at %s is unparsable", settings.ssh_host_key_path)
    return SshEndpoint(
        host=settings.ssh_host,
        port=int(settings.ssh_port),
        username=settings.ssh_user,
        host_key_fingerprint=fingerprint,
        host_key_type=key_type,
    )


def install_script(
    request: Request,
    db: DbSession,
    settings: SettingsDep,
    x_bootstrap_token: str | None = Header(default=None, alias="X-Bootstrap-Token"),
    os: str = "linux",
) -> Response:
    """Serve the installer with the panel URL and the token substituted into it.

    `os` selects the dialect only; the body is POSIX sh either way, which busybox ash accepts.
    """
    ip = client_ip(request)
    _throttle(ip, "install")
    router_row = bootstrap_service.resolve_router_for_script(db, x_bootstrap_token)
    if os not in ("linux", "freebsd", "windows"):
        raise ApiError(400, "validation_error", "os must be one of linux, freebsd, windows")
    # Only after the token proved usable: an unknown token must not burn quota that belongs to
    # a real one, and the digest never leaves this process.
    _throttle_token(hash_token((x_bootstrap_token or "").strip()))
    body = bootstrap_service.render_install_script(x_bootstrap_token or "", os, settings, db=db)
    db.commit()
    log.info("served install script for router %s to %s", router_row.slug, ip)
    return PlainTextResponse(
        content=body,
        media_type=SCRIPT_MEDIA_TYPE,
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": 'inline; filename="tunnelgate-install.sh"',
        },
    )


def _console_spec(router_row, settings) -> ConsoleSpec:
    return ConsoleSpec(
        enabled=bool(settings.console_enabled),
        ssh_user=keys_service.console_remote_user(),
        allowed_from=settings.console_bind_address,
        console_port=int(router_row.console_port or 0),
        target_port=int(router_row.console_ssh_port or 22),
        authorized_keys_path=keys_service.ROUTER_AUTHORIZED_KEYS_PATH,
        shell=keys_service.ROUTER_SHELL,
    )


@router.post("/bootstrap/exchange", response_model=BootstrapExchangeOut)
async def exchange(
    request: Request,
    db: DbSession,
    settings: SettingsDep,
    report: BootstrapReport | None = None,
    x_bootstrap_token: str | None = Header(default=None, alias="X-Bootstrap-Token"),
) -> BootstrapExchangeOut:
    """Consume the token, hand the router its private key and coordinates, once."""
    ip = client_ip(request)
    _throttle(ip, "exchange")
    router_row, private_key = bootstrap_service.exchange_token(
        db,
        x_bootstrap_token,
        (report.model_dump() if report else {}),
        ip,
        settings=settings,
    )
    audit_record(
        db,
        "router.exchange",
        router=router_row,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
        detail={"key_serial": int(router_row.key_serial or 0)},
    )
    db.commit()
    db.refresh(router_row)
    base = agent_endpoint.agent_url(db, settings)
    return BootstrapExchangeOut(
        router_id=router_row.id,
        router_name=router_row.name,
        slug=router_row.slug,
        ssh=_ssh_endpoint(settings),
        tunnel=TunnelSpec(
            remote_port=int(router_row.remote_port or 0),
            bind_address=router_row.bind_address or settings.bind_address,
            router_http_port=int(router_row.http_port),
            local_target=f"{settings.bind_address}:{int(router_row.http_port)}",
            url=settings.router_url(router_row.slug),
        ),
        console=_console_spec(router_row, settings),
        private_key=private_key,
        private_key_path_hint="/root/.ssh/tunnelgate_ed25519",
        api_token=keys_service.api_token(router_row.public_key) or "",
        heartbeat_url=f"{base}/api/v1/routers/{router_row.id}/heartbeat",
        key_fingerprint=router_row.key_fingerprint or "",
        server_time=iso(utcnow()) or "",
    )
