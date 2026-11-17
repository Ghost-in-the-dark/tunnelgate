"""Bootstrap tokens and the install script: the router onboarding half of the API.

The plaintext token exists exactly twice: in the HTTP response that created it and in the
script body served back to the router. Everywhere else - the database, the logs, the audit
trail - only sha256(token) appears, and the token is consumed in the same transaction that
generates the router key pair, so two simultaneous exchanges cannot both win.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings, get_settings, utcnow
from ..errors import ApiError
from ..models import STATUS_AWAITING, BootstrapToken, Router, User
from ..security import hash_token, new_token
from . import keys as keys_service
from . import ports as ports_service

log = logging.getLogger(__name__)

AGENT_DIR = Path(__file__).resolve().parent.parent.parent / "agent"
INSTALL_SCRIPT_PATH = AGENT_DIR / "install.sh"
SCRIPT_CONTENT_TYPE = "text/x-shellscript; charset=utf-8"

PURPOSE_INSTALL = "install"
PURPOSE_ROTATE = "rotate"


def issue_bootstrap_token(
    db: Session,
    router: Router,
    purpose: str = PURPOSE_INSTALL,
    actor: User | None = None,
    *,
    settings: Settings | None = None,
) -> tuple[str, BootstrapToken]:
    """Create a single-use token and return (plaintext, row).

    Any earlier unused token for the same router is invalidated first: the operator asked for
    "the" install command, so two live commands must not exist at the same time.
    """
    s = settings or get_settings()
    now = utcnow()
    stale = (
        db.execute(
            select(BootstrapToken).where(
                BootstrapToken.router_id == router.id,
                BootstrapToken.used_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    for row in stale:
        row.used_at = now
    plaintext = new_token()
    row = BootstrapToken(
        router_id=router.id,
        purpose=purpose,
        token_hash=hash_token(plaintext),
        expires_at=now + timedelta(minutes=int(s.bootstrap_ttl_minutes)),
        created_by_id=actor.id if actor else None,
    )
    db.add(row)
    db.flush()
    return plaintext, row


def find_token(db: Session, plaintext: str | None) -> BootstrapToken:
    """Resolve a supplied token or raise 401 invalid_token.

    Unknown, already used and expired all map to ONE code on purpose: distinguishing them
    would tell an attacker whether a stolen token was real but merely stale.
    """
    invalid = ApiError(401, "invalid_token", "Bootstrap token is invalid or expired")
    if not plaintext:
        raise invalid
    row = db.execute(
        select(BootstrapToken).where(BootstrapToken.token_hash == hash_token(plaintext.strip()))
    ).scalar_one_or_none()
    if row is None or not row.is_usable:
        raise invalid
    return row


def resolve_router_for_script(db: Session, plaintext: str | None) -> Router:
    """The router a token belongs to, for GET /install."""
    row = find_token(db, plaintext)
    router = db.get(Router, row.router_id)
    if router is None or router.status == "revoked":
        raise ApiError(401, "invalid_token", "Bootstrap token is invalid or expired")
    return router


def _allocate_missing_ports(db: Session, router: Router) -> None:
    """Give the router the two listener ports it is about to advertise.

    A rotate keeps the ports it already holds so the vhost and firewall rules keep working; only
    a first exchange allocates. Console ports are only allocated when the feature is on.
    """
    s = get_settings()
    if not router.remote_port:
        router.remote_port = ports_service.allocate_port(db, kind=ports_service.KIND_TUNNEL)
    if s.console_enabled and not router.console_port:
        router.console_port = ports_service.allocate_port(db, kind=ports_service.KIND_CONSOLE)
    if not router.bind_address:
        router.bind_address = s.bind_address
    if not router.ssh_user:
        router.ssh_user = s.ssh_user


def exchange_token(
    db: Session,
    plaintext: str | None,
    report: dict | None = None,
    ip: str | None = None,
    *,
    settings: Settings | None = None,
) -> tuple[Router, str]:
    """Consume the token, mint the key pair and return (router, private_key).

    Everything happens inside the caller transaction: the token is marked used before the key
    exists, and the row is flushed with the new public key in the same commit. A second request
    carrying the same token therefore fails with invalid_token rather than producing a second
    key for the same router.
    """
    s = settings or get_settings()
    row = find_token(db, plaintext)
    router = db.get(Router, row.router_id)
    if router is None:
        raise ApiError(401, "invalid_token", "Bootstrap token is invalid or expired")

    row.used_at = utcnow()
    row.used_ip = ip
    db.flush()

    _allocate_missing_ports(db, router)
    keypair = keys_service.issue_key(db, router)

    data = report or {}
    for field in ("hostname", "model", "openwrt_version", "mac", "client_version"):
        value = data.get(field)
        if value:
            setattr(router, field, str(value)[:128])
    if data.get("uptime_seconds") is not None:
        router.uptime_seconds = int(data["uptime_seconds"])
    if ip:
        router.client_ip = ip
    router.status = STATUS_AWAITING
    router.last_seen_at = utcnow()
    db.flush()
    keys_service.write_authorized_keys(db, s)
    log.info("router %s exchanged its token and received a key", router.slug)
    return router, keypair.private_openssh


def build_install_command(token: str, settings: Settings | None = None) -> str:
    """The one-liner an operator pastes on the router.

    The token travels in a header, never in the URL: a URL ends up in access logs, in shell
    history and in ps output, and this token is a one-shot credential to become a router.
    """
    s = settings or get_settings()
    base = s.panel_url.rstrip("/")
    url = f"{base}/api/v1/routers/install?os=linux"
    return f"curl -fsSL -H 'X-Bootstrap-Token: {token}' '{url}' | sh"


def install_script_url(settings: Settings | None = None) -> str:
    s = settings or get_settings()
    return f"{s.panel_url.rstrip('/')}/api/v1/routers/install?os=linux"


def load_install_script() -> str:
    """The unrendered installer body shipped with the panel.

    Missing script is a server-side deployment error, not a client error: 503 is the honest
    answer, and the operator gets told to install the agent directory.
    """
    try:
        return INSTALL_SCRIPT_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        log.error("install script is unreadable at %s: %s", INSTALL_SCRIPT_PATH, exc)
        raise ApiError(
            503,
            "install_script_missing",
            "The panel has no router installer bundled; deploy the agent directory",
        ) from exc


def render_install_script(
    token: str, os_type: str = "linux", settings: Settings | None = None
) -> str:
    """Substitute the panel URL and the token into the installer body.

    Substitution happens server-side so the token never appears in a URL, a redirect header or
    a shell command line. Values are injected as shell assignments rather than string-spliced
    into commands, so a token containing quotes cannot break out of its context.
    """
    s = settings or get_settings()
    body = load_install_script()
    base = s.panel_url.rstrip("/")
    header = "\n".join(
        [
            "# --- injected by the panel ---",
            f"TG_PANEL_URL={keys_service.shell_quote(base)}",
            f"TG_BOOTSTRAP_TOKEN={keys_service.shell_quote(token)}",
            f"TG_OS_TYPE={keys_service.shell_quote(os_type)}",
            "# ------------------------------",
            "",
        ]
    )
    return header + body
