"""Bootstrap tokens and the install script: the router onboarding half of the API.

The plaintext token exists in exactly three places, all of them the same onboarding response:
the JSON body that created it, the "install_command" the operator pastes on the router, and the
script body served back to the router. The install command carries it as a basic-auth username,
because no stock OpenWrt has curl and its uclient-fetch had no --header before 24.10. Everywhere else -
the database, the logs, the audit trail - only sha256(token) appears, and the token is consumed
in the same transaction that generates the router key pair, so two simultaneous exchanges
cannot both win.
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
from . import agent_endpoint
from . import keys as keys_service
from . import ports as ports_service

log = logging.getLogger(__name__)

AGENT_DIR = Path(__file__).resolve().parent.parent.parent / "agent"
INSTALL_SCRIPT_PATH = AGENT_DIR / "install.sh"
SCRIPT_CONTENT_TYPE = "text/x-shellscript; charset=utf-8"

# The installer's own second line, in agent/install.sh. The install command greps the fetched
# body for it before running anything: a 401, a captive portal or an "nginx welcome" page all
# answer a body that is not the installer, and piping that into sh is silently a no-op. This is
# a cross-file contract - agent/install.sh must keep the line, and the panel test that reads the
# shipped script asserts it does.
INSTALL_SENTINEL = "TunnelGate router agent installer"

# $$ is the shell's own PID, so two installs running on one router cannot clobber each other.
INSTALL_TMP_PATH = "/tmp/tg-install.$$.sh"

# A NON-EMPTY, obviously-fake password for the wget branch. uclient-fetch builds its Authorization
# payload by joining user and password with a colon, and drops the colon entirely when the password
# is empty - it then sends base64(TOKEN) with no colon, which every RFC 7617 parser may reject. The
# panel never looks at the password half (app/security.py::basic_auth_username) so this value is a
# formality, not a secret; it is deliberately short and meaningless so nobody mistakes it for one.
INSTALL_AUTH_PASSWORD = "x"

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


def _agent_base(db=None, settings: Settings | None = None) -> str:
    """The base URL a router is told to dial.

    Not settings.panel_url directly: the panel's own address (what nginx proxy_passes to) and
    the address a router on a customer network reaches are allowed to differ, and an admin can
    change the latter from the UI. See app/services/agent_endpoint.py.
    """
    return agent_endpoint.agent_url(db, settings or get_settings())


def install_script_url(settings: Settings | None = None, *, db=None) -> str:
    """The bare, token-less installer URL: the manual path, and what the UI shows as the source.

    Handing this out with no token is deliberate - it is a pointer to the endpoint, not a
    credential, so it is safe for the operator to read, paste or log.
    """
    return f"{_agent_base(db, settings)}/api/v1/routers/install?os=linux"


def _tls_verifying(db=None, settings: Settings | None = None) -> bool:
    """Whether the router should verify the panel certificate: the effective endpoint's policy.

    Defaults to True when no endpoint can be resolved, because the safe side of this switch is
    verifying: a missing setting must never silently turn certificate checks off.
    """
    endpoint = agent_endpoint.effective(db, settings or get_settings())
    return True if endpoint is None else endpoint.verify_tls


def build_install_command(token: str, settings: Settings | None = None, *, db=None) -> str:
    """The command an operator pastes on the router: probe the fetcher, fetch, verify, run.

    Why this shape, and not the obvious "curl -fsSL -H ... | sh":

    * curl does not exist on stock OpenWrt of any generation, and its /usr/bin/wget is a symlink
      to uclient-fetch, which had no --header before 24.10. A header-carrying curl one-liner
      therefore cannot work on a stock router at all.
    * The token rides as the basic-auth USERNAME for both fetchers, with a non-empty placeholder
      password. This is not a style choice, it is what a stock router demands: uclient-fetch is a
      challenge-response client that sends no Authorization on the first request, retries only
      after our 401 + WWW-Authenticate challenge, and drops the user:password colon when the
      password is empty or absent. Measured on 19.07.10 / 22.03.7 / 23.05.5 / 24.10.1 through a
      logging proxy: an empty password sends base64(TOKEN) with no colon and the panel answers
      401; a non-empty one sends base64(TOKEN:x) and the panel answers 200 with the installer.
    * NOT URL userinfo any more: GNU wget 1.25 rejects a userinfo URL outright (exit 6), and both
      fetchers already accept --user, so the token has one channel instead of two.
    * The fetcher is chosen with if/elif, never "curl ... || wget ...": a failed curl must not
      fire a second request, because every render burns the same per-token quota.
    * The body is fetched to a file, grepped for the installer's sentinel and only then run. A
      401 answers an empty body, and "| sh" on it is a silent success that leaves the operator
      staring at a router that never dials in. uclient-fetch exits 0 on an HTTP error, so the
      sentinel check - not the fetch status - is what distinguishes the installer from any body.
    * When the panel is behind a self-signed certificate the operator has explicitly accepted
      (Settings > Agent endpoint), the fetchers get -k / --no-check-certificate and the command
      opens with one comment line saying so. Without it the very first fetch fails and the
      router can never be installed. The flags are written explicitly rather than as -fsSLk:
      a reader must be able to see the certificate check being switched off in the command they
      paste, and copy back exactly what they ran when they ask for help.
    """
    url = f"{_agent_base(db, settings)}/api/v1/routers/install?os=linux"
    verify_tls = _tls_verifying(db, settings)
    # curl: -k is its own argument so it is greppable; wget/uclient-fetch wants the long form.
    curl_flags = "-fsSL -k" if not verify_tls else "-fsSL"
    wget_flags = "-q --no-check-certificate" if not verify_tls else "-q"
    lines = []
    if not verify_tls:
        lines.append(
            "# TLS certificate verification is OFF for this panel (Settings > Agent endpoint)."
        )
    # The token is quoted for the shell, not spliced into the URL: it must survive as one word
    # even if a future token alphabet brought in a quote or a space.
    lines += [
        f"TK={keys_service.shell_quote(token)}; U={keys_service.shell_quote(url)};"
        f" F={INSTALL_TMP_PATH}",
        # One probe, one request. An "else" that merely warns is not enough: the operator
        # needs to know the router has neither fetcher, which is unusual but possible on a
        # stripped image, so this exits non-zero with a next step.
        # curl's "TOKEN:" sends base64(TOKEN:) - preemptively, no challenge round trip.
        f'if command -v curl >/dev/null 2>&1; then curl {curl_flags} -o "$F" -u "$TK:" "$U"',
        # The placeholder password exists only to keep uclient-fetch's colon; see
        # INSTALL_AUTH_PASSWORD. --user alone would also drop it.
        f'elif command -v wget >/dev/null 2>&1; then wget {wget_flags} -O "$F"'
        f' --user="$TK" --password={INSTALL_AUTH_PASSWORD} "$U"',
        "else echo 'TunnelGate: neither curl nor wget is installed on this router' >&2; exit 1; fi",
        f"grep -q '{INSTALL_SENTINEL}' \"$F\" 2>/dev/null || {{"
        ' echo "TunnelGate: the panel did not return the installer; mint a fresh install'
        ' command and retry" >&2; rm -f "$F"; exit 1; }',
        'sh "$F"',
    ]
    return "\n".join(lines)


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
    token: str, os_type: str = "linux", settings: Settings | None = None, *, db=None
) -> str:
    """Substitute the panel URL and the token into the installer body.

    Substitution happens server-side so the token never appears in a URL, a redirect header or
    a shell command line. Values are injected as shell assignments rather than string-spliced
    into commands, so a token containing quotes cannot break out of its context.
    """
    body = load_install_script()
    base = _agent_base(db, settings)
    # Always emitted, never omitted when it is 1: the agent reads TG_TLS_VERIFY unconditionally,
    # so its absence would be indistinguishable from "the panel is older than this field".
    tls_verify = "1" if _tls_verifying(db, settings) else "0"
    header = "\n".join(
        [
            "# --- injected by the panel ---",
            f"TG_PANEL_URL={keys_service.shell_quote(base)}",
            f"TG_BOOTSTRAP_TOKEN={keys_service.shell_quote(token)}",
            f"TG_OS_TYPE={keys_service.shell_quote(os_type)}",
            f"TG_TLS_VERIFY={keys_service.shell_quote(tls_verify)}",
            "# ------------------------------",
            "",
        ]
    )
    # The shebang (line 1) and the installer's identifying comment (line 2) must stay the file's
    # first two lines: the kernel only honours a shebang at offset 0, so a served script that
    # starts with the injected block is not executable as a file - and the failure is silent,
    # because the caller's shell happily interprets it. Putting the header after those two lines
    # also keeps the installer's own head-check (agent/install.sh::check_self) correct by
    # construction: the sentinel it greps for is then on line 2, not buried under the header.
    shebang, ident, rest = body.split("\n", 2)
    return f"{shebang}\n{ident}\n{header}{rest}"
