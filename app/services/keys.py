"""Key material: the router tunnel key (public half only here) and the console key (sealed).

Two separate key pairs exist per router and they point in opposite directions:

* **tunnel key** - the ROUTER owns the private half. It is generated during exchange and handed
  back once; the panel keeps only the public line so it can render authorized_keys. Losing it
  means rotating.
* **console key** - the PANEL owns the private half, because the panel is the SSH client when an
  operator opens a shell. It is sealed with AES-256-GCM (security.encrypt_secret) before it is
  written to the database and only unsealed for the lifetime of one handshake.

Nothing in this module logs key material. The authorized_keys file is rewritten atomically and
only ever contains lines that can do nothing but open the two allocated reverse listeners.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import os
import subprocess
import tempfile
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings, get_settings, utcnow
from ..models import Router
from ..schemas import ConsoleRegistration
from ..security import (
    KeyPair,
    authorized_key_line,
    encrypt_secret,
    generate_ed25519_keypair,
)

log = logging.getLogger(__name__)

API_TOKEN_PREFIX = "tg_"
CONSOLE_KEY_COMMENT = "tunnelgate-console"
ROUTER_AUTHORIZED_KEYS_PATH = "/etc/dropbear/authorized_keys"
CONSOLE_REMOTE_USER = "root"
ROUTER_SHELL = "/bin/ash"


def tunnel_comment(router: Router) -> str:
    """Comment embedded in the public key, so ssh logs name the router, not an id."""
    return f"tunnelgate:{router.slug}"


def api_token(public_key: str | None) -> str | None:
    """Derive the heartbeat token from the router public key.

    The token is deliberately not a stored secret: it is a pure function of the public key, so
    it needs no column, no rotation ceremony and no plaintext at rest, and by itself it can only
    report that one router metadata.
    """
    if not public_key:
        return None
    digest = hashlib.sha256(public_key.strip().encode()).hexdigest()
    return API_TOKEN_PREFIX + digest[:40]


def api_token_matches(router: Router, supplied: str | None) -> bool:
    expected = api_token(router.public_key)
    if not expected or not supplied:
        return False
    return hmac.compare_digest(expected, supplied.strip())


def issue_key(db: Session, router: Router) -> KeyPair:
    """Generate a fresh tunnel key pair and store ONLY the public half.

    The private half is returned to the caller, travels to the router once and is then gone:
    it is never written to the database, a file, a cache or a log line.
    """
    keypair = generate_ed25519_keypair(tunnel_comment(router))
    router.public_key = keypair.public_line
    router.key_fingerprint = keypair.fingerprint
    router.key_serial = int(router.key_serial or 0) + 1
    router.revoked_at = None
    db.flush()
    log.info("issued tunnel key %s for router %s", keypair.fingerprint, router.slug)
    return keypair


def _line_for_router(router: Router, settings: Settings) -> str | None:
    """Render the single authorized_keys line for one router, or None when it cannot have one."""
    if not router.public_key or router.status == "revoked" or router.revoked_at is not None:
        return None
    if not router.remote_port:
        return None
    bind = router.bind_address or settings.bind_address
    extra = ""
    console_port = getattr(router, "console_port", None)
    if console_port and settings.console_enabled:
        # Second listener: panel loopback -> router dropbear. Added as an extra option because
        # authorized_key_line takes a single bind address for the tunnel listener.
        extra = f'permitlisten="{settings.console_bind_address}:{int(console_port)}"'
    try:
        return authorized_key_line(
            router.public_key,
            bind_address=bind,
            ports=int(router.remote_port),
            comment=tunnel_comment(router),
            extra_options=extra,
        )
    except ValueError:
        log.warning("router %s has no usable listener port; skipping its key line", router.slug)
        return None


def render_authorized_keys(db: Session, settings: Settings | None = None) -> str:
    """The complete authorized_keys body for every router that still holds a key."""
    s = settings or get_settings()
    routers = db.execute(select(Router).order_by(Router.slug)).scalars().all()
    lines = [line for router in routers if (line := _line_for_router(router, s))]
    return "".join(line + "\n" for line in lines)


def _reload_sshd(settings: Settings) -> None:
    """Ask sshd to re-read authorized_keys. Best effort: never fail the caller over this."""
    command = (settings.sshd_reload_command or "").strip()
    if not command:
        return
    try:
        subprocess.run(
            command,
            shell=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        log.warning("sshd reload command failed: %s", command, exc_info=True)


def write_authorized_keys(db: Session, settings: Settings | None = None) -> int:
    """Atomically replace the authorized_keys file. Returns the number of lines written.

    Atomicity matters: sshd may read this file at any moment, so a partially written file would
    lock operators out of their own routers. The content is written to a sibling temp file,
    chmod-ed, fsync-ed and then renamed over the target in one step.
    """
    s = settings or get_settings()
    body = render_authorized_keys(db, s)
    target = Path(s.authorized_keys_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = int(s.authorized_keys_mode)
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".authorized_keys.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise
    _reload_sshd(s)
    return body.count("\n")


def revoke_router_key(db: Session, router: Router) -> None:
    """Drop the tunnel key of one router and rewrite authorized_keys immediately.

    Order matters: the file is rewritten BEFORE the row is touched downstream, so there is no
    window in which the database says "revoked" while a live line still grants a listener.
    """
    router.public_key = None
    router.key_fingerprint = None
    # revoked_at marks "this row has no usable key right now". It is cleared again by issue_key,
    # so a rotate-then-reinstall cycle (rotate sets it, the exchange clears it) stays coherent,
    # while the monitor`s revoked_at IS NULL filter keeps skipped from probing a keyless router.
    router.revoked_at = utcnow()
    db.flush()
    write_authorized_keys(db)
    log.info("revoked tunnel key for router %s", router.slug)


def sync_authorized_keys(db: Session, router: Router | None = None) -> int:
    """Rewrite authorized_keys after a change. The router argument is informative only."""
    count = write_authorized_keys(db)
    if router is not None:
        log.debug("authorized_keys rewritten for router %s (%s lines)", router.slug, count)
    return count


# ------------------------------------------------------------------ console key
def issue_console_key(db: Session, router: Router) -> KeyPair:
    """Create (or re-create) the panel-owned console key, sealed at rest.

    The private half is sealed with AES-256-GCM under the panel master key and stored in
    console_key_sealed; the public half is delivered to the router through the heartbeat so it
    can authorise the panel in its own authorized_keys.
    """
    from . import ports as ports_service

    keypair = generate_ed25519_keypair(f"{CONSOLE_KEY_COMMENT}:{router.slug}")
    router.console_public_key = keypair.public_line
    router.console_key_sealed = encrypt_secret(keypair.private_openssh)
    router.console_key_fingerprint = keypair.fingerprint
    router.console_key_serial = int(router.console_key_serial or 0) + 1
    router.console_installed_at = None
    if not router.console_port:
        router.console_port = ports_service.allocate_port(db, kind=ports_service.KIND_CONSOLE)
    db.flush()
    log.info(
        "issued console key %s (serial %s) for router %s",
        keypair.fingerprint,
        router.console_key_serial,
        router.slug,
    )
    return keypair


def console_remote_user() -> str:
    """The account the panel logs in as on the router.

    dropbear on OpenWrt only has root and optionally an admin user, so this is deliberately a
    module constant rather than a per-router column: one operator decision, one place to change.
    """
    return CONSOLE_REMOTE_USER


def console_key_registration(router: Router) -> ConsoleRegistration | None:
    """The router-side key registration, while it has not been delivered yet.

    Delivery is one-shot per key version: a heartbeat that carries the registration is the
    moment the panel stops advertising it, which keeps heartbeat traffic idempotent instead of
    rewriting the router authorized_keys on every poll.
    """
    if not getattr(router, "has_console_key", False):
        return None
    if getattr(router, "console_installed_at", None) is not None:
        return None
    return ConsoleRegistration(
        serial=int(router.console_key_serial or 1),
        user=console_remote_user(),
        public_key=router.console_public_key or "",
        fingerprint=router.console_key_fingerprint or "",
        authorized_keys_path=ROUTER_AUTHORIZED_KEYS_PATH,
        shell=ROUTER_SHELL,
    )


def install_console_key_on_router(router: Router) -> str:
    """POSIX-sh snippet the installer appends to the router to authorise the panel.

    Kept next to the key service so the script and the heartbeat registration cannot drift: both
    describe the same file, the same comment and the same restrictions.
    """
    public_key = router.console_public_key or ""
    if not public_key:
        return ""
    line = f"{public_key.strip()} {CONSOLE_KEY_COMMENT}:{router.slug}"
    return "\n".join(
        [
            "  # console: allow the panel to open a shell here",
            f"  TG_CK={shell_quote(line)}",
            f"  mkdir -p $(dirname {ROUTER_AUTHORIZED_KEYS_PATH})",
            f"  touch {ROUTER_AUTHORIZED_KEYS_PATH}",
            f"  grep -qF \"$(echo $TG_CK | cut -d' ' -f2)\" {ROUTER_AUTHORIZED_KEYS_PATH} \\",
            f'    || echo "$TG_CK" >> {ROUTER_AUTHORIZED_KEYS_PATH}',
            f"  chmod 600 {ROUTER_AUTHORIZED_KEYS_PATH}",
        ]
    )


def shell_quote(value: str) -> str:
    """Single-quote a value for POSIX sh (the only quoting busybox ash always honours)."""
    return "'" + value.replace("'", "'\\''") + "'"
