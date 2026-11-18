"""Console (web terminal) plumbing: SSH dial-out, one-time tickets, live session registry.

Architecture (CONTRACT.md ADDENDUM 1)
-------------------------------------
The router opens a **second** reverse listener on the panel host loopback
(`127.0.0.1:<Router.console_port>`) and forwards it to its own sshd
(`127.0.0.1:<Router.console_ssh_port>`, 22 by default). The panel therefore logs *in* to the
router instead of the other way round, which is what makes an interactive shell possible while
the tunnel key stays restricted to `permitlisten`.

That inverts the key ownership: the panel owns the ed25519 **private** half, so it is sealed
with AES-256-GCM (`app.security.encrypt_secret`) in `Router.console_key_sealed` and is unsealed
for exactly one handshake inside :func:`open_ssh`. The router only ever receives the public
half.

Host key verification
---------------------
The peer is only reachable through the loopback listener that the *router's own* authenticated
tunnel connection created, so router identity is already established at the tunnel layer.
`Router` currently carries no stored console host key, so :class:`ConsoleHostKeyPolicy`
**records** the observed fingerprint and still refuses a mismatch whenever a fingerprint is
available (today via `Router.console_host_key_fingerprint` / `Router.console_host_key` when a
future model revision adds them, and via `:func:`app.security.key_fingerprint` for a public
key line). Nothing is trusted from the network in the meantime: `allow_agent=False` and
`look_for_keys=False` mean a wrong key never reaches the wire.

Nothing in this module logs key material, keystrokes or shell output.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import io
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

from paramiko import (
    AuthenticationException,
    BadHostKeyException,
    Ed25519Key,
    MissingHostKeyPolicy,
    SSHClient,
    SSHException,
)

from ..config import Settings, get_settings
from ..models import STATUS_ONLINE, STATUS_REVOKED, Router
from ..security import decrypt_secret, hash_token, key_fingerprint
from .keys import console_remote_user

log = logging.getLogger("tunnelgate.console")

# One-time ticket handed to the browser between "panel dialled the router" and "browser opened
# the WebSocket". 30 s is plenty for a local round trip and keeps the replay window tiny.
CONSOLE_TICKET_TTL_SECONDS = 30.0
# SSH keepalive so a quiet shell does not get dropped by the SSH transport behind a NAT/proxy.
CONSOLE_KEEPALIVE_SECONDS = 30
# Bytes pulled from the SSH channel per read.
CONSOLE_READ_CHUNK = 4096
DEFAULT_CONSOLE_TERM = "xterm-256color"
DEFAULT_CONSOLE_COLS = 80
DEFAULT_CONSOLE_ROWS = 24

# console_state() results (frozen vocabulary - the API and the frontend switch on these).
STATE_DISABLED = "disabled"
STATE_NO_KEY = "no_key"
STATE_NOT_INSTALLED = "not_installed"
STATE_READY = "ready"
STATE_OFFLINE = "offline"


class ConsoleError(Exception):
    """A console problem that is safe to surface to the caller.

    `code` goes into the API error envelope, `status` is the HTTP status the API layer raises,
    and `message` is user-facing (never contains key material).
    """

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


# --------------------------------------------------------------------------- state
_STATE_ERRORS: dict[str, tuple[int, str, str]] = {
    STATE_DISABLED: (
        403,
        "console_disabled",
        "The web console is disabled for this panel (TUNNELGATE_CONSOLE_ENABLED=false)",
    ),
    STATE_NO_KEY: (
        409,
        "console_no_key",
        "No console key has been issued for this router yet; open the console again to "
        "provision one",
    ),
    STATE_NOT_INSTALLED: (
        409,
        "console_not_installed",
        "The router has not installed the console key yet; it picks the key up on its next "
        "heartbeat",
    ),
    STATE_OFFLINE: (
        409,
        "console_offline",
        "The router is offline, so its console listener is not reachable through the tunnel",
    ),
}


def state_error(state: str) -> tuple[int, str, str]:
    """Map a non-ready console state to (http_status, code, message) for the API layer."""
    return _STATE_ERRORS.get(
        state, (409, "console_unavailable", "The console is not available for this router")
    )


def console_state(db, router: Router, settings: Settings | None = None) -> str:
    """Return the console lifecycle state for `router`.

    Order matters: a missing key pair is reported before "not installed", because issuing the
    key is the precondition for installing it. `db` is accepted for signature compatibility and
    future runtime lookups; the decision is made from the router row and settings alone so the
    API cannot disagree with the installer.
    """
    s = settings or get_settings()
    if not s.console_enabled:
        return STATE_DISABLED
    if getattr(router, "status", None) == STATUS_REVOKED:
        return STATE_NO_KEY
    if not getattr(router, "has_console_key", False):
        return STATE_NO_KEY
    if not getattr(router, "console_port", None):
        return STATE_NOT_INSTALLED
    if getattr(router, "console_installed_at", None) is None:
        return STATE_NOT_INSTALLED
    if getattr(router, "status", None) != STATUS_ONLINE:
        return STATE_OFFLINE
    return STATE_READY


# --------------------------------------------------------------------------- tickets
@dataclass(frozen=True, slots=True)
class ConsoleTicket:
    """A consumed ticket: proves *which* router and user the WebSocket belongs to."""

    router_id: str
    user_id: int
    client_ip: str
    issued_at: float
    expires_at: float

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self.expires_at


class ConsoleTicketStore:
    """In-memory, thread-safe, single-use tickets with a short TTL.

    Only the SHA-256 of a ticket is stored, exactly like every other token in TunnelGate, so a
    process memory dump cannot replay a live ticket. Expired tickets are purged on every
    access, which bounds the dictionary without a background task.
    """

    def __init__(self, ttl: float = CONSOLE_TICKET_TTL_SECONDS) -> None:
        self._ttl = float(ttl)
        self._lock = threading.RLock()
        self._tickets: dict[str, ConsoleTicket] = {}

    @property
    def ttl(self) -> float:
        return self._ttl

    def issue(self, router_id: str, user_id: int, client_ip: str = "") -> str:
        """Create a ticket bound to one router + user and return the plaintext (shown once)."""
        ticket = secrets.token_urlsafe(32)
        now = time.monotonic()
        record = ConsoleTicket(
            router_id=router_id,
            user_id=int(user_id),
            client_ip=client_ip or "",
            issued_at=now,
            expires_at=now + self._ttl,
        )
        with self._lock:
            self._purge_locked(time.monotonic())
            self._tickets[hash_token(ticket)] = record
        return ticket

    # CONTRACT.md line 51 calls this "ticket()"; keep both spellings working.
    def ticket(self, router_id: str, user_id: int, client_ip: str = "") -> str:
        return self.issue(router_id, user_id, client_ip)

    def consume(self, ticket: str | None) -> ConsoleTicket | None:
        """Redeem a ticket exactly once. Returns None for unknown, expired or reused tickets."""
        if not ticket:
            return None
        digest = hash_token(ticket)
        now = time.monotonic()
        with self._lock:
            self._purge_locked(now)
            record = self._tickets.pop(digest, None)
        if record is None or record.expires_at <= now:
            return None
        return record

    def _purge_locked(self, now: float) -> None:
        for digest, record in list(self._tickets.items()):
            if record.expires_at <= now:
                del self._tickets[digest]

    def purge_expired(self) -> int:
        with self._lock:
            before = len(self._tickets)
            self._purge_locked(time.monotonic())
            return before - len(self._tickets)

    def __len__(self) -> int:
        with self._lock:
            self._purge_locked(time.monotonic())
            return len(self._tickets)

    def clear(self) -> None:
        with self._lock:
            self._tickets.clear()

    def reset(self) -> None:
        """Alias used by tests/conftest.py between cases."""
        self.clear()


# --------------------------------------------------------------------------- live sessions
@dataclass(slots=True)
class ActiveConsoleSession:
    """Handle on one bridged shell, so the API can count and kill live sessions."""

    session_id: str
    router_id: str
    user_id: int | None
    username: str | None
    client_ip: str | None
    started_at: float
    loop: asyncio.AbstractEventLoop
    stop: asyncio.Event
    close_reason: str | None = None

    def request_close(self, reason: str = "killed") -> None:
        """Ask the handler to tear down this session. Safe from any thread."""
        with contextlib.suppress(RuntimeError):
            self.loop.call_soon_threadsafe(self._mark, reason)

    def _mark(self, reason: str) -> None:
        if self.close_reason is None:
            self.close_reason = reason
        self.stop.set()

    def snapshot(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "router_id": self.router_id,
            "user_id": self.user_id,
            "username": self.username,
            "client_ip": self.client_ip,
            "started_at": self.started_at,
            "close_reason": self.close_reason,
        }


class ConsoleSessionRegistry:
    """Live console sessions: per-user and per-router counts plus the 'kill console' action."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, ActiveConsoleSession] = {}

    def add(self, session: ActiveConsoleSession) -> None:
        with self._lock:
            self._sessions[session.session_id] = session

    def remove(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def get(self, session_id: str) -> ActiveConsoleSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def active(self) -> list[ActiveConsoleSession]:
        with self._lock:
            return list(self._sessions.values())

    def active_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def count_for_user(self, user_id: int | None) -> int:
        if user_id is None:
            return 0
        with self._lock:
            return sum(1 for s in self._sessions.values() if s.user_id == user_id)

    def count_for_router(self, router_id: str) -> int:
        with self._lock:
            return sum(1 for s in self._sessions.values() if s.router_id == router_id)

    def close_all(self, router_id: str, reason: str = "killed") -> int:
        """Ask every live session of `router_id` to close. Returns how many were signalled."""
        with self._lock:
            targets = [s for s in self._sessions.values() if s.router_id == router_id]
        for session in targets:
            session.request_close(reason)
        return len(targets)

    def __len__(self) -> int:
        return self.active_count()

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()

    def reset(self) -> None:
        """Alias used by tests/conftest.py between cases."""
        self.clear()


# Module-level singletons. The names TICKETS and SESSIONS are part of the contract (the test
# conftest resets objects exposing .reset()/.clear()).
TICKETS = ConsoleTicketStore()
SESSIONS = ConsoleSessionRegistry()


# --------------------------------------------------------------------------- ssh
def console_ssh_user(router: Router) -> str:
    """The login the panel uses on the router: exactly the account the key was installed for.

    This MUST agree with the account named in the console key registration
    (app.services.keys.console_remote_user), because that is who the panel told the installer
    and the heartbeat to authorise. Reading Router.ssh_user here - as an earlier revision did -
    silently breaks every real router: Router.ssh_user is the panel-side TUNNEL login
    ("tunnelgate"), an account that does not exist on OpenWrt at all, so the dial failed with
    "Authentication failed" while console_state() still reported "ready".

    A future per-router console account needs a dedicated column that the registration honours
    too; until then there is exactly one source of truth and this function returns it.
    """
    del router  # kept in the signature so callers need no change
    return console_remote_user()


def _fingerprint_of_key(key: Any) -> str:
    blob = key.asbytes()
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _pinned_host_key_fingerprint(router: Router) -> str | None:
    """Best-effort pin: a stored fingerprint if a future model revision provides one."""
    for attr in ("console_host_key_fingerprint", "host_key_fingerprint"):
        value = getattr(router, attr, None)
        if value:
            return str(value).strip()
    public_line = getattr(router, "console_host_key", None)
    if public_line:
        with contextlib.suppress(ValueError):
            return key_fingerprint(str(public_line))
    return None


class ConsoleHostKeyPolicy(MissingHostKeyPolicy):
    """Accept the router's host key on first use, but refuse a changed one.

    See the module docstring: the peer is authenticated by the tunnel that created the loopback
    listener, so the host key here is defence in depth, not the trust anchor.
    """

    def __init__(self, router: Router) -> None:
        self.router = router
        self.observed: str | None = None

    def missing_host_key(self, client, hostname: str, key) -> None:
        observed = _fingerprint_of_key(key)
        self.observed = observed
        expected = _pinned_host_key_fingerprint(self.router)
        if expected and not hmac.compare_digest(expected, observed):
            raise ConsoleError(
                "console_auth_failed",
                "The router presented an unexpected SSH host key; refusing to open a shell",
                502,
            )
        log.debug("console host key for %s is %s (unpinned)", hostname, observed)


def _connect_blocking(router: Router, settings: Settings) -> SSHClient:
    """Blocking half of :func:`open_ssh`: unseal, handshake, keep the session. No channel yet."""
    sealed = getattr(router, "console_key_sealed", None)
    port = getattr(router, "console_port", None)
    if not sealed or not port:
        raise ConsoleError(
            "console_no_key",
            "The console is not provisioned for this router yet "
            "(no sealed console key or no console port allocated)",
            409,
        )

    try:
        plaintext = decrypt_secret(sealed, settings)
    except Exception as exc:
        # Deliberately does not echo the exception text: it can contain key/ciphertext bytes.
        raise ConsoleError(
            "console_no_key",
            "The stored console key cannot be unsealed (corrupt row or changed "
            "TUNNELGATE_SECRET_KEY); re-issue the console key for this router",
            409,
        ) from exc

    if not plaintext:
        raise ConsoleError("console_no_key", "The stored console key is empty", 409)

    key_file = io.StringIO(plaintext)
    try:
        pkey = Ed25519Key.from_private_key(key_file)
    except (SSHException, ValueError) as exc:
        raise ConsoleError(
            "console_no_key", "The stored console key is not a usable ed25519 private key", 409
        ) from exc
    finally:
        key_file.close()  # close immediately; the plaintext must not linger in a buffer
        del plaintext

    client = SSHClient()
    client.set_missing_host_key_policy(ConsoleHostKeyPolicy(router))
    timeout = float(settings.console_connect_timeout_seconds or 10.0)
    try:
        client.connect(
            hostname=settings.console_bind_address,
            port=int(port),
            username=console_ssh_user(router),
            pkey=pkey,
            allow_agent=False,
            look_for_keys=False,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            channel_timeout=timeout,
        )
    except ConsoleError:
        _close_quietly(client)
        raise
    except AuthenticationException as exc:
        _close_quietly(client)
        raise ConsoleError(
            "console_auth_failed",
            "The router rejected the panel console key; re-issue the console key and let the "
            "router install it again",
            502,
        ) from exc
    except BadHostKeyException as exc:
        _close_quietly(client)
        raise ConsoleError(
            "console_auth_failed",
            "The router presented an unexpected SSH host key",
            502,
        ) from exc
    except (SSHException, OSError, EOFError) as exc:
        _close_quietly(client)
        raise ConsoleError(
            "console_unreachable",
            "Cannot reach the router console listener; the router is probably offline or the "
            "reverse forward is not up",
            502,
        ) from exc
    except Exception as exc:
        _close_quietly(client)
        raise ConsoleError("console_unreachable", "Console connection failed", 502) from exc

    transport = None
    with contextlib.suppress(Exception):
        transport = client.get_transport()
    if transport is not None and hasattr(transport, "set_keepalive"):
        with contextlib.suppress(Exception):
            transport.set_keepalive(CONSOLE_KEEPALIVE_SECONDS)

    policy = None
    with contextlib.suppress(Exception):
        policy = client._policy
    if isinstance(policy, ConsoleHostKeyPolicy) and policy.observed:
        with contextlib.suppress(Exception):
            client._tg_console_host_key_fingerprint = policy.observed
    return client


def _close_quietly(client: Any) -> None:
    with contextlib.suppress(Exception):
        client.close()


async def open_ssh(router: Router, settings: Settings | None = None) -> SSHClient:
    """Dial the router's console listener and return a connected, authenticated SSH client.

    Runs the whole blocking handshake in a worker thread. Raises :class:`ConsoleError` with
    `console_no_key` / `console_auth_failed` / `console_unreachable`; the caller is responsible
    for closing the returned client (that is what a throwaway reachability probe does).
    """
    s = settings or get_settings()
    if not s.console_enabled:
        raise ConsoleError(STATE_DISABLED, "The web console is disabled", 403)
    timeout = float(s.console_connect_timeout_seconds or 10.0)
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_connect_blocking, router, s), timeout=timeout * 3 + 5
        )
    except TimeoutError as exc:
        raise ConsoleError(
            "console_unreachable", "Timed out while connecting to the router console", 502
        ) from exc


@dataclass(slots=True)
class ConsoleConnection:
    """One open interactive shell: the SSH client plus its shell channel."""

    client: Any
    channel: Any
    host_key_fingerprint: str | None = None

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.channel.close()
        _close_quietly(self.client)


def _invoke_shell_blocking(client: Any, settings: Settings, cols: int, rows: int) -> Any:
    """Open a pty+shell on an already connected client (`invoke_shell` issues the pty-req)."""
    term = settings.console_term or DEFAULT_CONSOLE_TERM
    channel = client.invoke_shell(
        term=term,
        width=max(1, int(cols)),
        height=max(1, int(rows)),
    )
    with contextlib.suppress(Exception):
        channel.settimeout(None)  # blocking reads; the browser drives the lifetime
    return channel


async def open_shell(
    router: Router,
    settings: Settings | None = None,
    *,
    cols: int = DEFAULT_CONSOLE_COLS,
    rows: int = DEFAULT_CONSOLE_ROWS,
) -> ConsoleConnection:
    """Connect and immediately request an interactive pty/shell channel."""
    s = settings or get_settings()
    client = await open_ssh(router, s)
    try:
        channel = await asyncio.to_thread(_invoke_shell_blocking, client, s, cols, rows)
    except ConsoleError:
        _close_quietly(client)
        raise
    except Exception as exc:
        _close_quietly(client)
        raise ConsoleError(
            "console_unreachable", "The router refused to open an interactive shell", 502
        ) from exc
    fingerprint = getattr(client, "_tg_console_host_key_fingerprint", None)
    return ConsoleConnection(client=client, channel=channel, host_key_fingerprint=fingerprint)
