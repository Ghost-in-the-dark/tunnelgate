"""Router launch: carry an authenticated operator from the panel to one router's LuCI.

The problem this module exists for
----------------------------------
A router's LuCI is published at `https://<slug>.<host_suffix>`, a host the browser holds no
panel cookie for (the session cookie is host-only on purpose - see docs/SECURITY.md section 6 and
threat A11). `auth_request` therefore answers 401, nginx bounces the visitor to the panel login,
the operator signs in *on the panel host*, and the cookie they receive is scoped to that host -
so the next visit to the router host 401s again. That is the login loop users reported.

Widening the session cookie to the whole domain would "fix" it and hand every router (and
anything that can read a router's traffic) a live panel session, which is exactly the trade the
security model refuses. So the credential never travels: instead the panel mints a one-time
ticket bound to (user, router), the router vhost's `/__tg/enter` redeems it through the panel,
and the panel answers with a cookie scoped to THAT router host plus a redirect to the page that
was asked for. The panel session stays on the panel origin; the router host gets its own,
narrower, shorter-lived credential that only authorises that one device.

Two mechanisms, both here:

* `LaunchTicketStore` - in-memory, single-use, SHA-256-keyed tickets (the same shape as the
  console tickets in `app/services/console.py`, deliberately: one pattern, one review).
* the router cookie - `router_id.user_id.expiry.signature`, signed with a key derived from
  `TUNNELGATE_SECRET_KEY`, so the gate can validate it without trusting the router that
  presents it.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

from ..security import hash_token, master_key

log = logging.getLogger("tunnelgate.launch")

# Where a router vhost sends the browser. Mirrored by render_nginx() and render_caddy_route(),
# so a change here is a change in app/services/proxy.py too.
ENTER_PATH = "/__tg/enter"
# The panel-side endpoint that mints a ticket. It lives on the panel host because that is the
# only origin where the browser attaches the panel session cookie.
LAUNCH_PATH = "/__tg/launch"
DEFAULT_TICKET_TTL_SECONDS = 120.0
_TICKET_BYTES = 32
_MAX_TARGET_LENGTH = 512


# --------------------------------------------------------------------------- targets
def safe_target(raw: str | None, default: str = "/") -> str:
    """Reduce an untrusted "where do I go afterwards" value to a path on the current host.

    The value reaches us from a query string, so it must never be able to leave the router
    host: an absolute URL, a protocol-relative "//host", a backslash variant (which some
    browsers treat as a slash) or a scheme would all turn the launch endpoint into an open
    redirect. Anything that is not a plain absolute path falls back to the default.
    """
    if not raw:
        return default
    text = str(raw).strip().replace("\\", "/")
    # Strip control characters some clients use to confuse log parsing / header splitting.
    text = "".join(ch for ch in text if ch.isprintable())
    if not text.startswith("/") or text.startswith("//"):
        return default
    if len(text) > _MAX_TARGET_LENGTH:
        text = text[:_MAX_TARGET_LENGTH]
    return text or default


def default_target(settings, slug: str) -> str:
    """Where a launched router lands when the operator did not ask for a page.

    "/" is only right in subdomain mode, where the router host's root IS the router. In path
    mode the root belongs to the gateway (which answers 404 by design), so the landing page is
    that router's own prefix.
    """
    return settings.router_prefix(slug) + "/" if settings.path_routing else "/"


def launch_url(settings, slug: str, ticket: str | None = None) -> str:
    """The URL a click on "Open LuCI" / "Public route" follows.

    The ticket is optional. Without one this is still useful: `/__tg/enter` falls back to the
    panel login, which mints a ticket once the operator is signed in and finishes the trip -
    that is what keeps a bookmarked or pasted public URL working instead of looping.
    """
    if settings.path_routing:
        # https://<gateway>/<slug>/__tg/enter - the gateway host is shared by the whole fleet,
        # so the slug has to be in the path. This is the only form that works without DNS for
        # *.<suffix> or a wildcard certificate (and the only one that works when the suffix is
        # a bare IP, which a browser refuses to parse as a subdomain).
        base = f"https://{settings.gateway}{settings.router_prefix(slug)}{ENTER_PATH}"
    else:
        base = f"https://{slug}.{settings.host_suffix}{ENTER_PATH}"
    return f"{base}?t={ticket}" if ticket else base


def launch_login_url(settings, slug: str, target: str = "/") -> str:
    """The panel path that mints a ticket, used as the post-sign-in destination."""
    return f"{LAUNCH_PATH}?" + urlencode({"router": slug, "next": target})


def panel_login_url(settings, slug: str | None, target: str = "/") -> str:
    """Where `/__tg/enter` sends a browser that has no (or a stale) ticket.

    `next` is carried through so the login screen can hand the browser back with a fresh
    ticket for the page that was actually asked for, instead of the panel dashboard.
    """
    from .proxy import public_origin

    query = {"next": target}
    if slug:
        query["router"] = slug
    return f"{public_origin(settings)}/login?" + urlencode(query)


def slug_from_path(raw: str | None) -> str | None:
    """The router slug in a path-mode request path: "/<slug>/cgi-bin/luci" -> "<slug>".

    Only the FIRST segment can be a slug, so this never guesses: "/cgi-bin/luci" (a request
    that lost its prefix) yields None and the caller falls back to the login hand-off.
    """
    if not raw:
        return None
    path = str(raw).split("?", 1)[0].split("#", 1)[0].strip("/")
    if not path:
        return None
    first = path.split("/", 1)[0]
    return first or None


def _is_router_host(settings, host: str | None) -> bool:
    """True when `host` is `<label>.<host_suffix>` - a host this panel generates routes for.

    Always False in path mode: there is exactly one host (the gateway) and it belongs to no
    single router. Anything that resolves a slug from the Host header must therefore consult
    slug_from_path() instead; see app/api/launch.py.
    """
    if not host or settings.path_routing:
        return False
    name = host.split(":")[0].strip().lower().rstrip(".")
    suffix = str(settings.host_suffix).strip().lower().rstrip(".")
    return bool(suffix) and name.endswith("." + suffix) and len(name) > len(suffix) + 1


def host_router_slug(settings, host: str | None) -> str | None:
    """The slug encoded in a router hostname, or None when the host is not one of ours."""
    if not _is_router_host(settings, host):
        return None
    name = str(host).split(":")[0].strip().lower().rstrip(".")
    suffix = str(settings.host_suffix).strip().lower().rstrip(".")
    return name[: -(len(suffix) + 1)] or None


def expected_router_host(settings, slug: str) -> str:
    """The Host header a request for `slug` must carry (used by the doctor and the tests)."""
    if settings.path_routing:
        return str(settings.gateway).lower().rstrip(".")
    return f"{slug}.{settings.host_suffix}".lower().rstrip(".")


def router_cookie_path(settings, slug: str) -> str:
    """The Path a router cookie is scoped to.

    "/" on a per-router host - the host is the scope. In path mode every router shares one
    host, so the cookie must be scoped to that router's prefix or router A's credential would
    be sent to router B (and, being the same cookie name, would overwrite it). Browsers allow
    several cookies with one name at different paths, which is exactly what this needs.
    """
    return settings.router_prefix(slug) + "/" if settings.path_routing else "/"


def ticket_from_uri(raw: str | None) -> str | None:
    """Pull `t` out of an original request URI, for the proxy -> panel hand-off."""
    if not raw:
        return None
    for pair in urlsplit(str(raw)).query.split("&"):
        key, _, value = pair.partition("=")
        if key == "t" and value:
            return value
    return None


# --------------------------------------------------------------------------- tickets
@dataclass(frozen=True, slots=True)
class LaunchTicket:
    """One pending panel -> router hand-off. Single use, short lived, bound to both ends."""

    router_id: str
    user_id: int
    target: str
    issued_at: float
    expires_at: float

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self.expires_at


class LaunchTicketStore:
    """In-memory, thread-safe, single-use launch tickets (mirrors ConsoleTicketStore)."""

    def __init__(self, ttl: float = DEFAULT_TICKET_TTL_SECONDS) -> None:
        self._ttl = float(ttl)
        self._lock = threading.RLock()
        self._tickets: dict[str, LaunchTicket] = {}

    @property
    def ttl(self) -> float:
        return self._ttl

    def issue(
        self,
        router_id: str,
        user_id: int,
        target: str = "/",
        ttl: float | None = None,
    ) -> str:
        """Mint a ticket and return the plaintext; only its SHA-256 is retained."""
        ticket = secrets.token_urlsafe(_TICKET_BYTES)
        now = time.monotonic()
        record = LaunchTicket(
            router_id=str(router_id),
            user_id=int(user_id),
            target=safe_target(target),
            issued_at=now,
            expires_at=now + float(ttl if ttl is not None else self._ttl),
        )
        with self._lock:
            self._purge_locked(now)
            self._tickets[hash_token(ticket)] = record
        return ticket

    def consume(self, ticket: str | None) -> LaunchTicket | None:
        """Redeem exactly once; None for unknown, expired or already-used tickets."""
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

    # Tests and the console store both spell the reset "reset"; keep one name working.
    def reset(self) -> None:
        self.clear()


TICKETS = LaunchTicketStore()


# --------------------------------------------------------------------------- router cookie
def _cookie_key(settings) -> bytes:
    """Per-deployment signing key, derived from TUNNELGATE_SECRET_KEY via the secret store."""
    return hashlib.sha256(b"tunnelgate:launch-cookie:" + master_key(settings)).digest()


def _cookie_signature(settings, router_id: str, user_id: int, expires_at: int) -> str:
    message = f"{router_id}.{int(user_id)}.{int(expires_at)}".encode()
    return hmac.new(_cookie_key(settings), message, hashlib.sha256).hexdigest()


def issue_router_cookie(settings, router_id: str, user_id: int) -> tuple[str, int]:
    """(value, max_age_seconds) for the cookie scoped to one router host."""
    ttl = max(1, int(settings.router_session_ttl_minutes)) * 60
    expires_at = int(time.time()) + ttl
    signature = _cookie_signature(settings, router_id, user_id, expires_at)
    return f"{router_id}.{int(user_id)}.{expires_at}.{signature}", ttl


def verify_router_cookie(settings, router_id: str, value: str | None) -> int | None:
    """The user id when `value` authorises `router_id`, else None.

    Fails closed on every shape problem: wrong number of fields, a different router id in the
    value (a cookie minted for router A must never open router B), an expired stamp, or a
    signature that does not compare equal. The signature is constant-time compared.
    """
    if not value or not router_id:
        return None
    parts = str(value).split(".")
    if len(parts) != 4:
        return None
    cookie_router, raw_user, raw_expiry, signature = parts
    if not hmac.compare_digest(cookie_router, str(router_id)):
        return None
    try:
        user_id = int(raw_user)
        expires_at = int(raw_expiry)
    except (TypeError, ValueError):
        return None
    if expires_at <= int(time.time()):
        return None
    expected = _cookie_signature(settings, cookie_router, user_id, expires_at)
    if not hmac.compare_digest(expected, signature):
        return None
    return user_id


def cookie_header_name(cookie_name: str) -> str:
    """`tg_luci` -> `X-Tg-Luci-Cookie`, the header the proxy sets on the auth subrequest.

    Derived from the cookie name rather than hard-coded, so renaming the cookie through
    TUNNELGATE_ROUTER_COOKIE_NAME keeps the snippet, the gate and this module in step. The
    "X-"/"-Cookie" wrapper is what makes the header obviously ours in a router's logs.
    """
    cleaned = "".join(ch for ch in str(cookie_name) if ch.isalnum() or ch == "_")
    parts = [part.capitalize() for part in cleaned.split("_") if part]
    return "X-" + "-".join(parts) + "-Cookie"


def router_cookie_names(settings) -> tuple[str, str]:
    """(cookie name, header name) the router vhost uses to carry the credential to the gate.

    nginx cannot pass a cookie to a subrequest any other way, and `proxy_pass` copies the
    browser headers verbatim, so the snippet copies exactly one cookie into a dedicated header
    using `$cookie_<name>` rather than `$http_cookie`: a router then never sees - and cannot
    forge - anything else the browser holds.
    """
    name = str(settings.router_cookie_name or "tg_luci").strip() or "tg_luci"
    return name, cookie_header_name(name)


def is_same_origin_target(url: str) -> bool:
    """Small helper used by the API to refuse a target that is not a path."""
    parts = urlsplit(url)
    return not parts.scheme and not parts.netloc
