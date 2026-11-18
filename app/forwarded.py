"""Client identity behind a reverse proxy.

The panel is normally published by nginx, Caddy, Traefik or a cloud load balancer, so the
socket peer is the proxy and the real client address arrives in "X-Forwarded-For". Believing
that header unconditionally is a hole: any client can send it, and the leftmost entry - the one
a naive implementation reads - is entirely attacker-controlled. Rotating it defeats every IP
rate limit and forges every audit row (audit finding F1).

The rule implemented here is the only one that holds up:

* forwarded headers are believed ONLY when the immediate peer ("request.client.host") is one
  of "settings.trusted_proxies";
* the client address is taken from the RIGHT of the chain, counting past exactly
  "settings.forwarded_allow_hops" of our own proxies, because everything a client wrote itself
  sits on the left while each proxy appends the peer it actually saw on the right;
* anything else (malformed entries, fewer hops than configured, header absent) falls back to
  the socket peer, which can be wrong but can never be forged.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

log = logging.getLogger(__name__)


def normalize_ip(value: str | None) -> str | None:
    """Canonical form of an address, or None when it is not one.

    "::ffff:127.0.0.1" and "127.0.0.1" are the same peer, so both sides of every comparison go
    through here; otherwise a trusted-proxy entry would never match on a dual-stack listener.
    """
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


def peer_ip(request: Any) -> str:
    """The address of the socket peer. Never attacker-controlled."""
    client = getattr(request, "client", None)
    host = getattr(client, "host", None) if client is not None else None
    return normalize_ip(host) or "unknown"


def _proxy_entries(settings: Any) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    entries: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in getattr(settings, "trusted_proxies", None) or []:
        text = str(raw).strip()
        if not text:
            continue
        try:
            entries.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            log.warning("ignoring trusted-proxy entry %r: not an address or network", text)
    return entries


def is_trusted_proxy(address: str, settings: Any) -> bool:
    """True when the given address is a proxy whose forwarded headers may be believed."""
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return False
    for network in _proxy_entries(settings):
        if addr.version == network.version and addr in network:
            return True
    return False


def trusted_peer(request: Any, settings: Any) -> bool:
    """True when this request arrived from one of our own proxies."""
    peer = peer_ip(request)
    if peer == "unknown":
        return False
    return is_trusted_proxy(peer, settings)


def forwarded_chain(request: Any) -> list[str]:
    """The X-Forwarded-For chain, left to right, with anything unparsable dropped."""
    raw = request.headers.get("x-forwarded-for") or ""
    out: list[str] = []
    for part in raw.split(","):
        item = normalize_ip(part)
        if item is not None:
            out.append(item)
    return out


def client_ip(request: Any, settings: Any) -> str:
    """The best address we can defend for the caller of a request.

    The argument is any Starlette HTTPConnection: Request and WebSocket behave identically here.
    """
    peer = peer_ip(request)
    if not getattr(settings, "trust_proxy_headers", False):
        return peer
    if not trusted_peer(request, settings):
        # The peer is not one of our proxies: whatever it claims is its own assertion.
        return peer

    chain = forwarded_chain(request)
    if chain:
        hops = max(1, int(getattr(settings, "forwarded_allow_hops", 1) or 1))
        index = len(chain) - hops
        if index < 0:
            # FEWER entries than configured hops: the chain does not carry the proxies that would
            # justify reading that far left, so its leftmost entry is whatever the client typed.
            # Reading it would hand the identity back to exactly the attacker this module exists
            # to stop, so fail closed: the socket peer can be wrong but never forged.
            return peer
        return chain[index]

    real = normalize_ip(request.headers.get("x-real-ip"))
    if real:
        return real
    return peer


def request_scheme(request: Any, settings: Any) -> str:
    """The scheme the client used: "https" behind a trusted TLS terminator, else the socket's.

    Only consulted when the peer is one of our proxies AND "trust_forwarded_proto" is on;
    anything else keeps the scheme uvicorn saw, so an untrusted client cannot talk the panel
    into upgrading (or downgrading) its own request. The one consumer today is the Secure flag
    on the session cookie, which must not depend on an operator remembering to set it.
    """
    trusted = bool(getattr(settings, "trust_proxy_headers", False)) and bool(
        getattr(settings, "trust_forwarded_proto", False)
    )
    if trusted and trusted_peer(request, settings):
        proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
        if proto in ("http", "https"):
            return proto
    scope = getattr(request, "scope", None) or {}
    return str(scope.get("scheme") or "http")
