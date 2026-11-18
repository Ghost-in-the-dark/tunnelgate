"""The agent-facing base URL: where a router is told to dial the panel.

Two values matter and they are not the same thing:

* "panel_url" is where the panel itself lives *for its own proxy* - the internal address nginx
  proxy_passes to, e.g. http://127.0.0.1:8080. It must stay authoritative because an admin who
  typed a public hostname here would break the panel's own routing.
* the agent endpoint is what the installer writes into a router as TUNNELGATE_PANEL_URL, i.e.
  the public address a router on the customer network dials: https://panel.example.com:443.

The environment (TUNNELGATE_PANEL_URL) is the fallback, and a database row overrides it. That
ordering is deliberate: a fresh install behaves exactly as documented by its env file, and an
operator who moves the panel - new hostname, TLS terminating in front, a non-default port - can
re-point already-issued install scripts from the UI without touching env files or restarting.

The override is stored in "panel_settings" under AGENT_ENDPOINT_KEY as JSON with three fields:
scheme ("http" or "https"), host (no scheme, no port, no path) and port (1..65535, or null for
the scheme default). Validation happens on the way in AND on the way out: a row written by an
older or buggier version must not be able to produce an unparsable agent URL, so a bad row is
ignored with a warning and the environment value is used instead.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from ..config import Settings, get_settings, utcnow
from ..models import PanelSetting

log = logging.getLogger(__name__)

AGENT_ENDPOINT_KEY = "agent_endpoint"
DEFAULT_PORTS = {"http": 80, "https": 443}
SOURCE_ENVIRONMENT = "environment"
SOURCE_DATABASE = "database"

# A hostname, an IPv4 literal or a bracketed IPv6 literal. Nothing that could change the shape
# of the URL once it is pasted into a shell command: no scheme, no port, no path, no userinfo.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass(frozen=True)
class AgentEndpoint:
    """The normalised endpoint, independent of where it came from."""

    scheme: str
    host: str
    port: int | None
    source: str = SOURCE_ENVIRONMENT

    @property
    def effective_port(self) -> int:
        """The port a client will actually connect to (the scheme default when unset)."""
        return int(self.port) if self.port is not None else DEFAULT_PORTS[self.scheme]

    @property
    def url(self) -> str:
        """The value handed to routers. No trailing slash: callers append paths."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        if self.port is None or int(self.port) == DEFAULT_PORTS[self.scheme]:
            return f"{self.scheme}://{host}"
        return f"{self.scheme}://{host}:{int(self.port)}"

    def as_dict(self) -> dict:
        return {
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "source": self.source,
        }


def _host_problem(host: str) -> str | None:
    """Why a host string is unusable, or None when it is fine."""
    text = (host or "").strip()
    if not text:
        return "Host is required"
    if len(text) > 253:
        return "Host is too long (253 characters maximum)"
    if "://" in text:
        return "Enter only the host: the scheme is chosen above"
    if any(ch in text for ch in "/?#@;'\" <>%") or " " in text:
        return "Host must not contain spaces, paths, credentials or separators"
    if text.startswith("[") or text.endswith("]"):
        if not (text.startswith("[") and text.endswith("]")):
            return "Brackets must surround the whole IPv6 address"
        inner = text[1:-1]
        return None if _valid_ipv6(inner) else "Not a valid IPv6 address"
    if ":" in text:
        # A bare IPv6 address is legal but must be bracketed in a URL; accept it and bracket it.
        return None if _valid_ipv6(text) else "Not a valid IPv6 address"
    if text.startswith(".") or text.endswith("."):
        return "Host must not start or end with a dot"
    if _IPV4_RE.match(text):
        parts = [int(p) for p in text.split(".")]
        return None if all(0 <= p <= 255 for p in parts) else "Not a valid IPv4 address"
    if not _HOSTNAME_RE.match(text.lower()):
        return "Not a valid hostname"
    return None


def _valid_ipv6(text: str) -> bool:
    import ipaddress

    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def _port_problem(port: int | None, scheme: str) -> str | None:
    if port is None:
        return None
    if isinstance(port, bool) or not isinstance(port, int):
        return "Port must be a number"
    if not 1 <= int(port) <= 65535:
        return "Port must be between 1 and 65535"
    if int(port) == DEFAULT_PORTS[scheme]:
        # Not an error, but storing it would render the same URL; normalise to None instead.
        return None
    return None


def normalize(
    scheme: str | None, host: str | None, port: int | None
) -> tuple[AgentEndpoint | None, dict[str, str]]:
    """Validate an endpoint and return (endpoint, {field: message}).

    Field keys are the JSON body names ("scheme", "host", "port") because the SPA maps them
    straight onto its inputs.
    """
    problems: dict[str, str] = {}
    scheme_text = (scheme or "").strip().lower()
    if scheme_text not in DEFAULT_PORTS:
        problems["scheme"] = "Scheme must be http or https"

    host_text = (host or "").strip()
    host_problem = _host_problem(host_text)
    if host_problem:
        problems["host"] = host_problem

    port_problem = _port_problem(port, scheme_text if scheme_text in DEFAULT_PORTS else "http")
    if port_problem:
        problems["port"] = port_problem

    if problems:
        return None, problems

    cleaned_host = host_text
    if ":" in cleaned_host and not cleaned_host.startswith("["):
        cleaned_host = cleaned_host  # stored unbracketed; render brackets it
    elif cleaned_host.startswith("["):
        cleaned_host = cleaned_host[1:-1]

    normalized_port = None if port is None else int(port)
    if normalized_port == DEFAULT_PORTS[scheme_text]:
        normalized_port = None
    return AgentEndpoint(scheme_text, cleaned_host, normalized_port), {}


def from_panel_url(panel_url: str) -> AgentEndpoint | None:
    """Interpret TUNNELGATE_PANEL_URL as an agent endpoint, or None when it is unusable.

    A URL with a path is not a base URL for a router to dial, so its path is ignored here - the
    agent appends its own paths. The scheme and port are kept exactly.
    """
    parts = urlsplit((panel_url or "").strip())
    if parts.scheme not in DEFAULT_PORTS or not parts.hostname:
        return None
    host = parts.hostname
    port = parts.port
    if port == DEFAULT_PORTS[parts.scheme]:
        port = None
    return AgentEndpoint(parts.scheme, host, port, SOURCE_ENVIRONMENT)


def _load_row(db: Session) -> AgentEndpoint | None:
    row = db.get(PanelSetting, AGENT_ENDPOINT_KEY)
    if row is None:
        return None
    try:
        data = json.loads(row.value or "")
    except (TypeError, ValueError):
        log.warning("ignoring %s: stored value is not JSON", AGENT_ENDPOINT_KEY)
        return None
    if not isinstance(data, dict):
        log.warning("ignoring %s: stored value is not an object", AGENT_ENDPOINT_KEY)
        return None
    endpoint, problems = normalize(data.get("scheme"), data.get("host"), data.get("port"))
    if endpoint is None:
        log.warning("ignoring %s: stored value is invalid (%s)", AGENT_ENDPOINT_KEY, problems)
        return None
    return AgentEndpoint(endpoint.scheme, endpoint.host, endpoint.port, SOURCE_DATABASE)


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _is_loopback(host: str | None) -> bool:
    return (host or "").strip("[]").lower() in _LOOPBACK_HOSTS


def environment_endpoint(settings: Settings | None = None) -> AgentEndpoint | None:
    """What TUNNELGATE_* says routers should dial.

    TUNNELGATE_PANEL_URL is authoritative when it names something a router can reach. It is
    loopback on the documented install shape (nginx on the same host proxy_passes to it), and a
    router on a customer network can never dial 127.0.0.1 - so a loopback value falls through
    to TUNNELGATE_PUBLIC_URL, which is the same origin by definition and is what the operator
    typed when they set the install up. Without that fallback a fresh install handed out
    "http://127.0.0.1:8080" as the agent URL and the install command could only work on the
    panel host itself. The loopback value is still returned when nothing better exists, so
    doctor can report it instead of claiming there is no setting at all.
    """
    s = settings or get_settings()
    endpoint = from_panel_url(s.panel_url)
    if endpoint is not None and not _is_loopback(endpoint.host):
        return endpoint
    public = from_panel_url(str(getattr(s, "public_url", None) or ""))
    if public is not None and not _is_loopback(public.host):
        return public
    return endpoint


def effective(db: Session | None = None, settings: Settings | None = None) -> AgentEndpoint | None:
    """The endpoint routers should dial: the database override, else the environment.

    A session is optional so read-only callers (the health page, a CLI command) do not have to
    open one; with no session the environment value is authoritative.
    """
    s = settings or get_settings()
    if db is not None:
        stored = _load_row(db)
        if stored is not None:
            return stored
    return environment_endpoint(s)


def agent_url(db: Session | None = None, settings: Settings | None = None) -> str:
    """The effective base URL, falling back to the raw setting when it cannot be parsed.

    Never raises: the installer must still be renderable when the operator typed a broken
    TUNNELGATE_PANEL_URL, and "the string they configured" is more useful than a 500.
    """
    s = settings or get_settings()
    endpoint = effective(db, s)
    if endpoint is not None:
        return endpoint.url
    return str(s.panel_url).rstrip("/")


def save(
    db: Session,
    scheme: str,
    host: str,
    port: int | None,
    *,
    user=None,
) -> tuple[AgentEndpoint | None, dict[str, str]]:
    """Persist an override. Returns (endpoint, field problems); nothing is written on error."""
    endpoint, problems = normalize(scheme, host, port)
    if endpoint is None:
        return None, problems
    payload = json.dumps(
        {"scheme": endpoint.scheme, "host": endpoint.host, "port": endpoint.port},
        sort_keys=True,
    )
    row = db.get(PanelSetting, AGENT_ENDPOINT_KEY)
    if row is None:
        row = PanelSetting(key=AGENT_ENDPOINT_KEY, value=payload)
        db.add(row)
    else:
        row.value = payload
    row.updated_at = utcnow()
    row.updated_by_id = getattr(user, "id", None)
    row.updated_by_username = getattr(user, "username", None)
    db.flush()
    return AgentEndpoint(endpoint.scheme, endpoint.host, endpoint.port, SOURCE_DATABASE), {}


def clear(db: Session) -> bool:
    """Drop the override so the environment value applies again. True when a row was removed."""
    row = db.get(PanelSetting, AGENT_ENDPOINT_KEY)
    if row is None:
        return False
    db.delete(row)
    db.flush()
    return True


def probe(url: str, timeout: float = 5.0) -> dict:
    """One unauthenticated GET against "<url>/api/v1/health" to prove a router could reach it.

    Returns the shape the SPA's test button renders: ok, checked_url, status_code, latency_ms,
    error. Never raises: an unreachable endpoint is the answer, not a failure.
    """
    import time

    import httpx

    target = url.rstrip("/") + "/api/v1/health"
    started = time.monotonic()
    try:
        response = httpx.get(target, timeout=timeout, follow_redirects=False)
    except Exception as exc:  # network, DNS, TLS, proxy - all the same answer to the operator
        return {
            "ok": False,
            "checked_url": target,
            "status_code": None,
            "latency_ms": None,
            "error": f"{type(exc).__name__}: {exc}"[:300],
        }
    elapsed = int((time.monotonic() - started) * 1000)
    body_ok = False
    try:
        data = response.json()
        body_ok = isinstance(data, dict) and data.get("status") == "ok"
    except ValueError:
        body_ok = False
    if response.status_code == 200 and body_ok:
        return {
            "ok": True,
            "checked_url": target,
            "status_code": response.status_code,
            "latency_ms": elapsed,
            "error": None,
        }
    error = None
    if response.status_code != 200:
        error = f"HTTP {response.status_code} from {target}"
    elif not body_ok:
        error = "Reached something, but it is not a TunnelGate panel (no health payload)"
    return {
        "ok": False,
        "checked_url": target,
        "status_code": response.status_code,
        "latency_ms": elapsed,
        "error": error,
    }
