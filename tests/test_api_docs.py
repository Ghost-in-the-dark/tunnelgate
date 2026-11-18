"""docs/API.md versus the routes the app actually serves.

This exists because the gap it catches was real: docs/OPERATIONS.md and docs/API.md both
promised an admin could terminate a console session, and no such route had ever been written.
A promise in the docs that no handler fulfils is worse than a missing feature - it fails at the
moment an operator most needs it.

The test reads both sides and fails in either direction:

* a route that exists but is not documented (an operator cannot discover it), and
* a documented route that does not exist (the operator follows the docs into a 404).

Routes come from the OpenAPI schema for HTTP and from the API routers for WebSockets, because
WebSocket routes never appear in the schema.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
from pathlib import Path

from app.main import app

REPO = Path(__file__).resolve().parent.parent
API_DOC = REPO / "docs" / "API.md"

_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")

# Two spellings are used in the docs: a full heading per route, and inline one-liners where a
# chapter documents several routes at once (the Users chapter does that).
_HEADING = re.compile(r"^###\s+.*?`(GET|POST|PUT|PATCH|DELETE|WS) ([^`]+)`", re.MULTILINE)
_INLINE = re.compile(r"`(GET|POST|PUT|PATCH|DELETE) (/[^`\s]*)`")
_PARAM = re.compile(r"\{[^}]+\}")


def _normalise(path: str) -> str:
    """Drop the query string and parameter NAMES: the docs say {id}, the code says {router_id}."""
    return _PARAM.sub("{}", path.split("?")[0]).rstrip("/") or "/"


def _http_routes() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for path, operations in app.openapi()["paths"].items():
        for method in operations:
            if method.upper() in _METHODS:
                found.add((method.upper(), _normalise(path)))
    return found


def _websocket_routes() -> set[tuple[str, str]]:
    """Walk the API modules directly: app.routes wraps included routers in this FastAPI."""
    found: set[tuple[str, str]] = set()
    package = importlib.import_module("app.api")
    for info in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"app.api.{info.name}")
        router = getattr(module, "router", None)
        if router is None:
            continue
        for route in getattr(router, "routes", ()):
            if type(route).__name__.endswith("WebSocketRoute"):
                found.add(("WS", _normalise(route.path)))
    return found


def _live_routes() -> set[tuple[str, str]]:
    return _http_routes() | _websocket_routes()


def _documented_routes() -> set[tuple[str, str]]:
    text = API_DOC.read_text(encoding="utf-8")
    found: set[tuple[str, str]] = set()
    for match in _HEADING.finditer(text):
        found.add((match.group(1), _normalise(match.group(2))))
    for match in _INLINE.finditer(text):
        found.add((match.group(1), _normalise(match.group(2))))
    return found


def _fmt(routes: set[tuple[str, str]]) -> str:
    return "\n".join(f"  {method:6} {path}" for method, path in sorted(routes))


def test_every_route_the_app_serves_is_documented() -> None:
    missing = _live_routes() - _documented_routes()
    assert not missing, (
        "these routes exist but docs/API.md never mentions them, so nobody can find them:\n"
        + _fmt(missing)
    )


def test_every_documented_route_actually_exists() -> None:
    phantom = _documented_routes() - _live_routes()
    assert not phantom, (
        "docs/API.md promises these routes but the app does not serve them - an operator "
        "following the docs hits a 404:\n" + _fmt(phantom)
    )
