"""The nginx `auth_request` subrequest: the authorization boundary for every router vhost.

nginx calls `GET /__tg/auth?router_id=...&uri=...` for each request to
`https://<slug>.<domain>` and proxies the request only on `200`. Two credentials are accepted:

* the panel session cookie - the normal path when the panel cookie happens to cover this host
  (`TUNNELGATE_COOKIE_DOMAIN`), which is why the old flow still works where it used to;
* the router cookie issued by `/__tg/enter` - scoped to this router host, signed with the panel
  secret and bound to exactly one router id. This is the credential a correct deployment uses,
  and it is why the gate no longer requires a domain-wide session cookie to exist at all.

The router id comes from the vhost, never from the client.

Fail closed is the whole design: anything other than a clean 200 makes nginx deny. A panel crash
therefore denies access rather than opening it, and an unknown router id is a plain 401 - the
gate must not become a router-existence oracle for an unauthenticated caller.
"""

from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse

from ..deps import DbSession, OptionalSession, SettingsDep, client_ip
from ..models import Router, User
from ..services.audit import record as audit_record
from ..services.launch import router_cookie_names, verify_router_cookie

log = logging.getLogger(__name__)

router = APIRouter(prefix="/__tg", tags=["internal"])

# One audit row per (user, router, minute): a LuCI page pulls dozens of subresources and the log
# must answer "who looked at which router", not "how many PNGs did the browser fetch".
LUCI_AUDIT_WINDOW_SECONDS = 60.0
LUCI_AUDIT_MAX_ENTRIES = 4096
_LUCI_AUDIT: dict[tuple[int, str], float] = {}


def _should_audit(user_id: int, router_id: str, now: float) -> bool:
    key = (user_id, router_id)
    last = _LUCI_AUDIT.get(key)
    if last is not None and now - last < LUCI_AUDIT_WINDOW_SECONDS:
        return False
    _LUCI_AUDIT[key] = now
    # Bound the dict without a background sweeper. Pruning only entries older than the window
    # is not enough on its own: a burst of distinct (user, router) pairs inside one window is
    # all "fresh", so the cap has to evict the oldest survivors too, or the dict grows forever.
    if len(_LUCI_AUDIT) > LUCI_AUDIT_MAX_ENTRIES:
        cutoff = now - LUCI_AUDIT_WINDOW_SECONDS
        for stale in [k for k, ts in _LUCI_AUDIT.items() if ts < cutoff]:
            _LUCI_AUDIT.pop(stale, None)
        overflow = len(_LUCI_AUDIT) - LUCI_AUDIT_MAX_ENTRIES
        if overflow > 0:
            for stale in list(_LUCI_AUDIT)[:overflow]:
                _LUCI_AUDIT.pop(stale, None)
    return True


def _deny(message: str = "Authentication required") -> Response:
    """A 401 with a body nginx will not pass through; the SPA turns it into a login redirect."""
    return JSONResponse(
        status_code=401,
        content={"error": {"code": "not_authenticated", "message": message}},
        headers={"Cache-Control": "no-store"},
    )


def _router_cookie_value(request: Request, settings) -> str | None:
    """The router-host credential as the proxy presents it.

    The proxy copies exactly one cookie into a dedicated header (`$cookie_tg_luci`), because
    nginx cannot hand a cookie to an auth subrequest any other way. Reading the header FIRST
    and the cookie jar second keeps both routes working: the header on a real deployment, the
    cookie when the panel is reached directly (tests, a single-host trial without a vhost).
    """
    name, header = router_cookie_names(settings)
    return request.headers.get(header) or request.cookies.get(name)


@router.get("/auth")
async def auth_request(
    request: Request,
    db: DbSession,
    settings: SettingsDep,
    session: OptionalSession,
    router_id: str | None = Query(default=None),
    uri: str | None = Query(default=None),
) -> Response:
    """200 + X-Tg-* headers when this caller may read this router; 401 otherwise."""
    user: User | None = None
    via_router_cookie = False

    if session is not None:
        user = db.get(User, session.user_id)
        if user is not None and not user.is_active:
            return _deny("Account is disabled")

    if user is None:
        # The panel session is absent (the usual case: it is scoped to the panel host). Fall
        # back to the router-scoped cookie the launch endpoint installed on THIS host.
        if not router_id:
            return _deny("No router in this request")
        user_id = verify_router_cookie(settings, router_id, _router_cookie_value(request, settings))
        if user_id is None:
            return _deny()
        user = db.get(User, user_id)
        if user is None or not user.is_active:
            return _deny("Account is disabled")
        via_router_cookie = True

    if not router_id:
        return _deny("No router in this request")
    item = db.get(Router, router_id)
    if item is None:
        # Deliberately the same answer as "not authenticated": an unauthenticated caller must not
        # learn which router ids exist by comparing status codes.
        log.info("gate: unknown router id %s requested by %s", router_id, user.username)
        return _deny()

    if _should_audit(user.id, item.id, time.monotonic()):
        audit_record(
            db,
            "luci.open",
            actor=user,
            router=item,
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
            detail={
                "uri": (uri or "/")[:255],
                # How this request authenticated matters when reading the log later: a
                # router-cookie open means the router host held a credential of its own.
                "credential": "router-cookie" if via_router_cookie else "panel-session",
            },
        )
        db.commit()

    return Response(
        content=b"",
        status_code=200,
        headers={
            "X-Tg-User": user.username,
            "X-Tg-Role": user.role,
            "X-Tg-Router": item.slug,
            "Cache-Control": "no-store",
        },
    )
