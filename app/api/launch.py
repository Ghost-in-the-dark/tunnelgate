"""The two ends of the router launch hand-off: `/__tg/launch` (panel) and `/__tg/enter` (router).

`/__tg/launch` runs on the panel host, where the session cookie actually is. It authenticates the
operator the ordinary way, mints a single-use ticket bound to (user, router) and redirects to that
router's `/__tg/enter?t=...`.

`/__tg/enter` runs on the router host: the browser reaches it through the router vhost, which is
the entire point - the `Set-Cookie` on its response is therefore scoped to the router host, and
that is the credential the gate accepts from then on. It never needs, and never receives, the
panel session. Without a usable ticket it hands the operator to the panel login carrying the
launch path as `next`, so signing in finishes the trip instead of dropping them on the dashboard.

Threat notes for the ticket itself: it travels in a URL that ends up on the router host, so the
router sees its own ticket. That is acceptable because the ticket only ever authorises the router
it was minted for, is single-use, and dies after TUNNELGATE_LAUNCH_TICKET_TTL_SECONDS. The panel
session - the credential that is actually worth stealing - never leaves the panel origin, and the
router cookie this endpoint installs is bound to one router id and signed with the panel secret.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select

from ..config import get_settings
from ..deps import DbSession, OptionalSession, SettingsDep, client_ip
from ..errors import ApiError
from ..forwarded import request_scheme
from ..models import STATUS_REVOKED, Router, User
from ..services.access import can_access_router
from ..services.audit import record as audit_record
from ..services.launch import (
    TICKETS,
    default_target,
    issue_router_cookie,
    launch_url,
    panel_login_url,
    router_cookie_names,
    router_cookie_path,
    safe_target,
    slug_from_path,
    ticket_from_uri,
    verify_router_cookie,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/__tg", tags=["internal"])


def _redirect(url: str) -> RedirectResponse:
    """A redirect that must never be cached: it carries a single-use ticket."""
    return RedirectResponse(url, status_code=303, headers={"Cache-Control": "no-store"})


def _router_by(db, reference: str | None) -> Router | None:
    """Accept a slug (what the UI has) or an id (what the proxy has)."""
    text = (reference or "").strip()
    if not text:
        return None
    found = db.execute(select(Router).where(Router.slug == text)).scalar_one_or_none()
    if found is None:
        found = db.get(Router, text)
    return found


def _cookie_secure(request: Request, settings) -> bool:
    """Secure unless this is a plain-http deployment (development or a loopback trial)."""
    return bool(settings.cookie_secure) or request_scheme(request, settings) == "https"


def _prefers_html(request: Request) -> bool:
    """True for a browser navigation, false for an API client (including the tests).

    The two callers of /__tg/launch need different answers when signed out: a browser must be
    sent to the login FORM, an API client must get the usual 401 envelope. Accept is the only
    signal that separates them, and browsers always advertise text/html.
    """
    return "text/html" in request.headers.get("accept", "").lower()


@router.get("/launch")
def mint_launch_ticket(
    request: Request,
    db: DbSession,
    settings: SettingsDep,
    session: OptionalSession,
    reference: str | None = Query(default=None, alias="router"),
    target: str | None = Query(default=None, alias="next"),
) -> Response:
    """Panel side: turn a signed-in operator into one short-lived router ticket.

    This is a GET because it is a navigation target - the browser follows a link or a 302, so
    there is no request body and no CSRF header to send. That is safe here: minting a ticket
    grants nothing by itself, the ticket only authorises the router this operator may already
    open, it is single use and it expires.

    Signed out, it is still a navigation target: a browser that clicks "Open LuCI" on a fresh
    profile must land on the login form, not on a JSON 401 rendered as text. The redirect keeps
    the router and the wanted path, so signing in resumes the hand-off instead of dropping the
    operator on the dashboard. API callers keep the 401 they can parse.
    """
    item = _router_by(db, reference)
    if item is None or str(item.status) == STATUS_REVOKED:
        raise ApiError(404, "router_not_found", "Router not found")

    destination = safe_target(target, default=default_target(settings, item.slug))
    if session is None:
        if _prefers_html(request):
            return _redirect(panel_login_url(settings, item.slug, destination))
        raise ApiError(401, "unauthorized", "Authentication required")
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        if _prefers_html(request):
            return _redirect(panel_login_url(settings, item.slug, destination))
        raise ApiError(401, "unauthorized", "Account is disabled")

    # A ticket is a credential for this router, so minting one needs the same per-router
    # decision the gate makes. The gate does refuse the resulting cookie for an ungranted
    # viewer, so this is not the only barrier - but minting a credential that is born dead
    # wastes an audit row (luci.launch says a hand-off happened), burns a ticket store slot
    # and sends the operator on a redirect that ends in a 401. Refuse here, in the shape the
    # caller can act on: a browser navigating gets the login hand-off, an API client a 403.
    if not can_access_router(db, user, item):
        log.info(
            "launch: denied router %s for %s (role %s) - no grant",
            item.slug,
            user.username,
            user.role,
        )
        if _prefers_html(request):
            return _redirect(panel_login_url(settings, item.slug, destination))
        raise ApiError(403, "forbidden", "You do not have access to this router")

    ttl = max(1, int(settings.launch_ticket_ttl_seconds))
    ticket = TICKETS.issue(item.id, user.id, destination, ttl=float(ttl))
    audit_record(
        db,
        "luci.launch",
        actor=user,
        router=item,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        detail={"next": destination},
    )
    db.commit()
    return _redirect(launch_url(settings, item.slug, ticket))


@router.get("/enter")
def enter_router(
    request: Request,
    db: DbSession,
    settings: SettingsDep,
    session: OptionalSession,
    reference: str | None = Query(default=None, alias="router"),
    ticket: str | None = Query(default=None, alias="t"),
    target: str | None = Query(default=None, alias="next"),
) -> Response:
    """Router side: redeem a ticket (or an existing router cookie) and land on the real page.

    The response is served *through* the router vhost, so the cookie it sets is scoped to the
    router hostname and nothing else. That is the whole replacement for a domain-wide session
    cookie: one credential per device, signed, single-purpose and short lived.
    """
    # In subdomain mode the router is named by the Host header; in path mode by the first
    # path segment, which nginx copies into X-Original-URI together with the rest of the URI.
    # Either way the name comes from the proxy, never from the client's query string alone.
    host_slug = _host_slug(settings, request.headers.get("host"))
    path_slug = _path_slug(settings, request)
    named = path_slug if settings.path_routing else host_slug
    slug = (reference or named or "").strip()
    item = _router_by(db, slug) if slug else None
    # The default landing page depends on the router, so it can only be computed once we
    # know there IS one. An unknown reference must reach the login hand-off below, never
    # raise: this endpoint is unauthenticated by design (the ticket is the credential).
    landing = default_target(settings, item.slug) if item is not None else "/"
    wanted = safe_target(target, default=landing)
    if item is None or (named and named != item.slug):
        # Either we do not know this router, or the vhost/path and the request disagree about
        # which one this is. Never hand out a credential on that basis: start the login over
        # instead, which also stops a router from widening its own authority by editing its
        # Host header (or, in path mode, the prefix in front of the hand-off).
        if item is not None:
            log.warning("launch: %r does not match router %r", named, item.slug)
        return _redirect(panel_login_url(settings, item.slug if item is not None else None, wanted))

    pending = TICKETS.consume(ticket or ticket_from_uri(request.headers.get("x-original-uri")))
    if pending is not None and pending.router_id != item.id:
        log.warning("launch: ticket for %s presented on %s", pending.router_id, item.id)
        pending = None

    cookie_name, _ = router_cookie_names(settings)
    user_id: int | None = None
    if pending is not None:
        user_id = pending.user_id
        wanted = pending.target or wanted
        if settings.path_routing and wanted == "/":
            # A ticket minted before path mode was switched on (or by any caller that left
            # next empty) says "/" - which on the gateway is a 404, because the root belongs
            # to no router. Send it to the router's own prefix instead.
            wanted = default_target(settings, item.slug)
    else:
        user_id = verify_router_cookie(settings, item.id, request.cookies.get(cookie_name))

    if user_id is not None:
        user = db.get(User, user_id)
        if user is not None and user.is_active:
            value, max_age = issue_router_cookie(settings, item.id, user.id)
            response = _redirect(wanted)
            response.set_cookie(
                cookie_name,
                value,
                max_age=max_age,
                # In path mode every router shares one host, so "/" would send router A's
                # credential to router B (and, same name, overwrite it). Scope it to this
                # router's prefix; browsers keep one cookie per name and path happily.
                path=router_cookie_path(settings, item.slug),
                httponly=True,
                secure=_cookie_secure(request, settings),
                samesite="lax",
            )
            response.headers["X-Tg-Router"] = item.slug
            response.headers["X-Tg-User"] = user.username
            return response

    # No usable ticket and no live cookie: hand the operator to the panel login, which returns
    # here with a fresh ticket once they are signed in.
    return _redirect(panel_login_url(settings, item.slug, wanted))


@router.get("/enter/status")
def enter_status(
    request: Request,
    db: DbSession,
    settings: SettingsDep,
    reference: str | None = Query(default=None, alias="router"),
) -> Response:
    """Whether this browser still holds a usable router cookie (read-only, for diagnostics)."""
    item = _router_by(db, reference)
    if item is None:
        raise ApiError(404, "router_not_found", "Router not found")
    cookie_name, _ = router_cookie_names(settings)
    user_id = verify_router_cookie(settings, item.id, request.cookies.get(cookie_name))
    user = db.get(User, user_id) if user_id is not None else None
    authorized = user is not None and user.is_active
    return JSONResponse(
        {
            "authorized": authorized,
            "router": item.slug,
            "user": user.username if authorized else None,
            "cookie": cookie_name,
        },
        headers={"Cache-Control": "no-store"},
    )


def _host_slug(settings, host: str | None) -> str | None:
    from ..services.launch import host_router_slug

    return host_router_slug(settings if settings is not None else get_settings(), host)


def _path_slug(settings, request: Request) -> str | None:
    """The router named by a path-mode request's first segment, if the proxy sent one.

    nginx sets X-Original-URI to $request_uri, so this is "/<slug>/__tg/enter?t=...". A
    request without that header was not relayed by the gateway and yields None, which makes
    the caller fall through to the ordinary login hand-off rather than guessing.
    """
    if not settings.path_routing:
        return None
    raw = request.headers.get("x-original-uri")
    return slug_from_path(raw)
