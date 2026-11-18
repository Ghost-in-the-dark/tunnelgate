"""Application factory: middleware, routers, lifespan (monitor + proxy sync), SPA hosting."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import Settings, get_settings, set_settings_override
from .db import init_db, session_scope
from .errors import install_error_handlers

log = logging.getLogger("tunnelgate")

MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Explicit CORS allow-lists. A wildcard here would mirror the caller's request back at them,
# which is exactly the combination the credentialed-request check exists to prevent.
CORS_ALLOW_METHODS = ("GET", "POST", "PATCH", "DELETE", "OPTIONS")
CORS_ALLOW_HEADERS = ("Accept", "Content-Type", "X-Requested-With")


def _seed_admin() -> None:
    """Create the first admin only when the users table is empty and a password is configured."""
    from sqlalchemy import func, select

    from .models import User
    from .security import hash_password

    s = get_settings()
    with session_scope() as db:
        if db.execute(select(func.count(User.id))).scalar_one():
            return
        if not s.admin_password:
            log.warning(
                "no users exist and TUNNELGATE_ADMIN_PASSWORD is unset: the panel has no login. "
                "Set it once, or run: .venv/bin/python -m app.cli create-admin"
            )
            return
        db.add(
            User(
                username=s.admin_username,
                display_name="Administrator",
                password_hash=hash_password(s.admin_password),
                role="admin",
            )
        )
        log.info("created initial admin user %s", s.admin_username)


@asynccontextmanager
async def lifespan(app: FastAPI):
    s: Settings = get_settings()
    s.ensure_dirs()
    init_db()

    from .services.monitor import run_monitor
    from .services.proxy import ProxyManager

    stop = asyncio.Event()
    proxy = ProxyManager()
    app.state.settings = s
    app.state.proxy = proxy
    app.state.stop_event = stop
    app.state.monitor_task = None

    _seed_admin()
    try:
        await proxy.reload()
    except Exception:
        log.exception("initial proxy sync failed")

    if getattr(app.state, "use_monitor", True):
        app.state.monitor_task = asyncio.create_task(run_monitor(stop, proxy))

    try:
        yield
    finally:
        stop.set()
        task = app.state.monitor_task
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


def create_app(settings: Settings | None = None, *, use_monitor: bool = True) -> FastAPI:
    if settings is not None:
        set_settings_override(settings)
    s = get_settings()

    # The OpenAPI schema and the interactive docs describe every route, every field and every
    # auth scheme in the panel, unauthenticated. That is a gift to reconnaissance on a public
    # deployment and useless to the SPA, which talks to the typed client in web/src/lib/api.ts.
    # Settings.docs_visible resolves TUNNELGATE_DOCS_ENABLED (when set) against the environment,
    # so production closes the hole by default while development keeps the schema. The fallback
    # keeps this module importable against a config.py that predates the property.
    docs_enabled = getattr(s, "docs_visible", None)
    if docs_enabled is None:
        docs_enabled = (s.env or "").strip().lower() not in ("prod", "production")
    if not docs_enabled:
        log.info("api docs and OpenAPI schema are disabled (env=%s)", s.env)

    app = FastAPI(
        title="TunnelGate",
        version=__version__,
        description="Centralised LuCI access for OpenWrt routers over SSH reverse tunnels.",
        docs_url="/api/docs" if docs_enabled else None,
        openapi_url="/api/openapi.json" if docs_enabled else None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.use_monitor = use_monitor
    install_error_handlers(app)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "SAMEORIGIN")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        if request.url.path.startswith("/api/"):
            h.setdefault("Cache-Control", "no-store")
        return response

    cors_origins = [origin.strip() for origin in s.cors_origins if origin.strip()]
    if cors_origins:
        # allow_credentials=True plus any wildcard is the classic CORS foot-gun: with
        # allow_headers=["*"] the browser accepts a *preflight* for any header, and with a "*"
        # origin starlette reflects the caller's Origin back, so every site on the internet
        # could read authenticated responses. Neither wildcard buys anything here: the panel
        # is same-origin (Vite proxies /api in development), so this list only exists for
        # explicitly configured third-party front-ends. Fail fast instead of shipping it.
        #
        # The check runs on the *normalized* list, not the raw setting: matching the setting
        # would let `" * "` through to CORSMiddleware as `"*"` after stripping, which is the
        # exact combination this guard exists to reject.
        if "*" in cors_origins:
            raise ValueError(
                "TUNNELGATE_CORS_ORIGINS must list explicit origins: allow_credentials=True "
                "cannot be combined with a wildcard origin"
            )
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=list(CORS_ALLOW_METHODS),
            allow_headers=[*CORS_ALLOW_HEADERS, s.csrf_header],
        )
        log.info("cors: allowing credentialed requests from %s", ", ".join(cors_origins))

    from .api import (
        audit,
        auth,
        bootstrap,
        console,
        console_ws,
        gate,
        heartbeat,
        launch,
        meta,
        users,
    )
    from .api import routers as routers_api
    from .api import settings as settings_api

    for mod in (
        auth,
        routers_api,
        bootstrap,
        heartbeat,
        console,
        console_ws,
        audit,
        users,
        settings_api,
        meta,
        gate,
        launch,
    ):
        app.include_router(mod.router)

    static_dir = s.web_dist
    if static_dir.exists():
        assets = static_dir / "assets"
        if assets.exists():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa(full_path: str):
            if full_path.startswith(("api/", "__tg/")):
                return JSONResponse(
                    {"error": {"code": "not_found", "message": "Not found"}}, status_code=404
                )
            candidate = (static_dir / full_path).resolve()
            if full_path and candidate.is_file() and static_dir.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(static_dir / "index.html")

    else:

        @app.get("/", include_in_schema=False)
        async def placeholder():
            return JSONResponse(
                {
                    "service": "tunnelgate",
                    "version": __version__,
                    "ui": "not built - run: cd web && npm ci && npm run build",
                    "docs": "/api/docs",
                }
            )

    return app


app = create_app()
