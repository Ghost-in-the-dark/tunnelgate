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

    app = FastAPI(
        title="TunnelGate",
        version=__version__,
        description="Centralised LuCI access for OpenWrt routers over SSH reverse tunnels.",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
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

    if s.cors_origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=s.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    from .api import audit, auth, bootstrap, console, console_ws, gate, heartbeat, meta, users
    from .api import routers as routers_api

    for mod in (
        auth,
        routers_api,
        bootstrap,
        heartbeat,
        console,
        console_ws,
        audit,
        users,
        meta,
        gate,
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
