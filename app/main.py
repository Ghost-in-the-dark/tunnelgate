"""Application factory: middleware, routers, lifespan (monitor + proxy sync), SPA hosting."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import Settings, get_settings, set_settings_override
from .db import init_db, session_scope
from .errors import install_error_handlers

log = logging.getLogger("tunnelgate")

# The logger names the panel's own diagnostics ("tunnelgate" and its "tunnelgate.*" children:
# proxy, monitor, console, launch, api.*). Uvicorn configures only its own "uvicorn" loggers and
# leaves the root logger bare, so without this the tree inherits root's WARNING default and every
# log.info() in app/ is silently dropped - including the operator-facing ones (created initial
# admin user, router state changes, the console-session sweep). TUNNELGATE_LOG_LEVEL was
# documented in three places before anything read it; this is what reads it.
LOG_LEVELS = {
    "critical": logging.CRITICAL,
    "error": logging.ERROR,
    "warning": logging.WARNING,
    "info": logging.INFO,
    "debug": logging.DEBUG,
}


class _StderrHandler(logging.StreamHandler):
    """A stderr sink that follows sys.stderr instead of pinning it at construction.

    logging.StreamHandler captures its stream when it is built. That is fine for a process
    that never swaps stderr, but the panel is also started by wrappers, test harnesses and
    journald bridges that replace sys.stderr after import time - the handler would then write
    to a stale (often closed) object and the diagnostics would disappear again.
    """

    def __init__(self) -> None:
        super().__init__(sys.stderr)
        self._tunnelgate_sink = True  # type: ignore[attr-defined]

    @property
    def stream(self):  # type: ignore[override]
        return sys.stderr

    @stream.setter
    def stream(self, value) -> None:
        """Accepted and ignored: StreamHandler.__init__ assigns here."""


MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Explicit CORS allow-lists. A wildcard here would mirror the caller's request back at them,
# which is exactly the combination the credentialed-request check exists to prevent.
CORS_ALLOW_METHODS = ("GET", "POST", "PATCH", "DELETE", "OPTIONS")
CORS_ALLOW_HEADERS = ("Accept", "Content-Type", "X-Requested-With")


def configure_logging(settings: Settings) -> None:
    """Apply TUNNELGATE_LOG_LEVEL to the panel's logger tree, with one stderr sink.

    Called from create_app, i.e. on every process start (systemd, docker, uvicorn, and each
    app instance a test builds). Idempotent: the sink carries a marker attribute and is only
    added when absent, so a second call cannot make every line appear twice.

    Propagation is left on so an embedding process that configures its own root handler
    (uvicorn --log-config, gunicorn, pytest's log capture) still receives the records. A plain
    deployment gets exactly one sink, because neither uvicorn nor the interpreter puts a
    handler on the root logger - which is exactly why INFO lines vanished before this existed.
    """
    name = str(getattr(settings, "log_level", "info") or "info").strip().lower()
    level = LOG_LEVELS.get(name)
    logger = logging.getLogger("tunnelgate")
    logger.setLevel(level if level is not None else logging.INFO)
    if not any(getattr(h, "_tunnelgate_sink", False) for h in logger.handlers):
        handler = _StderrHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
        logger.addHandler(handler)
    if level is None:
        # Not fatal: a typo in one env var must not stop the panel from booting, and INFO is
        # the documented default. Say so, because silently logging more than asked for (or
        # less) is how "why is my log empty" tickets start.
        log.warning("unknown TUNNELGATE_LOG_LEVEL %r: using info", name)


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

    from .services.console_ws import close_orphaned_session_rows
    from .services.monitor import run_monitor
    from .services.proxy import ProxyManager

    # Before serving anything: console rows left open by a previous process can never be
    # closed by anything else, and /api/v1/stats reads them as live shells (see the docstring).
    try:
        reaped = close_orphaned_session_rows()
    except Exception:
        log.exception("could not close console sessions left open by a previous process")
    else:
        if reaped:
            log.info("closed %d console session(s) orphaned by a previous process", reaped)

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
    configure_logging(s)

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
