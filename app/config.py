"""Central configuration. Every knob is an environment variable prefixed TUNNELGATE_."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parent.parent
SLUG_RE = r"^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$"


def utcnow() -> datetime:
    """Naive UTC now. Every datetime inside TunnelGate is naive UTC; the API adds a Z."""
    return datetime.now(UTC).replace(tzinfo=None)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TUNNELGATE_",
        env_file=os.environ.get("TUNNELGATE_ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------ runtime
    env: str = "dev"
    log_level: str = "info"
    db_url: str = "sqlite:///./data/tunnelgate.db"
    data_dir: Path = Path("./data")

    # ------------------------------------------------------------------ panel / http
    panel_url: str = "http://127.0.0.1:8080"
    panel_host: str = "panel.example.com"
    cookie_name: str = "tg_session"
    cookie_domain: str | None = None
    cookie_secure: bool = False
    session_ttl_minutes: int = 720
    csrf_header: str = "X-CSRF-Token"
    # Reverse-proxy support. The panel is usually published by nginx, Caddy, Traefik or a cloud
    # load balancer, so the socket peer is the proxy and the client address arrives in
    # X-Forwarded-For. Those headers are attacker-controlled unless the peer is one of ours,
    # which is why the list below is the whole trust boundary: everything else falls back to
    # the socket peer. Keeping the loopback defaults means "behind a proxy on this host works
    # out of the box, a proxy anywhere else must be named".
    trust_proxy_headers: bool = True
    trusted_proxies: list[str] = Field(default_factory=lambda: ["127.0.0.1", "::1"])
    # How many proxy hops of our own sit in front of the panel. 1 = one proxy appending XFF
    # (nginx/Caddy default). Set 2 for e.g. Cloudflare -> nginx, so the client address is read
    # one entry further from the right. Higher values move the answer left, never right.
    forwarded_allow_hops: int = 1
    # Believe "X-Forwarded-Proto: https" from a trusted peer, so a panel published behind a TLS
    # terminator marks its session cookie Secure without the operator also setting
    # TUNNELGATE_COOKIE_SECURE. Off means the scheme is whatever uvicorn saw. Never believed
    # from an untrusted peer, so a client cannot upgrade its own request.
    trust_forwarded_proto: bool = True
    login_rate_limit: int = 10
    login_rate_window_seconds: int = 900
    admin_username: str = "admin"
    admin_password: str | None = None
    cors_origins: list[str] = Field(default_factory=list)

    # ------------------------------------------------------------------ ssh
    ssh_host: str = "127.0.0.1"
    ssh_port: int = 22
    ssh_user: str = "tunnelgate"
    ssh_host_key_path: Path = Path("/etc/ssh/ssh_host_ed25519_key.pub")
    authorized_keys_path: Path = Path("./data/authorized_keys")
    authorized_keys_mode: int = 0o600
    sshd_reload_command: str = ""

    # ------------------------------------------------------------------ tunnels
    port_min: int = 20000
    port_max: int = 25000
    bind_address: str = "127.0.0.1"
    router_http_port: int = 80
    bootstrap_ttl_minutes: int = 15
    tunnel_poll_seconds: int = 5
    health_timeout_seconds: float = 3.0
    health_path: str = "/"
    stale_offline_seconds: int = 90
    require_health_for_online: bool = True

    # ------------------------------------------------------------------ reverse proxy
    proxy_driver: str = "nginx"  # nginx | caddy | none
    proxy_routes_path: Path = Path("./data/tunnelgate.routes.conf")
    proxy_reload_command: str = "nginx -s reload"
    caddy_admin_url: str = "http://127.0.0.1:2019"
    caddy_server: str = "srv0"
    subdomain_suffix: str | None = None

    # ------------------------------------------------------------------ console (web terminal)
    console_enabled: bool = True
    console_port_min: int = 25001
    console_port_max: int = 30000
    console_idle_timeout_seconds: int = 900
    console_max_sessions_per_user: int = 3
    console_max_session_seconds: int = 7200
    console_term: str = "xterm-256color"
    # The account the panel logs in as on the router. "root" is the dropbear default and the
    # only account guaranteed to exist on OpenWrt; docs/SECURITY.md explains how to create a
    # dedicated user and point this at it. Changing it makes the panel re-issue console keys,
    # because the key registration tells the installer which account to authorise.
    console_ssh_user: str = "root"
    console_connect_timeout_seconds: float = 10.0
    secret_key: str | None = None

    # ------------------------------------------------------------------ frontend
    static_dir: Path | None = None
    # Swagger UI and the OpenAPI document are development aids: an unauthenticated /api/docs
    # advertises every route and every schema to anyone who can reach the panel. None means
    # "on unless TUNNELGATE_ENV=production", which keeps the dev experience and closes the
    # hole in the default production deployment.
    docs_enabled: bool | None = None

    # ------------------------------------------------------------------ derived
    @property
    def is_sqlite(self) -> bool:
        return self.db_url.startswith("sqlite")

    @property
    def docs_visible(self) -> bool:
        """Whether /api/docs and /api/openapi.json are served (secure by default)."""
        if self.docs_enabled is not None:
            return bool(self.docs_enabled)
        return (self.env or "").strip().lower() not in ("prod", "production")

    @property
    def host_suffix(self) -> str:
        return self.subdomain_suffix or self.panel_host

    @property
    def web_dist(self) -> Path:
        return self.static_dir or (REPO_ROOT / "web" / "dist")

    def router_url(self, slug: str) -> str:
        return f"https://{slug}.{self.host_suffix}"

    @property
    def console_bind_address(self) -> str:
        """The console listener lives on loopback only; the panel dials it from the same host."""
        return "127.0.0.1"

    @property
    def console_ttl_seconds(self) -> int:
        """Router-side single-use console registration TTL (independent of install tokens)."""
        return 900

    def ensure_dirs(self) -> None:
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        Path(self.authorized_keys_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.proxy_routes_path).parent.mkdir(parents=True, exist_ok=True)


_OVERRIDE: Settings | None = None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    if _OVERRIDE is not None:
        return _OVERRIDE
    return Settings()


def set_settings_override(settings: Settings | None) -> None:
    """Used by the app factory and by tests to install an explicit Settings object."""
    global _OVERRIDE
    _OVERRIDE = settings
    get_settings.cache_clear()


def clear_settings_cache() -> None:
    global _OVERRIDE
    _OVERRIDE = None
    get_settings.cache_clear()


def reload_settings() -> Settings:
    get_settings.cache_clear()
    return get_settings()
