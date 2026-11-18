"""Pydantic request/response contracts. The API surface is frozen here."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import RESERVED_SLUGS, SLUG_RE

Role = Literal["admin", "operator", "viewer"]
OsType = Literal["linux", "freebsd", "windows"]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


def iso(dt: datetime | None) -> str | None:
    """Naive-UTC datetime -> ISO-8601 with Z, as JSON clients expect."""
    if dt is None:
        return None
    return dt.replace(microsecond=0).isoformat() + "Z"


# ------------------------------------------------------------------ auth
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserOut(ORMModel):
    id: int
    username: str
    display_name: str | None = None
    role: str
    is_active: bool
    created_at: datetime | None = None
    last_login_at: datetime | None = None


class SessionOut(BaseModel):
    user: UserOut
    csrf_token: str
    expires_at: str | None = None


class UserCreate(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    display_name: str | None = None
    role: Role = "viewer"

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9._-]+$", v):
            raise ValueError("username may contain letters, digits, dot, underscore, hyphen")
        return v


class UserUpdate(BaseModel):
    display_name: str | None = None
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=256)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=256)


# ------------------------------------------------------------------ routers
class RouterCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    slug: str | None = Field(default=None, max_length=63)
    group_name: str | None = Field(default=None, max_length=64)
    integrations: list[str] = Field(default_factory=list)
    os_type: OsType = "linux"
    notes: str | None = None
    http_port: int = Field(default=80, ge=1, le=65535)

    @field_validator("slug")
    @classmethod
    def _slug(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip().lower()
        if not v:
            return None
        if not re.match(SLUG_RE, v):
            raise ValueError("slug must be 1-40 chars of a-z, 0-9 and single hyphens")
        if v in RESERVED_SLUGS:
            # These are the panel's own first path segments (see config.RESERVED_SLUGS): in
            # path mode a router published at <gateway>/<slug>/ would either break nginx
            # outright or shadow - or infinitely redirect around - the panel page.
            raise ValueError("slug is reserved for the panel's own paths; choose another name")
        return v


class RouterUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    group_name: str | None = Field(default=None, max_length=64)
    notes: str | None = None
    http_port: int | None = Field(default=None, ge=1, le=65535)


class RouterOut(BaseModel):
    id: str
    name: str
    slug: str
    group_name: str | None = None
    integrations: list[str] = Field(default_factory=list)
    os_type: str
    notes: str | None = None
    status: str
    online: bool
    http_port: int
    remote_port: int | None = None
    reverse_port: int | None = None
    console_port: int | None = None
    console_ready: bool = False
    bind_address: str | None = None
    url: str | None = None
    # The URL a click must follow: same host, but through /__tg/enter, which turns the panel
    # session into a router-scoped cookie. `url` stays as the plain public address (bookmarks,
    # clipboard, "is it up?" checks); `launch_url` is what "Open LuCI" links to.
    launch_url: str | None = None
    hostname: str | None = None
    model: str | None = None
    openwrt_version: str | None = None
    mac: str | None = None
    client_ip: str | None = None
    client_version: str | None = None
    uptime_seconds: int | None = None
    key_fingerprint: str | None = None
    has_key: bool = False
    installed: bool = False
    tunnel_present: bool = False
    health_ok: bool | None = None
    created_at: str | None = None
    updated_at: str | None = None
    last_seen_at: str | None = None
    last_heartbeat_at: str | None = None
    online_since: str | None = None
    bootstrap_expires_at: str | None = None


class RouterCreatedOut(RouterOut):
    """Returned exactly once: the only moment the plaintext bootstrap token exists."""

    bootstrap_token: str
    bootstrap_expires_at: str
    install_command: str
    install_script_url: str


class RotateKeyOut(BaseModel):
    bootstrap_token: str
    bootstrap_expires_at: str
    install_command: str
    install_script_url: str
    note: str = "The previous key is revoked immediately; the router re-registers itself."


class RouterListOut(BaseModel):
    items: list[RouterOut]
    total: int
    online: int
    offline: int
    pending: int


# ------------------------------------------------------------------ bootstrap
class BootstrapReport(BaseModel):
    """What the router reports about itself while exchanging the bootstrap token."""

    hostname: str | None = Field(default=None, max_length=128)
    model: str | None = Field(default=None, max_length=128)
    openwrt_version: str | None = Field(default=None, max_length=64)
    mac: str | None = Field(default=None, max_length=32)
    uptime_seconds: int | None = Field(default=None, ge=0)
    client_version: str | None = Field(default=None, max_length=32)


class SshEndpoint(BaseModel):
    host: str
    port: int
    username: str
    host_key_fingerprint: str | None = None
    host_key_type: str | None = None


class TunnelSpec(BaseModel):
    remote_port: int
    bind_address: str
    router_http_port: int
    local_target: str
    url: str | None = None


class ConsoleSpec(BaseModel):
    """Everything the router needs to accept a console connection from the panel.

    `enabled` false means the operator disabled the console for this router: the installer
    then skips the console users/keys entirely and the panel refuses to open a session.
    """

    enabled: bool = True
    ssh_user: str
    allowed_from: str
    console_port: int
    target_port: int = 22
    authorized_keys_path: str = "/etc/dropbear/authorized_keys"
    shell: str = "/bin/ash"


class BootstrapExchangeOut(BaseModel):
    router_id: str
    router_name: str
    slug: str
    ssh: SshEndpoint
    tunnel: TunnelSpec
    console: ConsoleSpec
    private_key: str
    private_key_path_hint: str
    api_token: str
    heartbeat_url: str
    key_fingerprint: str
    server_time: str


class HeartbeatIn(BaseModel):
    hostname: str | None = None
    model: str | None = None
    openwrt_version: str | None = None
    uptime_seconds: int | None = None
    mac: str | None = None
    tunnel_pid: int | None = None
    client_version: str | None = None
    # Set by the agent once it has rewritten its authorized_keys to the serial the panel
    # handed out; this is what flips a console from "not_installed" to "ready".
    console_serial: int | None = None
    console_installed: bool | None = None


class ConsoleRegistration(BaseModel):
    """The router's own authorized_keys entry for the panel, delivered once per key version.

    The router compares `serial` with the value it stores in UCI and only rewrites its
    authorized_keys file when the number moved on (rotation), which keeps heartbeat traffic
    idempotent.
    """

    serial: int
    user: str
    public_key: str
    fingerprint: str
    authorized_keys_path: str
    shell: str


class HeartbeatOut(BaseModel):
    ok: bool = True
    status: str
    server_time: str
    tunnel_present: bool
    desired: dict | None = None
    console: ConsoleRegistration | None = None


# ------------------------------------------------------------------ status / audit / meta
class StatusOut(BaseModel):
    id: str
    status: str
    phase: Literal["waiting", "connected", "reporting", "done", "offline"]
    online: bool
    tunnel_present: bool
    health_ok: bool | None = None
    last_seen_at: str | None = None
    last_heartbeat_at: str | None = None
    message: str | None = None


class AuditOut(BaseModel):
    id: int
    ts: str | None = None
    actor_username: str | None = None
    action: str
    outcome: str
    router_id: str | None = None
    router_name: str | None = None
    ip: str | None = None
    detail: str | None = None


class AuditListOut(BaseModel):
    items: list[AuditOut]
    total: int


class ConsoleStartOut(BaseModel):
    """Returned when the panel has dialled the router and is ready to hand out a ticket."""

    router_id: str
    ticket: str
    ws_path: str
    expires_at: str
    console_port: int


class ConsoleSessionOut(BaseModel):
    id: str
    router_id: str
    router_name: str | None = None
    username: str | None = None
    client_ip: str | None = None
    started_at: str | None = None
    closed_at: str | None = None
    close_reason: str | None = None
    bytes_in: int = 0
    bytes_out: int = 0


class ConsoleSessionListOut(BaseModel):
    items: list[ConsoleSessionOut]
    total: int


class AgentEndpointOut(BaseModel):
    """Where routers are told to dial, and whether that came from the env file or the UI."""

    scheme: Literal["http", "https"]
    host: str
    # None means "the scheme default" (80/443), which is also what the SPA renders when the
    # operator leaves the port box empty.
    port: int | None = None
    source: Literal["environment", "database"]


class AgentEndpointIn(BaseModel):
    """PUT body. Validation lives in app/services/agent_endpoint.py so the 422 can carry the
    per-field messages the SPA maps onto its inputs."""

    scheme: str
    host: str
    port: int | None = None


class AgentEndpointOutEnvelope(BaseModel):
    """What a save or reset returns: the effective URL plus the row behind it."""

    agent_url: str
    agent_endpoint: AgentEndpointOut


class AgentEndpointTestIn(BaseModel):
    """POST body for the probe: a candidate that is validated but never stored."""

    scheme: str
    host: str
    port: int | None = None


class AgentEndpointTestOut(BaseModel):
    """Result of the "Test connection" button. Nothing is persisted by a test."""

    ok: bool
    checked_url: str
    status_code: int | None = None
    latency_ms: int | None = None
    error: str | None = None


class ConfigOut(BaseModel):
    panel_url: str
    subdomain_suffix: str
    # How routers are published: "subdomain" (https://<slug>.<suffix>) or "path"
    # (https://<gateway>/<slug>/). The SPA needs this to explain the shape of a router URL
    # and to know which host the gateway lives on.
    route_mode: str = "subdomain"
    gateway_host: str = ""
    bootstrap_ttl_minutes: int
    poll_interval_seconds: int
    proxy_driver: str
    version: str
    # The agent-facing URL is separate from panel_url on purpose: panel_url is the panel's own
    # internal address (what nginx proxy_passes to), while agent_url is what a router dials.
    agent_url: str = ""
    agent_endpoint: AgentEndpointOut | None = None
    # False when the effective endpoint cannot be probed from the panel (no hostname at all).
    agent_endpoint_testable: bool = True


class StatsOut(BaseModel):
    routers_total: int
    routers_online: int
    routers_offline: int
    routers_pending: int
    ports_free: int
    users_total: int
    console_sessions_active: int = 0
