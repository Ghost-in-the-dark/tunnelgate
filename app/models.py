"""ORM models. Shared contract: other modules import these names."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .config import utcnow
from .db import Base

ROLES = ("admin", "operator", "viewer")

# Router lifecycle. A router counts as online only when a reverse tunnel is actually
# observable (the remote port is owned by sshd) AND a health check against LuCI passed.
STATUS_PENDING = "pending"  # created, bootstrap token issued, no key handed out yet
STATUS_AWAITING = "awaiting"  # key handed out, waiting for the first tunnel
STATUS_ONLINE = "online"  # tunnel present + health check ok
STATUS_OFFLINE = "offline"  # key exists, tunnel currently absent
STATUS_REVOKED = "revoked"  # key revoked, port released
ROUTER_STATUSES = (STATUS_PENDING, STATUS_AWAITING, STATUS_ONLINE, STATUS_OFFLINE, STATUS_REVOKED)


def _uuid() -> str:
    return uuid.uuid4().hex


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(128), default=None)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)

    sessions: Mapped[list[PanelSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class PanelSession(Base):
    """Server-side panel session. The cookie carries a random token, the DB stores its hash."""

    __tablename__ = "panel_sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    ip: Mapped[str | None] = mapped_column(String(64), default=None)
    user_agent: Mapped[str | None] = mapped_column(String(255), default=None)

    user: Mapped[User] = relationship(back_populates="sessions")


class Router(Base):
    __tablename__ = "routers"
    __table_args__ = (
        UniqueConstraint("remote_port", name="uq_routers_remote_port"),
        UniqueConstraint("slug", name="uq_routers_slug"),
        Index("ix_routers_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128))
    slug: Mapped[str] = mapped_column(String(63), index=True)
    group_name: Mapped[str | None] = mapped_column(String(64), default=None)
    integrations: Mapped[list] = mapped_column(JSON, default=list)
    os_type: Mapped[str] = mapped_column(String(16), default="linux")
    notes: Mapped[str | None] = mapped_column(Text, default=None)

    status: Mapped[str] = mapped_column(String(16), default=STATUS_PENDING)
    http_port: Mapped[int] = mapped_column(Integer, default=80)

    # tunnel coordinates (remote_port NULL means nothing is allocated)
    remote_port: Mapped[int | None] = mapped_column(Integer, default=None)
    # console coordinates: a second reverse listener on the panel host loopback that is
    # forwarded by the router's ssh client to the router's own sshd (port 22 by default).
    console_port: Mapped[int | None] = mapped_column(Integer, default=None)
    console_ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    bind_address: Mapped[str] = mapped_column(String(64), default="127.0.0.1")
    ssh_user: Mapped[str] = mapped_column(String(64), default="tunnelgate")

    # credentials. The private key never touches this database: only the public half
    # (and its fingerprint) is persisted so authorized_keys can be rendered.
    public_key: Mapped[str | None] = mapped_column(Text, default=None)
    key_fingerprint: Mapped[str | None] = mapped_column(String(128), default=None)
    key_serial: Mapped[int] = mapped_column(Integer, default=0)

    # Console (web terminal) key pair. The panel must be able to log IN to the router,
    # which is the mirror image of the tunnel key: here the SERVER owns the private half.
    # It is therefore sealed with AES-256-GCM under TUNNELGATE_SECRET_KEY before it is
    # persisted (security.encrypt_secret) and is only ever unsealed for the lifetime of a
    # single SSH handshake while opening a console session. The router only ever receives
    # the public half, installed into its own authorized_keys by the installer.
    console_public_key: Mapped[str | None] = mapped_column(Text, default=None)
    console_key_sealed: Mapped[str | None] = mapped_column(Text, default=None)
    console_key_fingerprint: Mapped[str | None] = mapped_column(String(128), default=None)
    console_key_serial: Mapped[int] = mapped_column(Integer, default=0)
    console_installed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)

    # The router's SSH host key, learned on the FIRST successful console handshake and then
    # required never to change. The console connection dials a loopback listener that the
    # router's own authenticated tunnel created, so the tunnel already establishes identity;
    # this is defence in depth for the case that matters - a router whose tunnel key was
    # stolen, or one that has been reflashed or replaced by an attacker who took the device.
    # Without it a router could present any host key and the panel would accept the session.
    # NULL means "not yet observed": the first handshake records it (trust on first use) and
    # every later handshake refuses a different value until an admin clears the pin.
    console_host_key_fingerprint: Mapped[str | None] = mapped_column(String(128), default=None)
    console_host_key_seen_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)

    # reported by the router at exchange time / heartbeat
    hostname: Mapped[str | None] = mapped_column(String(128), default=None)
    model: Mapped[str | None] = mapped_column(String(128), default=None)
    openwrt_version: Mapped[str | None] = mapped_column(String(64), default=None)
    mac: Mapped[str | None] = mapped_column(String(32), default=None)
    client_ip: Mapped[str | None] = mapped_column(String(64), default=None)
    client_version: Mapped[str | None] = mapped_column(String(32), default=None)
    uptime_seconds: Mapped[int | None] = mapped_column(Integer, default=None)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), default=None)

    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    online_since: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)

    bootstrap_tokens: Mapped[list[BootstrapToken]] = relationship(
        back_populates="router", cascade="all, delete-orphan"
    )
    runtime: Mapped[RouterRuntime | None] = relationship(
        back_populates="router", cascade="all, delete-orphan", uselist=False
    )

    @property
    def has_key(self) -> bool:
        return bool(self.public_key)

    @property
    def has_console_key(self) -> bool:
        return bool(self.console_public_key and self.console_key_sealed)

    @property
    def is_online(self) -> bool:
        return self.status == STATUS_ONLINE


class RouterGrant(Base):
    """One router a particular viewer is allowed to see. The row IS the permission.

    Why only viewers get a row here. The admin and operator roles are implicitly allowed on
    every router: they create, re-key, rotate and delete routers, and rotating a router's key
    hands the panel a working credential to it anyway, so a per-router grant on top of that
    would be theatre - it would refuse an operator a router they can already take by pressing
    rotate. The viewer role is the read-only one, and it was the accident: before this table
    existed the gate let any authenticated user, viewer included, straight into any router's
    LuCI, so one tenant's account could reach every tenant's device. Grants are how that is
    now narrowed, one explicit row at a time, and app/services/access.py is the single place
    that reads them.

    Why a new table instead of a column on users or routers. The panel has no migration
    engine: init_db is Base.metadata.create_all, so a new table appears on upgrade by itself
    while a new column on an existing table does not (that is exactly why app/cli.py
    check-schema exists). A grant also wants its own created_at/created_by_id so an access
    review can say who handed out a router and when, which a comma-separated id column could
    not carry.

    The unique constraint is part of the permission, not decoration: two rows for the same
    pair would make "is there a grant" ambiguous, and every caller would have to know which
    duplicate counts. ondelete CASCADE on both sides means deleting a user or a router takes
    its grants with it instead of leaving orphan rows that would silently come back to life
    if an id were ever reused.
    """

    __tablename__ = "router_grants"
    __table_args__ = (
        UniqueConstraint("user_id", "router_id", name="uq_router_grants_user_router"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    router_id: Mapped[str] = mapped_column(ForeignKey("routers.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), default=None)

    # foreign_keys is explicit: this table has two foreign keys into users (the grantee and
    # the admin who granted it), so SQLAlchemy cannot guess which one "user" means.
    user: Mapped[User] = relationship(foreign_keys=[user_id])
    router: Mapped[Router] = relationship()


class BootstrapToken(Base):
    """Single-use, short-lived token. Only the SHA-256 of the token is stored."""

    __tablename__ = "bootstrap_tokens"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    router_id: Mapped[str] = mapped_column(ForeignKey("routers.id", ondelete="CASCADE"), index=True)
    purpose: Mapped[str] = mapped_column(String(16), default="install")  # install | rotate
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    used_ip: Mapped[str | None] = mapped_column(String(64), default=None)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), default=None)

    router: Mapped[Router] = relationship(back_populates="bootstrap_tokens")

    @property
    def is_usable(self) -> bool:
        return self.used_at is None and self.expires_at > utcnow()


class RouterRuntime(Base):
    """Live tunnel observations. Kept out of `routers` so a status poll never rewrites a row
    the panel is also reading, and so the observation history can be dropped independently."""

    __tablename__ = "router_runtime"

    router_id: Mapped[str] = mapped_column(
        ForeignKey("routers.id", ondelete="CASCADE"), primary_key=True
    )
    tunnel_present: Mapped[bool] = mapped_column(Boolean, default=False)
    health_ok: Mapped[bool | None] = mapped_column(Boolean, default=None)
    health_checked_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    tunnel_pid: Mapped[int | None] = mapped_column(Integer, default=None)
    console_present: Mapped[bool] = mapped_column(Boolean, default=False)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    last_error: Mapped[str | None] = mapped_column(String(255), default=None)

    router: Mapped[Router] = relationship(back_populates="runtime")


class ConsoleSession(Base):
    """Audit trail for interactive shell sessions opened through the panel."""

    __tablename__ = "console_sessions"
    __table_args__ = (Index("ix_console_router_ts", "router_id", "started_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    router_id: Mapped[str] = mapped_column(ForeignKey("routers.id", ondelete="CASCADE"), index=True)
    router_name: Mapped[str | None] = mapped_column(String(128), default=None)
    user_id: Mapped[int | None] = mapped_column(Integer, default=None)
    username: Mapped[str | None] = mapped_column(String(64), default=None)
    client_ip: Mapped[str | None] = mapped_column(String(64), default=None)
    user_agent: Mapped[str | None] = mapped_column(String(255), default=None)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    close_reason: Mapped[str | None] = mapped_column(String(32), default=None)
    bytes_in: Mapped[int] = mapped_column(Integer, default=0)
    bytes_out: Mapped[int] = mapped_column(Integer, default=0)


class PanelSetting(Base):
    """Typed key/value store for panel settings an admin can change from the UI.

    Deliberately not a wide "settings" row with one column per knob: the set of editable
    settings is small, each one has its own validation and audit story, and a key/value table
    means adding the next one never needs a migration. "value" holds JSON so a setting can grow
    a shape later without another schema change; the caller validates on the way out.

    Why this exists at all: TUNNELGATE_PANEL_URL is what the installer tells a router to dial,
    and an operator who moves the panel (new hostname, TLS terminating in front, a different
    port) cannot re-run env vars on already-installed routers. A database-backed override, with
    the environment value as the fallback, is the smallest thing that makes that fixable from
    the UI while keeping "env wins on a fresh install" understandable.
    """

    __tablename__ = "panel_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by_id: Mapped[int | None] = mapped_column(Integer, default=None)
    updated_by_username: Mapped[str | None] = mapped_column(String(64), default=None)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_ts", "ts"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor_id: Mapped[int | None] = mapped_column(Integer, default=None)
    actor_username: Mapped[str | None] = mapped_column(String(64), default=None)
    action: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(16), default="ok")  # ok | denied | error
    router_id: Mapped[str | None] = mapped_column(String(32), default=None)
    router_name: Mapped[str | None] = mapped_column(String(128), default=None)
    ip: Mapped[str | None] = mapped_column(String(64), default=None)
    user_agent: Mapped[str | None] = mapped_column(String(255), default=None)
    detail: Mapped[str | None] = mapped_column(Text, default=None)
