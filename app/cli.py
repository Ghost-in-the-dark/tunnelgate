"""Operator CLI for TunnelGate.

Everything here is meant to run from a shell on the panel host, before or beside the
service:

    .venv/bin/python -m app.cli init-db
    .venv/bin/python -m app.cli seed-admin --password '...'
    .venv/bin/python -m app.cli doctor
    .venv/bin/python -m app.cli check-schema      # prints ALTER TABLEs; there is no migration engine
    .venv/bin/python -m app.cli seed-demo         # fake routers so the UI is not empty
    .venv/bin/python -m app.cli render-proxy      # regenerate routes.conf without the API
    .venv/bin/python -m app.cli console-url <router>

Exit codes: 0 = fine, 1 = a blocking problem was found (doctor/check-schema),
2 = bad usage. Every command prints what to do next, not just what is wrong.
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import json
import os
import shutil
import socket
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import inspect as sa_inspect
from sqlalchemy import select, text

from . import __version__
from .config import Settings, get_settings
from .db import init_db, session_scope

OK = "ok"
WARN = "warn"
FAIL = "fail"

STATUS_MARK = {OK: "OK  ", WARN: "WARN", FAIL: "FAIL"}


@dataclass
class Check:
    """One doctor finding. A failing check makes the command exit non-zero."""

    name: str
    status: str
    detail: str = ""
    fix: str = ""

    @property
    def blocking(self) -> bool:
        return self.status == FAIL


class Report:
    def __init__(self) -> None:
        self.checks: list[Check] = []

    def add(self, name: str, status: str, detail: str = "", fix: str = "") -> Check:
        check = Check(name=name, status=status, detail=detail, fix=fix)
        self.checks.append(check)
        return check

    def ok(self, name: str, detail: str = "") -> Check:
        return self.add(name, OK, detail)

    def warn(self, name: str, detail: str = "", fix: str = "") -> Check:
        return self.add(name, WARN, detail, fix)

    def fail(self, name: str, detail: str = "", fix: str = "") -> Check:
        return self.add(name, FAIL, detail, fix)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.status == FAIL]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.status == WARN]

    def render(self, *, as_json: bool = False) -> str:
        if as_json:
            return json.dumps(
                {
                    "version": __version__,
                    "ok": not self.failures,
                    "checks": [
                        {
                            "name": c.name,
                            "status": c.status,
                            "detail": c.detail,
                            "fix": c.fix,
                        }
                        for c in self.checks
                    ],
                },
                indent=2,
                ensure_ascii=False,
            )
        lines = []
        for check in self.checks:
            head = STATUS_MARK[check.status] + " " + check.name
            if check.detail:
                head += ": " + check.detail
            lines.append(head)
            if check.fix and check.status != OK:
                lines.append("      -> " + check.fix)
        passed = len(self.checks) - len(self.warnings) - len(self.failures)
        lines.append("")
        lines.append(
            f"{len(self.checks)} checks: {passed} ok, {len(self.warnings)} warning(s), "
            f"{len(self.failures)} failure(s)"
        )
        return "\n".join(lines)


def _say(message: str = "") -> None:
    print(message)


def _err(message: str) -> None:
    print(message, file=sys.stderr)


def _relpath(path: object) -> str:
    try:
        resolved = Path(str(path)).expanduser().resolve()
    except OSError:  # pragma: no cover - defensive
        return str(path)
    try:
        return str(resolved.relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(resolved)


def _settings() -> Settings:
    return get_settings()


def _ensure_runtime_dirs(settings: Settings) -> None:
    settings.ensure_dirs()
    for path in (
        Path(settings.authorized_keys_path).parent,
        Path(settings.proxy_routes_path).parent,
    ):
        path.mkdir(parents=True, exist_ok=True)


def _tcp_reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _writable_dir(path: Path) -> tuple[bool, str]:
    """Probe a directory without leaving a file behind."""
    probe = path / ".tunnelgate-write-probe"
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True, ""
    except OSError as exc:
        return False, str(exc)
    finally:
        with contextlib.suppress(OSError):
            probe.unlink()


# --------------------------------------------------------------------------- init-db
def cmd_init_db(args: argparse.Namespace) -> int:
    settings = _settings()
    _ensure_runtime_dirs(settings)
    init_db()
    _say("database ready: " + _relpath(settings.db_url.replace("sqlite:///", "")))
    if settings.is_sqlite and ":memory:" not in settings.db_url:
        _say("tables: " + ", ".join(_table_names()))
    return 0


def _table_names() -> list[str]:
    from .db import engine

    if engine is None:  # pragma: no cover - init_db always sets it
        return []
    return sorted(sa_inspect(engine).get_table_names())


# ----------------------------------------------------------------------- seed-admin
def cmd_seed_admin(args: argparse.Namespace) -> int:
    from .models import User
    from .security import hash_password, password_problem

    settings = _settings()
    _ensure_runtime_dirs(settings)
    init_db()

    username = args.username or settings.admin_username
    password = args.password
    if password is None:
        if not sys.stdin.isatty():
            _err("error: --password is required when stdin is not a terminal")
            return 2
        password = getpass.getpass(f"password for {username}: ")
        confirm = getpass.getpass("repeat password: ")
        if password != confirm:
            _err("error: passwords do not match")
            return 2

    problem = password_problem(password)
    if problem:
        _err("error: " + problem)
        return 2

    with session_scope() as db:
        user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
        created = user is None
        if user is None:
            user = User(username=username, display_name="Administrator", role="admin")
            db.add(user)
        user.password_hash = hash_password(password)
        user.role = "admin"
        user.is_active = True
        db.flush()
        _say("{} user {!r} (id={})".format("created" if created else "updated", username, user.id))
        if created:
            # The agent-facing address is the one an operator can reach from their laptop;
            # panel_url is what the reverse proxy forwards to and is often loopback-only.
            from .services import agent_endpoint

            _say("log in at " + agent_endpoint.agent_url(db, settings).rstrip("/") + "/login")
    return 0


# ----------------------------------------------------------------------- check-schema
def _model_columns() -> dict[str, list[tuple[str, str]]]:
    """{table: [(column, rendered type)]} straight from the SQLAlchemy metadata."""
    from . import models  # noqa: F401  (register mappers)
    from .db import Base

    out: dict[str, list[tuple[str, str]]] = {}
    for table in Base.metadata.sorted_tables:
        out[table.name] = [(c.name, c.type.compile()) for c in table.columns]
    return out


def cmd_check_schema(args: argparse.Namespace) -> int:
    """Compare the ORM metadata with the live database and print the DDL to reconcile.

    There is no migration engine by design: the schema only ever grows, so a
    missing column is fixed with an ALTER TABLE that init-db cannot generate.
    """
    settings = _settings()
    init_db()
    from .db import engine

    assert engine is not None
    inspector = sa_inspect(engine)
    existing_tables = set(inspector.get_table_names())
    expected = _model_columns()

    missing_tables: list[str] = []
    missing_columns: list[tuple[str, str, str]] = []
    extra_columns: list[tuple[str, str]] = []

    for table_name, columns in expected.items():
        if table_name not in existing_tables:
            missing_tables.append(table_name)
            continue
        live = {c["name"] for c in inspector.get_columns(table_name)}
        wanted = {c[0] for c in columns}
        for column_name, column_type in columns:
            if column_name not in live:
                missing_columns.append((table_name, column_name, column_type))
        for column_name in sorted(live - wanted):
            extra_columns.append((table_name, column_name))

    if args.json:
        _say(
            json.dumps(
                {
                    "ok": not (missing_tables or missing_columns),
                    "db_url": settings.db_url,
                    "missing_tables": missing_tables,
                    "missing_columns": [
                        {"table": t, "column": c, "type": ty} for t, c, ty in missing_columns
                    ],
                    "extra_columns": [{"table": t, "column": c} for t, c in extra_columns],
                },
                indent=2,
            )
        )
        return 0 if not (missing_tables or missing_columns) else 1

    if not missing_tables and not missing_columns:
        _say(f"schema up to date ({len(expected)} tables)")
        if extra_columns:
            _say("")
            _say("note: columns present in the database but not in the models:")
            for table_name, column_name in extra_columns:
                _say(f"  {table_name}.{column_name}")
            _say("These are harmless, but they usually mean a rollback or a hand edit.")
        return 0

    _say("schema drift detected in " + _relpath(settings.db_url.replace("sqlite:///", "")))
    _say("")
    if missing_tables:
        _say("Missing tables - this is NOT fixable with ALTER TABLE; restore a backup or")
        _say("start a fresh database (init-db already created what it could):")
        for table_name in missing_tables:
            _say("  " + table_name)
        _say("")
    if missing_columns:
        _say("Apply these statements, then restart the panel:")
        _say("")
        for table_name, column_name, column_type in missing_columns:
            nullable, default = _column_default(table_name, column_name, column_type)
            _say(
                f"  ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type};"
                + nullable
                + default
            )
        _say("")
        _say("Back up the database first: sqlite3 <db> '.backup <db>.bak'")
        _say("Add NOT NULL only after you have values to backfill; SQLite cannot add a")
        _say("NOT NULL column without a default.")
    return 1


def _column_default(table_name: str, column_name: str, column_type: str) -> tuple[str, str]:
    """SQLite refuses to ADD COLUMN with NOT NULL and no default - render one that works."""
    from .db import Base

    table = Base.metadata.tables.get(table_name)
    column = table.columns.get(column_name) if table is not None else None
    if column is None:  # pragma: no cover - only reachable if metadata changed mid-run
        return " ", ""
    if column.nullable or not column.default:
        return " ", ""
    if column.default.is_scalar:
        value = column.default.arg
        if isinstance(value, bool):
            return " NOT NULL ", f"DEFAULT {1 if value else 0} "
        if isinstance(value, (int, float)):
            return " NOT NULL ", f"DEFAULT {value} "
        if isinstance(value, str):
            return " NOT NULL ", "DEFAULT '{}'".format(value.replace("'", "''"))
    return " ", ""


# --------------------------------------------------------------------------- doctor
def cmd_doctor(args: argparse.Namespace) -> int:
    from .services.tunnels import is_tunnel_up  # noqa: F401  (import surfaces breakage early)

    settings = _settings()
    report = Report()

    _check_runtime(settings, report)
    _check_storage(settings, report)
    _check_ssh(settings, report)
    _check_ports(settings, report)
    _check_proxy(settings, report)
    _check_console(settings, report)
    _check_frontend(settings, report)

    _say(report.render(as_json=args.json))
    return 1 if report.failures else 0


def _check_runtime(settings: Settings, report: Report) -> None:
    from . import __version__

    _check_version(report, __version__)
    if settings.env == "production":
        if settings.secret_key:
            report.ok("secret key", "configured")
        else:
            report.fail(
                "secret key",
                "TUNNELGATE_SECRET_KEY is unset in production",
                "openssl rand -base64 48 -> /etc/tunnelgate.env, then restart. Without it the "
                "app refuses to start and stored console keys cannot be decrypted.",
            )
    elif settings.secret_key:
        report.ok("secret key", "configured")
    else:
        report.warn(
            "secret key",
            "not set (dev mode)",
            "fine for development; production refuses to start without it",
        )
    if settings.cookie_secure or settings.env != "production":
        report.ok("cookie flags", f"secure={settings.cookie_secure}")
    else:
        # Not a failure any more, and it cannot be decided from configuration alone: the app
        # also sets Secure when a request arrives over HTTPS from a trusted proxy, which is how
        # a TLS-terminating deployment should behave. Forcing the flag on is only safe when the
        # panel is *never* served over plain http - a LAN deployment that forces it hands out a
        # cookie browsers silently drop.
        report.warn(
            "cookie flags",
            "TUNNELGATE_COOKIE_SECURE is false in production",
            "the cookie is still marked Secure when the request arrives over https from a "
            "trusted proxy (TUNNELGATE_TRUSTED_PROXIES). Set TUNNELGATE_COOKIE_SECURE=true only "
            "if the panel is never reachable over plain http; otherwise leave it and let the "
            "request scheme decide.",
        )


def _check_version(report: Report, version: str) -> None:
    report.ok("python", "{}.{}.{} / tunnelgate {}".format(*sys.version_info[:3], version))


def _check_storage(settings: Settings, report: Report) -> None:
    data_dir = Path(settings.data_dir)
    writable, error = _writable_dir(data_dir)
    if writable:
        report.ok("data dir", _relpath(data_dir))
    else:
        report.fail(
            "data dir",
            f"{_relpath(data_dir)} is not writable: {error}",
            "install -d -o tunnelgate -g tunnelgate -m 0750 " + str(data_dir),
        )

    if settings.is_sqlite:
        db_path = Path(settings.db_url.split("sqlite:///", 1)[-1])
        if db_path.exists():
            report.ok("database", _relpath(db_path))
        else:
            report.warn(
                "database",
                f"{_relpath(db_path)} does not exist yet",
                "run: python -m app.cli init-db",
            )
    try:
        from .db import session_scope

        with session_scope() as db:
            db.execute(text("SELECT 1"))
            tables = len(sa_inspect(db.get_bind()).get_table_names())
        report.ok("database connect", f"{tables} table(s)")
        if tables == 0:
            report.warn("database schema", "no tables", "run: python -m app.cli init-db")
    except Exception as exc:
        report.fail(
            "database connect",
            f"{type(exc).__name__}: {exc}",
            "check TUNNELGATE_DB_URL and file permissions; run init-db",
        )

    keys_path = Path(settings.authorized_keys_path)
    keys_dir_ok, keys_dir_error = _writable_dir(keys_path.parent)
    if keys_dir_ok:
        report.ok("authorized_keys dir", _relpath(keys_path.parent) + " writable")
    else:
        report.fail(
            "authorized_keys dir",
            f"{_relpath(keys_path.parent)} not writable: {keys_dir_error}",
            "install -d -o tunnelgate -g tunnelgate -m 0755 " + str(keys_path.parent),
        )
        return
    if keys_path.exists():
        mode = keys_path.stat().st_mode & 0o777
        if mode & 0o077:
            report.warn(
                "authorized_keys mode",
                f"{mode:04o} is group/world readable",
                "chmod 600 " + str(keys_path) + " (sshd ignores a loose file in StrictModes)",
            )
        else:
            report.ok("authorized_keys mode", f"{mode:04o}")
    else:
        report.ok("authorized_keys", "not created yet (written on the first router)")


def _check_ssh(settings: Settings, report: Report) -> None:
    if _tcp_reachable(settings.ssh_host, settings.ssh_port):
        report.ok("sshd reachable", f"{settings.ssh_host}:{settings.ssh_port}")
    else:
        report.fail(
            "sshd reachable",
            f"cannot connect to {settings.ssh_host}:{settings.ssh_port}",
            "the router tunnels connect to this host; without sshd nothing can be installed",
        )

    dropin = Path("/etc/ssh/sshd_config.d/tunnelgate.conf")
    if dropin.exists():
        body = dropin.read_text(encoding="utf-8", errors="replace")
        if "AllowTcpForwarding remote" in body and "GatewayPorts no" in body:
            report.ok("sshd drop-in", str(dropin))
        else:
            report.fail(
                "sshd drop-in",
                f"{dropin} exists but lacks AllowTcpForwarding remote / GatewayPorts no",
                "install -m 0644 deploy/sshd/tunnelgate.conf /etc/ssh/sshd_config.d/ && "
                "sshd -t && systemctl reload ssh",
            )
    else:
        report.warn(
            "sshd drop-in",
            f"{dropin} missing",
            "install -m 0644 deploy/sshd/tunnelgate.conf /etc/ssh/sshd_config.d/ && sshd -t "
            "&& systemctl reload ssh",
        )

    ssh_user = settings.ssh_user
    user_known = False
    try:
        import pwd

        pwd.getpwnam(ssh_user)
        user_known = True
    except (ImportError, KeyError):
        pass
    if user_known:
        report.ok("ssh user", ssh_user)
    else:
        report.warn(
            "ssh user",
            f"{ssh_user} does not exist on this host",
            f"useradd --system --home {settings.data_dir} --shell /usr/sbin/nologin {ssh_user}",
        )


def _check_ports(settings: Settings, report: Report) -> None:
    from .services import ports as ports_service

    try:
        _ensure_runtime_dirs(settings)
        init_db()
        with session_scope():
            tunnel_free = ports_service.free_port_count(ports_service.KIND_TUNNEL)
            console_free = ports_service.free_port_count(ports_service.KIND_CONSOLE)
    except Exception as exc:
        report.fail(
            "port pools",
            f"cannot read the pools: {type(exc).__name__}: {exc}",
            "fix the database first (init-db / check-schema)",
        )
        return

    total_tunnel = max(0, int(settings.port_max) - int(settings.port_min) + 1)
    if tunnel_free <= 0:
        report.fail(
            "tunnel ports",
            f"0 free of {total_tunnel}",
            "delete stale routers, or widen TUNNELGATE_PORT_MIN..MAX",
        )
    elif tunnel_free * 100 // max(1, total_tunnel) < 10:
        report.warn(
            "tunnel ports",
            f"{tunnel_free} free of {total_tunnel}",
            "the pool is nearly exhausted; widen TUNNELGATE_PORT_MIN..MAX or prune routers",
        )
    else:
        report.ok("tunnel ports", f"{tunnel_free} free of {total_tunnel}")

    if int(settings.console_port_min) <= int(settings.port_max) and int(
        settings.console_port_max
    ) >= int(settings.port_min):
        report.fail(
            "console ports",
            f"the console pool {settings.console_port_min}..{settings.console_port_max} overlaps the tunnel pool {settings.port_min}..{settings.port_max}",
            "give the pools disjoint ranges; an overlap hands the same port to two listeners",
        )
    else:
        report.ok(
            "console ports",
            f"{console_free} free of {int(settings.console_port_max) - int(settings.console_port_min) + 1}",
        )

    if settings.bind_address != "127.0.0.1":
        report.warn(
            "tunnel bind address",
            f"TUNNELGATE_BIND_ADDRESS={settings.bind_address} (not loopback)",
            "the tunnel listeners must stay on loopback; nginx is the only public listener",
        )
    else:
        report.ok("tunnel bind address", "127.0.0.1")


def _check_proxy(settings: Settings, report: Report) -> None:
    driver = (settings.proxy_driver or "none").strip().lower()
    if driver == "none":
        report.warn(
            "proxy driver",
            "none - no router vhosts are generated",
            "set TUNNELGATE_PROXY_DRIVER=nginx for a real deployment (dev uses none)",
        )
        return
    if driver not in {"nginx", "caddy"}:
        report.fail(
            "proxy driver",
            f"unknown value {settings.proxy_driver!r}",
            "use nginx, caddy or none",
        )
        return
    report.ok("proxy driver", driver)

    routes_path = Path(settings.proxy_routes_path)
    parent_ok, parent_error = _writable_dir(routes_path.parent)
    if parent_ok:
        report.ok("routes dir", _relpath(routes_path.parent) + " writable")
    else:
        report.fail(
            "routes dir",
            f"{_relpath(routes_path.parent)} not writable: {parent_error}",
            "install -d -o tunnelgate -g tunnelgate -m 0750 " + str(routes_path.parent),
        )

    if driver == "nginx":
        nginx = shutil.which("nginx") or (
            "/usr/sbin/nginx" if os.path.exists("/usr/sbin/nginx") else None
        )
        if nginx:
            report.ok("nginx", nginx)
        else:
            report.fail(
                "nginx",
                "not found in PATH",
                "apt-get install -y nginx-light; the panel only writes config, nginx serves it",
            )
        command = (settings.proxy_reload_command or "").strip()
        if command:
            binary = command.split()[0]
            if shutil.which(binary) or os.path.exists(binary):
                report.ok("reload command", command)
            else:
                report.fail(
                    "reload command",
                    f"{binary!r} is not executable",
                    "fix TUNNELGATE_PROXY_RELOAD_COMMAND or leave it empty and use the "
                    "tunnelgate-nginx-reload.path unit",
                )
            if "&&" in command or ";" in command:
                report.warn(
                    "reload command",
                    "runs a shell compound: " + command,
                    "fine with the shipped unit; it validates with nginx -t before reloading",
                )
        else:
            report.warn(
                "reload command",
                "empty - the panel writes routes.conf but never reloads nginx",
                "intended with deploy/systemd/tunnelgate-nginx-reload.path (recommended) or "
                "docker-compose nginx watcher; otherwise routes stay stale until a manual reload",
            )
    else:
        report.ok("caddy admin", settings.caddy_admin_url)
        if not _is_loopback_url(settings.caddy_admin_url):
            report.warn(
                "caddy admin",
                f"{settings.caddy_admin_url} is not on loopback",
                "the admin API is unauthenticated by design - keep it on 127.0.0.1",
            )


def _is_loopback_url(url: str) -> bool:
    from urllib.parse import urlsplit

    host = (urlsplit(str(url)).hostname or "").lower()
    return host in {"127.0.0.1", "::1", "localhost"}


def _check_console(settings: Settings, report: Report) -> None:
    if not settings.console_enabled:
        report.ok("console", "disabled")
        return
    report.ok(
        "console",
        f"ports {settings.console_port_min}..{settings.console_port_max} on {settings.console_bind_address} (loopback only - do NOT open them in the firewall)",
    )
    try:
        import paramiko  # noqa: F401
    except ImportError:
        report.fail(
            "console ssh client",
            "paramiko is not importable",
            "pip install -r requirements.txt inside the venv; console sessions cannot start "
            "without it, tunnels are unaffected",
        )
    else:
        report.ok("console ssh client", "paramiko " + _module_version("paramiko"))

    if int(settings.console_port_max) < int(settings.console_port_min):
        report.fail(
            "console port range",
            f"min {settings.console_port_min} > max {settings.console_port_max}",
            "fix TUNNELGATE_CONSOLE_PORT_MIN/MAX; no router can get a console port",
        )
    else:
        free = int(settings.console_port_max) - int(settings.console_port_min) + 1
        report.ok("console port range", f"{free} ports")

    if not settings.secret_key:
        report.warn(
            "console key storage",
            "no TUNNELGATE_SECRET_KEY: console private keys cannot be sealed",
            "generate one; console provisioning fails without it in production",
        )


def _module_version(name: str) -> str:
    try:
        from importlib.metadata import version

        return version(name)
    except Exception:  # pragma: no cover - metadata is optional
        return "unknown"


def _check_frontend(settings: Settings, report: Report) -> None:
    dist = Path(settings.web_dist)
    index = dist / "index.html"
    if index.exists():
        report.ok("web UI", _relpath(dist))
    else:
        report.warn(
            "web UI",
            f"{_relpath(dist)} has no index.html",
            "cd web && npm ci && npm run build (the app still serves /api and /health without it)",
        )


# ------------------------------------------------------------------------- seed-demo
DEMO_ROUTERS = [
    {
        "slug": "demo-office",
        "name": "Office AP (demo)",
        "group_name": "Office",
        "status": "online",
        "model": "Xiaomi AX3000T",
        "openwrt_version": "23.05.5",
        "hostname": "OpenWrt-office",
        "notes": "Demo data - safe to delete.",
    },
    {
        "slug": "demo-lab",
        "name": "Lab router (demo)",
        "group_name": "Lab",
        "status": "offline",
        "model": "GL.iNet MT3000",
        "openwrt_version": "24.10.0",
        "hostname": "OpenWrt-lab",
        "notes": "Demo data - safe to delete.",
    },
    {
        "slug": "demo-garage",
        "name": "Garage repeater (demo)",
        "group_name": "Home",
        "status": "pending",
        "notes": "Demo data - never installed, which is why it is pending.",
    },
]


def cmd_seed_demo(args: argparse.Namespace) -> int:
    """Create a couple of fake routers so the UI is not an empty shell on a fresh install."""
    from .config import utcnow
    from .models import Router, RouterRuntime
    from .services import ports as ports_service

    settings = _settings()
    _ensure_runtime_dirs(settings)
    init_db()

    created: list[str] = []
    skipped: list[str] = []
    with session_scope() as db:
        for spec in DEMO_ROUTERS:
            existing = db.execute(
                select(Router).where(Router.slug == spec["slug"])
            ).scalar_one_or_none()
            if existing is not None:
                skipped.append(spec["slug"])
                continue
            router = Router(
                name=spec["name"],
                slug=spec["slug"],
                group_name=spec.get("group_name"),
                notes=spec.get("notes"),
                os_type="openwrt",
                status=spec["status"],
                hostname=spec.get("hostname"),
                model=spec.get("model"),
                openwrt_version=spec.get("openwrt_version"),
            )
            if spec["status"] != "pending":
                # A non-pending router needs a port, otherwise the proxy renderer has
                # nothing to point nginx at and the demo vhost never appears.
                router.remote_port = ports_service.allocate_port(db) if not args.no_ports else None
                router.bind_address = settings.bind_address
                db.add(router)
                db.flush()
                db.add(
                    RouterRuntime(
                        router_id=router.id,
                        tunnel_present=spec["status"] == "online",
                        health_ok=True if spec["status"] == "online" else None,
                        health_checked_at=utcnow() if spec["status"] == "online" else None,
                        observed_at=utcnow(),
                        last_error=None if spec["status"] == "online" else "no listener observed",
                    )
                )
            else:
                db.add(router)
            db.flush()
            created.append(f"{router.slug} ({router.status})")

    for row in created:
        _say("created demo router " + row)
    for row in skipped:
        _say("skipped existing router " + row)
    if not created:
        _say("nothing to do; delete the demo routers first or use a fresh database")
    else:
        _say("")
        _say("These are fake. Remove them before going live:")
        _say("  python -m app.cli seed-demo --purge")
    return 0


def cmd_seed_demo_purge() -> int:
    from .models import Router

    with session_scope() as db:
        routers = db.execute(select(Router).where(Router.slug.like("demo-%"))).scalars().all()
        if not routers:
            _say("no demo routers found")
            return 0
        for router in routers:
            db.delete(router)
        _say(f"deleted {len(routers)} demo router(s)")
    return 0


# ------------------------------------------------------------------------ render-proxy
def cmd_render_proxy(args: argparse.Namespace) -> int:
    """Write the reverse-proxy config without going through the running panel."""
    import asyncio

    from .services.proxy import ProxyManager

    settings = _settings()
    _ensure_runtime_dirs(settings)

    async def _run() -> bool:
        manager = ProxyManager(settings)
        await manager.startup()
        changed = await manager.sync_routes()
        info = manager.info()
        if info.get("last_error"):
            raise SystemExit("proxy sync failed: " + str(info["last_error"]))
        _say(
            "{} driver: {} route(s) -> {}".format(
                info.get("driver"), info.get("routes"), _relpath(info["routes_path"])
            )
        )
        _say(
            "changed: {} ({})".format(
                "yes" if changed else "no",
                "nginx must be reloaded" if changed else "no reload needed",
            )
        )
        return changed

    try:
        asyncio.run(_run())
    except Exception as exc:
        _err(f"error: {type(exc).__name__}: {exc}")
        return 1
    return 0


# ------------------------------------------------------------------------- console-url
def cmd_console_url(args: argparse.Namespace) -> int:
    """Print the URL and the loopback helpers for a router console."""
    from .models import Router

    settings = _settings()
    init_db()
    with session_scope() as db:
        if args.router:
            query = select(Router).where(
                (Router.slug == args.router)
                | (Router.id == args.router)
                | (Router.name == args.router)
            )
            router = db.execute(query).scalar_one_or_none()
            if router is None:
                _err(f"error: no router matching {args.router!r}")
                return 1
            targets = [router]
        else:
            targets = list(db.execute(select(Router).order_by(Router.slug)).scalars().all())
            if not targets:
                _err("error: no routers yet")
                return 1

    if args.json:
        _say(
            json.dumps(
                [
                    {
                        "id": r.id,
                        "slug": r.slug,
                        "name": r.name,
                        "status": r.status,
                        "console_host": "console." + settings.host_suffix,
                        "console_port": r.console_port,
                        "luci_url": settings.router_url(r.slug),
                        "console_url": f"https://console.{settings.host_suffix}/#/routers/{r.id}",
                    }
                    for r in targets
                ],
                indent=2,
            )
        )
        return 0

    for router in targets:
        console_host = "console." + settings.host_suffix
        _say(f"{router.name} ({router.slug})")
        _say("  id:          " + router.id)
        _say("  status:      " + router.status)
        _say("  LuCI:        " + settings.router_url(router.slug))
        _say(f"  console:     https://{console_host}/#/routers/{router.id}")
        if router.console_port:
            _say(
                f"  direct ssh:  ssh -p {router.console_port} {router.ssh_user or settings.ssh_user}@127.0.0.1     # from the panel host only"
            )
        else:
            _say("  direct ssh:  (no console port allocated yet)")
        _say("")
    _say("Console ports bind 127.0.0.1 on the panel host and are never opened in the firewall.")
    return 0


# ---------------------------------------------------------------------------- argparse
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="TunnelGate operator CLI. Run as the tunnelgate user, with the venv active.",
    )
    parser.add_argument("--version", action="version", version="tunnelgate " + __version__)
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_init = sub.add_parser("init-db", help="create the database schema (idempotent)")
    p_init.set_defaults(func=cmd_init_db)

    p_admin = sub.add_parser("seed-admin", help="create or reset an admin user")
    p_admin.add_argument("--username", default=None, help="default: TUNNELGATE_ADMIN_USERNAME")
    p_admin.add_argument(
        "--password",
        default=None,
        help="prompted for when omitted; there is no default password",
    )
    p_admin.set_defaults(func=cmd_seed_admin)

    p_doctor = sub.add_parser("doctor", help="check this host before or after an install")
    p_doctor.add_argument("--json", action="store_true", help="machine-readable output")
    p_doctor.set_defaults(func=cmd_doctor)

    p_schema = sub.add_parser("check-schema", help="compare models with the live database")
    p_schema.add_argument("--json", action="store_true", help="machine-readable output")
    p_schema.set_defaults(func=cmd_check_schema)

    p_demo = sub.add_parser("seed-demo", help="insert demo routers so the UI is not empty")
    p_demo.add_argument("--no-ports", action="store_true", help="do not allocate tunnel ports")
    p_demo.add_argument(
        "--purge", action="store_true", help="delete the demo routers instead of creating them"
    )
    p_demo.set_defaults(func=cmd_seed_demo)

    p_proxy = sub.add_parser("render-proxy", help="write the proxy config from the database")
    p_proxy.set_defaults(func=cmd_render_proxy)

    p_url = sub.add_parser("console-url", help="print console and LuCI URLs for routers")
    p_url.add_argument("router", nargs="?", help="slug, id or name; omitted = every router")
    p_url.add_argument("--json", action="store_true", help="machine-readable output")
    p_url.set_defaults(func=cmd_console_url)

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    if args.command == "seed-demo" and getattr(args, "purge", False):
        return cmd_seed_demo_purge()
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        _err("aborted")
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
