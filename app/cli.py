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
import subprocess
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
    _check_ss(report)
    _check_storage(settings, report)
    _check_ssh(settings, report)
    _check_ports(settings, report)
    _check_proxy(settings, report)
    _check_launch(settings, report)
    _check_slug_namespace(settings, report)
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


def _check_ss(report: Report) -> None:
    """Is 'ss' installed? It is the only source of truth for "is the tunnel up".

    The monitor asks the kernel for the listening sockets with a single ss call and the
    routers' status is derived from that answer, not from the heartbeat. Without ss the
    host is unobservable by design (tunnels.py returns an empty map) and every router
    sits at awaiting/offline no matter how healthy it is - so this is a blocking check,
    not a warning. python:slim and minimal images ship without iproute2.
    """
    if shutil.which("ss"):
        report.ok("socket inventory", "ss")
        return
    report.fail(
        "socket inventory",
        "'ss' is not installed, so the panel cannot see any tunnel",
        "apt-get install -y iproute2 (the monitor reads 'ss -Hltnp'; without it every router "
        "stays awaiting/offline and api/health reports status ok while nothing is online)",
    )


def _check_version(report: Report, version: str) -> None:
    report.ok("python", "{}.{}.{} / tunnelgate {}".format(*sys.version_info[:3], version))


def _dir_fix(path: Path, mode: str) -> str:
    """The ownership one-liner, for both deployment shapes.

    Bare metal owns these directories as the 'tunnelgate' user; the container image runs
    as a fixed uid 10001, so 'install -d -o tunnelgate' silently does the wrong thing
    there and the panel keeps failing to write. Name both forms rather than guessing
    which deployment the operator is running.
    """
    return f"install -d -o tunnelgate -g tunnelgate -m {mode} {path} (container: -o 10001 -g 10001)"


def _db_access_hint(exc: BaseException) -> str:
    """The fix line for "cannot open the database": permission, or schema.

    A PermissionError here is almost always the documented uid mismatch rather than a
    missing schema - the panel runs as one uid and the data directory is owned by another
    (container uid 10001 vs the host user, or doctor invoked with sudo/another account).
    Saying "run init-db" at that point sends the operator down the wrong path.
    """
    if isinstance(exc, PermissionError):
        return (
            "the user running doctor cannot read the data directory; run it as the "
            "tunnelgate service user, or chown the data dir to the uid the panel runs as "
            "(container: 10001) - see docs/OPERATIONS.md"
        )
    return "fix the database first (init-db / check-schema)"


def _exists(path: Path) -> bool:
    """Path.exists() that answers False instead of raising on EACCES.

    stat() needs execute permission on every parent directory, so a doctor run as the
    wrong user (root-owned 0750 data dir, or the reverse: the tunnelgate user inside a
    container whose mount is owned by the host uid) used to traceback here before
    reporting anything. "Cannot see it" is reported by the data-dir check above; this
    one must not replace the whole report with a stack trace.
    """
    try:
        return path.exists()
    except OSError:
        return False


def _check_storage(settings: Settings, report: Report) -> None:
    data_dir = Path(settings.data_dir)
    writable, error = _writable_dir(data_dir)
    if writable:
        report.ok("data dir", _relpath(data_dir))
    else:
        report.fail(
            "data dir",
            f"{_relpath(data_dir)} is not writable: {error}",
            _dir_fix(data_dir, "0750"),
        )

    if settings.is_sqlite:
        db_path = Path(settings.db_url.split("sqlite:///", 1)[-1])
        if _exists(db_path):
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
            _dir_fix(keys_path.parent, "0755"),
        )
        return
    if _exists(keys_path):
        try:
            mode = keys_path.stat().st_mode & 0o777
        except OSError:
            mode = 0
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
    if _exists(dropin):
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


def _check_slug_namespace(settings: Settings, report: Report) -> None:
    """Do any existing router slugs collide with the panel's own paths?

    Creation refuses a reserved slug (config.RESERVED_SLUGS), but a panel upgraded from an
    older build can already own one, and in path mode the collision is not cosmetic:

      * "api" / "assets" - nginx declares location /api/ and /assets/ in the panel vhost, so
        the rendered routes.conf produces a duplicate location and nginx -t rejects the WHOLE
        config: the panel can no longer push routes at all;
      * "login" and friends - the router location shadows the panel page; for /login the
        result is an unbreakable 308 -> 401 -> 302 /login?router=login loop, i.e. the operator
        is locked out of the panel and cannot rename it through the UI.

    Only path mode renders those locations, so subdomain deployments are unaffected even
    though the slug itself is just as undesirable there (a mode switch would hit it later).
    """
    if not settings.path_routing:
        return
    from .config import RESERVED_SLUGS
    from .models import Router

    try:
        _ensure_runtime_dirs(settings)
        init_db()
        with session_scope() as db:
            clashes = sorted(
                slug
                for (slug,) in db.execute(select(Router.slug)).all()
                if str(slug) in RESERVED_SLUGS
            )
    except Exception as exc:
        report.warn(
            "slug namespace",
            f"cannot check router slugs: {type(exc).__name__}: {exc}",
            _db_access_hint(exc),
        )
        return

    if not clashes:
        report.ok("slug namespace", "no router slug shadows a panel path")
        return
    breaking = sorted(s for s in clashes if s in {"api", "assets"})
    detail = ", ".join(clashes)
    if breaking:
        report.fail(
            "slug namespace",
            f"router slug(s) {detail} collide with the panel's own locations",
            f"rename {', '.join(breaking)} before the next route render, or nginx -t will "
            "reject the whole config and no route update can be published. Set the router's "
            "name in the panel; the slug follows the name at creation and is immutable, so "
            "the affected router has to be re-created",
        )
    else:
        report.fail(
            "slug namespace",
            f"router slug(s) {detail} shadow a panel page",
            "re-create the affected router under another name: /" + clashes[0] + "/ would be "
            "served by the router instead of the panel, and for /login that is a redirect "
            "loop that locks you out of the panel",
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
            _db_access_hint(exc),
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


def _nginx_modules(nginx: str) -> str | None:
    """Return the configure arguments of an nginx binary, or None.

    nginx -V writes to stderr and exits 0; a wrapper that prints nothing is
    treated as unknown rather than as "no modules", so a doctor run can never
    turn a probe failure into a false failure of the deployment.
    """
    try:
        proc = subprocess.run(  # fixed argv, no shell
            [nginx, "-V"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = (proc.stderr or "") + (proc.stdout or "")
    if "configure arguments" not in text:
        return None
    return text


def _check_sub_filter(nginx: str, report: Report) -> None:
    """Fail when path routing is on but this nginx cannot rewrite HTML.

    Path mode is the only mode that needs sub_filter: LuCI emits root-absolute
    URLs and they must be moved under /<slug>/. A stock "nginx" build carries
    the module, a slim one may not, and the breakage is invisible until a
    router page loads with broken CSS and dead links - so it is checked here
    rather than discovered there.
    """
    modules = _nginx_modules(nginx)
    if modules is None:
        report.warn(
            "sub_filter module",
            f"could not read the module list from {nginx} -V",
            "path routing rewrites LuCI's HTML with sub_filter; check it by hand with "
            "nginx -V 2>&1 | grep -o with-http_sub_module",
        )
        return
    if "with-http_sub_module" in modules:
        report.ok("sub_filter module", "with-http_sub_module")
    else:
        report.fail(
            "sub_filter module",
            f"{nginx} was built without --with-http_sub_module",
            "path routing rewrites LuCI's absolute links with sub_filter; install the distro "
            "'nginx' package (nginx-common + nginx), not a minimal build, or switch to "
            "TUNNELGATE_ROUTE_MODE=subdomain",
        )


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
    if driver == "caddy" and settings.path_routing:
        # Caught here rather than at the first sync: the proxy manager would raise on every
        # reconcile, so every router route would silently stay unpublished.
        report.fail(
            "proxy driver",
            "TUNNELGATE_ROUTE_MODE=path with TUNNELGATE_PROXY_DRIVER=caddy",
            "path routing rewrites LuCI's HTML and scopes cookies per prefix, which only the "
            "nginx renderer does; use nginx, or switch back to subdomain routing",
        )
    else:
        report.ok("proxy driver", driver)

    routes_path = Path(settings.proxy_routes_path)
    parent_ok, parent_error = _writable_dir(routes_path.parent)
    if parent_ok:
        report.ok("routes dir", _relpath(routes_path.parent) + " writable")
    else:
        report.fail(
            "routes dir",
            f"{_relpath(routes_path.parent)} not writable: {parent_error}",
            _dir_fix(routes_path.parent, "0750"),
        )

    if driver == "nginx":
        nginx = shutil.which("nginx") or (
            "/usr/sbin/nginx" if os.path.exists("/usr/sbin/nginx") else None
        )
        if nginx:
            report.ok("nginx", nginx)
            if settings.path_routing:
                _check_sub_filter(nginx, report)
                _check_routes_include(settings, report, nginx)
        else:
            # A warning, not a failure: in the supported container deployment nginx is a
            # SEPARATE service (docker-compose.yml has a tunnelgate-nginx container), so the
            # panel image legitimately has no nginx binary - and deploy/README.md documents
            # running doctor via docker exec. On bare metal this is also not fatal to the
            # panel, which only writes config; it just means nothing is serving it yet.
            report.warn(
                "nginx",
                "no nginx binary in this process's PATH",
                "fine when nginx runs in another container or on the host (the panel only "
                "writes config, it never executes nginx for routing); otherwise install "
                "nginx-light and check that TUNNELGATE_PROXY_ROUTES_PATH is included by it",
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


def _check_routes_include(settings: Settings, report: Report, nginx: str) -> None:
    """Is routes.conf included where the layout requires, and does nginx accept the result?

    Path mode has two layouts and they differ in nothing more consequential than this
    include. Separate: routes.conf declares its own server{} block, so it belongs in the
    *http* context. Merged: it declares locations only, so it belongs INSIDE the panel server
    block - in the http context nginx rejects the bare "location" directives with
    "location directive is not allowed here" and the router paths never appear.

    Rather than guess from the file alone, this asks nginx itself: the rendered config either
    parses (and the operator is fine) or it does not, and nginx names the file and line that
    broke. That covers the reverse mistake too - a separate-layout file included inside a
    server block is equally illegal - and it needs no knowledge of where the operator keeps
    their vhosts.
    """
    routes_path = Path(settings.proxy_routes_path)
    if not _exists(routes_path):
        return  # _check_launch already reports a missing render
    code, output = _run_quiet([nginx, "-t"])
    if code == 0:
        report.ok("routes include", "nginx accepts the rendered config")
        return
    if _nginx_test_did_not_reach_the_config(output):
        # "nginx -t" is a full start-up: it parses the config, then tries to open the pid file
        # and temp paths. Run as the unprivileged service account, it dies on those with
        # "open() /run/nginx.pid failed (13: Permission denied)" and exits non-zero - which
        # says nothing about the include. Blaming the include there sends an operator to move
        # a correct include and leaves the real reason (who ran doctor) unmentioned.
        report.warn(
            "routes include",
            "the config parses, but nginx -t could not finish: " + _nginx_blocking_error(output),
            "re-run doctor as root (sudo -u root ... or just sudo), or grant this user write "
            "access to nginx's pid file and temp paths; the include placement itself is fine",
        )
        return
    detail = " | ".join(line.strip() for line in output.splitlines() if line.strip())[:400]
    if settings.gateway_merged:
        fix = (
            "in the merged layout routes.conf holds locations only: include it INSIDE the "
            "panel server block (server_name " + settings.gateway + "), not in the http context"
        )
    else:
        fix = (
            "in the separate layout routes.conf declares its own server{} block: include it "
            "from the *http* context (deploy/nginx/tunnelgate.conf does), not inside a server"
        )
    report.fail("routes include", "nginx rejects the rendered config: " + detail, fix)


def _nginx_test_did_not_reach_the_config(output: str) -> bool:
    """Did "nginx -t" reject the CONFIG, or fail before judging it?

    nginx prints "the configuration file ... syntax is ok" only once parsing has succeeded, so
    that line plus a non-zero exit means the config is fine and nginx fell over on a runtime
    prerequisite (unwritable pid file, missing temp dir, privileged port). This distinction
    matters because the fix is completely different - and because doctor is normally run as
    the same unprivileged account that runs the panel.
    """
    lowered = output.lower()
    return "syntax is ok" in lowered or "test is successful" in lowered


def _nginx_blocking_error(output: str) -> str:
    """The last [emerg] line of a failed nginx -t, which is the reason it stopped."""
    for line in reversed([ln.strip() for ln in output.splitlines() if ln.strip()]):
        if "[emerg]" in line or "[alert]" in line:
            return line[:300]
    return " | ".join(ln.strip() for ln in output.splitlines() if ln.strip())[:300]


def _run_quiet(argv: list[str]) -> tuple[int, str]:
    """Run a command, returning (exit code, combined output). Never raises."""
    import subprocess

    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover - broken install
        return 1, f"{type(exc).__name__}: {exc}"
    return completed.returncode, (completed.stdout or "") + (completed.stderr or "")


def _check_launch(settings: Settings, report: Report) -> None:
    """Can a browser actually get from this panel into a router's LuCI?

    "Public route" is https://<slug>.<suffix> - a host the browser holds no panel cookie for -
    so the way in is a one-time ticket redeemed at /__tg/enter, which installs a cookie scoped
    to that router host. Two things break that quietly, and both look identical from the UI
    (an endless bounce through /login):

      * router hostnames that cannot exist, e.g. an IP or a bare name as the suffix;
      * proxy config rendered before the hand-off existed, so the vhost has no /__tg/enter and
        its auth subrequest does not carry the router cookie.

    The second one is the common upgrade mistake, and it is only visible in the generated
    files, which is exactly why it belongs here rather than in the UI.
    """
    from .services.launch import cookie_header_name

    raw_mode = str(getattr(settings, "route_mode", "") or "").strip().lower()
    if raw_mode and raw_mode not in {"subdomain", "path"}:
        report.warn(
            "route mode",
            f"TUNNELGATE_ROUTE_MODE={raw_mode!r} is not 'subdomain' or 'path'",
            "the panel falls back to subdomain routing; fix or unset the variable",
        )

    suffix = str(settings.host_suffix or "").strip()
    if settings.path_routing:
        # Path mode publishes everything on ONE name, so what has to be usable is that name -
        # not "<slug>.<suffix>". An IP still fails here, but for the opposite reason: it would
        # be the gateway host itself, and a certificate for a bare IP is not obtainable.
        gateway = str(settings.gateway or "").strip()
        problem = _gateway_problem(gateway)
        if problem:
            report.fail(
                "router hostnames",
                f"gateway host {gateway!r} is not a usable host: {problem}",
                "set TUNNELGATE_GATEWAY_HOST to the public name routers are published under "
                "(for example gate.example.com); in path mode every router is "
                "https://<gateway>/<slug>/ and no wildcard DNS or certificate is needed",
            )
        else:
            report.ok("router hostnames", f"{gateway}/<slug>/")

        panel = str(settings.panel_host or "").strip(".").lower()
        if settings.gateway_merged:
            # Supported, but not free: same scheme+host+port means a path is not an origin
            # boundary, so a hostile router page runs in the panel's origin. The layout also
            # changes where routes.conf has to be included - locations are illegal in the
            # http context and a server{} block is illegal inside a server block, so nginx
            # rejects the config outright rather than failing quietly (verified on 1.26.3).
            # Cheap to get wrong, cheap to detect: _check_routes_include runs nginx -t.
            report.warn(
                "gateway host",
                f"{gateway} is the panel's own host: routers share the panel origin",
                "keep the gateway on a separate name if you have one - see docs/SECURITY.md "
                "'Path mode on the panel's own host' for what the shared origin costs. In this "
                "layout routes.conf holds locations only and must be included INSIDE the panel "
                "server block (doctor checks that under 'routes include')",
            )
        else:
            report.ok("gateway host", f"{gateway} (panel on {panel or 'unset'})")
    else:
        problem = _hostname_problem(suffix)
        if problem:
            report.fail(
                "router hostnames",
                f"<slug>.{suffix} is not a usable host: {problem}",
                "set TUNNELGATE_SUBDOMAIN_SUFFIX to a real domain (router.example.com gives "
                "lab.router.example.com), or unset it and point TUNNELGATE_PANEL_HOST at the "
                "panel; with no usable domain at all, set TUNNELGATE_ROUTE_MODE=path and "
                "publish routers under one gateway host instead",
            )
        else:
            report.ok("router hostnames", f"<slug>.{suffix}")

    if settings.cookie_domain:
        report.warn(
            "cookie scope",
            f"TUNNELGATE_COOKIE_DOMAIN={settings.cookie_domain} widens the panel session to "
            "every router host",
            "unset it: /__tg/enter gives each router its own short-lived cookie, so the "
            "domain-wide session cookie is no longer needed (docs/SECURITY.md section 6)",
        )

    # A loopback panel_url is the documented shape behind a TLS terminator, and it is fine
    # for proxy_pass - but every redirect this panel writes names the browser's origin, so
    # without an explicit public origin a router visitor is sent to http://127.0.0.1:8080.
    if not str(getattr(settings, "public_url", None) or "").strip():
        from urllib.parse import urlsplit as _urlsplit

        host = (_urlsplit(str(settings.panel_url)).hostname or "").lower()
        if host in {"127.0.0.1", "::1", "localhost"}:
            report.warn(
                "public origin",
                f"TUNNELGATE_PANEL_URL={settings.panel_url} is loopback, and "
                "TUNNELGATE_PUBLIC_URL is unset, so login redirects name 127.0.0.1",
                "set TUNNELGATE_PUBLIC_URL to the https origin operators use "
                f"(https://{settings.panel_host}); a browser cannot reach 127.0.0.1 on the "
                "panel host",
            )

    driver = (settings.proxy_driver or "none").strip().lower()
    if driver == "caddy":
        report.warn(
            "launch config",
            "caddy keeps routes in memory, so they cannot be checked from here",
            "after upgrading, run: python -m app.cli render-proxy   # re-pushes every route "
            "with /__tg/enter",
        )
        return
    if driver != "nginx":
        return

    from .services.proxy import auth_snippet_path

    routes_path = Path(settings.proxy_routes_path)
    snippet_path = auth_snippet_path(routes_path)
    absent = [path for path in (routes_path, snippet_path) if not _exists(path)]
    if absent:
        report.warn(
            "launch config",
            ", ".join(_relpath(path) for path in absent) + " not written yet",
            "start the panel once, or run: python -m app.cli render-proxy",
        )
        return

    header = cookie_header_name(settings.router_cookie_name)
    routes_text = _read_text(routes_path)
    stale = []
    if "/__tg/enter" not in routes_text:
        stale.append("the router vhosts have no /__tg/enter, so Public route loops via /login")
    if settings.path_routing:
        # Path mode has no per-router vhost and no shared snippet: the auth location is part
        # of the same file, so both facts are checked in routes.conf.
        if header not in routes_text or "/__tg/auth" not in routes_text:
            stale.append(
                f"the gateway auth location never forwards {header}, so the gate cannot see a "
                "router cookie"
            )
    elif header not in _read_text(snippet_path):
        stale.append(
            f"the auth subrequest never forwards {header}, so the gate cannot see a router cookie"
        )
    if stale:
        report.fail(
            "launch config",
            "; ".join(stale),
            "python -m app.cli render-proxy   # then reload nginx (the .path unit does it)",
        )
    else:
        report.ok("launch config", "/__tg/enter is served and the gate sees the router cookie")


def _gateway_problem(host: str) -> str:
    """Why `host` is wrong as the single gateway name in path mode, or "" when usable.

    Stricter than `_hostname_problem` in one respect: a bare IP is rejected outright, because
    this host has to hold a real certificate. Public CAs issue for names, not for 192.168.x.x.
    """
    if not host:
        return "it is empty"
    if any(ch.isspace() for ch in host):
        return "it contains whitespace"
    if ":" in host or host.replace(".", "").isdigit():
        return "it is an IP address"
    if "." not in host:
        return "it has no dot, so no certificate authority would issue for it"
    for label in host.split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return f"{label!r} is not a valid DNS label"
    return ""


def _hostname_problem(host: str) -> str:
    """Why <slug>.<host> would not resolve, or "" when the name looks usable."""
    if not host:
        return "it is empty"
    if any(ch.isspace() for ch in host):
        return "it contains whitespace"
    candidate = host[2:] if host.startswith("*.") else host
    if ":" in candidate or candidate.replace(".", "").isdigit():
        return "it is an IP address"
    if "." not in candidate:
        return "it has no dot, so <slug>.<host> would not resolve"
    for label in candidate.split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return f"{label!r} is not a valid DNS label"
    return ""


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


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
    if _exists(index):
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
    from .services.launch import launch_url

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
                        "launch_url": launch_url(settings, r.slug),
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
        # The address that works from a browser. The plain LuCI URL above only authenticates
        # a browser that already holds that router's cookie; this one installs it.
        _say("  open:        " + launch_url(settings, router.slug))
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
