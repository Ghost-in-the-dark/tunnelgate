"""Port pool allocation for the two loopback listener pools.

Both pools are owned by sshd on the panel host (see ARCHITECTURE.md section 8):

* tunnel   - port_min..port_max: one reverse listener per router, feeding LuCI.
* console  - console_port_min..console_port_max: a second reverse listener that feeds the
             router own dropbear.

SQLite has no advisory locks and two API requests can allocate concurrently inside the same
process, so the candidate search is serialised with a process-wide threading.Lock. The lock is
held only while a candidate is chosen; the caller persists the port in the same transaction, and
the UNIQUE constraint on routers.remote_port is the last line of defence across processes. On top
of the database, port_free_in_os refuses a port that some other process already holds, so a stray
listener can never be handed to a router.
"""

from __future__ import annotations

import logging
import socket
import threading

from sqlalchemy import Column, or_, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import session_scope
from ..errors import ApiError
from ..models import Router

log = logging.getLogger(__name__)

KIND_TUNNEL = "tunnel"
KIND_CONSOLE = "console"

_ALLOCATE_LOCK = threading.Lock()


def _pool(kind: str) -> tuple[int, int, Column]:
    """Return (low, high, router column) for a pool kind."""
    s = get_settings()
    if kind == KIND_TUNNEL:
        return int(s.port_min), int(s.port_max), Router.remote_port
    if kind == KIND_CONSOLE:
        return int(s.console_port_min), int(s.console_port_max), Router.console_port
    raise ValueError(f"unknown port pool kind: {kind!r}")


def used_ports(db: Session, kind: str = KIND_TUNNEL) -> set[int]:
    """Ports already recorded on a router row (allocated, whatever the router status is)."""
    _, _, column = _pool(kind)
    rows = db.execute(select(column).where(column.is_not(None))).scalars().all()
    return {int(p) for p in rows}


def port_free_in_os(port: int, *, host: str | None = None) -> bool:
    """True when nothing on this host currently holds the port.

    SO_REUSEADDR is set deliberately: a socket left in TIME_WAIT by a closed connection must not
    look "taken" (it would leak pool entries on every router reconnect), while a real listener
    still makes bind fail with EADDRINUSE.
    """
    s = get_settings()
    address = host or s.bind_address or "127.0.0.1"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((address, int(port)))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def allocate_port(db: Session, *, kind: str = KIND_TUNNEL, exclude: set[int] | None = None) -> int:
    """Lowest free port in the pool. Raises 503 no_free_port when the pool is exhausted."""
    low, high, _ = _pool(kind)
    if low > high:
        raise ApiError(
            503,
            "no_free_port",
            f"The {kind} port pool is empty ({low}-{high}); widen the range in the settings",
        )
    skip = exclude or set()
    with _ALLOCATE_LOCK:
        taken = used_ports(db, kind) | skip
        for port in range(low, high + 1):
            if port in taken:
                continue
            if not port_free_in_os(port):
                log.debug("port %s is held by the OS, skipping", port)
                continue
            return port
    raise ApiError(
        503,
        "no_free_port",
        f"The {kind} port pool ({low}-{high}) is exhausted; free a router or widen the range",
    )


def release_port(db: Session, port: int | None) -> bool:
    """Drop a port from whichever router still records it. Returns True when something changed."""
    if port is None:
        return False
    changed = False
    routers = (
        db.execute(
            select(Router).where(
                or_(Router.remote_port == int(port), Router.console_port == int(port))
            )
        )
        .scalars()
        .all()
    )
    for router in routers:
        if router.remote_port == port:
            router.remote_port = None
            changed = True
        if router.console_port == port:
            router.console_port = None
            changed = True
    if changed:
        db.flush()
    return changed


def free_port_count(kind: str = KIND_TUNNEL) -> int:
    """How many ports of the pool are not recorded on any router.

    This is a database-level estimate on purpose: probing thousands of sockets on every
    /api/v1/stats call would be far more expensive than the number is worth. Allocation still
    performs the OS check per candidate.
    """
    low, high, _ = _pool(kind)
    with session_scope() as db:
        taken = {p for p in used_ports(db, kind) if low <= p <= high}
    return max(0, (high - low + 1) - len(taken))
