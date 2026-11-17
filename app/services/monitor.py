"""Background tunnel monitor.

One cycle does three things, in this order, and nothing else:

1. Ask the kernel (a single 'ss' call) which loopback ports have a listening socket.
2. For the routers that DO have a listener, run one HTTP GET against LuCI through the
   tunnel. Ports without a listener are never probed - a connect to a closed port only
   costs a timeout.
3. Persist the observation into router_runtime and move the router between
   awaiting / online / offline with the transition rules from docs/ARCHITECTURE.md
   section 7.

The loop is written so that a failure in any single step cannot stop it: a broken sshd,
a hanging health check, a locked database or an exception inside the reverse-proxy sync
all end up in the log and in RouterRuntime.last_error, and the next cycle retries.
That matters because this task is the only thing that ever moves a router to online.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shutil
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select

from ..config import Settings, get_settings, utcnow
from ..db import session_scope
from ..models import (
    STATUS_AWAITING,
    STATUS_OFFLINE,
    STATUS_ONLINE,
    STATUS_PENDING,
    STATUS_REVOKED,
    Router,
    RouterRuntime,
)
from . import tunnels

log = logging.getLogger("tunnelgate.monitor")

# Statuses that are worth observing. A pending router has no key and therefore cannot
# have a tunnel; a revoked one is finished and its port is released.
OBSERVED_STATUSES = (STATUS_AWAITING, STATUS_ONLINE, STATUS_OFFLINE)


@dataclass(frozen=True)
class Observation:
    """One router's observation for one cycle. Frozen so it can cross into the threadpool."""

    router_id: str
    tunnel_present: bool
    console_present: bool
    health_ok: bool | None
    tunnel_pid: int | None
    error: str | None = None


@dataclass(frozen=True)
class CycleReport:
    """What one cycle did. Returned mainly so tests and operators can assert on it."""

    observed: int
    online: int
    offline: int
    health_checked: int
    routes_changed: bool
    error: str | None = None


def decide_status(
    status: str,
    *,
    tunnel_present: bool,
    health_ok: bool | None,
    require_health: bool,
    heartbeat_stale: bool,
    observable: bool,
) -> str:
    """The transition rule from docs/ARCHITECTURE.md section 7, as a pure function.

    * online requires an observed listener AND (when configured) a passing health
      check. Nothing else can promote a router: the heartbeat is advisory.
    * A listener that disappeared demotes to offline immediately - that is the whole
      point of polling the kernel instead of trusting a self-report.
    * observable is False when ss itself is unavailable. Then a missing listener is not
      evidence of anything, so the router only goes offline once its heartbeat has also
      gone stale; otherwise it keeps its previous status rather than flapping every
      cycle on a broken host.
    """
    if status in (STATUS_PENDING, STATUS_REVOKED):
        return status
    if tunnel_present:
        alive = bool(health_ok) if require_health else True
        return STATUS_ONLINE if alive else STATUS_OFFLINE
    if not observable:
        return STATUS_OFFLINE if heartbeat_stale else status
    return STATUS_OFFLINE if status == STATUS_ONLINE else status


def _heartbeat_stale(router: Router, now: datetime, stale_after: int) -> bool:
    """True when the router has been silent longer than stale_offline_seconds.

    The reference is the NEWEST of last_heartbeat_at and last_seen_at. last_seen_at is
    refreshed on every agent contact (hello, install, heartbeat), so a router whose
    heartbeat field lags but which is clearly alive must not be demoted: taking the
    heartbeat alone would mark a healthy device offline on a field the agent updates less
    often than it talks to us.
    """
    if stale_after <= 0:
        return False
    stamps = [
        stamp for stamp in (router.last_heartbeat_at, router.last_seen_at) if stamp is not None
    ]
    if not stamps:
        return False
    return (now - max(stamps)).total_seconds() > stale_after


def _observable_routers(db, settings: Settings) -> list[Router]:
    """Routers that can possibly have a tunnel: they hold a key and a port."""
    stmt = (
        select(Router)
        .where(
            Router.status.in_(OBSERVED_STATUSES),
            Router.remote_port.is_not(None),
            Router.revoked_at.is_(None),
        )
        .order_by(Router.slug)
    )
    return list(db.execute(stmt).scalars().all())


def probe_health(routers: list[Router], settings: Settings, listeners: dict[int, dict]):
    """Health-check the routers that have a listener. Runs in the threadpool.

    Returns a plain dict keyed by router id so it can leave the worker thread without
    touching ORM objects (which belong to the caller's session): {id: (ok|None, error)}.
    """
    results: dict[str, tuple[bool | None, str | None]] = {}
    for router in routers:
        port = int(router.remote_port or 0)
        if port not in listeners:
            results[router.id] = (None, None)
            continue
        try:
            healthy = tunnels.health_check(
                port,
                path=settings.health_path,
                timeout=settings.health_timeout_seconds,
            )
            error = None if healthy else f"LuCI did not answer on port {port}"
            results[router.id] = (healthy, error)
        except Exception as exc:
            log.debug("health check failed for router %s: %r", router.slug, exc)
            results[router.id] = (False, f"{type(exc).__name__}: {exc}")
    return results


def collect(routers: list[Router], listeners: dict[int, dict]) -> list[Observation]:
    """One Observation per router, pure with respect to the database.

    Console presence comes from the same ss snapshot: a console listener is a second
    reverse tunnel on console_port, so one poll answers both questions.
    """
    observations: list[Observation] = []
    for router in routers:
        port = int(router.remote_port or 0)
        listener = listeners.get(port)
        console_port = int(getattr(router, "console_port", 0) or 0)
        observations.append(
            Observation(
                router_id=router.id,
                tunnel_present=listener is not None,
                console_present=bool(console_port) and console_port in listeners,
                health_ok=None,
                tunnel_pid=(listener or {}).get("pid"),
            )
        )
    return observations


def apply_cycle(
    settings: Settings,
    listeners: dict[int, dict],
    health: dict[str, tuple[bool | None, str | None]],
) -> CycleReport:
    """Persist one observation cycle and return what changed.

    Runs synchronously in the threadpool: the ORM is sync, and a few milliseconds of
    blocking every tunnel_poll_seconds is cheaper than an asyncio DB layer.
    """
    now = utcnow()
    # When ss produced nothing at all the host may simply not have ss installed, so a
    # missing listener is not evidence. A single observed listener proves ss works, and
    # then absence genuinely means down.
    observable = bool(listeners)
    online = offline = checked = 0
    try:
        with session_scope() as db:
            routers = _observable_routers(db, settings)
            for router in routers:
                port = int(router.remote_port or 0)
                listener = listeners.get(port)
                present = listener is not None
                console_port = int(router.console_port or 0)
                health_ok, error = health.get(router.id, (None, None))
                if present and health_ok is not None:
                    checked += 1

                new_status = decide_status(
                    router.status,
                    tunnel_present=present,
                    health_ok=health_ok,
                    require_health=bool(settings.require_health_for_online),
                    heartbeat_stale=_heartbeat_stale(
                        router, now, int(settings.stale_offline_seconds)
                    ),
                    observable=observable,
                )
                if new_status != router.status:
                    log.info(
                        "router %s: %s -> %s (tunnel=%s health=%s)",
                        router.slug,
                        router.status,
                        new_status,
                        "up" if present else "down",
                        health_ok,
                    )
                    router.status = new_status
                    if new_status == STATUS_ONLINE:
                        router.online_since = router.online_since or now
                    else:
                        router.online_since = None
                if new_status == STATUS_ONLINE:
                    online += 1
                elif new_status == STATUS_OFFLINE:
                    offline += 1

                runtime = router.runtime
                created = runtime is None
                if runtime is None:
                    runtime = RouterRuntime(router_id=router.id)
                    db.add(runtime)
                runtime.tunnel_present = present
                runtime.console_present = bool(console_port) and console_port in listeners
                runtime.tunnel_pid = (listener or {}).get("pid")
                runtime.health_ok = health_ok
                if present and health_ok is not None:
                    runtime.health_checked_at = now
                runtime.observed_at = now
                runtime.last_error = None if present and not error else error
                if created:
                    db.flush()

            db.flush()
    except Exception as exc:
        log.exception("monitor: observation cycle failed")
        return CycleReport(0, 0, 0, 0, False, f"{type(exc).__name__}: {exc}")

    return CycleReport(
        observed=len(routers),
        online=online,
        offline=offline,
        health_checked=checked,
        routes_changed=False,
    )


def read_stale(settings: Settings, listeners: dict[int, dict]) -> int:
    """Routers whose heartbeat went quiet while ss could not confirm them.

    Separate pass, and only when ss gave us something: with a working listener table the
    listener itself is the truth, and a missing heartbeat from a live router is normal
    (the agent only heartbeats every few minutes).
    """
    if not listeners or int(settings.stale_offline_seconds) <= 0:
        return 0
    now = utcnow()
    demoted = 0
    with session_scope() as db:
        routers = _observable_routers(db, settings)
        for router in routers:
            if router.status != STATUS_ONLINE:
                continue
            if int(router.remote_port or 0) in listeners:
                continue
            if not _heartbeat_stale(router, now, int(settings.stale_offline_seconds)):
                continue
            log.info("router %s: online -> offline (heartbeat stale)", router.slug)
            router.status = STATUS_OFFLINE
            router.online_since = None
            demoted += 1
        db.flush()
    return demoted


def observe_once(settings: Settings) -> CycleReport:
    """One full cycle, synchronously. Imported by tests and by the CLI doctor."""
    listeners = tunnels.list_listening_tunnels()
    with session_scope() as db:
        routers = _observable_routers(db, settings)
        db.expunge_all()
    health = probe_health(routers, settings, listeners) if routers else {}
    report = apply_cycle(settings, listeners, health)
    read_stale(settings, listeners)
    return report


async def _sync_proxy(proxy, report: CycleReport) -> CycleReport:
    """Push the observed state into the reverse proxy, if a manager was supplied."""
    if proxy is None:
        return report
    try:
        changed = await proxy.sync()
    except Exception as exc:
        log.warning("monitor: proxy sync failed: %r", exc)
        return report
    return CycleReport(
        observed=report.observed,
        online=report.online,
        offline=report.offline,
        health_checked=report.health_checked,
        routes_changed=bool(changed),
        error=report.error,
    )


def _ss_available() -> bool:
    """Best-effort check used only for the one-time startup warning."""
    return shutil.which("ss") is not None


async def run_monitor(stop_event: asyncio.Event, proxy=None) -> None:
    """The background task created by app.main lifespan.

    Never raises out: an exception here would kill the task that is the only producer of
    router status, and the panel would silently show stale state forever. Every cycle is
    wrapped, and the loop only ends when stop_event is set or the task is cancelled.
    """
    settings = get_settings()
    interval = max(1, int(settings.tunnel_poll_seconds))
    log.info("monitor started (every %ss, driver=%s)", interval, settings.proxy_driver)
    if not _ss_available():
        log.warning(
            "ss is not installed: tunnel presence cannot be observed and every router will "
            "stay awaiting/offline until it is (apt-get install iproute2)"
        )
    cycle = 0
    while not stop_event.is_set():
        try:
            report = await asyncio.to_thread(observe_once, settings)
            report = await _sync_proxy(proxy, report)
            cycle += 1
            if report.error:
                log.warning("monitor cycle %d failed: %s", cycle, report.error)
            elif cycle == 1 or report.routes_changed:
                log.info(
                    "monitor cycle %d: %d observed, %d online, %d offline, %d health-checked%s",
                    cycle,
                    report.observed,
                    report.online,
                    report.offline,
                    report.health_checked,
                    ", routes updated" if report.routes_changed else "",
                )
        except asyncio.CancelledError:
            log.info("monitor cancelled")
            raise
        except Exception:
            log.exception("monitor cycle raised; continuing")

        wait = min(interval, 5) if cycle == 0 else interval
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(wait):
                await stop_event.wait()
        if stop_event.is_set():
            break
    log.info("monitor stopped after %d cycle(s)", cycle)
