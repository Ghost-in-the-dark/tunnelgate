"""Tests for the tunnel monitor: status rules, cycle persistence, and the loop itself.

The monitor is the only thing that ever moves a router to online, so the tests pin the
transition rules from docs/ARCHITECTURE.md section 7 rather than the implementation.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from app.config import utcnow
from app.db import session_scope
from app.models import (
    STATUS_AWAITING,
    STATUS_OFFLINE,
    STATUS_ONLINE,
    STATUS_PENDING,
    STATUS_REVOKED,
    Router,
    RouterRuntime,
)
from app.services import monitor
from app.services.monitor import CycleReport, decide_status


# --------------------------------------------------------------------------- fixtures
def _make_router(db, settings, **kw) -> Router:
    defaults = {
        "name": "Edge One",
        "slug": "edge-one",
        "status": STATUS_AWAITING,
        "http_port": 80,
        "remote_port": 20001,
        "console_port": 25001,
        "bind_address": "127.0.0.1",
        "ssh_user": "tunnelgate",
        "last_seen_at": utcnow(),
        "last_heartbeat_at": utcnow(),
    }
    defaults.update(kw)
    item = Router(**defaults)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@pytest.fixture()
def router(db, settings) -> Router:
    return _make_router(db, settings)


def _reload(router_id: str) -> Router:
    with session_scope() as session:
        item = session.get(Router, router_id)
        assert item is not None
        session.expunge(item)
        return item


def _runtime(router_id: str) -> RouterRuntime | None:
    with session_scope() as session:
        return session.get(RouterRuntime, router_id)


# ----------------------------------------------------------------------- decide_status
@pytest.mark.parametrize("status", [STATUS_PENDING, STATUS_REVOKED])
def test_terminal_statuses_are_never_touched(status: str):
    assert (
        decide_status(
            status,
            tunnel_present=True,
            health_ok=True,
            require_health=True,
            heartbeat_stale=False,
            observable=True,
        )
        == status
    )


def test_listener_and_health_promote_to_online():
    assert (
        decide_status(
            STATUS_AWAITING,
            tunnel_present=True,
            health_ok=True,
            require_health=True,
            heartbeat_stale=False,
            observable=True,
        )
        == STATUS_ONLINE
    )


def test_listener_without_health_is_not_online_when_health_is_required():
    """A listening socket is not enough: another process could own the port."""
    assert (
        decide_status(
            STATUS_AWAITING,
            tunnel_present=True,
            health_ok=False,
            require_health=True,
            heartbeat_stale=False,
            observable=True,
        )
        == STATUS_OFFLINE
    )


def test_listener_alone_promotes_when_health_is_not_required():
    assert (
        decide_status(
            STATUS_AWAITING,
            tunnel_present=True,
            health_ok=None,
            require_health=False,
            heartbeat_stale=False,
            observable=True,
        )
        == STATUS_ONLINE
    )


def test_missing_listener_demotes_an_online_router():
    assert (
        decide_status(
            STATUS_ONLINE,
            tunnel_present=False,
            health_ok=None,
            require_health=True,
            heartbeat_stale=False,
            observable=True,
        )
        == STATUS_OFFLINE
    )


def test_awaiting_stays_awaiting_while_the_tunnel_is_absent():
    assert (
        decide_status(
            STATUS_AWAITING,
            tunnel_present=False,
            health_ok=None,
            require_health=True,
            heartbeat_stale=True,
            observable=True,
        )
        == STATUS_AWAITING
    )


def test_unobservable_host_only_demotes_on_a_stale_heartbeat():
    """ss unavailable: absence of a listener proves nothing, so keep the last known state."""
    kwargs = {
        "tunnel_present": False,
        "health_ok": None,
        "require_health": True,
        "observable": False,
    }
    assert decide_status(STATUS_ONLINE, heartbeat_stale=False, **kwargs) == STATUS_ONLINE
    assert decide_status(STATUS_ONLINE, heartbeat_stale=True, **kwargs) == STATUS_OFFLINE


# ------------------------------------------------------------------------ heartbeat age
def test_heartbeat_staleness_uses_the_newest_of_heartbeat_and_last_seen(db, settings):
    now = utcnow()
    fresh = _make_router(
        db, settings, slug="fresh", remote_port=20010, console_port=25010, last_heartbeat_at=now
    )
    old_beat = _make_router(
        db,
        settings,
        slug="old-beat",
        remote_port=20011,
        console_port=25011,
        last_heartbeat_at=now - timedelta(seconds=600),
        last_seen_at=now,
    )
    assert monitor._heartbeat_stale(fresh, now, 90) is False
    assert monitor._heartbeat_stale(old_beat, now, 90) is False

    silent = _make_router(
        db,
        settings,
        slug="silent",
        remote_port=20012,
        console_port=25012,
        last_heartbeat_at=None,
        last_seen_at=now - timedelta(seconds=600),
    )
    assert monitor._heartbeat_stale(silent, now, 90) is True
    assert monitor._heartbeat_stale(silent, now, 0) is False


def test_router_without_any_timestamp_is_not_treated_as_stale(db, settings):
    never = _make_router(
        db,
        settings,
        slug="never",
        remote_port=20013,
        console_port=25013,
        last_heartbeat_at=None,
        last_seen_at=None,
    )
    assert monitor._heartbeat_stale(never, utcnow(), 90) is False


# ------------------------------------------------------------------- apply_cycle
def test_cycle_persists_the_observation_and_promotes(db, settings, router):
    settings.require_health_for_online = False
    settings.tunnel_poll_seconds = 5
    listeners = {20001: {"port": 20001, "pid": 4242, "address": "127.0.0.1"}}

    report = monitor.apply_cycle(settings, listeners, {router.id: (None, None)})

    assert report.observed == 1
    assert report.online == 1
    assert report.error is None
    reloaded = _reload(router.id)
    assert reloaded.status == STATUS_ONLINE
    assert reloaded.online_since is not None

    runtime = _runtime(router.id)
    assert runtime is not None
    assert runtime.tunnel_present is True
    assert runtime.tunnel_pid == 4242
    assert runtime.observed_at is not None
    assert runtime.last_error is None


def test_cycle_uses_health_and_records_the_failure(db, settings, router):
    settings.require_health_for_online = True
    listeners = {20001: {"port": 20001, "pid": 1}}
    health = {router.id: (False, "LuCI did not answer on port 20001")}

    report = monitor.apply_cycle(settings, listeners, health)

    assert report.offline == 1
    assert report.health_checked == 1
    assert _reload(router.id).status == STATUS_OFFLINE
    runtime = _runtime(router.id)
    assert runtime is not None
    assert runtime.health_ok is False
    assert runtime.health_checked_at is not None
    assert runtime.last_error == "LuCI did not answer on port 20001"


def test_cycle_does_not_demote_anything_when_ss_is_unobservable(db, settings, router):
    """An empty listener table can just mean ss failed: absence is not evidence."""
    with session_scope() as session:
        item = session.get(Router, router.id)
        item.status = STATUS_ONLINE
        session.flush()

    report = monitor.apply_cycle(settings, {}, {router.id: (None, None)})

    assert report.observed == 1
    assert _reload(router.id).status == STATUS_ONLINE


def test_cycle_demotes_when_the_listener_disappears(db, settings):
    alive = _make_router(db, settings, slug="alive", status=STATUS_ONLINE)
    gone = _make_router(
        db,
        settings,
        slug="gone",
        status=STATUS_ONLINE,
        remote_port=20002,
        console_port=25002,
        online_since=utcnow(),
    )
    listeners = {alive.remote_port: {"port": alive.remote_port, "pid": 1}}

    report = monitor.apply_cycle(settings, listeners, {})

    assert report.online == 1
    assert report.offline == 1
    assert _reload(alive.id).status == STATUS_ONLINE
    demoted = _reload(gone.id)
    assert demoted.status == STATUS_OFFLINE
    assert demoted.online_since is None


def test_cycle_skips_pending_and_revoked_routers(db, settings):
    _make_router(db, settings, slug="pending-one", status=STATUS_PENDING)
    _make_router(db, settings, slug="revoked-one", status=STATUS_REVOKED, remote_port=20003)

    report = monitor.apply_cycle(settings, {20001: {"port": 20001, "pid": 1}}, {})

    assert report.observed == 0


def test_cycle_captures_console_presence_from_the_same_snapshot(db, settings, router):
    listeners = {
        20001: {"port": 20001, "pid": 7},
        25001: {"port": 25001, "pid": 7},
    }
    monitor.apply_cycle(settings, listeners, {})
    runtime = _runtime(router.id)
    assert runtime is not None
    assert runtime.console_present is True


def test_cycle_reports_database_failures_instead_of_raising(settings, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(monitor, "_observable_routers", boom)
    report = monitor.apply_cycle(settings, {20001: {"port": 20001}}, {})
    assert report.observed == 0
    assert report.error is not None and "database is locked" in report.error


# ---------------------------------------------------------------------- read_stale
def test_stale_pass_demotes_only_a_quiet_router(db, settings):
    old = utcnow() - timedelta(seconds=600)
    silent = _make_router(
        db,
        settings,
        slug="silent",
        status=STATUS_ONLINE,
        remote_port=20004,
        last_heartbeat_at=old,
        last_seen_at=old,
    )
    talkative = _make_router(
        db,
        settings,
        slug="talkative",
        status=STATUS_ONLINE,
        remote_port=20005,
        last_heartbeat_at=utcnow(),
    )
    listeners = {20001: {"port": 20001, "pid": 1}}

    assert monitor.read_stale(settings, listeners) == 1

    assert _reload(silent.id).status == STATUS_OFFLINE
    assert _reload(talkative.id).status == STATUS_ONLINE


def test_stale_pass_is_a_noop_without_a_listener_table(db, settings, router):
    with session_scope() as session:
        session.get(Router, router.id).status = STATUS_ONLINE
        session.flush()
    assert monitor.read_stale(settings, {}) == 0
    assert _reload(router.id).status == STATUS_ONLINE


def test_stale_pass_is_disabled_by_zero(db, settings, router):
    settings.stale_offline_seconds = 0
    old = utcnow() - timedelta(seconds=600)
    with session_scope() as session:
        item = session.get(Router, router.id)
        item.status = STATUS_ONLINE
        item.last_heartbeat_at = old
        item.last_seen_at = old
        session.flush()
    assert monitor.read_stale(settings, {20001: {}}) == 0
    assert _reload(router.id).status == STATUS_ONLINE


# --------------------------------------------------------------------- observe_once
def test_observe_once_reads_the_kernel_then_probes_only_listening_ports(
    db, settings, router, monkeypatch
):
    probed: list[int] = []
    monkeypatch.setattr(
        monitor.tunnels,
        "list_listening_tunnels",
        lambda: {20001: {"port": 20001, "pid": 9}},
    )

    def fake_health(port, path=None, timeout=None):
        probed.append(port)
        return True

    monkeypatch.setattr(monitor.tunnels, "health_check", fake_health)
    settings.require_health_for_online = True

    report = monitor.observe_once(settings)

    assert probed == [20001]
    assert report.observed == 1
    assert _reload(router.id).status == STATUS_ONLINE


def test_probe_health_skips_ports_without_a_listener(db, settings, router, monkeypatch):
    def explode(*args, **kwargs):  # pragma: no cover - must not be called
        raise AssertionError("health check must not run without a listener")

    monkeypatch.setattr(monitor.tunnels, "health_check", explode)
    with session_scope() as session:
        item = session.get(Router, router.id)
        session.expunge(item)
        routers = [item]
    assert monitor.probe_health(routers, settings, {}) == {router.id: (None, None)}


# ---------------------------------------------------------------------- run_monitor
def test_run_monitor_survives_a_failing_cycle(settings, monkeypatch):
    """The loop is the only status producer: one bad cycle must not end it."""
    calls: list[int] = []

    def flaky(_settings):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")
        return CycleReport(0, 0, 0, 0, False)

    monkeypatch.setattr(monitor, "observe_once", flaky)
    settings.tunnel_poll_seconds = 1
    stop = asyncio.Event()

    async def main():
        task = asyncio.create_task(monitor.run_monitor(stop, None))
        for _ in range(200):
            await asyncio.sleep(0.01)
            if len(calls) >= 2:
                break
        stop.set()
        await asyncio.wait_for(task, timeout=5)

    asyncio.run(main())
    assert len(calls) >= 2


def test_run_monitor_syncs_the_proxy_and_reports_changes(settings, monkeypatch):
    synced: list[int] = []

    class FakeProxy:
        async def sync(self, db=None):
            synced.append(1)
            return len(synced) == 1

    def once(_settings):
        return CycleReport(1, 1, 0, 0, False)

    monkeypatch.setattr(monitor, "observe_once", once)
    settings.tunnel_poll_seconds = 1
    stop = asyncio.Event()

    async def main():
        task = asyncio.create_task(monitor.run_monitor(stop, FakeProxy()))
        for _ in range(200):
            await asyncio.sleep(0.01)
            if synced:
                break
        stop.set()
        await asyncio.wait_for(task, timeout=5)

    asyncio.run(main())
    assert synced == [1]


def test_run_monitor_keeps_running_when_the_proxy_sync_raises(settings, monkeypatch):
    calls: list[int] = []

    class BrokenProxy:
        async def sync(self, db=None):
            raise RuntimeError("nginx exploded")

    def once(_settings):
        calls.append(1)
        return CycleReport(0, 0, 0, 0, False)

    monkeypatch.setattr(monitor, "observe_once", once)
    settings.tunnel_poll_seconds = 1
    stop = asyncio.Event()

    async def main():
        task = asyncio.create_task(monitor.run_monitor(stop, BrokenProxy()))
        for _ in range(400):
            await asyncio.sleep(0.01)
            if len(calls) >= 2:
                break
        stop.set()
        await asyncio.wait_for(task, timeout=5)

    asyncio.run(main())
    assert len(calls) >= 2


def test_run_monitor_returns_when_the_stop_event_is_already_set(settings):
    stop = asyncio.Event()
    stop.set()
    asyncio.run(asyncio.wait_for(monitor.run_monitor(stop, None), timeout=5))
