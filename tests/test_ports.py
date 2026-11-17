"""Port pool tests: allocation, uniqueness, release and accounting."""

from __future__ import annotations

import socket

import pytest

from app.db import session_scope
from app.errors import ApiError
from app.models import Router
from app.services import ports as ports_service


def _router(db, **kw) -> Router:
    defaults = {"name": "R", "slug": "r", "status": "pending"}
    defaults.update(kw)
    item = Router(**defaults)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def test_allocate_returns_port_inside_the_configured_pool(settings, db):
    port = ports_service.allocate_port(db)
    assert settings.port_min <= port <= settings.port_max
    db.commit()


def test_allocate_skips_ports_already_recorded_on_a_router(settings, db):
    first = ports_service.allocate_port(db)
    item = _router(db, slug="a", remote_port=first)
    assert item.remote_port == first
    second = ports_service.allocate_port(db)
    assert second != first
    assert settings.port_min <= second <= settings.port_max


def test_allocate_respects_excludes(db):
    skip = set(range(20000, 20010))
    port = ports_service.allocate_port(db, exclude=skip)
    assert port not in skip


def test_allocate_skips_ports_busy_in_the_os(settings, db, monkeypatch):
    monkeypatch.setattr(ports_service, "port_free_in_os", lambda port, host=None: port != 20000)
    port = ports_service.allocate_port(db)
    assert port != 20000


def test_allocate_raises_503_when_the_pool_is_exhausted(settings, db):
    with session_scope() as s:
        for i, p in enumerate(range(settings.port_min, settings.port_max + 1)):
            s.add(Router(name=f"R{i}", slug=f"r{i}", status="pending", remote_port=p))
    with pytest.raises(ApiError) as exc:
        ports_service.allocate_port(db)
    assert exc.value.status == 503
    assert exc.value.code == "no_free_port"


def test_console_pool_is_separate_from_the_tunnel_pool(settings, db):
    tunnel = ports_service.allocate_port(db, kind=ports_service.KIND_TUNNEL)
    console = ports_service.allocate_port(db, kind=ports_service.KIND_CONSOLE)
    assert settings.port_min <= tunnel <= settings.port_max
    assert settings.console_port_min <= console <= settings.console_port_max
    assert tunnel != console


def test_console_allocation_ignores_tunnel_ports(settings, db):
    with session_scope() as s:
        s.add(Router(name="a", slug="a", status="pending", remote_port=settings.port_min))
    port = ports_service.allocate_port(db, kind=ports_service.KIND_CONSOLE)
    assert settings.console_port_min <= port <= settings.console_port_max


def test_release_frees_the_port_for_reallocation(settings, db):
    port = ports_service.allocate_port(db)
    item = _router(db, slug="rel", remote_port=port)
    assert ports_service.release_port(db, port) is True
    db.commit()
    again = ports_service.allocate_port(db)
    assert again == port
    assert item.remote_port is None


def test_release_unknown_port_is_a_noop(db):
    assert ports_service.release_port(db, 65535) is False
    assert ports_service.release_port(db, None) is False


def test_release_clears_console_column_too(settings, db):
    item = _router(db, slug="c", console_port=settings.console_port_min)
    assert ports_service.release_port(db, settings.console_port_min) is True
    db.commit()
    db.refresh(item)
    assert item.console_port is None


def test_free_port_count_matches_the_pool_size(settings, db):
    before = ports_service.free_port_count()
    assert before == settings.port_max - settings.port_min + 1
    port = ports_service.allocate_port(db)
    _router(db, slug="occupies", remote_port=port)
    db.commit()
    assert ports_service.free_port_count() == before - 1


def test_port_free_in_os_detects_a_bound_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    try:
        busy = sock.getsockname()[1]
        assert ports_service.port_free_in_os(busy, host="127.0.0.1") is False
    finally:
        sock.close()
