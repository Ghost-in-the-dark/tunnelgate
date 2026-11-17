"""Engine / session plumbing. SQLAlchemy 2.0 sync ORM, SQLite by default, PostgreSQL optional."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


def _build_engine(url: str | None = None):
    s = get_settings()
    url = url or s.db_url
    kwargs: dict = {"future": True, "pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _rec):  # pragma: no cover - driver hook
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA busy_timeout=30000")
            cur.close()

    return engine


engine = None
SessionLocal: sessionmaker[Session] | None = None


def init_engine(url: str | None = None, *, recreate: bool = False) -> None:
    """(Re)create the global engine. Used at startup and by tests."""
    global engine, SessionLocal
    if engine is not None and (url is None or str(engine.url) == url) and not recreate:
        return
    if engine is not None:
        engine.dispose()
    engine = _build_engine(url)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def init_db(url: str | None = None) -> None:
    from . import models  # noqa: F401  (register mappers)

    init_engine(url)
    assert engine is not None
    Base.metadata.create_all(engine)


def get_db() -> Iterator[Session]:
    if SessionLocal is None:
        init_db()
    assert SessionLocal is not None
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Standalone session for background workers (monitor, proxy sync)."""
    if SessionLocal is None:
        init_db()
    assert SessionLocal is not None
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def reset_for_tests() -> None:
    global engine, SessionLocal
    if engine is not None:
        engine.dispose()
    engine = None
    SessionLocal = None
