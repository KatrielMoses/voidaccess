"""
SQLAlchemy engine and session factory.

Usage (application code)
------------------------
    from db.session import get_session

    with get_session() as session:
        session.add(some_object)
        # commits on exit, rolls back on exception

For async code, prefer get_async_session() with async with:
------------------------
    from db.session import get_async_session

    async with get_async_session() as session:
        await session.add(some_object)
        await session.commit()

For short-lived async operations, use async_session_scope():
------------------------
    from db.session import async_session_scope

    async with async_session_scope() as session:
        # session is auto-committed on exit, rolled back on exception
        await session.execute(...)

Usage (testing — pass an explicit URL to avoid needing DATABASE_URL in env)
---------------------------------------------------------------------------
    from db.session import get_engine, get_session_factory
    from db.models import Base

    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = get_session_factory("sqlite:///:memory:")
"""

from __future__ import annotations

from functools import lru_cache
import os

from contextlib import asynccontextmanager, contextmanager
from typing import AsyncGenerator, Generator, Optional

from sqlalchemy import create_engine, Engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker, Session

import config

# Kept as a compatibility/testing hook.  Production lookups below use the
# current environment so apply_env() can run before the first DB operation.
DATABASE_URL = config.DATABASE_URL
_INITIAL_DATABASE_URL = DATABASE_URL


def _database_url() -> Optional[str]:
    # Preserve the long-standing test/embedding hook of monkeypatching this
    # module's DATABASE_URL. Otherwise, read the live environment so a caller
    # can inject DATABASE_URL after db.session has been imported.
    if DATABASE_URL != _INITIAL_DATABASE_URL:
        return DATABASE_URL
    return os.getenv("DATABASE_URL") or DATABASE_URL
_async_engine_cache: dict[str, "AsyncEngine"] = {}


class _EngineCacheCompat:
    def pop(self, url: str, default=None):
        try:
            engine = get_engine(url)
            engine.dispose()
        except Exception:
            return default
        finally:
            _get_engine_cached.cache_clear()
        return engine

    def clear(self) -> None:
        _get_engine_cached.cache_clear()


_engine_cache = _EngineCacheCompat()


@lru_cache(maxsize=8)
def _get_engine_cached(target_url: str) -> Engine:
    is_sqlite = target_url.startswith("sqlite")

    if is_sqlite:
        engine = create_engine(
            target_url,
            pool_pre_ping=True,
            connect_args={"check_same_thread": False},
        )
    else:
        engine = create_engine(
            target_url,
            pool_pre_ping=True,
            pool_size=20,
            max_overflow=40,
            pool_timeout=30,
            pool_recycle=1800,
        )

    return engine


def get_engine(url: Optional[str] = None) -> Engine:
    """
    Return a SQLAlchemy Engine for *url* (defaults to DATABASE_URL env var).

    Uses lru_cache with maxsize=8 to bound the cache and prevent unbounded
    growth during test suites. Least-recently-used engines are evicted
    automatically when the limit is reached.

    PostgreSQL gets a connection pool tuned for the scraping workload.
    SQLite skips pool parameters that only apply to QueuePool.
    """
    target_url = url or _database_url()
    if not target_url:
        raise RuntimeError(
            "DATABASE_URL is not configured.\n"
            "Add it to your .env file, e.g.:\n"
            "  DATABASE_URL=postgresql://voidaccess:voidaccess@localhost:5433/voidaccess"
        )

    return _get_engine_cached(target_url)


def release_engine(url: Optional[str] = None) -> None:
    """
    Explicitly release and remove an engine from the cache.

    Calls engine.dispose() to release connection pool resources and file handles,
    then clears the cache. Use this in test teardown to prevent leaks.
    """
    target_url = url or _database_url()
    if target_url:
        try:
            engine = get_engine(target_url)
            engine.dispose()
        except Exception:
            pass
        _get_engine_cached.cache_clear()


def get_async_engine(url: Optional[str] = None) -> "AsyncEngine":
    """
    Return an async SQLAlchemy AsyncEngine for *url*.

    Converts postgresql:// to postgresql+asyncpg:// and sqlite:// to sqlite+aiosqlite://.
    """

    target_url = url or _database_url()
    if not target_url:
        raise RuntimeError(
            "DATABASE_URL is not configured.\n"
            "Add it to your .env file, e.g.:\n"
            "  DATABASE_URL=postgresql://voidaccess:voidaccess@localhost:5433/voidaccess"
        )

    if target_url in _async_engine_cache:
        return _async_engine_cache[target_url]

    if target_url.startswith("postgresql://"):
        async_url = target_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif target_url.startswith("sqlite://"):
        async_url = target_url.replace("sqlite://", "sqlite+aiosqlite://", 1)
    else:
        async_url = target_url

    is_sqlite = "sqlite" in async_url

    if is_sqlite:
        engine = create_async_engine(
            async_url,
            pool_pre_ping=True,
            connect_args={"check_same_thread": False},
        )
    else:
        engine = create_async_engine(
            async_url,
            pool_pre_ping=True,
            pool_size=20,
            max_overflow=40,
            pool_timeout=30,
            pool_recycle=1800,
        )

    _async_engine_cache[target_url] = engine
    return engine


def release_async_engine(url: Optional[str] = None) -> None:
    """
    Explicitly release and remove an async engine from the cache.

    Calls engine.dispose() to release connection pool resources and file handles.
    """
    target_url = url or _database_url()
    if target_url in _async_engine_cache:
        _async_engine_cache[target_url].dispose()
        del _async_engine_cache[target_url]


def get_session_factory(url: Optional[str] = None) -> sessionmaker:
    """Return a sessionmaker bound to an engine for *url*."""
    engine = get_engine(url)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_async_session_factory(url: Optional[str] = None) -> async_sessionmaker:
    """Return an async_sessionmaker bound to an async engine for *url*."""
    engine = get_async_engine(url)
    return async_sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@contextmanager
def get_session(url: Optional[str] = None) -> Generator[Session, None, None]:
    """
    Context manager that yields a sync Session, commits on clean exit,
    rolls back on any exception, and always closes.

    Example::

        with get_session() as session:
            session.add(entity)
        # committed here
    """
    factory = get_session_factory(url)
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a database session.
    The session is closed automatically after the request.
    Usage: db: Session = Depends(get_db)
    """
    factory = get_session_factory()
    db = factory()
    try:
        yield db
    finally:
        db.close()


@asynccontextmanager
async def get_async_session(url: Optional[str] = None) -> AsyncGenerator[AsyncSession, None]:
    """
    Async generator that yields an AsyncSession.

    Usage::

        async with get_async_session() as session:
            await session.add(entity)
            await session.commit()

    The session is automatically closed on exit.
    """
    factory = get_async_session_factory(url)
    async with factory() as session:
        yield session


@asynccontextmanager
async def async_session_scope(
    url: Optional[str] = None,
) -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager for short-lived sessions.

    Automatically commits on clean exit, rolls back on exception,
    and always closes the session. Use this for targeted DB operations.

    Example::

        async with async_session_scope() as session:
            result = await session.execute(select(Investigation))
            await session.commit()

    This is the preferred pattern for the investigation pipeline —
    each step gets its own session that commits and closes immediately.
    """
    factory = get_async_session_factory(url)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
