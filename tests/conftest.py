from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine

from mcp_warden.db import make_engine, make_sessionmaker, upgrade
from mcp_warden.identity import IdentityStore


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    """A file-backed SQLite database, so worker threads get real connections."""
    return f"sqlite:///{tmp_path / 'warden.db'}"


@pytest.fixture
def db_engine(db_url: str) -> Iterator[Engine]:
    engine = make_engine(db_url)
    upgrade(engine)
    yield engine
    engine.dispose()


class FakeClock:
    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 10, 15, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def store(db_engine: Engine, clock: FakeClock) -> IdentityStore:
    return IdentityStore(make_sessionmaker(db_engine), clock=clock)


class FakeMonotonic:
    """A seconds clock for the rate limiter, moved by hand."""

    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def seconds() -> FakeMonotonic:
    return FakeMonotonic()
