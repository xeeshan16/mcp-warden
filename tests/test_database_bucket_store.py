"""The database bucket store on SQLite, and on PostgreSQL when one is configured.

Set ``WARDEN_TEST_POSTGRES_URL`` (a ``postgresql+psycopg://`` URL to a
throwaway database) to also run the shared-bucket tests against PostgreSQL,
including a concurrency test that relies on row locks.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import Engine, func, select, text
from sqlalchemy.exc import IntegrityError

from conftest import FakeMonotonic
from mcp_warden.db import RateLimitBucket, make_engine, make_sessionmaker, upgrade
from mcp_warden.ratelimit import BucketSpec, DatabaseBucketStore
from mcp_warden.ratelimit.database import digest

POSTGRES_URL = os.environ.get("WARDEN_TEST_POSTGRES_URL")

FAST = BucketSpec("fast", capacity=3, refill_per_second=1.0)
SLOW = BucketSpec("slow", capacity=2, refill_per_second=0.1)


@pytest.fixture(params=["sqlite", "postgresql"])
def engine(request: pytest.FixtureRequest, db_engine: Engine) -> Iterator[Engine]:
    if request.param == "sqlite":
        yield db_engine
        return
    if not POSTGRES_URL:
        pytest.skip("WARDEN_TEST_POSTGRES_URL is not set")
    pg = make_engine(POSTGRES_URL)
    upgrade(pg)
    with pg.begin() as conn:
        conn.execute(text("DELETE FROM rate_limit_buckets"))
    yield pg
    pg.dispose()


@pytest.fixture
def store(engine: Engine, seconds: FakeMonotonic) -> DatabaseBucketStore:
    return DatabaseBucketStore(make_sessionmaker(engine), clock=seconds)


def rows(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(conn.execute(select(func.count()).select_from(RateLimitBucket)).scalar_one())


def test_burst_then_refill(store: DatabaseBucketStore, seconds: FakeMonotonic) -> None:
    assert [store.acquire_sync([FAST]).allowed for _ in range(3)] == [True, True, True]
    refused = store.acquire_sync([FAST])
    assert not refused.allowed
    assert refused.limiting_key == "fast"
    assert refused.retry_after == pytest.approx(1.0)
    seconds.advance(1.0)
    assert store.acquire_sync([FAST]).allowed


def test_all_or_nothing(store: DatabaseBucketStore) -> None:
    store.acquire_sync([SLOW])
    store.acquire_sync([SLOW])
    for _ in range(5):
        assert not store.acquire_sync([FAST, SLOW]).allowed
    assert [store.acquire_sync([FAST]).allowed for _ in range(4)] == [True, True, True, False]


def test_keys_are_stored_as_digests(store: DatabaseBucketStore, engine: Engine) -> None:
    long_key = '["limit","agent","server","' + "t" * 500 + '"]'
    assert store.acquire_sync([BucketSpec(long_key, 1, 1)]).allowed
    with engine.connect() as conn:
        keys = conn.execute(select(RateLimitBucket.key)).scalars().all()
    assert keys == [digest(long_key)]


def test_refusal_writes_nothing(store: DatabaseBucketStore, engine: Engine) -> None:
    one = BucketSpec("one", 1, 0.5)
    store.acquire_sync([one])
    with engine.connect() as conn:
        before = conn.execute(select(RateLimitBucket.updated_at)).scalar_one()
    assert not store.acquire_sync([one, FAST]).allowed
    assert rows(engine) == 1
    with engine.connect() as conn:
        assert conn.execute(select(RateLimitBucket.updated_at)).scalar_one() == before


def test_prune_removes_refilled_buckets(
    store: DatabaseBucketStore, engine: Engine, seconds: FakeMonotonic
) -> None:
    store.acquire_sync([FAST])
    store.acquire_sync([SLOW])
    assert rows(engine) == 2
    seconds.advance(1.5)
    assert store.prune() == 1
    seconds.advance(100)
    assert store.prune() == 1
    assert rows(engine) == 0
    # A pruned bucket is simply full again.
    assert [store.acquire_sync([FAST]).allowed for _ in range(3)] == [True, True, True]


def test_concurrent_insert_is_retried(
    store: DatabaseBucketStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []
    original = DatabaseBucketStore._attempt

    def flaky(self: DatabaseBucketStore, *args: Any) -> Any:
        calls.append(1)
        if len(calls) == 1:
            raise IntegrityError("INSERT", {}, Exception("duplicate key"))
        return original(self, *args)

    monkeypatch.setattr(DatabaseBucketStore, "_attempt", flaky)
    assert store.acquire_sync([FAST]).allowed
    assert len(calls) == 2


def test_empty_request_touches_nothing(store: DatabaseBucketStore, engine: Engine) -> None:
    assert store.acquire_sync([]).allowed
    assert rows(engine) == 0


@pytest.mark.anyio
async def test_async_acquire(store: DatabaseBucketStore) -> None:
    assert (await store.acquire([FAST])).allowed


def test_two_stores_share_buckets(engine: Engine, seconds: FakeMonotonic) -> None:
    """Two gateway instances on one database draw from the same bucket."""
    a = DatabaseBucketStore(make_sessionmaker(engine), clock=seconds)
    b = DatabaseBucketStore(make_sessionmaker(engine), clock=seconds)
    results = [s.acquire_sync([FAST]).allowed for s in (a, b, a, b)]
    assert results == [True, True, True, False]


def test_concurrent_callers_never_overspend(engine: Engine) -> None:
    """Many threads, separate stores (as separate replicas would be), one bucket."""
    frozen = FakeMonotonic()
    spec = BucketSpec("shared", capacity=10, refill_per_second=0.001)
    stores = [DatabaseBucketStore(make_sessionmaker(engine), clock=frozen) for _ in range(4)]
    allowed: list[bool] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        try:
            for _ in range(10):
                ok = stores[i % len(stores)].acquire_sync([spec]).allowed
                with lock:
                    allowed.append(ok)
        except BaseException as exc:
            errors.append(exc)

    if engine.dialect.name == "sqlite":
        # SQLite has no row locks; one store per process is the supported setup.
        stores = stores[:1]
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(allowed) == 80
    assert sum(allowed) == 10
