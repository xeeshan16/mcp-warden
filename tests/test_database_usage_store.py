"""The database usage ledger on SQLite, and on PostgreSQL when one is configured.

Set ``WARDEN_TEST_POSTGRES_URL`` to also run these against PostgreSQL,
including a concurrency test that relies on row locks.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from datetime import timedelta

import pytest
from sqlalchemy import Engine, func, select, text
from sqlalchemy.exc import IntegrityError

from conftest import FakeClock
from mcp_warden.budget import DatabaseUsageStore, Exhausted, Usage
from mcp_warden.db import UsageCounter, make_engine, make_sessionmaker, upgrade
from mcp_warden.policy import BudgetWindow, LimitScope
from test_budget_ledger import NOW, charge

POSTGRES_URL = os.environ.get("WARDEN_TEST_POSTGRES_URL")


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
        conn.execute(text("DELETE FROM usage_counters"))
    yield pg
    pg.dispose()


@pytest.fixture
def ledger_clock() -> FakeClock:
    return FakeClock(NOW)


@pytest.fixture
def store(engine: Engine, ledger_clock: FakeClock) -> DatabaseUsageStore:
    return DatabaseUsageStore(make_sessionmaker(engine), clock=ledger_clock)


def rows(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(conn.execute(select(func.count()).select_from(UsageCounter)).scalar_one())


def test_reserve_books_until_the_limit(store: DatabaseUsageStore, engine: Engine) -> None:
    c = charge(max_calls=2)
    assert store.reserve_sync([c], 5) is None
    assert store.reserve_sync([c], 5) is None
    refusal = store.reserve_sync([c], 5)
    assert refusal is not None
    assert (refusal.exhausted, refusal.used, refusal.limit) == (Exhausted.CALLS, 2, 2)
    assert store.usage(c) == Usage(2, 10)
    assert rows(engine) == 1


def test_refusals_write_nothing(store: DatabaseUsageStore, engine: Engine) -> None:
    roomy, tight = charge("roomy", max_calls=10), charge("tight", max_tokens=5)
    assert store.reserve_sync([roomy, tight], 6) is not None
    assert rows(engine) == 0
    assert store.reserve_sync([roomy, tight], 5) is None
    assert store.reserve_sync([roomy, tight], 1) is not None
    assert store.usage(roomy) == Usage(1, 5)


def test_settle_adds_reply_tokens(store: DatabaseUsageStore) -> None:
    c = charge(max_tokens=100)
    store.reserve_sync([c], 10)
    store.settle_sync([c], 95)
    store.settle_sync([c], 0)
    assert store.usage(c) == Usage(1, 105)
    refusal = store.reserve_sync([c], 0)
    assert refusal is not None and refusal.exhausted is Exhausted.TOKENS


def test_windows_are_separate_rows(store: DatabaseUsageStore, engine: Engine) -> None:
    today, tomorrow = charge(max_calls=1), charge(max_calls=1, now=NOW + timedelta(days=1))
    assert store.reserve_sync([today], 0) is None
    assert store.reserve_sync([today], 0) is not None
    assert store.reserve_sync([tomorrow], 0) is None
    assert rows(engine) == 2


def test_records_and_prune(
    store: DatabaseUsageStore, engine: Engine, ledger_clock: FakeClock
) -> None:
    hourly = charge("hourly", window=BudgetWindow.HOUR, scope=LimitScope.TOOL, max_calls=9)
    daily = charge("daily", max_calls=9, agent="other")
    store.reserve_sync([hourly], 3)
    store.reserve_sync([daily], 4)
    assert {
        (r.budget_id, r.agent, r.server, r.tool, r.calls, r.tokens) for r in store.records()
    } == {
        ("hourly", "bot", "demo", "echo", 1, 3),
        ("daily", "other", None, None, 1, 4),
    }
    assert [r.budget_id for r in store.records(agent="other")] == ["daily"]

    ledger_clock.advance(timedelta(hours=1))
    assert [r.budget_id for r in store.records()] == ["daily"]
    assert len(store.records(current_only=False)) == 2
    assert store.prune(ledger_clock()) == 1
    assert rows(engine) == 1


def test_long_names_are_cut_in_labels_only(store: DatabaseUsageStore) -> None:
    long_tool = "t" * 500
    c = charge(scope=LimitScope.TOOL, tool=long_tool, max_calls=1)
    assert store.reserve_sync([c], 0) is None
    (record,) = store.records()
    assert record.tool == "t" * 200
    # The counter is still identified by the full name.
    assert (
        store.reserve_sync([charge(scope=LimitScope.TOOL, tool="t" * 499, max_calls=1)], 0) is None
    )
    assert store.reserve_sync([c], 0) is not None


def test_retries_once_when_a_concurrent_insert_wins(
    store: DatabaseUsageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = store._attempt
    calls = {"n": 0}

    def flaky(*args: object) -> object:
        calls["n"] += 1
        if calls["n"] == 1:
            raise IntegrityError("insert", {}, Exception("duplicate key"))
        return real(*args)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "_attempt", flaky)
    assert store.reserve_sync([charge(max_calls=1)], 0) is None
    assert calls["n"] == 2


def test_empty_charges_are_allowed(store: DatabaseUsageStore, engine: Engine) -> None:
    assert store.reserve_sync([], 10) is None
    assert rows(engine) == 0


@pytest.mark.anyio
async def test_async_wrappers(store: DatabaseUsageStore) -> None:
    c = charge(max_calls=1)
    assert await store.reserve([c], 2) is None
    await store.settle([c], 3)
    assert store.usage(c) == Usage(1, 5)


def test_concurrent_reservations_never_overspend(engine: Engine, ledger_clock: FakeClock) -> None:
    """Several stores (as on several gateway hosts) share one budget of 10 calls."""
    if engine.dialect.name != "postgresql":
        pytest.skip("row locks are a PostgreSQL feature")
    stores = [DatabaseUsageStore(make_sessionmaker(engine), clock=ledger_clock) for _ in range(4)]
    c = charge(max_calls=10)
    allowed: list[bool] = []
    lock = threading.Lock()
    start = threading.Barrier(8)

    def worker(i: int) -> None:
        store = stores[i % len(stores)]
        start.wait()
        for _ in range(10):
            result = store.reserve_sync([c], 1) is None
            with lock:
                allowed.append(result)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert allowed.count(True) == 10
    assert stores[0].usage(c) == Usage(10, 10)
