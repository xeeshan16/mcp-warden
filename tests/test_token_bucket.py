"""Token-bucket arithmetic and the in-memory store."""

from __future__ import annotations

import pytest

from conftest import FakeMonotonic
from mcp_warden.ratelimit import BucketSpec, BucketState, InMemoryBucketStore
from mcp_warden.ratelimit.bucket import decide, full_at, level, unique_specs

FAST = BucketSpec("fast", capacity=3, refill_per_second=1.0)
SLOW = BucketSpec("slow", capacity=2, refill_per_second=0.1)


def test_level_of_an_unknown_bucket_is_full() -> None:
    assert level(FAST, None, 5.0) == 3


def test_level_refills_linearly_and_caps_at_capacity() -> None:
    state = BucketState(tokens=0.5, updated_at=10.0)
    assert level(FAST, state, 11.0) == pytest.approx(1.5)
    assert level(FAST, state, 100.0) == 3


def test_clock_going_backwards_adds_nothing() -> None:
    assert level(FAST, BucketState(1.0, 10.0), 4.0) == 1.0


def test_full_at() -> None:
    assert full_at(SLOW, 0.0, 100.0) == pytest.approx(120.0)
    assert full_at(SLOW, 2.0, 100.0) == 100.0


def test_decide_reports_the_longest_wait() -> None:
    result = decide([FAST, SLOW], {"fast": 0.5, "slow": 0.0}, 1.0)
    assert not result.allowed
    assert result.limiting_key == "slow"
    assert result.retry_after == pytest.approx(10.0)


def test_decide_allows_when_every_bucket_has_a_token() -> None:
    assert decide([FAST, SLOW], {"fast": 1.0, "slow": 1.0}, 1.0).allowed


def test_decide_rejects_impossible_costs() -> None:
    with pytest.raises(ValueError, match="capacity"):
        decide([SLOW], {"slow": 2.0}, 3.0)
    with pytest.raises(ValueError, match="positive"):
        decide([SLOW], {"slow": 2.0}, 0)


def test_spec_validation() -> None:
    with pytest.raises(ValueError):
        BucketSpec("x", 0, 1)
    with pytest.raises(ValueError):
        BucketSpec("x", 1, 0)


def test_unique_specs_sorts_and_dedupes() -> None:
    dup = BucketSpec("fast", 99, 99)
    assert unique_specs([SLOW, FAST, dup]) == [FAST, SLOW]


def test_memory_store_burst_then_refill(seconds: FakeMonotonic) -> None:
    store = InMemoryBucketStore(clock=seconds)
    assert [store.acquire_sync([FAST]).allowed for _ in range(3)] == [True, True, True]
    refused = store.acquire_sync([FAST])
    assert not refused.allowed
    assert refused.retry_after == pytest.approx(1.0)
    seconds.advance(refused.retry_after)
    assert store.acquire_sync([FAST]).allowed
    assert not store.acquire_sync([FAST]).allowed


def test_memory_store_is_all_or_nothing(seconds: FakeMonotonic) -> None:
    store = InMemoryBucketStore(clock=seconds)
    assert store.acquire_sync([SLOW]).allowed
    assert store.acquire_sync([SLOW]).allowed
    # SLOW is empty, so FAST must not be charged for the refused call.
    for _ in range(5):
        assert not store.acquire_sync([FAST, SLOW]).allowed
    assert [store.acquire_sync([FAST]).allowed for _ in range(4)] == [True, True, True, False]


def test_memory_store_without_specs_allows(seconds: FakeMonotonic) -> None:
    store = InMemoryBucketStore(clock=seconds)
    assert store.acquire_sync([]).allowed
    assert len(store) == 0


def test_memory_store_prunes_full_buckets(seconds: FakeMonotonic) -> None:
    store = InMemoryBucketStore(clock=seconds)
    store.acquire_sync([FAST])
    store.acquire_sync([SLOW])
    seconds.advance(1.5)
    assert store.prune() == 1  # FAST is full again, SLOW is not
    assert len(store) == 1
    seconds.advance(100)
    assert store.prune() == 1
    assert len(store) == 0


def test_memory_store_stays_bounded(seconds: FakeMonotonic) -> None:
    store = InMemoryBucketStore(clock=seconds, max_buckets=3)
    for i in range(10):
        assert store.acquire_sync([BucketSpec(f"k{i}", 5, 0.001)]).allowed
    assert len(store) == 3


def test_memory_store_rejects_a_zero_bound() -> None:
    with pytest.raises(ValueError):
        InMemoryBucketStore(max_buckets=0)


@pytest.mark.anyio
async def test_async_acquire(seconds: FakeMonotonic) -> None:
    store = InMemoryBucketStore(clock=seconds)
    assert (await store.acquire([FAST])).allowed
