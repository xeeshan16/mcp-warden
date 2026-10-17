"""Token estimation, the budget decision and the in-memory usage ledger."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mcp_warden.budget import (
    Charge,
    CharRatioEstimator,
    Exhausted,
    InMemoryUsageStore,
    Usage,
    canonical_json,
    decide,
    window_bounds,
)
from mcp_warden.policy import Budget, BudgetWindow, LimitScope

NOW = datetime(2026, 10, 17, 9, 30, tzinfo=UTC)


def charge(
    budget_id: str = "b",
    *,
    window: BudgetWindow = BudgetWindow.DAY,
    max_calls: int | None = 1000,
    max_tokens: int | None = None,
    scope: LimitScope = LimitScope.AGENT,
    agent: str = "bot",
    tool: str = "echo",
    now: datetime = NOW,
) -> Charge:
    budget = Budget(
        id=budget_id,
        window=window,
        max_calls=max_calls,
        max_tokens=max_tokens,
        scope=scope,
    )
    start, end = window_bounds(window, now)
    per_tool = scope is LimitScope.TOOL
    return Charge(
        budget, agent, "demo" if per_tool else None, tool if per_tool else None, start, end
    )


# --- estimator ----------------------------------------------------------------


def test_char_ratio_rounds_up() -> None:
    est = CharRatioEstimator()
    assert [est.count(""), est.count("a"), est.count("abcd"), est.count("abcde")] == [0, 1, 1, 2]
    assert CharRatioEstimator(2.5).count("abcdef") == 3


@pytest.mark.parametrize("ratio", [0, -1, float("nan"), float("inf")])
def test_char_ratio_must_be_positive_and_finite(ratio: float) -> None:
    with pytest.raises(ValueError, match="positive"):
        CharRatioEstimator(ratio)


def test_canonical_json_ignores_key_order_and_whitespace() -> None:
    assert canonical_json({"b": 1, "a": [1, 2]}) == '{"a":[1,2],"b":1}'
    assert canonical_json({"a": [1, 2], "b": 1}) == canonical_json({"b": 1, "a": [1, 2]})
    assert canonical_json({"t": "é"}) == '{"t":"é"}'


# --- charges and decide -------------------------------------------------------


def test_keys_depend_on_scope() -> None:
    agent_scoped = charge(tool="echo")
    assert agent_scoped.key == '["b","bot"]'
    assert charge(tool="add").slot == agent_scoped.slot
    per_tool = charge(scope=LimitScope.TOOL)
    assert per_tool.key == '["b","bot","demo","echo"]'
    assert charge(scope=LimitScope.TOOL, tool="add").slot != per_tool.slot


def test_slot_changes_with_the_window() -> None:
    today, tomorrow = charge(), charge(now=NOW + timedelta(days=1))
    assert today.digest == tomorrow.digest
    assert today.slot != tomorrow.slot


def test_decide_calls_and_tokens() -> None:
    c = charge(max_calls=2, max_tokens=100)
    assert decide([c], {}, 100) is None
    assert decide([c], {c.slot: Usage(1, 50)}, 50) is None
    calls = decide([c], {c.slot: Usage(2, 0)}, 1)
    assert calls is not None
    assert (calls.exhausted, calls.used, calls.limit) == (Exhausted.CALLS, 2, 2)
    tokens = decide([c], {c.slot: Usage(0, 90)}, 11)
    assert tokens is not None
    assert (tokens.exhausted, tokens.used, tokens.limit) == (Exhausted.TOKENS, 90, 100)


def test_decide_reports_the_budget_that_resets_last() -> None:
    hourly = charge("hourly", window=BudgetWindow.HOUR, max_calls=1)
    monthly = charge("monthly", window=BudgetWindow.MONTH, max_calls=1)
    full = {hourly.slot: Usage(1, 0), monthly.slot: Usage(1, 0)}
    refusal = decide([hourly, monthly], full, 0)
    assert refusal is not None
    assert refusal.charge.budget.id == "monthly"


def test_decide_rejects_negative_tokens() -> None:
    with pytest.raises(ValueError, match="negative"):
        decide([charge(max_calls=1)], {}, -1)


# --- in-memory store ----------------------------------------------------------


def test_reserve_books_calls_and_tokens() -> None:
    store = InMemoryUsageStore()
    c = charge(max_calls=2)
    assert store.reserve_sync([c], 7) is None
    assert store.reserve_sync([c], 3) is None
    assert store.usage(c) == Usage(2, 10)
    refusal = store.reserve_sync([c], 1)
    assert refusal is not None and refusal.exhausted is Exhausted.CALLS
    assert store.usage(c) == Usage(2, 10)


def test_reserve_is_all_or_nothing() -> None:
    store = InMemoryUsageStore()
    roomy, tight = charge("roomy", max_calls=10), charge("tight", max_calls=1)
    assert store.reserve_sync([roomy, tight], 0) is None
    assert store.reserve_sync([roomy, tight], 0) is not None
    assert store.usage(roomy) == Usage(1, 0)


def test_duplicate_charges_book_once() -> None:
    store = InMemoryUsageStore()
    c = charge(max_calls=5)
    assert store.reserve_sync([c, c], 4) is None
    assert store.usage(c) == Usage(1, 4)


def test_settle_adds_tokens_and_can_cross_the_limit() -> None:
    store = InMemoryUsageStore()
    c = charge(max_tokens=100)
    assert store.reserve_sync([c], 10) is None
    store.settle_sync([c], 150)
    assert store.usage(c) == Usage(1, 160)
    refusal = store.reserve_sync([c], 0)
    assert refusal is not None
    assert (refusal.exhausted, refusal.used) == (Exhausted.TOKENS, 160)


def test_settle_ignores_zero_and_unknown_counters() -> None:
    store = InMemoryUsageStore()
    c = charge(max_tokens=100)
    store.settle_sync([c], 50)
    assert len(store) == 0
    store.reserve_sync([c], 1)
    store.settle_sync([c], 0)
    assert store.usage(c) == Usage(1, 1)


def test_new_window_starts_from_zero() -> None:
    store = InMemoryUsageStore()
    today = charge(max_calls=1)
    assert store.reserve_sync([today], 0) is None
    assert store.reserve_sync([today], 0) is not None
    assert store.reserve_sync([charge(max_calls=1, now=NOW + timedelta(days=1))], 0) is None


def test_prune_forgets_ended_windows() -> None:
    store = InMemoryUsageStore()
    hourly = charge("h", window=BudgetWindow.HOUR, max_calls=5)
    daily = charge("d", max_calls=5)
    store.reserve_sync([hourly, daily], 0)
    assert store.prune(hourly.window_end) == 1
    assert store.usage(hourly) == Usage()
    assert store.usage(daily) == Usage(1, 0)


def test_memory_stays_bounded() -> None:
    store = InMemoryUsageStore(max_counters=3)
    old = charge("old", window=BudgetWindow.HOUR, max_calls=5, now=NOW - timedelta(hours=2))
    store.reserve_sync([old], 0)
    for i in range(3):
        store.reserve_sync([charge(f"b{i}", max_calls=5)], 0)
    # The ended window went first; nothing current was lost.
    assert len(store) == 3
    assert store.usage(old) == Usage()
    store.reserve_sync([charge("b3", max_calls=5)], 0)
    assert len(store) == 3
    assert store.usage(charge("b0", max_calls=5)) == Usage()  # least recently used


def test_max_counters_must_be_positive() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        InMemoryUsageStore(max_counters=0)
