"""The approval gate: what an agent sees for each state of its request."""

from __future__ import annotations

from datetime import timedelta

import pytest

from conftest import FakeClock
from mcp_warden.approval import (
    ApprovalGate,
    ApprovalPendingError,
    ApprovalTimings,
    InMemoryApprovalStore,
)
from mcp_warden.jsonrpc import ErrorCode, JsonRpcError, RetryAfterError
from mcp_warden.policy import Decision, Effect
from test_approval_stores import T0

pytestmark = pytest.mark.anyio

DECISION = Decision(Effect.REQUIRE_APPROVAL, "writes-need-a-human", "writes need sign-off")
ARGS = {"title": "Fix CI"}


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(T0)


@pytest.fixture
def store() -> InMemoryApprovalStore:
    return InMemoryApprovalStore()


def make_gate(store: InMemoryApprovalStore, clock: FakeClock, **kwargs: object) -> ApprovalGate:
    return ApprovalGate(store, ApprovalTimings(max_pending_per_agent=2), clock=clock, **kwargs)  # type: ignore[arg-type]


async def admit(gate: ApprovalGate, **arguments: object) -> str:
    return await gate.admit("bot", "github", "create_issue", dict(arguments or ARGS), DECISION)


async def test_a_new_call_is_parked(store: InMemoryApprovalStore, clock: FakeClock) -> None:
    gate = make_gate(store, clock, retry_after=7)
    with pytest.raises(ApprovalPendingError) as caught:
        await admit(gate)
    err = caught.value
    assert err.code == ErrorCode.APPROVAL_REQUIRED
    assert err.retry_after == 7
    assert err.data["status"] == "pending"
    assert err.data["rule_id"] == "writes-need-a-human"
    assert err.data["expires_at"] == "2026-10-18T09:15:00Z"
    assert err.data["approval_id"] == store.list(T0)[0].id
    # Asking again does not open a second request.
    with pytest.raises(ApprovalPendingError):
        await admit(gate)
    assert len(store) == 1


async def test_an_approved_call_is_admitted_then_claimed(
    store: InMemoryApprovalStore, clock: FakeClock
) -> None:
    gate = make_gate(store, clock)
    with pytest.raises(ApprovalPendingError) as caught:
        await admit(gate)
    approval_id = caught.value.data["approval_id"]
    store.decide(
        approval_id, approve=True, reviewer="alice", note=None, now=T0, timings=gate.timings
    )
    assert await admit(gate) == approval_id
    await gate.claim(approval_id, "github", "create_issue")
    with pytest.raises(JsonRpcError) as spent:
        await gate.claim(approval_id, "github", "create_issue")
    assert spent.value.code == ErrorCode.APPROVAL_REQUIRED
    assert "already used" in spent.value.message


async def test_a_denied_call_is_refused_with_the_note(
    store: InMemoryApprovalStore, clock: FakeClock
) -> None:
    gate = make_gate(store, clock)
    with pytest.raises(ApprovalPendingError) as caught:
        await admit(gate)
    store.decide(
        caught.value.data["approval_id"],
        approve=False,
        reviewer="bob",
        note="use the staging repo",
        now=T0,
        timings=gate.timings,
    )
    with pytest.raises(JsonRpcError) as denied:
        await admit(gate)
    assert denied.value.code == ErrorCode.POLICY_DENIED
    assert not isinstance(denied.value, RetryAfterError)
    assert denied.value.data["status"] == "denied"
    assert denied.value.data["decided_by"] == "bob"
    assert denied.value.data["note"] == "use the staging repo"


async def test_waiting_returns_a_decision_that_arrives_in_time(
    store: InMemoryApprovalStore, clock: FakeClock
) -> None:
    sleeps: list[float] = []

    async def reviewer_acts(seconds: float) -> None:
        sleeps.append(seconds)
        clock.advance(timedelta(seconds=seconds))
        if len(sleeps) == 2:
            (pending,) = store.list(clock.now)
            store.decide(
                pending.id,
                approve=True,
                reviewer="a",
                note=None,
                now=clock.now,
                timings=gate.timings,
            )

    gate = make_gate(
        store, clock, wait=timedelta(seconds=10), poll_interval=0.5, sleep=reviewer_acts
    )
    approval_id = await admit(gate)
    assert sleeps == [0.5, 0.5]
    assert store.get(approval_id).decided_by == "a"


async def test_waiting_gives_up_after_the_wait(
    store: InMemoryApprovalStore, clock: FakeClock
) -> None:
    sleeps: list[float] = []

    async def nobody(seconds: float) -> None:
        sleeps.append(seconds)
        clock.advance(timedelta(seconds=seconds))

    gate = make_gate(store, clock, wait=timedelta(seconds=3), poll_interval=1, sleep=nobody)
    with pytest.raises(ApprovalPendingError):
        await admit(gate)
    assert sleeps == [1, 1, 1]


async def test_too_many_pending_requests(store: InMemoryApprovalStore, clock: FakeClock) -> None:
    gate = make_gate(store, clock, retry_after=9)
    for n in range(2):
        with pytest.raises(ApprovalPendingError):
            await admit(gate, n=n)
    with pytest.raises(RetryAfterError) as caught:
        await admit(gate, n=2)
    assert caught.value.code == ErrorCode.RATE_LIMITED
    assert caught.value.data["pending_limit"] == 2
    assert caught.value.retry_after == 9


def test_gate_settings_are_validated(store: InMemoryApprovalStore) -> None:
    with pytest.raises(ValueError, match="wait"):
        ApprovalGate(store, wait=timedelta(seconds=-1))
    with pytest.raises(ValueError, match="positive"):
        ApprovalGate(store, poll_interval=0)
    with pytest.raises(ValueError, match="positive"):
        ApprovalGate(store, retry_after=0)
