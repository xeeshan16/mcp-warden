"""Both approval stores against one contract; PostgreSQL too when configured.

Set ``WARDEN_TEST_POSTGRES_URL`` to also run the database store against
PostgreSQL, including the concurrency tests that rely on the unique
``open_key`` and on conditional updates.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, text

from mcp_warden.approval import (
    ApprovalConflictError,
    ApprovalNotFoundError,
    ApprovalStatus,
    ApprovalStore,
    ApprovalTimings,
    DatabaseApprovalStore,
    InMemoryApprovalStore,
    NewApproval,
    TooManyPendingError,
    fingerprint,
)
from mcp_warden.db import make_engine, make_sessionmaker, upgrade

POSTGRES_URL = os.environ.get("WARDEN_TEST_POSTGRES_URL")
T0 = datetime(2026, 10, 18, 9, 0, tzinfo=UTC)
TIMINGS = ApprovalTimings(
    pending_ttl=timedelta(minutes=15), decision_ttl=timedelta(minutes=10), max_pending_per_agent=3
)


def new(agent: str = "bot", tool: str = "create_issue", **arguments: Any) -> NewApproval:
    return NewApproval(
        agent, "github", tool, arguments or {"title": "t"}, "writes-need-a-human", "writes"
    )


@pytest.fixture(params=["memory", "sqlite", "postgresql"])
def store(request: pytest.FixtureRequest, db_engine: Engine) -> Iterator[ApprovalStore]:
    if request.param == "memory":
        yield InMemoryApprovalStore()
        return
    if request.param == "sqlite":
        yield DatabaseApprovalStore(make_sessionmaker(db_engine))
        return
    if not POSTGRES_URL:
        pytest.skip("WARDEN_TEST_POSTGRES_URL is not set")
    pg = make_engine(POSTGRES_URL)
    upgrade(pg)
    with pg.begin() as conn:
        conn.execute(text("DELETE FROM approval_requests"))
    yield DatabaseApprovalStore(make_sessionmaker(pg))
    pg.dispose()


def approve(store: ApprovalStore, approval_id: str, now: datetime = T0) -> None:
    store.decide(approval_id, approve=True, reviewer="alice", note=None, now=now, timings=TIMINGS)


def test_open_creates_a_pending_request(store: ApprovalStore) -> None:
    request = store.open(new(title="Fix CI"), T0, TIMINGS)
    assert request.id.startswith("apr_")
    assert request.status is ApprovalStatus.PENDING
    assert request.arguments == {"title": "Fix CI"}
    assert request.arguments_size == len('{"title":"Fix CI"}')
    assert request.expires_at == T0 + TIMINGS.pending_ttl
    assert (request.agent, request.server, request.tool) == ("bot", "github", "create_issue")
    assert request.rule_id == "writes-need-a-human"
    assert store.get(request.id) == request


def test_the_same_call_finds_the_same_request(store: ApprovalStore) -> None:
    first = store.open(new(a=1, b=[1, 2]), T0, TIMINGS)
    again = store.open(
        NewApproval("bot", "github", "create_issue", {"b": [1, 2], "a": 1}, None, ""),
        T0 + timedelta(minutes=5),
        TIMINGS,
    )
    assert again.id == first.id


@pytest.mark.parametrize(
    "other",
    [
        new(title="other"),
        new(agent="other-bot"),
        new(tool="update_issue"),
        NewApproval("bot", "gitlab", "create_issue", {"title": "t"}, None, ""),
    ],
)
def test_any_difference_is_a_different_request(store: ApprovalStore, other: NewApproval) -> None:
    assert store.open(new(), T0, TIMINGS).id != store.open(other, T0, TIMINGS).id


def test_fingerprint_ignores_key_order() -> None:
    assert fingerprint("a", "s", "t", {"x": 1, "y": 2}) == fingerprint(
        "a", "s", "t", {"y": 2, "x": 1}
    )
    assert fingerprint("a", "s", "t", {"x": 1}) != fingerprint("a", "s", "t", {"x": "1"})


def test_approval_is_spent_exactly_once(store: ApprovalStore) -> None:
    request = store.open(new(), T0, TIMINGS)
    assert not store.claim(request.id, T0)  # still pending
    approve(store, request.id)
    assert store.open(new(), T0, TIMINGS).status is ApprovalStatus.APPROVED
    assert store.claim(request.id, T0 + timedelta(minutes=1))
    assert not store.claim(request.id, T0 + timedelta(minutes=1))
    spent = store.get(request.id)
    assert spent.status is ApprovalStatus.EXECUTED
    assert spent.executed_at == T0 + timedelta(minutes=1)
    assert spent.arguments is None  # only the digest and size remain
    assert spent.arguments_digest == request.arguments_digest
    # The fingerprint is free again: the next identical call needs a new approval.
    fresh = store.open(new(), T0 + timedelta(minutes=2), TIMINGS)
    assert fresh.id != request.id
    assert fresh.status is ApprovalStatus.PENDING


def test_decide_records_the_reviewer_and_restarts_the_clock(store: ApprovalStore) -> None:
    request = store.open(new(), T0, TIMINGS)
    later = T0 + timedelta(minutes=14)
    decided = store.decide(
        request.id, approve=True, reviewer="alice", note="ok", now=later, timings=TIMINGS
    )
    assert decided.status is ApprovalStatus.APPROVED
    assert (decided.decided_by, decided.note, decided.decided_at) == ("alice", "ok", later)
    assert decided.expires_at == later + TIMINGS.decision_ttl
    assert decided.arguments == {"title": "t"}


def test_an_unused_approval_expires(store: ApprovalStore) -> None:
    request = store.open(new(), T0, TIMINGS)
    approve(store, request.id)
    after = T0 + TIMINGS.decision_ttl
    assert not store.claim(request.id, after)
    assert store.get(request.id).state(after) is ApprovalStatus.EXPIRED
    reopened = store.open(new(), after, TIMINGS)
    assert reopened.id != request.id
    assert store.get(request.id).status is ApprovalStatus.EXPIRED


def test_a_denial_is_repeated_while_it_holds(store: ApprovalStore) -> None:
    request = store.open(new(), T0, TIMINGS)
    denied = store.decide(
        request.id, approve=False, reviewer="bob", note="no", now=T0, timings=TIMINGS
    )
    assert denied.status is ApprovalStatus.DENIED
    assert denied.arguments is None
    assert not store.claim(request.id, T0)
    repeat = store.open(new(), T0 + timedelta(minutes=9), TIMINGS)
    assert repeat.id == request.id
    assert repeat.status is ApprovalStatus.DENIED
    assert store.open(new(), T0 + timedelta(minutes=10), TIMINGS).id != request.id


def test_a_request_nobody_decided_expires(store: ApprovalStore) -> None:
    request = store.open(new(), T0, TIMINGS)
    after = T0 + TIMINGS.pending_ttl
    with pytest.raises(ApprovalConflictError, match="expired"):
        approve(store, request.id, after)
    assert store.open(new(), after, TIMINGS).id != request.id


@pytest.mark.parametrize("approve_first", [True, False])
def test_only_pending_requests_can_be_decided(store: ApprovalStore, approve_first: bool) -> None:
    request = store.open(new(), T0, TIMINGS)
    store.decide(
        request.id, approve=approve_first, reviewer="a", note=None, now=T0, timings=TIMINGS
    )
    for verdict in (True, False):
        with pytest.raises(ApprovalConflictError):
            store.decide(
                request.id, approve=verdict, reviewer="b", note=None, now=T0, timings=TIMINGS
            )
    assert store.get(request.id).decided_by == "a"


def test_unknown_ids(store: ApprovalStore) -> None:
    with pytest.raises(ApprovalNotFoundError):
        store.get("apr_missing")
    with pytest.raises(ApprovalNotFoundError):
        approve(store, "apr_missing")
    assert not store.claim("apr_missing", T0)


def test_pending_requests_are_capped_per_agent(store: ApprovalStore) -> None:
    ids = [store.open(new(n=n), T0, TIMINGS).id for n in range(3)]
    with pytest.raises(TooManyPendingError):
        store.open(new(n=99), T0, TIMINGS)
    # Repeats of a waiting call and other agents are unaffected.
    assert store.open(new(n=0), T0, TIMINGS).id == ids[0]
    store.open(new(agent="other", n=99), T0, TIMINGS)
    # Deciding one frees a slot, and so does expiry.
    approve(store, ids[0])
    store.open(new(n=3), T0, TIMINGS)
    store.open(new(n=4), T0 + TIMINGS.pending_ttl, TIMINGS)


def test_list_filters_by_status_as_of_now(store: ApprovalStore) -> None:
    pending = store.open(new(n=1), T0, TIMINGS)
    approved = store.open(new(n=2), T0 + timedelta(seconds=1), TIMINGS)
    denied = store.open(new(n=3), T0 + timedelta(seconds=2), TIMINGS)
    other = store.open(new(agent="other"), T0 + timedelta(seconds=3), TIMINGS)
    approve(store, approved.id)
    store.decide(denied.id, approve=False, reviewer="b", note=None, now=T0, timings=TIMINGS)

    def ids(now: datetime = T0, **kwargs: Any) -> list[str]:
        return [r.id for r in store.list(now, **kwargs)]

    assert ids() == [other.id, denied.id, approved.id, pending.id]
    assert ids(status=ApprovalStatus.PENDING) == [other.id, pending.id]
    assert ids(status=ApprovalStatus.PENDING, agent="bot") == [pending.id]
    assert ids(status=ApprovalStatus.APPROVED) == [approved.id]
    assert ids(status=ApprovalStatus.DENIED) == [denied.id]
    assert ids(limit=1) == [other.id]
    later = T0 + TIMINGS.pending_ttl + timedelta(seconds=10)
    assert ids(later, status=ApprovalStatus.PENDING) == []
    assert set(ids(later, status=ApprovalStatus.EXPIRED)) == {
        other.id,
        denied.id,
        approved.id,
        pending.id,
    }
    store.claim(approved.id, T0)
    assert ids(later, status=ApprovalStatus.EXECUTED) == [approved.id]


def test_to_dict_reports_the_current_state(store: ApprovalStore) -> None:
    request = store.open(new(), T0, TIMINGS)
    view = request.to_dict(T0 + TIMINGS.pending_ttl)
    assert view["status"] == "expired"
    assert view["created_at"] == "2026-10-18T09:00:00Z"
    assert view["arguments"] == {"title": "t"}


def test_long_labels_are_cut_but_still_distinguished(store: ApprovalStore) -> None:
    long_a = NewApproval("bot", "github", "x" * 250 + "a", {}, None, "r" * 600)
    long_b = NewApproval("bot", "github", "x" * 250 + "b", {}, None, "")
    a = store.open(long_a, T0, TIMINGS)
    assert len(a.tool) == 200
    assert len(a.reason) == 500
    assert store.open(long_b, T0, TIMINGS).id != a.id


def test_memory_store_is_bounded() -> None:
    store = InMemoryApprovalStore(max_requests=3)
    first = store.open(new(n=0), T0, TIMINGS)
    approve(store, first.id)
    assert store.claim(first.id, T0)
    kept = [store.open(new(agent=f"a{n}"), T0, TIMINGS).id for n in range(3)]
    assert len(store) == 3
    with pytest.raises(ApprovalNotFoundError):
        store.get(first.id)  # the finished request went first
    store.open(new(agent="a9"), T0, TIMINGS)
    assert len(store) == 3
    with pytest.raises(ApprovalNotFoundError):
        store.get(kept[0])  # then the oldest of any kind
    with pytest.raises(ValueError, match="max_requests"):
        InMemoryApprovalStore(max_requests=0)


def test_timings_are_validated() -> None:
    with pytest.raises(ValueError, match="TTL"):
        ApprovalTimings(pending_ttl=timedelta(0))
    with pytest.raises(ValueError, match="max_pending"):
        ApprovalTimings(max_pending_per_agent=0)


@pytest.fixture
def pg_store() -> Iterator[DatabaseApprovalStore]:
    if not POSTGRES_URL:
        pytest.skip("WARDEN_TEST_POSTGRES_URL is not set")
    pg = make_engine(POSTGRES_URL, pool_size=10)
    upgrade(pg)
    with pg.begin() as conn:
        conn.execute(text("DELETE FROM approval_requests"))
    yield DatabaseApprovalStore(make_sessionmaker(pg))
    pg.dispose()


def _race(n: int, work: Any) -> list[Any]:
    barrier = threading.Barrier(n)
    results: list[Any] = [None] * n

    def run(i: int) -> None:
        barrier.wait()
        results[i] = work()

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def test_postgres_concurrent_identical_calls_open_one_request(
    pg_store: DatabaseApprovalStore,
) -> None:
    sessions = pg_store._sessions
    stores = [DatabaseApprovalStore(sessions) for _ in range(4)]
    counter = iter(range(1000))
    lock = threading.Lock()

    def open_one() -> str:
        with lock:
            i = next(counter)
        return stores[i % 4].open(new(), T0, TIMINGS).id

    ids = _race(8, open_one)
    assert len(set(ids)) == 1
    assert len(pg_store.list(T0)) == 1


def test_postgres_an_approval_is_claimed_once(pg_store: DatabaseApprovalStore) -> None:
    request = pg_store.open(new(), T0, TIMINGS)
    approve(pg_store, request.id)
    results = _race(8, lambda: DatabaseApprovalStore(pg_store._sessions).claim(request.id, T0))
    assert results.count(True) == 1


def test_prune_removes_finished_requests_only(store: ApprovalStore) -> None:
    pending = store.open(new(title="pending"), T0, TIMINGS)
    denied = store.open(new(title="denied"), T0, TIMINGS)
    store.decide(denied.id, approve=False, reviewer="a", note=None, now=T0, timings=TIMINGS)
    executed = store.open(new(title="executed"), T0, TIMINGS)
    approve(store, executed.id)
    assert store.claim(executed.id, T0 + timedelta(minutes=1))
    approved = store.open(new(title="approved"), T0, TIMINGS)
    approve(store, approved.id)

    # Nothing has finished long enough ago yet.
    assert store.prune(T0) == 0
    # Executed at +1m; decision windows end at +10m, the pending one at +15m.
    assert store.prune(T0 + timedelta(minutes=2)) == 1
    with pytest.raises(ApprovalNotFoundError):
        store.get(executed.id)
    assert store.prune(T0 + timedelta(minutes=11)) == 2  # the denial and the unused approval
    assert store.get(pending.id).status is ApprovalStatus.PENDING
    assert store.prune(T0 + timedelta(minutes=16)) == 1
    assert store.list(T0 + timedelta(days=1)) == []
    # The fingerprint was released with the request: the same call opens a new one.
    assert store.open(new(title="pending"), T0 + timedelta(days=1), TIMINGS).id != pending.id
