"""Both audit stores against one contract; PostgreSQL too when configured."""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, text

from mcp_warden.audit import (
    AuditEvent,
    AuditQuery,
    AuditStore,
    Cursor,
    DatabaseAuditStore,
    InMemoryAuditStore,
    Outcome,
)
from mcp_warden.db import make_engine, make_sessionmaker, upgrade

POSTGRES_URL = os.environ.get("WARDEN_TEST_POSTGRES_URL")
T0 = datetime(2026, 10, 19, 9, 0, tzinfo=UTC)


def event(minute: int = 0, **overrides: object) -> AuditEvent:
    fields: dict[str, object] = {
        "occurred_at": T0 + timedelta(minutes=minute),
        "agent": "bot",
        "server": "demo",
        "method": "tools/call",
        "outcome": Outcome.FORWARDED,
        "latency_ms": 2.25,
        "tool": "echo",
    }
    fields.update(overrides)
    return AuditEvent.create(**fields)  # type: ignore[arg-type]


@pytest.fixture(params=["memory", "sqlite", "postgresql"])
def store(request: pytest.FixtureRequest, db_engine: Engine) -> Iterator[AuditStore]:
    if request.param == "memory":
        yield InMemoryAuditStore()
        return
    if request.param == "sqlite":
        yield DatabaseAuditStore(make_sessionmaker(db_engine))
        return
    if not POSTGRES_URL:
        pytest.skip("WARDEN_TEST_POSTGRES_URL is not set")
    pg = make_engine(POSTGRES_URL)
    upgrade(pg)
    with pg.begin() as conn:
        conn.execute(text("DELETE FROM audit_events"))
    yield DatabaseAuditStore(make_sessionmaker(pg))
    pg.dispose()


def ids(events: list[AuditEvent]) -> list[str]:
    return [e.id for e in events]


def test_events_round_trip_unchanged(store: AuditStore) -> None:
    full = event(
        effect="require_approval",
        rule_id="urgent",
        approval_id="apr_123",
        error_code=-32002,
        tool_error=False,
        arguments_digest="ab" * 32,
        arguments_size=42,
        occurred_at=T0 + timedelta(microseconds=123_456),
    )
    bare = event(1, tool=None, method="initialize", outcome=Outcome.UPSTREAM_ERROR)
    store.append([full, bare])
    assert store.query(AuditQuery()).events == [bare, full]


def test_newest_first_regardless_of_arrival_order(store: AuditStore) -> None:
    late, early = event(5), event(1)
    store.append([late])
    store.append([early])
    assert ids(store.query(AuditQuery()).events) == [late.id, early.id]


def test_filters_combine(store: AuditStore) -> None:
    a = event(0)
    b = event(1, agent="other")
    c = event(2, tool="add", outcome=Outcome.DENIED, error_code=-32001)
    d = event(3, server="github", tool="create_issue")
    e = event(4, method="tools/list", tool=None)
    store.append([a, b, c, d, e])
    assert ids(store.query(AuditQuery(agent="other")).events) == [b.id]
    assert ids(store.query(AuditQuery(tool="add")).events) == [c.id]
    assert ids(store.query(AuditQuery(server="github")).events) == [d.id]
    assert ids(store.query(AuditQuery(method="tools/list")).events) == [e.id]
    assert ids(store.query(AuditQuery(outcome=Outcome.DENIED)).events) == [c.id]
    assert ids(store.query(AuditQuery(agent="bot", server="demo", tool="echo")).events) == [a.id]
    window = AuditQuery(since=T0 + timedelta(minutes=1), until=T0 + timedelta(minutes=3))
    assert ids(store.query(window).events) == [c.id, b.id]


def test_pages_cover_everything_once_even_with_equal_times(store: AuditStore) -> None:
    # Seven events, three sharing one timestamp: the id breaks the tie.
    events = [event(m) for m in (0, 1, 1, 1, 2, 3, 4)]
    store.append(events)
    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        page = store.query(AuditQuery(limit=2, cursor=cursor))
        pages += 1
        seen += ids(page.events)
        if page.next_cursor is None:
            break
        cursor = Cursor.decode(page.next_cursor)
    assert pages == 4
    assert sorted(seen) == sorted(ids(events)) and len(seen) == len(set(seen))
    expected = sorted(events, key=lambda e: (e.occurred_at, e.id), reverse=True)
    assert seen == ids(expected)


def test_a_full_last_page_has_no_cursor(store: AuditStore) -> None:
    store.append([event(0), event(1)])
    page = store.query(AuditQuery(limit=2))
    assert len(page.events) == 2 and page.next_cursor is None


def test_new_events_do_not_shift_later_pages(store: AuditStore) -> None:
    store.append([event(m) for m in range(4)])
    first = store.query(AuditQuery(limit=2))
    store.append([event(10)])  # newer than everything already listed
    assert first.next_cursor is not None
    second = store.query(AuditQuery(limit=2, cursor=Cursor.decode(first.next_cursor)))
    assert [e.occurred_at.minute for e in second.events] == [1, 0]


def test_prune_removes_only_older_events(store: AuditStore) -> None:
    old, edge, new = event(0), event(10), event(20)
    store.append([old, edge, new])
    assert store.prune(T0 + timedelta(minutes=10)) == 1
    assert ids(store.query(AuditQuery()).events) == [new.id, edge.id]
    assert store.prune(T0) == 0


def test_appending_nothing_is_a_no_op(store: AuditStore) -> None:
    store.append([])
    assert store.query(AuditQuery()).events == []


def test_memory_store_is_bounded() -> None:
    store = InMemoryAuditStore(max_events=3)
    store.append([event(m) for m in range(5)])
    assert len(store) == 3
    assert [e.occurred_at.minute for e in store.query(AuditQuery()).events] == [4, 3, 2]
    with pytest.raises(ValueError, match="max_events"):
        InMemoryAuditStore(0)
