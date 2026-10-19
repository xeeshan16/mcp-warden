"""The retention job across every store it prunes, the CLI and the gateway loop."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, text

from mcp_warden.__main__ import main
from mcp_warden.approval import (
    ApprovalTimings,
    DatabaseApprovalStore,
    InMemoryApprovalStore,
    NewApproval,
)
from mcp_warden.audit import AuditEvent, AuditQuery, DatabaseAuditStore, InMemoryAuditStore, Outcome
from mcp_warden.budget import DatabaseUsageStore
from mcp_warden.db import (
    ApprovalRequestRow,
    AuditEventRow,
    RateLimitBucket,
    UsageCounter,
    make_engine,
    make_sessionmaker,
    upgrade,
)
from mcp_warden.ratelimit import DatabaseBucketStore
from mcp_warden.retention import RetentionJob, RetentionReport

POSTGRES_URL = os.environ.get("WARDEN_TEST_POSTGRES_URL")
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
KEEP = timedelta(days=30)
TABLES = ("audit_events", "approval_requests", "usage_counters", "rate_limit_buckets")


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
        for table in TABLES:
            conn.execute(text(f"DELETE FROM {table}"))  # noqa: S608 - fixed table names
    yield pg
    pg.dispose()


def audit_event(at: datetime) -> AuditEvent:
    return AuditEvent.create(
        occurred_at=at,
        agent="bot",
        server="demo",
        method="tools/call",
        outcome=Outcome.FORWARDED,
        latency_ms=1.0,
        tool="echo",
    )


def usage_row(key: str, start: datetime, end: datetime) -> UsageCounter:
    return UsageCounter(
        key=key,
        window_start=start,
        window_end=end,
        budget_id="daily",
        agent="bot",
        calls=1,
        tokens=10,
        updated_at=start,
    )


def count(engine: Engine, model: type) -> int:
    with engine.connect() as conn:
        return int(conn.execute(select(func.count()).select_from(model)).scalar_one())


def seed(engine: Engine) -> None:
    sessions = make_sessionmaker(engine)
    DatabaseAuditStore(sessions).append(
        [audit_event(NOW - timedelta(days=40)), audit_event(NOW - timedelta(days=1))]
    )
    approvals = DatabaseApprovalStore(sessions)
    timings = ApprovalTimings()
    old = NOW - timedelta(days=31)
    approvals.open(NewApproval("bot", "demo", "t", {"n": 1}, None, "r"), old, timings)
    approvals.open(NewApproval("bot", "demo", "t", {"n": 2}, None, "r"), NOW, timings)
    epoch = NOW.timestamp()
    with sessions.begin() as session:
        session.add_all(
            [
                usage_row("a" * 64, NOW - timedelta(days=40), NOW - timedelta(days=39)),
                usage_row("b" * 64, NOW - timedelta(days=2), NOW - timedelta(days=1)),
                usage_row("c" * 64, NOW.replace(hour=0), NOW.replace(hour=0) + timedelta(days=1)),
                RateLimitBucket(key="d" * 64, tokens=1, updated_at=epoch, full_at=epoch - 5),
                RateLimitBucket(key="e" * 64, tokens=1, updated_at=epoch, full_at=epoch + 60),
            ]
        )


def job(engine: Engine) -> RetentionJob:
    sessions = make_sessionmaker(engine)
    return RetentionJob(
        KEEP,
        audit=DatabaseAuditStore(sessions),
        approvals=DatabaseApprovalStore(sessions),
        usage=DatabaseUsageStore(sessions),
        buckets=DatabaseBucketStore(sessions, clock=NOW.timestamp),
        clock=lambda: NOW,
    )


def test_one_run_prunes_every_store(engine: Engine) -> None:
    seed(engine)
    report = job(engine).run()
    assert report == RetentionReport(NOW - KEEP, 1, 1, 1, 1)
    assert report.to_dict() == {
        "cutoff": "2026-09-19T12:00:00Z",
        "audit_events": 1,
        "approval_requests": 1,
        "usage_counters": 1,
        "rate_limit_buckets": 1,
    }
    assert [count(engine, m) for m in (AuditEventRow, ApprovalRequestRow)] == [1, 1]
    assert [count(engine, m) for m in (UsageCounter, RateLimitBucket)] == [2, 1]
    # A second run finds nothing more.
    assert job(engine).run() == RetentionReport(NOW - KEEP, 0, 0, 0, 0)


def test_steps_without_a_store_are_skipped() -> None:
    audit = InMemoryAuditStore()
    audit.append([audit_event(NOW - timedelta(days=31)), audit_event(NOW)])
    report = RetentionJob(KEEP, audit=audit, clock=lambda: NOW).run()
    assert report == RetentionReport(NOW - KEEP, audit_events=1)
    assert len(audit) == 1
    assert RetentionJob(KEEP, approvals=InMemoryApprovalStore(), clock=lambda: NOW).run() == (
        RetentionReport(NOW - KEEP, approval_requests=0)
    )


def test_the_period_must_be_positive() -> None:
    with pytest.raises(ValueError, match="positive"):
        RetentionJob(timedelta(0))


@pytest.mark.anyio
async def test_periodic_runs_survive_failures(caplog: pytest.LogCaptureFixture) -> None:
    class Flaky(InMemoryAuditStore):
        calls = 0

        def prune(self, before: datetime) -> int:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("database unavailable")
            return super().prune(before)

    store = Flaky()
    slept: list[float] = []

    async def sleep(seconds: float) -> None:
        slept.append(seconds)

    caplog.set_level("INFO", logger="mcp_warden.retention")
    await RetentionJob(KEEP, audit=store, clock=lambda: NOW).run_periodically(
        60, sleep=sleep, runs=3
    )
    assert slept == [60, 60, 60] and store.calls == 3
    assert "retention run failed" in caplog.text
    assert caplog.text.count("retention run: ") == 2
    with pytest.raises(ValueError, match="positive"):
        await RetentionJob(KEEP).run_periodically(0)


def test_the_gateway_runs_the_job_and_stops_it_on_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gateway_helpers import make_client

    cancelled: list[bool] = []

    async def fake_loop(self: RetentionJob, interval: float) -> None:
        assert interval == 3600
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            cancelled.append(True)
            raise

    monkeypatch.setattr(RetentionJob, "run_periodically", fake_loop)
    client: TestClient = make_client(retention_interval_seconds=3600)
    with client:
        assert client.get("/healthz").status_code == 200
        assert client.app.state.retention.audit is not None  # type: ignore[attr-defined]
    assert cancelled == [True]


def test_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    url = f"sqlite:///{tmp_path / 'r.db'}"
    assert main(["db", "upgrade", "--database-url", url]) == 0
    engine = make_engine(url)
    sessions = make_sessionmaker(engine)
    now = datetime.now(UTC)
    DatabaseAuditStore(sessions).append(
        [audit_event(now - timedelta(days=10)), audit_event(now - timedelta(hours=1))]
    )
    capsys.readouterr()
    assert main(["retention", "--database-url", url]) == 0
    assert capsys.readouterr().out.startswith("removed 0 audit events")
    assert main(["retention", "--days", "7", "--database-url", url]) == 0
    out = capsys.readouterr().out
    assert out.startswith("removed 1 audit events, 0 approval requests and 0 usage counters")
    assert "0 refilled rate-limit buckets" in out
    assert len(DatabaseAuditStore(sessions).query(AuditQuery()).events) == 1
    engine.dispose()
    for bad in ("0", "-1", "x", "4000"):
        with pytest.raises(SystemExit):
            main(["retention", "--days", bad, "--database-url", url])
    assert main(["retention", "--database-url", f"sqlite:///{tmp_path / 'none.db'}"]) == 1
