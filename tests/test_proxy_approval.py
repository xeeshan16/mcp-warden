"""Human approval end to end: agent → gateway → fake upstream, plus the admin API and CLI."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from conftest import FakeClock, FakeMonotonic
from gateway_helpers import EXAMPLE_POLICY, initialize, rpc
from mcp_warden import __main__ as cli
from mcp_warden.__main__ import main
from mcp_warden.app import create_app
from mcp_warden.approval import (
    ApprovalGate,
    ApprovalStatus,
    ApprovalTimings,
    DatabaseApprovalStore,
    InMemoryApprovalStore,
    NewApproval,
)
from mcp_warden.config import ApprovalStoreKind, AuthMode, Settings
from mcp_warden.db import make_engine, make_sessionmaker
from mcp_warden.fake_upstream import create_fake_upstream
from mcp_warden.identity import TrustedHeaderAuthenticator
from mcp_warden.jsonrpc import ErrorCode
from mcp_warden.policy import PolicyEngine, load_policy_file, parse_policy
from mcp_warden.proxy import HttpUpstreamClient, PolicyGuard, ProxyService
from mcp_warden.ratelimit import InMemoryBucketStore
from mcp_warden.upstreams import Upstream, UpstreamRegistry
from test_approval_stores import T0

TOKEN = "admin-token-for-tests-only"  # noqa: S105 - test fixture, not a secret
ADMIN = {"authorization": f"Bearer {TOKEN}"}
URGENT = {"title": "Database is down", "priority": "urgent"}


class RecordingUpstream:
    """The fake upstream behind a recorder, so tests see what was forwarded."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.app = create_fake_upstream()

    def transport(self) -> HttpUpstreamClient:
        inner = httpx.ASGITransport(app=self.app)
        calls = self.calls

        class Recording(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                body = request.content.decode()
                if '"tools/call"' in body:
                    calls.append(body)
                return await inner.handle_async_request(request)

        return HttpUpstreamClient(httpx.AsyncClient(transport=Recording()))


@pytest.fixture
def upstream() -> RecordingUpstream:
    return RecordingUpstream()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(T0)


def gateway(
    upstream: RecordingUpstream,
    clock: FakeClock,
    *,
    engine: PolicyEngine | None = None,
    store: Any = None,
    **settings: Any,
) -> TestClient:
    settings.setdefault("admin_token", TOKEN)
    cfg = Settings(
        policy_path=EXAMPLE_POLICY,
        upstreams_path=None,
        auth_mode=AuthMode.TRUSTED_HEADER,
        **settings,
    )
    gate = None
    if store is not None or "approval_store" not in settings:
        gate = ApprovalGate(
            store or InMemoryApprovalStore(),
            ApprovalTimings(max_pending_per_agent=cfg.approval_max_pending_per_agent),
            clock=clock,
        )
    app = create_app(
        cfg,
        engine=engine or PolicyEngine(load_policy_file(EXAMPLE_POLICY)),
        upstreams=UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})]),
        transport=upstream.transport(),
        bucket_store=InMemoryBucketStore(clock=FakeMonotonic()),
        approval_gate=gate,
    )
    return TestClient(app)


def session(client: TestClient, agent: str = "support-bot") -> dict[str, str]:
    headers = initialize(client)
    headers["x-warden-agent"] = agent
    return headers


def ticket(client: TestClient, headers: dict[str, str], **arguments: Any) -> httpx.Response:
    return client.post(
        "/mcp/demo",
        json=rpc("t", "tools/call", {"name": "create_ticket", "arguments": arguments or URGENT}),
        headers=headers,
    )


def decide(client: TestClient, approval_id: str, verdict: str, **body: Any) -> httpx.Response:
    body.setdefault("reviewer", "alice")
    return client.post(f"/v1/approvals/{approval_id}/{verdict}", json=body, headers=ADMIN)


def test_urgent_ticket_waits_for_a_human_then_runs_once(
    upstream: RecordingUpstream, clock: FakeClock
) -> None:
    with gateway(upstream, clock) as client:
        headers = session(client)
        first = ticket(client, headers)
        assert first.status_code == 200
        assert first.headers["retry-after"] == "5"
        error = first.json()["error"]
        assert error["code"] == ErrorCode.APPROVAL_REQUIRED
        assert error["data"]["status"] == "pending"
        assert error["data"]["rule_id"] == "urgent-tickets-need-a-human"
        approval_id = error["data"]["approval_id"]
        assert upstream.calls == []

        queue = client.get("/v1/approvals?status=pending", headers=ADMIN).json()["approvals"]
        assert [a["id"] for a in queue] == [approval_id]
        assert queue[0]["arguments"] == URGENT
        assert queue[0]["agent"] == "support-bot"

        # Still waiting: the same request, nothing forwarded.
        assert ticket(client, headers).json()["error"]["data"]["approval_id"] == approval_id
        assert upstream.calls == []

        decided = decide(client, approval_id, "approve", note="on-call agrees")
        assert decided.status_code == 200
        assert decided.json()["status"] == "approved"

        done = ticket(client, headers)
        assert "retry-after" not in done.headers
        assert done.json()["result"]["content"][0]["text"].startswith("created ticket T-")
        assert len(upstream.calls) == 1
        view = client.get(f"/v1/approvals/{approval_id}", headers=ADMIN).json()
        assert view["status"] == "executed"
        assert view["arguments"] is None

        # One approval, one execution: the next identical call needs a new one.
        again = ticket(client, headers).json()["error"]
        assert again["code"] == ErrorCode.APPROVAL_REQUIRED
        assert again["data"]["approval_id"] != approval_id
        assert len(upstream.calls) == 1


def test_an_approval_does_not_cover_other_arguments(
    upstream: RecordingUpstream, clock: FakeClock
) -> None:
    with gateway(upstream, clock) as client:
        headers = session(client)
        approval_id = ticket(client, headers).json()["error"]["data"]["approval_id"]
        decide(client, approval_id, "approve")
        other = ticket(client, headers, title="Something else", priority="urgent").json()
        assert other["error"]["data"]["approval_id"] != approval_id
        # ...and another agent cannot use it either (the example policy denies it outright).
        bot = session(client, "triage-bot")
        assert ticket(client, bot).json()["error"]["code"] == ErrorCode.POLICY_DENIED
        assert upstream.calls == []
        assert "result" in ticket(client, headers).json()


def test_a_denied_call_is_refused_with_the_reviewers_note(
    upstream: RecordingUpstream, clock: FakeClock
) -> None:
    with gateway(upstream, clock) as client:
        headers = session(client)
        approval_id = ticket(client, headers).json()["error"]["data"]["approval_id"]
        assert decide(client, approval_id, "deny", note="not an outage").status_code == 200
        for _ in range(2):
            refused = ticket(client, headers)
            assert "retry-after" not in refused.headers
            error = refused.json()["error"]
            assert error["code"] == ErrorCode.POLICY_DENIED
            assert error["data"]["note"] == "not an outage"
            assert error["data"]["decided_by"] == "alice"
        assert upstream.calls == []
        # Once the denial lapses the agent may ask again.
        clock.advance(timedelta(minutes=10))
        fresh = ticket(client, headers).json()["error"]
        assert fresh["code"] == ErrorCode.APPROVAL_REQUIRED
        assert fresh["data"]["approval_id"] != approval_id


def test_deciding_twice_or_late_conflicts(upstream: RecordingUpstream, clock: FakeClock) -> None:
    with gateway(upstream, clock) as client:
        headers = session(client)
        approval_id = ticket(client, headers).json()["error"]["data"]["approval_id"]
        assert decide(client, approval_id, "deny").status_code == 200
        assert decide(client, approval_id, "approve").status_code == 409
        assert decide(client, "apr_nope", "approve").status_code == 404
        late = ticket(client, headers, title="late", priority="urgent")
        late_id = late.json()["error"]["data"]["approval_id"]
        clock.advance(timedelta(minutes=15))
        conflict = decide(client, late_id, "approve")
        assert conflict.status_code == 409
        assert "expired" in conflict.json()["detail"]


def test_a_rate_limited_approved_call_keeps_its_approval(
    upstream: RecordingUpstream, clock: FakeClock
) -> None:
    policy: dict[str, Any] = {
        "version": 1,
        "default": "allow",
        "rules": [{"id": "gate-adds", "effect": "require_approval", "tools": ["add"]}],
        "rate_limits": [{"id": "one-add", "tools": ["add"], "requests": 1, "per": "hour"}],
    }
    with gateway(upstream, clock, engine=PolicyEngine(parse_policy(policy))) as client:
        headers = session(client)

        def add(a: int) -> dict[str, Any]:
            body = rpc(a, "tools/call", {"name": "add", "arguments": {"a": a, "b": 1}})
            result: dict[str, Any] = client.post("/mcp/demo", json=body, headers=headers).json()
            return result

        ids = [add(n)["error"]["data"]["approval_id"] for n in (1, 2)]
        for approval_id in ids:
            decide(client, approval_id, "approve")
        assert add(1)["result"]["structuredContent"] == {"sum": 2}
        limited = add(2)["error"]
        assert limited["code"] == ErrorCode.RATE_LIMITED
        listed = client.get("/v1/approvals?status=approved", headers=ADMIN).json()
        assert [a["id"] for a in listed["approvals"]] == [ids[1]]


def test_pending_calls_are_capped_per_agent(upstream: RecordingUpstream, clock: FakeClock) -> None:
    with gateway(upstream, clock, approval_max_pending_per_agent=2) as client:
        headers = session(client)
        for n in range(2):
            assert (
                ticket(client, headers, title=f"t{n}", priority="urgent").json()["error"]["code"]
                == ErrorCode.APPROVAL_REQUIRED
            )
        capped = ticket(client, headers, title="t2", priority="urgent")
        assert capped.json()["error"]["code"] == ErrorCode.RATE_LIMITED
        assert capped.headers["retry-after"] == "5"


def test_admin_api_needs_the_token(upstream: RecordingUpstream, clock: FakeClock) -> None:
    with gateway(upstream, clock) as client:
        missing = client.get("/v1/approvals")
        assert missing.status_code == 401
        assert missing.headers["www-authenticate"] == 'Bearer realm="mcp-warden-admin"'
        wrong = client.get("/v1/approvals", headers={"authorization": "Bearer nope"})
        assert wrong.status_code == 401
        assert client.post("/v1/approvals/apr_x/approve", json={"reviewer": "a"}).status_code == 401
        # The agent's own identity header is no admin credential.
        assert client.get("/v1/approvals", headers={"x-warden-agent": "admin"}).status_code == 401
    with gateway(upstream, clock, admin_token=None) as client:
        off = client.get("/v1/approvals", headers=ADMIN)
        assert off.status_code == 503
        assert "WARDEN_ADMIN_TOKEN" in off.json()["detail"]


def test_admin_api_validates_input(upstream: RecordingUpstream, clock: FakeClock) -> None:
    with gateway(upstream, clock) as client:
        headers = session(client)
        approval_id = ticket(client, headers).json()["error"]["data"]["approval_id"]
        bad = client.post(
            f"/v1/approvals/{approval_id}/approve", json={"reviewer": "<script>"}, headers=ADMIN
        )
        assert bad.status_code == 422
        long_note = decide(client, approval_id, "approve", note="x" * 501)
        assert long_note.status_code == 422
        assert client.get("/v1/approvals?status=bogus", headers=ADMIN).status_code == 422
        assert client.get("/v1/approvals?limit=0", headers=ADMIN).status_code == 422
        assert client.get(f"/v1/approvals/{'a' * 65}", headers=ADMIN).status_code == 422
        assert client.get("/v1/approvals/apr_nope", headers=ADMIN).status_code == 404


def test_short_admin_tokens_are_rejected() -> None:
    with pytest.raises(ValueError, match="at least 16"):
        Settings(admin_token="short")  # noqa: S106


def test_batch_entries_are_parked_independently(upstream: RecordingUpstream) -> None:
    # Retry-After is only set on single responses, as for rate limits.
    with gateway(upstream, FakeClock(T0)) as client:
        headers = {**session(client), "mcp-protocol-version": "2025-03-26"}
        batch = [
            rpc(1, "tools/call", {"name": "create_ticket", "arguments": URGENT}),
            rpc(2, "tools/call", {"name": "echo", "arguments": {"text": "hi"}}),
        ]
        replies = {r["id"]: r for r in client.post("/mcp/demo", json=batch, headers=headers).json()}
        assert replies[1]["error"]["code"] == ErrorCode.APPROVAL_REQUIRED
        assert "result" in replies[2]
        assert "retry-after" not in client.post("/mcp/demo", json=batch, headers=headers).headers


def test_database_store_end_to_end_with_the_cli(
    tmp_path: Path, upstream: RecordingUpstream, capsys: pytest.CaptureFixture[str]
) -> None:
    url = f"sqlite:///{tmp_path / 'approvals.db'}"
    assert main(["db", "upgrade", "--database-url", url]) == 0
    with gateway(
        upstream,
        FakeClock(T0),
        approval_store=ApprovalStoreKind.DATABASE,
        database_url=url,
    ) as client:
        gate = client.app.state.approvals  # type: ignore[attr-defined]
        assert isinstance(gate.store, DatabaseApprovalStore)
        headers = session(client)
        approval_id = ticket(client, headers).json()["error"]["data"]["approval_id"]
        capsys.readouterr()

        db = ["--database-url", url]
        assert main(["approvals", "list", *db]) == 0
        listing = capsys.readouterr().out
        assert approval_id in listing
        assert "support-bot\tdemo/create_ticket\turgent-tickets-need-a-human" in listing

        assert main(["approvals", "show", approval_id, *db]) == 0
        assert '"priority": "urgent"' in capsys.readouterr().out

        assert main(["approvals", "approve", approval_id, "--reviewer", "bob", *db]) == 0
        assert f"approved {approval_id}" in capsys.readouterr().out
        assert main(["approvals", "deny", approval_id, *db]) == 1
        assert "is approved" in capsys.readouterr().err

        assert "result" in ticket(client, headers).json()
        assert main(["approvals", "list", "--status", "executed", *db]) == 0
        assert approval_id in capsys.readouterr().out
        assert main(["approvals", "list", "--status", "all", "--agent", "nobody", *db]) == 0
        assert capsys.readouterr().out.count("\n") == 1  # header only

        assert main(["approvals", "show", "apr_missing", *db]) == 1
        assert "no approval request" in capsys.readouterr().err


def test_cli_deny_with_note(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    url = f"sqlite:///{tmp_path / 'deny.db'}"
    assert main(["db", "upgrade", "--database-url", url]) == 0
    engine = make_engine(url)
    store = DatabaseApprovalStore(make_sessionmaker(engine))
    request = store.open(
        NewApproval("bot", "github", "merge_pr", {"n": 1}, "r", "why"),
        datetime.now(UTC),
        ApprovalTimings(),
    )
    capsys.readouterr()
    db = ["--database-url", url]
    assert main(["approvals", "deny", request.id, "--note", "not today", *db]) == 0
    assert f"denied {request.id}" in capsys.readouterr().out
    assert store.get(request.id).status is ApprovalStatus.DENIED
    assert store.get(request.id).note == "not today"
    engine.dispose()
    with pytest.raises(SystemExit):
        main(["approvals", "approve", request.id, "--reviewer", "<bad>", *db])
    with pytest.raises(SystemExit):
        main(["approvals", "approve", request.id, "--note", "x" * 501, *db])


def test_cli_needs_a_migrated_database(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    url = f"sqlite:///{tmp_path / 'empty.db'}"
    assert main(["approvals", "list", "--database-url", url]) == 1
    assert "mcp-warden db upgrade" in capsys.readouterr().err


def test_settings_build_a_gate_from_configuration(upstream: RecordingUpstream) -> None:
    app = create_app(
        Settings(
            policy_path=EXAMPLE_POLICY,
            upstreams_path=None,
            auth_mode=AuthMode.TRUSTED_HEADER,
            approval_ttl_seconds=60,
            approval_decision_ttl_seconds=30,
            approval_wait_seconds=2,
            approval_max_pending_per_agent=4,
            approval_retry_after_seconds=11,
        ),
        transport=upstream.transport(),
    )
    gate: ApprovalGate = app.state.approvals
    assert isinstance(gate.store, InMemoryApprovalStore)
    assert gate.timings == ApprovalTimings(timedelta(seconds=60), timedelta(seconds=30), 4)
    assert gate.wait == timedelta(seconds=2)
    assert gate.retry_after == 11


@pytest.mark.anyio
async def test_without_a_gate_require_approval_is_refused(upstream: RecordingUpstream) -> None:
    proxy = ProxyService(
        UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})]),
        upstream.transport(),
        PolicyGuard(PolicyEngine(load_policy_file(EXAMPLE_POLICY))),
        TrustedHeaderAuthenticator(),
    )
    body = rpc(1, "tools/call", {"name": "create_ticket", "arguments": URGENT})
    result = await proxy.handle(
        "demo",
        json.dumps(body).encode(),
        {"x-warden-agent": "support-bot", "mcp-protocol-version": "2025-11-25"},
    )
    assert result.body["error"]["code"] == ErrorCode.APPROVAL_REQUIRED
    assert "approval_id" not in result.body["error"]["data"]
    assert "Retry-After" not in result.headers
    assert upstream.calls == []


def test_database_store_retries_a_lost_insert_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = f"sqlite:///{tmp_path / 'race.db'}"
    assert main(["db", "upgrade", "--database-url", url]) == 0
    engine = make_engine(url)
    store = DatabaseApprovalStore(make_sessionmaker(engine))
    real = store._open_once
    attempts: list[int] = []

    def flaky(*args: Any) -> Any:
        attempts.append(1)
        if len(attempts) == 1:
            raise IntegrityError("INSERT", {}, Exception("duplicate open_key"))
        return real(*args)

    monkeypatch.setattr(store, "_open_once", flaky)
    request = store.open(NewApproval("bot", "s", "t", {}, None, ""), T0, ApprovalTimings())
    assert request.status is ApprovalStatus.PENDING
    assert len(attempts) == 2
    engine.dispose()


def test_default_reviewer_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> str:
        raise OSError("no user")

    monkeypatch.setattr(cli.getpass, "getuser", broken)
    assert cli._default_reviewer() == "cli"
    monkeypatch.setattr(cli.getpass, "getuser", lambda: "名前")
    assert cli._default_reviewer() == "cli"
    monkeypatch.setattr(cli.getpass, "getuser", lambda: "zeeshan")
    assert cli._default_reviewer() == "zeeshan"
