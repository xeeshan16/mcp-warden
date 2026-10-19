"""The audit log end to end: agent → gateway → fake upstream, the query API and the CLI."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from conftest import FakeClock, FakeMonotonic
from gateway_helpers import EXAMPLE_POLICY, initialize, rpc
from mcp_warden.__main__ import main
from mcp_warden.app import create_app
from mcp_warden.approval import ApprovalGate, InMemoryApprovalStore
from mcp_warden.audit import (
    ArgumentHasher,
    AuditEvent,
    AuditQuery,
    DatabaseAuditStore,
    InMemoryAuditStore,
    Outcome,
)
from mcp_warden.config import AuditStoreKind, AuthMode, Settings
from mcp_warden.db import make_engine, make_sessionmaker
from mcp_warden.policy import PolicyEngine, load_policy_file
from mcp_warden.ratelimit import InMemoryBucketStore
from mcp_warden.upstreams import Upstream, UpstreamRegistry
from test_approval_stores import T0
from test_proxy_approval import ADMIN, TOKEN, RecordingUpstream

PRIVATE_TITLE = "Customer 4711 cannot log in"  # must never reach the audit log


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(T0)


def gateway(
    clock: FakeClock,
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
    app = create_app(
        cfg,
        engine=PolicyEngine(load_policy_file(EXAMPLE_POLICY)),
        upstreams=UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})]),
        transport=RecordingUpstream().transport(),
        bucket_store=InMemoryBucketStore(clock=FakeMonotonic()),
        approval_gate=ApprovalGate(InMemoryApprovalStore(), clock=clock),
        audit_store=store,
        audit_clock=clock,
    )
    return TestClient(app)


def session(client: TestClient, agent: str = "support-bot") -> dict[str, str]:
    headers = initialize(client)
    headers["x-warden-agent"] = agent
    return headers


def call(
    client: TestClient, headers: dict[str, str], tool: str, request_id: Any = 1, **arguments: Any
) -> dict[str, Any]:
    resp = client.post(
        "/mcp/demo",
        json=rpc(request_id, "tools/call", {"name": tool, "arguments": arguments}),
        headers=headers,
    )
    assert resp.status_code == 200
    body: dict[str, Any] = resp.json()
    return body


def events(store: Any, **filters: Any) -> list[AuditEvent]:
    found: list[AuditEvent] = store.query(AuditQuery(**filters)).events
    return found


def test_each_request_leaves_one_metadata_only_event(clock: FakeClock) -> None:
    store = InMemoryAuditStore()
    with gateway(clock, store) as client:
        headers = session(client)
        assert "result" in call(client, headers, "create_ticket", title=PRIVATE_TITLE)
    init, ticket = sorted(events(store), key=lambda e: e.method)
    assert (init.method, init.tool, init.outcome) == ("initialize", None, Outcome.FORWARDED)
    assert init.agent == "anonymous"  # initialize() sends no agent header
    assert ticket.agent == "support-bot" and ticket.server == "demo"
    assert (ticket.tool, ticket.outcome, ticket.effect) == ("create_ticket", "forwarded", "allow")
    assert ticket.rule_id == "support-bot-demo-tickets"
    assert ticket.tool_error is False and ticket.error_code is None
    digest, size = ArgumentHasher().digest({"title": PRIVATE_TITLE})
    assert (ticket.arguments_digest, ticket.arguments_size) == (digest, size)
    assert ticket.occurred_at == T0 and ticket.latency_ms >= 0
    dumped = json.dumps([e.to_dict() for e in events(store)])
    assert PRIVATE_TITLE not in dumped and "4711" not in dumped
    assert "T-" not in dumped  # nothing from the upstream's reply either


def test_refusals_are_recorded_with_their_rule_and_code(clock: FakeClock) -> None:
    store = InMemoryAuditStore()
    with gateway(clock, store) as client:
        headers = session(client)
        call(client, headers, "delete_records", table="users")
        call(client, headers, "sleep", seconds=10)
        call(client, headers, "create_ticket", title="Down", priority="urgent")
        for i in range(4):
            call(client, headers, "create_ticket", title=f"t{i}")
        call(client, headers, "echo")  # the fake tool fails: missing text
    by_outcome = {e.outcome: e for e in events(store, method="tools/call")}
    denied = events(store, outcome=Outcome.DENIED)
    assert {e.rule_id for e in denied} == {"never-destructive", "short-sleeps-only"}
    assert all(e.error_code == -32001 and e.effect == "deny" for e in denied)
    pending = by_outcome[Outcome.APPROVAL_PENDING]
    assert pending.approval_id is not None and pending.approval_id.startswith("apr_")
    assert (pending.effect, pending.rule_id) == ("require_approval", "urgent-tickets-need-a-human")
    limited = by_outcome[Outcome.RATE_LIMITED]
    assert limited.error_code == -32003 and limited.tool == "create_ticket"
    tool_failure = events(store, tool="echo")[0]
    assert (tool_failure.outcome, tool_failure.tool_error) == (Outcome.FORWARDED, True)


def test_approved_call_carries_its_approval_id(clock: FakeClock) -> None:
    store = InMemoryAuditStore()
    with gateway(clock, store) as client:
        headers = session(client)
        first = call(client, headers, "create_ticket", title="Down", priority="urgent")
        approval_id = first["error"]["data"]["approval_id"]
        clock.advance(timedelta(seconds=30))
        client.post(
            f"/v1/approvals/{approval_id}/approve", json={"reviewer": "alice"}, headers=ADMIN
        )
        assert "result" in call(client, headers, "create_ticket", title="Down", priority="urgent")
    tickets = events(store, tool="create_ticket")
    assert [e.outcome for e in tickets] == [Outcome.FORWARDED, Outcome.APPROVAL_PENDING]
    assert {e.approval_id for e in tickets} == {approval_id}
    assert tickets[0].arguments_digest == tickets[1].arguments_digest
    assert tickets[0].occurred_at - tickets[1].occurred_at == timedelta(seconds=30)


def test_invalid_params_and_unknown_methods(clock: FakeClock) -> None:
    store = InMemoryAuditStore()
    with gateway(clock, store) as client:
        headers = session(client)
        client.post("/mcp/demo", json=rpc(1, "tools/call", {"arguments": {}}), headers=headers)
        client.post("/mcp/demo", json=rpc(2, "nope/nothing"), headers=headers)
    invalid = events(store, outcome=Outcome.INVALID)
    assert len(invalid) == 1 and invalid[0].error_code == -32602 and invalid[0].tool is None
    unknown = events(store, method="nope/nothing")[0]
    assert unknown.outcome is Outcome.FORWARDED and unknown.error_code == -32601


def test_tools_list_and_notifications(clock: FakeClock) -> None:
    store = InMemoryAuditStore()
    with gateway(clock, store) as client:
        headers = session(client)
        clock.advance(timedelta(seconds=1))
        client.post("/mcp/demo", json=rpc(1, "tools/list"), headers=headers)
        resp = client.post(
            "/mcp/demo",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=headers,
        )
        assert resp.status_code == 202
    assert [e.method for e in events(store)] == ["tools/list", "initialize"]


def test_a_batch_is_written_in_one_append(clock: FakeClock) -> None:
    class Recording(InMemoryAuditStore):
        def __init__(self) -> None:
            super().__init__()
            self.appends: list[int] = []

        def append(self, events: Sequence[AuditEvent]) -> None:
            self.appends.append(len(events))
            super().append(events)

    store = Recording()
    with gateway(clock, store) as client:
        headers = session(client)
        headers["mcp-protocol-version"] = "2025-03-26"
        batch = [
            rpc(1, "tools/call", {"name": "add", "arguments": {"a": 1, "b": 2}}),
            rpc(2, "tools/call", {"name": "delete_records", "arguments": {"table": "t"}}),
        ]
        assert len(client.post("/mcp/demo", json=batch, headers=headers).json()) == 2
    assert store.appends == [1, 2]  # initialize, then the batch
    calls = events(store, method="tools/call")
    assert {e.outcome for e in calls} == {Outcome.FORWARDED, Outcome.DENIED}


def test_a_failing_store_never_fails_the_call(clock: FakeClock) -> None:
    class Broken(InMemoryAuditStore):
        def append(self, events: Sequence[AuditEvent]) -> None:
            raise RuntimeError("disk full")

    with gateway(clock, Broken()) as client:
        headers = session(client)
        assert call(client, headers, "add", a=2, b=3)["result"]["structuredContent"] == {"sum": 5}
        assert client.app.state.audit.failed_writes == 2  # type: ignore[attr-defined]


def test_keyed_digests(clock: FakeClock) -> None:
    store = InMemoryAuditStore()
    key = "an-audit-key-for-tests"
    with gateway(clock, store, audit_hash_key=key) as client:
        call(client, session(client), "add", a=1, b=1)
    expected, _ = ArgumentHasher(key.encode()).digest({"a": 1, "b": 1})
    assert events(store, tool="add")[0].arguments_digest == expected


def test_short_audit_keys_are_rejected() -> None:
    with pytest.raises(ValueError, match="16 bytes"):
        Settings(audit_hash_key="short")


def test_query_api_filters_and_pages(clock: FakeClock) -> None:
    with gateway(clock, InMemoryAuditStore()) as client:
        headers = session(client)
        for i in range(5):
            clock.advance(timedelta(seconds=1))
            call(client, headers, "add", i, a=i, b=1)
        call(client, headers, "delete_records", table="x")
        assert client.get("/v1/audit").status_code == 401
        page = client.get("/v1/audit?tool=add&limit=2", headers=ADMIN).json()
        seen = [e["id"] for e in page["events"]]
        while page["next_cursor"]:
            page = client.get(
                "/v1/audit",
                params={"tool": "add", "limit": 2, "cursor": page["next_cursor"]},
                headers=ADMIN,
            ).json()
            seen += [e["id"] for e in page["events"]]
        assert len(seen) == len(set(seen)) == 5
        denied = client.get("/v1/audit?outcome=denied", headers=ADMIN).json()["events"]
        assert [e["rule_id"] for e in denied] == ["never-destructive"]
        since = client.get(
            "/v1/audit", params={"since": "2026-10-18T09:00:03Z", "tool": "add"}, headers=ADMIN
        ).json()["events"]
        assert len(since) == 3
        assert client.get("/v1/audit?cursor=bogus", headers=ADMIN).status_code == 400
        naive = client.get("/v1/audit?since=2026-10-18T09:00:00", headers=ADMIN)
        assert naive.status_code == 422
        assert client.get("/v1/audit?outcome=maybe", headers=ADMIN).status_code == 422


def test_audit_off_disables_recording_and_the_api(clock: FakeClock) -> None:
    with gateway(clock, None, audit_store=AuditStoreKind.OFF) as client:
        call(client, session(client), "add", a=1, b=2)
        assert client.app.state.audit is None  # type: ignore[attr-defined]
        assert client.get("/v1/audit", headers=ADMIN).status_code == 404


def test_database_store_end_to_end_and_cli(
    tmp_path: Path, clock: FakeClock, capsys: pytest.CaptureFixture[str]
) -> None:
    url = f"sqlite:///{tmp_path / 'audit.db'}"
    assert main(["db", "upgrade", "--database-url", url]) == 0
    with gateway(clock, None, audit_store=AuditStoreKind.DATABASE, database_url=url) as client:
        headers = session(client)
        clock.advance(timedelta(seconds=1))
        call(client, headers, "create_ticket", title=PRIVATE_TITLE)
        clock.advance(timedelta(seconds=1))
        call(client, headers, "delete_records", table="users")
        api = client.get("/v1/audit?agent=support-bot", headers=ADMIN).json()["events"]
        assert [e["outcome"] for e in api] == ["denied", "forwarded"]
    engine = make_engine(url)
    stored = DatabaseAuditStore(make_sessionmaker(engine)).query(AuditQuery())
    engine.dispose()
    assert len(stored.events) == 3
    capsys.readouterr()

    db = ["--database-url", url]
    assert main(["audit", *db]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("time\tagent")
    assert len(out) == 4 and "demo/delete_records\tdenied\tnever-destructive\t-32001" in out[1]
    assert PRIVATE_TITLE not in "\n".join(out)

    assert main(["audit", "--outcome", "forwarded", "--tool", "create_ticket", "--json", *db]) == 0
    page = json.loads(capsys.readouterr().out)
    assert [e["tool"] for e in page["events"]] == ["create_ticket"]

    assert main(["audit", "--limit", "1", *db]) == 0
    captured = capsys.readouterr()
    cursor = captured.err.split("--cursor ")[1].strip()
    assert main(["audit", "--limit", "5", "--cursor", cursor, *db]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 3

    assert main(["audit", "--since", "2026-10-18T10:00Z", *db]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 1
    assert main(["audit", "--cursor", "bogus", *db]) == 2
    with pytest.raises(SystemExit):
        main(["audit", "--since", "2026-10-18T10:00", *db])
    with pytest.raises(SystemExit):
        main(["audit", "--since", "yesterday", *db])


def test_cli_needs_a_migrated_database(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    url = f"sqlite:///{tmp_path / 'empty.db'}"
    assert main(["audit", "--database-url", url]) == 1
    assert "mcp-warden db upgrade" in capsys.readouterr().err
