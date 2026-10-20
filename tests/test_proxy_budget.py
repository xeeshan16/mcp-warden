"""Budgets end to end: agent → gateway → fake upstream."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from conftest import FakeClock, FakeMonotonic
from gateway_helpers import ADMIN_HEADERS, ADMIN_TOKEN, EXAMPLE_POLICY, initialize, make_client, rpc
from mcp_warden.__main__ import main
from mcp_warden.app import create_app
from mcp_warden.budget import CharRatioEstimator, InMemoryUsageStore, Usage, canonical_json
from mcp_warden.config import AuthMode, Settings, UsageStoreKind
from mcp_warden.jsonrpc import ErrorCode
from mcp_warden.policy import PolicyEngine, parse_policy
from mcp_warden.proxy import HttpUpstreamClient
from mcp_warden.ratelimit import InMemoryBucketStore
from mcp_warden.upstreams import Upstream, UpstreamRegistry
from test_budget_ledger import NOW

POLICY: dict[str, Any] = {
    "version": 1,
    "default": "allow",
    "rules": [{"id": "no-deletes", "effect": "deny", "tools": ["delete_*"]}],
    "rate_limits": [
        {"id": "adds", "tools": ["add"], "requests": 1, "per": "hour", "burst": 3},
    ],
    "budgets": [
        {"id": "hourly-calls", "window": "hour", "max_calls": 5},
        {
            "id": "echo-tokens",
            "tools": ["echo"],
            "scope": "tool",
            "window": "day",
            "max_tokens": 60,
        },
    ],
}


@pytest.fixture
def day() -> FakeClock:
    return FakeClock(NOW)  # 09:30 UTC


def gateway(day: FakeClock, policy: dict[str, Any] | None = None, **kwargs: Any) -> TestClient:
    kwargs.setdefault("usage_ledger", InMemoryUsageStore())
    return make_client(
        engine=PolicyEngine(parse_policy(policy or POLICY)),
        bucket_store=InMemoryBucketStore(clock=FakeMonotonic()),
        budget_clock=day,
        **kwargs,
    )


def session(client: TestClient, agent: str = "bot") -> dict[str, str]:
    headers = initialize(client)
    headers["x-warden-agent"] = agent
    return headers


def call(client: TestClient, headers: dict[str, str], tool: str, **arguments: Any) -> Any:
    if not arguments:
        arguments = {"text": "hi"} if tool == "echo" else {"a": 1, "b": 2}
    return client.post(
        "/mcp/demo",
        json=rpc("c", "tools/call", {"name": tool, "arguments": arguments}),
        headers=headers,
    )


def ok(resp: Any) -> bool:
    return "result" in resp.json()


def test_call_budget_runs_out_and_resets_with_the_window(day: FakeClock) -> None:
    with gateway(day) as c:
        h = session(c)
        assert [ok(call(c, h, "get_forecast", city="Oslo")) for _ in range(6)] == [
            True,
            True,
            True,
            True,
            True,
            False,
        ]
        resp = call(c, h, "get_forecast", city="Oslo")
        error = resp.json()["error"]
        assert error["code"] == ErrorCode.BUDGET_EXHAUSTED
        assert error["message"] == "budget exhausted: hourly-calls"
        assert error["data"] == {
            "server": "demo",
            "tool": "get_forecast",
            "budget_id": "hourly-calls",
            "scope": "agent",
            "window": "hour",
            "exhausted": "calls",
            "used": 5,
            "limit": 5,
            "resets_at": "2026-10-17T10:00:00Z",
            "retry_after": 1800,
        }
        assert resp.headers["retry-after"] == "1800"

        day.advance(timedelta(minutes=30))
        assert ok(call(c, h, "get_forecast", city="Oslo"))


def test_agents_have_separate_budgets(day: FakeClock) -> None:
    with gateway(day) as c:
        bot, other = session(c, "bot"), session(c, "other")
        for _ in range(5):
            call(c, bot, "get_forecast", city="Oslo")
        assert not ok(call(c, bot, "get_forecast", city="Oslo"))
        assert ok(call(c, other, "get_forecast", city="Oslo"))


def test_token_budget_counts_arguments_and_replies(day: FakeClock) -> None:
    estimator = CharRatioEstimator()
    store = InMemoryUsageStore()
    with gateway(day, usage_ledger=store) as c:
        h = session(c)
        first = call(c, h, "echo", text="hello")
        assert ok(first)
    request_tokens = estimator.count(
        canonical_json({"name": "echo", "arguments": {"text": "hello"}})
    )
    reply_tokens = estimator.count(canonical_json(first.json()["result"]))
    # Both matching budgets (hourly-calls and echo-tokens) booked the same call.
    usages = [entry.usage for entry in store._entries.values()]
    assert usages == [Usage(1, request_tokens + reply_tokens)] * 2


def test_crossing_call_completes_then_later_calls_are_refused(day: FakeClock) -> None:
    with gateway(day) as c:
        h = session(c)
        # Each echo of 30 characters costs about 9 request + 20 reply tokens.
        results = [call(c, h, "echo", text="x" * 30) for _ in range(3)]
    assert [ok(r) for r in results] == [True, True, False]
    error = results[2].json()["error"]
    assert error["data"]["budget_id"] == "echo-tokens"
    assert error["data"]["exhausted"] == "tokens"
    assert error["data"]["used"] > 60  # the second call crossed the line and completed
    assert error["data"]["resets_at"] == "2026-10-18T00:00:00Z"


def test_tool_scope_counts_per_tool(day: FakeClock) -> None:
    with gateway(day) as c:
        h = session(c)
        call(c, h, "echo", text="x" * 30)
        call(c, h, "echo", text="x" * 30)
        assert not ok(call(c, h, "echo", text="x"))
        # echo-tokens does not apply to add; hourly-calls still has room.
        assert ok(call(c, h, "add"))


def test_denied_and_rate_limited_calls_spend_no_budget(day: FakeClock) -> None:
    with gateway(day) as c:
        h = session(c)
        for _ in range(10):
            assert call(c, h, "delete_records").json()["error"]["code"] == ErrorCode.POLICY_DENIED
        adds = [call(c, h, "add").json() for _ in range(6)]
        assert ["result" in a for a in adds] == [True, True, True, False, False, False]
        assert {a["error"]["code"] for a in adds[3:]} == {ErrorCode.RATE_LIMITED}
        # 3 of the 5 hourly calls are spent, so two more pass.
        assert [ok(call(c, h, "get_forecast", city="Oslo")) for _ in range(3)] == [
            True,
            True,
            False,
        ]


def test_tool_errors_count(day: FakeClock) -> None:
    with gateway(day) as c:
        h = session(c)
        for _ in range(5):
            body = call(c, h, "nope").json()
            assert body["error"]["code"] == -32602  # unknown tool, from the upstream
        assert call(c, h, "get_forecast", city="Oslo").json()["error"]["code"] == (
            ErrorCode.BUDGET_EXHAUSTED
        )


def test_unreachable_upstream_still_counts(day: FakeClock) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    app = create_app(
        Settings(
            policy_path=EXAMPLE_POLICY, upstreams_path=None, auth_mode=AuthMode.TRUSTED_HEADER
        ),
        engine=PolicyEngine(parse_policy(POLICY)),
        upstreams=UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})]),
        transport=HttpUpstreamClient(httpx.AsyncClient(transport=httpx.MockTransport(down))),
        usage_store=InMemoryUsageStore(),
        budget_clock=day,
    )
    h = {"x-warden-agent": "bot"}
    with TestClient(app) as c:
        codes = [call(c, h, "get_forecast", city="Oslo").json()["error"]["code"] for _ in range(6)]
    assert codes == [ErrorCode.UPSTREAM_ERROR] * 5 + [ErrorCode.BUDGET_EXHAUSTED]


def test_batch_entries_are_budgeted_independently(day: FakeClock) -> None:
    with gateway(day) as c:
        h = session(c)
        h["mcp-protocol-version"] = "2025-03-26"
        batch = [
            rpc(i, "tools/call", {"name": "get_forecast", "arguments": {"city": "Oslo"}})
            for i in range(7)
        ]
        resp = c.post("/mcp/demo", json=batch, headers=h)
    body = resp.json()
    assert sum("result" in m for m in body) == 5
    assert {m["error"]["code"] for m in body if "error" in m} == {ErrorCode.BUDGET_EXHAUSTED}
    assert "retry-after" not in resp.headers


def test_failing_settle_does_not_fail_the_call(
    day: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    class BrokenSettle(InMemoryUsageStore):
        async def settle(self, charges: Any, tokens: int) -> None:
            raise RuntimeError("database went away")

    with gateway(day, usage_ledger=BrokenSettle()) as c:
        h = session(c)
        assert ok(call(c, h, "echo"))
    assert "could not record reply tokens" in caplog.text


def test_database_ledger_from_settings_and_cli_report(
    db_engine: Engine, db_url: str, day: FakeClock, capsys: pytest.CaptureFixture[str]
) -> None:
    with gateway(
        day, usage_ledger=None, usage_store=UsageStoreKind.DATABASE, database_url=db_url
    ) as c:
        h = session(c)
        results = [ok(call(c, h, "get_forecast", city="Oslo")) for _ in range(6)]
    assert results == [True] * 5 + [False]

    assert main(["usage", "--database-url", db_url, "--all"]) == 0
    lines = capsys.readouterr().out.splitlines()
    # 5 calls x (13 request + 55 reply) estimated tokens.
    assert lines == [
        "budget\tagent\tserver/tool\twindow\tcalls\ttokens",
        "hourly-calls\tbot\t*\t2026-10-17T09:00:00Z..2026-10-17T10:00:00Z\t5\t340",
    ]


def test_cli_usage_needs_a_migrated_database(
    tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["usage", "--database-url", f"sqlite:///{tmp_path / 'empty.db'}"]) == 1
    assert "mcp-warden db upgrade" in capsys.readouterr().err


def test_policy_summary_lists_budgets(day: FakeClock) -> None:
    with gateway(day, admin_token=ADMIN_TOKEN) as c:
        body = c.get("/v1/policy", headers=ADMIN_HEADERS).json()
    assert body["budget_ids"] == ["hourly-calls", "echo-tokens"]


def test_cli_check_shows_matching_budgets(capsys: pytest.CaptureFixture[str]) -> None:
    args = ["check", str(EXAMPLE_POLICY), "--agent", "support-bot", "--server", "demo"]
    assert main([*args, "--tool", "echo"]) == 0
    out = capsys.readouterr().out
    assert "3 budgets" in out
    assert "budget daily-calls: 2000 calls per day, per agent" in out
    assert "budget support-bot-tokens: 200000 tokens per day, per agent" in out
    assert "budget demo-echo: 50 calls, 5000 tokens per hour, per tool" in out
