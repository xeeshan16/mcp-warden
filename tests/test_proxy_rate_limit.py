"""Rate limits end to end: agent → gateway → fake upstream."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from conftest import FakeMonotonic
from gateway_helpers import ADMIN_HEADERS, ADMIN_TOKEN, EXAMPLE_POLICY, initialize, make_client, rpc
from mcp_warden.__main__ import main
from mcp_warden.app import create_app
from mcp_warden.config import AuthMode, RateLimitStore, Settings
from mcp_warden.jsonrpc import ErrorCode
from mcp_warden.policy import PolicyEngine, parse_policy
from mcp_warden.proxy import HttpUpstreamClient
from mcp_warden.ratelimit import InMemoryBucketStore
from mcp_warden.upstreams import Upstream, UpstreamRegistry

POLICY: dict[str, Any] = {
    "version": 1,
    "default": "allow",
    "rules": [{"id": "no-deletes", "effect": "deny", "tools": ["delete_*"]}],
    "rate_limits": [
        {"id": "per-agent", "requests": 6, "per": "minute", "burst": 4},
        {
            "id": "echo-per-tool",
            "tools": ["echo"],
            "scope": "tool",
            "requests": 1,
            "per": "second",
            "burst": 2,
        },
    ],
}


def gateway(seconds: FakeMonotonic, **kwargs: Any) -> TestClient:
    return make_client(
        engine=PolicyEngine(parse_policy(POLICY)),
        bucket_store=InMemoryBucketStore(clock=seconds),
        **kwargs,
    )


def session(client: TestClient, agent: str = "bot") -> dict[str, str]:
    headers = initialize(client)
    headers["x-warden-agent"] = agent
    return headers


def call(client: TestClient, headers: dict[str, str], tool: str) -> Any:
    args = {"text": "hi"} if tool == "echo" else {"a": 1, "b": 2}
    return client.post(
        "/mcp/demo", json=rpc("c", "tools/call", {"name": tool, "arguments": args}), headers=headers
    )


def test_burst_then_rate_limited_with_retry_after(seconds: FakeMonotonic) -> None:
    with gateway(seconds) as c:
        h = session(c)
        assert [call(c, h, "echo").json().get("result") is not None for _ in range(2)] == [
            True,
            True,
        ]
        resp = call(c, h, "echo")
    assert resp.status_code == 200
    assert resp.headers["retry-after"] == "1"
    error = resp.json()["error"]
    assert error["code"] == ErrorCode.RATE_LIMITED
    assert error["message"] == "rate limit exceeded: echo-per-tool"
    assert error["data"] == {
        "server": "demo",
        "tool": "echo",
        "limit_id": "echo-per-tool",
        "scope": "tool",
        "requests": 1,
        "per": "second",
        "burst": 2,
        "retry_after": 1,
    }


def test_tokens_come_back_over_time(seconds: FakeMonotonic) -> None:
    with gateway(seconds) as c:
        h = session(c)
        call(c, h, "echo")
        call(c, h, "echo")
        assert "error" in call(c, h, "echo").json()
        seconds.advance(1.0)
        assert "result" in call(c, h, "echo").json()


def test_agent_scope_spans_tools_and_reports_the_longest_wait(seconds: FakeMonotonic) -> None:
    with gateway(seconds) as c:
        h = session(c)
        for _ in range(4):
            assert "result" in call(c, h, "add").json()
        resp = call(c, h, "echo")  # echo's own bucket is full; the agent's is empty
    error = resp.json()["error"]
    assert error["data"]["limit_id"] == "per-agent"
    assert error["data"]["retry_after"] == 10  # 6 per minute -> one every 10 s
    assert resp.headers["retry-after"] == "10"


def test_agents_have_separate_buckets(seconds: FakeMonotonic) -> None:
    with gateway(seconds) as c:
        bot, other = session(c, "bot"), session(c, "other")
        for _ in range(4):
            call(c, bot, "add")
        assert "error" in call(c, bot, "add").json()
        assert "result" in call(c, other, "add").json()


def test_policy_denials_do_not_spend_tokens(seconds: FakeMonotonic) -> None:
    with gateway(seconds) as c:
        h = session(c)
        for _ in range(10):
            body = call(c, h, "delete_records").json()
            assert body["error"]["code"] == ErrorCode.POLICY_DENIED
        assert [("result" in call(c, h, "add").json()) for _ in range(5)] == [
            True,
            True,
            True,
            True,
            False,
        ]


def test_other_methods_are_not_limited(seconds: FakeMonotonic) -> None:
    with gateway(seconds) as c:
        h = session(c)
        for _ in range(4):
            call(c, h, "add")
        for i in range(10):
            resp = c.post("/mcp/demo", json=rpc(i, "tools/list"), headers=h)
            assert "result" in resp.json()
            assert "retry-after" not in resp.headers


def test_batch_entries_each_take_a_token_and_get_no_header(seconds: FakeMonotonic) -> None:
    with gateway(seconds) as c:
        h = session(c)
        h["mcp-protocol-version"] = "2025-03-26"
        batch = [
            rpc(i, "tools/call", {"name": "echo", "arguments": {"text": str(i)}}) for i in range(3)
        ]
        resp = c.post("/mcp/demo", json=batch, headers=h)
    body = sorted(resp.json(), key=lambda m: m["id"])
    outcomes = ["result" in m for m in body]
    assert sorted(outcomes) == [False, True, True]
    assert next(m for m in body if "error" in m)["error"]["code"] == ErrorCode.RATE_LIMITED
    assert "retry-after" not in resp.headers


def test_upstream_rate_limit_errors_get_no_header(seconds: FakeMonotonic) -> None:
    """Only the gateway's own refusal sets Retry-After, not an upstream's error."""
    upstream_error = {
        "code": ErrorCode.RATE_LIMITED,
        "message": "slow down",
        "data": {"retry_after": 99},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "c", "error": upstream_error})

    transport = HttpUpstreamClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    app = create_app(
        Settings(
            policy_path=EXAMPLE_POLICY, upstreams_path=None, auth_mode=AuthMode.TRUSTED_HEADER
        ),
        engine=PolicyEngine(parse_policy(POLICY)),
        upstreams=UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})]),
        transport=transport,
        bucket_store=InMemoryBucketStore(clock=seconds),
    )
    with TestClient(app) as c:
        resp = call(c, {"x-warden-agent": "bot"}, "add")
    assert resp.json()["error"] == upstream_error
    assert "retry-after" not in resp.headers


def test_database_store_from_settings(db_engine: Engine, db_url: str) -> None:
    engine = PolicyEngine(parse_policy(POLICY))
    with make_client(
        engine=engine, rate_limit_store=RateLimitStore.DATABASE, database_url=db_url
    ) as c:
        h = session(c)
        results = [("result" in call(c, h, "echo").json()) for _ in range(3)]
    assert results == [True, True, False]


def test_database_store_requires_migrations(tmp_path: Path) -> None:
    from mcp_warden.db import DatabaseNotReadyError

    with pytest.raises(DatabaseNotReadyError):
        make_client(
            rate_limit_store=RateLimitStore.DATABASE,
            database_url=f"sqlite:///{tmp_path / 'empty.db'}",
        )


def test_policy_summary_lists_limits(seconds: FakeMonotonic) -> None:
    with gateway(seconds, admin_token=ADMIN_TOKEN) as c:
        body = c.get("/v1/policy", headers=ADMIN_HEADERS).json()
    assert body["rate_limit_ids"] == ["per-agent", "echo-per-tool"]


def test_cli_check_shows_matching_limits(capsys: pytest.CaptureFixture[str]) -> None:
    args = ["check", str(EXAMPLE_POLICY), "--agent", "support-bot", "--server", "demo"]
    assert main([*args, "--tool", "create_ticket"]) == 0
    out = capsys.readouterr().out
    assert "3 rate limits" in out
    assert "rate limit per-agent: 120/minute, burst 30, per agent" in out
    assert "rate limit demo-tickets: 3/minute, burst 3, per tool" in out
