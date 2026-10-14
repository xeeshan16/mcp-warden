"""Policy enforcement end to end: agent → gateway (example policy) → fake upstream."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from gateway_helpers import EXAMPLE_POLICY, initialize, make_client, rpc
from mcp_warden.app import create_app
from mcp_warden.config import Settings
from mcp_warden.jsonrpc import ErrorCode
from mcp_warden.policy import PolicyEngine, load_policy_file
from mcp_warden.proxy import HttpUpstreamClient
from mcp_warden.upstreams import Upstream, UpstreamRegistry


@pytest.fixture(params=[False, True], ids=["json", "sse"])
def client(request: pytest.FixtureRequest) -> Iterator[TestClient]:
    engine = PolicyEngine(load_policy_file(EXAMPLE_POLICY))
    with make_client(sse=request.param, engine=engine) as c:
        yield c


def session(client: TestClient, agent: str | None = None) -> dict[str, str]:
    headers = initialize(client)
    if agent is not None:
        headers["x-warden-agent"] = agent
    return headers


def call(
    client: TestClient, headers: dict[str, str], tool: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    payload = rpc("c", "tools/call", {"name": tool, "arguments": arguments})
    resp = client.post("/mcp/demo", json=payload, headers=headers)
    assert resp.status_code == 200
    body: dict[str, Any] = resp.json()
    assert body["id"] == "c"
    return body


def listed_tools(client: TestClient, headers: dict[str, str]) -> list[str]:
    body = client.post("/mcp/demo", json=rpc(1, "tools/list"), headers=headers).json()
    return [t["name"] for t in body["result"]["tools"]]


def test_tools_list_is_filtered_per_agent(client: TestClient) -> None:
    # delete_records is always denied; create_ticket is only possible for the
    # support bot (conditionally, on its title length).
    assert listed_tools(client, session(client)) == ["echo", "add", "get_forecast", "sleep"]
    assert listed_tools(client, session(client, "support-bot")) == [
        "echo",
        "add",
        "get_forecast",
        "create_ticket",
        "sleep",
    ]


def test_filtered_listing_keeps_tool_definitions_intact(client: TestClient) -> None:
    body = client.post("/mcp/demo", json=rpc(1, "tools/list"), headers=session(client)).json()
    echo = next(t for t in body["result"]["tools"] if t["name"] == "echo")
    assert echo["inputSchema"]["required"] == ["text"]
    assert echo["description"] == "Return the given text unchanged."


def test_allowed_call_is_forwarded(client: TestClient) -> None:
    body = call(client, session(client), "add", {"a": 2, "b": 3})
    assert body["result"]["structuredContent"] == {"sum": 5}


def test_denied_call_never_reaches_upstream(client: TestClient) -> None:
    body = call(client, session(client, "support-bot"), "delete_records", {"table": "users"})
    error = body["error"]
    assert error["code"] == ErrorCode.POLICY_DENIED
    assert error["data"] == {
        "server": "demo",
        "tool": "delete_records",
        "effect": "deny",
        "rule_id": "never-destructive",
        "reason": "Destructive tools are never allowed through the gateway.",
    }


def test_default_deny_reports_no_rule(client: TestClient) -> None:
    body = call(client, session(client), "create_ticket", {"title": "hi"})
    assert body["error"]["code"] == ErrorCode.POLICY_DENIED
    assert body["error"]["data"]["rule_id"] is None


@pytest.mark.parametrize(
    ("arguments", "allowed"),
    [
        ({"seconds": 0}, True),
        ({"seconds": 2.5}, False),
        ({"seconds": -1}, False),
        ({"seconds": "1"}, False),
        ({}, False),
    ],
)
def test_argument_matchers_decide_the_call(
    client: TestClient, arguments: dict[str, Any], allowed: bool
) -> None:
    body = call(client, session(client), "sleep", arguments)
    if allowed:
        assert "result" in body
    else:
        assert body["error"]["code"] == ErrorCode.POLICY_DENIED
        assert body["error"]["data"]["rule_id"] == "short-sleeps-only"


def test_conditional_allow(client: TestClient) -> None:
    headers = session(client, "support-bot")
    assert "result" in call(client, headers, "create_ticket", {"title": "Printer on fire"})
    denied = call(client, headers, "create_ticket", {"title": "x" * 121})
    assert denied["error"]["code"] == ErrorCode.POLICY_DENIED


def test_invalid_agent_header_is_rejected(client: TestClient) -> None:
    headers = session(client, "not a valid id!")
    resp = client.post("/mcp/demo", json=rpc(1, "tools/list"), headers=headers)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == ErrorCode.INVALID_REQUEST


def test_batch_entries_are_checked_independently() -> None:
    engine = PolicyEngine(load_policy_file(EXAMPLE_POLICY))
    with make_client(engine=engine) as c:
        headers = session(c)
        headers["mcp-protocol-version"] = "2025-03-26"
        batch = [
            rpc(1, "tools/call", {"name": "echo", "arguments": {"text": "ok"}}),
            rpc(2, "tools/call", {"name": "delete_records", "arguments": {"table": "t"}}),
        ]
        body = c.post("/mcp/demo", json=batch, headers=headers).json()
    assert body[0]["result"]["content"][0]["text"] == "ok"
    assert body[1]["error"]["code"] == ErrorCode.POLICY_DENIED


def _gateway_with_upstream_reply(result: Any, calls: list[str]) -> TestClient:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.content.decode())
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})

    transport = HttpUpstreamClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    registry = UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})])
    app = create_app(
        Settings(policy_path=EXAMPLE_POLICY, upstreams_path=None),
        upstreams=registry,
        transport=transport,
    )
    return TestClient(app)


def test_unreadable_tools_list_fails_closed() -> None:
    calls: list[str] = []
    with _gateway_with_upstream_reply({"tools": [{"name": "delete_all"}]}, calls) as c:
        body = c.post("/mcp/demo", json=rpc(1, "tools/list")).json()
    assert body["error"]["code"] == ErrorCode.UPSTREAM_ERROR
    assert body["error"]["data"] == {"server": "demo"}


def test_listing_extras_and_cursor_are_preserved() -> None:
    result = {
        "tools": [
            {"name": "get_x", "inputSchema": {"type": "object"}, "annotations": {"readOnly": True}},
            {"name": "delete_x", "inputSchema": {"type": "object"}},
        ],
        "nextCursor": "page-2",
        "_meta": {"k": "v"},
    }
    with _gateway_with_upstream_reply(result, []) as c:
        body = c.post("/mcp/demo", json=rpc(1, "tools/list")).json()
    assert body["result"] == {
        "tools": [result["tools"][0]],
        "nextCursor": "page-2",
        "_meta": {"k": "v"},
    }


def test_approval_required_is_its_own_error() -> None:
    calls: list[str] = []
    registry = UpstreamRegistry([Upstream("github", "http://upstream.test/mcp", 2.0, 1.0, {})])

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.content.decode())
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    transport = HttpUpstreamClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    app = create_app(
        Settings(policy_path=EXAMPLE_POLICY, upstreams_path=None),
        upstreams=registry,
        transport=transport,
    )
    with TestClient(app) as c:
        approval = c.post(
            "/mcp/github",
            json=rpc(1, "tools/call", {"name": "create_issue", "arguments": {"title": "t"}}),
        ).json()
        protected = c.post(
            "/mcp/github",
            json=rpc(2, "tools/call", {"name": "push_files", "arguments": {"branch": "main"}}),
        ).json()
    assert approval["error"]["code"] == ErrorCode.APPROVAL_REQUIRED
    assert approval["error"]["data"]["rule_id"] == "writes-need-a-human"
    # Deny overrides require_approval when the branch argument matches.
    assert protected["error"]["code"] == ErrorCode.POLICY_DENIED
    assert protected["error"]["data"]["rule_id"] == "no-pushes-to-default-branch"
    assert calls == []
