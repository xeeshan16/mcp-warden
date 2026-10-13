"""End-to-end tests: agent → warden HTTP app → fake upstream MCP server."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from mcp_warden.app import create_app
from mcp_warden.config import Settings
from mcp_warden.fake_upstream import TOOLS, create_fake_upstream
from mcp_warden.jsonrpc import ErrorCode
from mcp_warden.proxy import HttpUpstreamClient
from mcp_warden.upstreams import Upstream, UpstreamRegistry

EXAMPLE_POLICY = Path(__file__).resolve().parents[1] / "examples" / "policy.yaml"

INIT = {
    "jsonrpc": "2.0",
    "id": 0,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "test-agent", "version": "1"},
    },
}


def make_client(*, sse: bool = False, timeout: float = 2.0, **settings: Any) -> TestClient:
    fake = create_fake_upstream(sse=sse)
    transport = HttpUpstreamClient(httpx.AsyncClient(transport=httpx.ASGITransport(app=fake)))
    registry = UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", timeout, 1.0, {})])
    app = create_app(
        Settings(policy_path=EXAMPLE_POLICY, upstreams_path=None, **settings),
        upstreams=registry,
        transport=transport,
    )
    return TestClient(app)


@pytest.fixture(params=[False, True], ids=["json", "sse"])
def client(request: pytest.FixtureRequest) -> Iterator[TestClient]:
    with make_client(sse=request.param) as c:
        yield c


def initialize(client: TestClient) -> dict[str, str]:
    resp = client.post("/mcp/demo", json=INIT)
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == 0
    assert body["result"]["serverInfo"]["name"] == "mcp-warden-fake-upstream"
    return {"mcp-session-id": resp.headers["mcp-session-id"], "mcp-protocol-version": "2025-11-25"}


def rpc(request_id: Any, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def test_full_session(client: TestClient) -> None:
    headers = initialize(client)
    ack = client.post(
        "/mcp/demo",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers=headers,
    )
    assert ack.status_code == 202
    assert ack.content == b""

    listed = client.post("/mcp/demo", json=rpc(1, "tools/list"), headers=headers).json()
    assert [t["name"] for t in listed["result"]["tools"]] == [t["name"] for t in TOOLS]

    called = client.post(
        "/mcp/demo",
        json=rpc("call-1", "tools/call", {"name": "add", "arguments": {"a": 40, "b": 2}}),
        headers=headers,
    ).json()
    assert called == {
        "jsonrpc": "2.0",
        "id": "call-1",
        "result": {
            "content": [{"type": "text", "text": "42"}],
            "isError": False,
            "structuredContent": {"sum": 42},
        },
    }


def test_upstream_errors_keep_the_request_id(client: TestClient) -> None:
    headers = initialize(client)
    body = client.post(
        "/mcp/demo", json=rpc(9, "tools/call", {"name": "nope"}), headers=headers
    ).json()
    assert body["id"] == 9
    assert body["error"]["code"] == -32602


def test_unknown_server_is_404_without_network(client: TestClient) -> None:
    resp = client.post("/mcp/elsewhere", json=rpc(1, "ping"))
    assert resp.status_code == 404
    assert resp.json()["error"]["data"] == {"server": "elsewhere"}


def test_stale_session_is_passed_through_as_404(client: TestClient) -> None:
    resp = client.post("/mcp/demo", json=rpc(1, "ping"), headers={"mcp-session-id": "gone"})
    assert resp.status_code == 404


def test_agent_credentials_are_not_forwarded() -> None:
    seen: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    transport = HttpUpstreamClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    registry = UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})])
    app = create_app(
        Settings(policy_path=EXAMPLE_POLICY, upstreams_path=None),
        upstreams=registry,
        transport=transport,
    )
    with TestClient(app) as c:
        resp = c.post(
            "/mcp/demo",
            json=rpc(1, "ping"),
            headers={
                "authorization": "Bearer agent-key",
                "cookie": "a=b",
                "mcp-session-id": "s-1",
                "x-forwarded-for": "10.0.0.1",
            },
        )
    assert resp.status_code == 200
    assert "authorization" not in seen[0]
    assert "cookie" not in seen[0]
    assert "x-forwarded-for" not in seen[0]
    assert seen[0]["mcp-session-id"] == "s-1"


def test_malformed_tool_call_never_reaches_upstream(client: TestClient) -> None:
    headers = initialize(client)
    body = client.post(
        "/mcp/demo", json=rpc(3, "tools/call", {"name": "bad name!"}), headers=headers
    ).json()
    assert body["id"] == 3
    assert body["error"]["code"] == ErrorCode.INVALID_PARAMS


@pytest.mark.parametrize(
    ("payload", "status", "code", "request_id"),
    [
        (b"{nope", 400, ErrorCode.PARSE_ERROR, None),
        # The id is echoed back whenever it is readable, as JSON-RPC requires.
        (b'{"jsonrpc":"2.0","id":1}', 400, ErrorCode.INVALID_REQUEST, 1),
        # No MCP-Protocol-Version header: batching is refused.
        (b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]', 400, ErrorCode.INVALID_REQUEST, None),
    ],
)
def test_bad_payloads(
    client: TestClient, payload: bytes, status: int, code: int, request_id: int | None
) -> None:
    resp = client.post("/mcp/demo", content=payload, headers={"content-type": "application/json"})
    assert resp.status_code == status
    assert resp.json()["error"]["code"] == code
    assert resp.json()["id"] == request_id


def test_wrong_content_type(client: TestClient) -> None:
    resp = client.post("/mcp/demo", content=b"{}", headers={"content-type": "text/plain"})
    assert resp.status_code == 415


def test_payload_too_large() -> None:
    with make_client(max_message_bytes=200) as c:
        resp = c.post("/mcp/demo", json=rpc(1, "tools/call", {"name": "echo", "x": "y" * 500}))
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == ErrorCode.PAYLOAD_TOO_LARGE


def test_batches_only_for_old_protocol_revisions() -> None:
    with make_client() as c:
        headers = initialize(c)
        headers["mcp-protocol-version"] = "2025-03-26"
        batch = [
            rpc(1, "tools/call", {"name": "echo", "arguments": {"text": "a"}}),
            {"jsonrpc": "2.0", "method": "notifications/progress"},
            {"jsonrpc": "2.0", "id": 2},
            rpc(3, "tools/call", {"name": "add", "arguments": {"a": 1, "b": 1}}),
        ]
        resp = c.post("/mcp/demo", json=batch, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert [r["id"] for r in body] == [1, 2, 3]
    assert body[0]["result"]["content"][0]["text"] == "a"
    assert body[1]["error"]["code"] == ErrorCode.INVALID_REQUEST
    assert body[2]["result"]["structuredContent"] == {"sum": 2}


def test_upstream_timeout_is_a_jsonrpc_error() -> None:
    with make_client(timeout=0.05) as c:
        headers = initialize(c)
        body = c.post(
            "/mcp/demo",
            json=rpc(7, "tools/call", {"name": "sleep", "arguments": {"seconds": 1}}),
            headers=headers,
        ).json()
    assert body["id"] == 7
    assert body["error"]["code"] == ErrorCode.UPSTREAM_TIMEOUT


def test_get_and_delete_are_not_supported(client: TestClient) -> None:
    for method in ("GET", "DELETE"):
        resp = client.request(method, "/mcp/demo")
        assert resp.status_code == 405
        assert resp.headers["allow"] == "POST"


def test_failed_notification_is_still_acknowledged() -> None:
    # Notifications have no id, so an upstream failure cannot be reported back.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    transport = HttpUpstreamClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    registry = UpstreamRegistry([Upstream("demo", "http://upstream.test/mcp", 2.0, 1.0, {})])
    app = create_app(
        Settings(policy_path=EXAMPLE_POLICY, upstreams_path=None),
        upstreams=registry,
        transport=transport,
    )
    with TestClient(app) as c:
        resp = c.post("/mcp/demo", json={"jsonrpc": "2.0", "method": "notifications/x"})
    assert resp.status_code == 202
