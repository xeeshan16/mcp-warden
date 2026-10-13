from __future__ import annotations

from typing import Any

import httpx
import pytest

from mcp_warden.fake_upstream import create_fake_upstream
from mcp_warden.jsonrpc import ErrorCode, JsonRpcError, JsonRpcErrorResponse, JsonRpcSuccess
from mcp_warden.proxy import HttpUpstreamClient, UpstreamSessionNotFoundError
from mcp_warden.proxy.client import same_id
from mcp_warden.upstreams import Upstream

UP = Upstream(
    name="demo",
    url="http://upstream.test/mcp",
    timeout_seconds=2.0,
    connect_timeout_seconds=1.0,
    headers={"X-Upstream-Key": "synthetic"},
)

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    },
}


def fake_client(**kwargs: Any) -> HttpUpstreamClient:
    app = create_fake_upstream(**kwargs)
    return HttpUpstreamClient(httpx.AsyncClient(transport=httpx.ASGITransport(app=app)))


def mock_client(handler: Any, **kwargs: Any) -> HttpUpstreamClient:
    return HttpUpstreamClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)), **kwargs)


def call(request_id: int | str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }


async def session(client: HttpUpstreamClient) -> str:
    reply = await client.send(UP, INIT, response_id=1, headers={})
    assert reply.session_id is not None
    return reply.session_id


def test_same_id_distinguishes_types() -> None:
    assert same_id(1, 1)
    assert same_id("a", "a")
    assert not same_id(1, "1")
    assert not same_id(None, 0)


@pytest.mark.anyio
@pytest.mark.parametrize("sse", [False, True])
async def test_round_trip_json_and_sse(sse: bool) -> None:
    client = fake_client(sse=sse)
    sid = await session(client)
    reply = await client.send(
        UP, call("c1", "add", {"a": 1, "b": 2}), response_id="c1", headers={"mcp-session-id": sid}
    )
    await client.aclose()
    assert isinstance(reply.response, JsonRpcSuccess)
    assert reply.response.id == "c1"
    assert reply.response.result["structuredContent"] == {"sum": 3}
    # The SSE variant sends a progress notification before the response.
    assert reply.dropped_messages == (1 if sse else 0)


@pytest.mark.anyio
async def test_notification_is_acknowledged() -> None:
    client = fake_client()
    sid = await session(client)
    reply = await client.send(
        UP,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        response_id=None,
        headers={"mcp-session-id": sid},
    )
    assert reply.status == 202
    assert reply.response is None


@pytest.mark.anyio
async def test_upstream_jsonrpc_error_is_passed_through() -> None:
    client = fake_client()
    sid = await session(client)
    reply = await client.send(
        UP, call(5, "no_such_tool", {}), response_id=5, headers={"mcp-session-id": sid}
    )
    assert isinstance(reply.response, JsonRpcErrorResponse)
    assert reply.response.error.code == -32602


@pytest.mark.anyio
async def test_unknown_session_raises_not_found() -> None:
    client = fake_client()
    with pytest.raises(UpstreamSessionNotFoundError):
        await client.send(
            UP, call(1, "echo", {"text": "x"}), response_id=1, headers={"mcp-session-id": "stale"}
        )


@pytest.mark.anyio
async def test_deadline_maps_to_upstream_timeout() -> None:
    client = fake_client(require_session=False)
    fast = Upstream(name="demo", url=UP.url, timeout_seconds=0.05, connect_timeout_seconds=0.05)
    with pytest.raises(JsonRpcError) as info:
        await client.send(fast, call(1, "sleep", {"seconds": 1}), response_id=1, headers={})
    assert info.value.code == ErrorCode.UPSTREAM_TIMEOUT
    assert info.value.data == {"server": "demo", "timeout_seconds": 0.05}


@pytest.mark.anyio
async def test_sends_configured_and_protocol_headers() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    client = mock_client(handler)
    await client.send(
        UP,
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        response_id=1,
        headers={"mcp-protocol-version": "2025-11-25"},
    )
    assert seen["x-upstream-key"] == "synthetic"
    assert seen["mcp-protocol-version"] == "2025-11-25"
    assert seen["accept"] == "application/json, text/event-stream"
    assert seen["content-type"] == "application/json"


def _raise(exc: Exception) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    return handler


def _respond(*args: Any, **kwargs: Any) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(*args, **kwargs)

    return handler


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("handler", "code", "message"),
    [
        (_raise(httpx.ConnectError("refused")), ErrorCode.UPSTREAM_ERROR, "unreachable"),
        (_raise(httpx.ReadTimeout("slow")), ErrorCode.UPSTREAM_TIMEOUT, "timed out"),
        (_respond(502, text="bad gateway"), ErrorCode.UPSTREAM_ERROR, "HTTP error"),
        (_respond(500, json={"oops": True}), ErrorCode.UPSTREAM_ERROR, "HTTP error"),
        (_respond(200, text="hello"), ErrorCode.UPSTREAM_ERROR, "content type"),
        (
            _respond(200, content=b"{not json", headers={"content-type": "application/json"}),
            ErrorCode.UPSTREAM_ERROR,
            "invalid JSON",
        ),
        (
            _respond(200, json={"jsonrpc": "2.0", "id": 2, "result": {}}),
            ErrorCode.UPSTREAM_ERROR,
            "does not match",
        ),
        (
            _respond(200, json={"jsonrpc": "2.0", "id": "1", "result": {}}),
            ErrorCode.UPSTREAM_ERROR,
            "does not match",
        ),
        (
            _respond(200, json={"jsonrpc": "2.0", "method": "ping"}),
            ErrorCode.UPSTREAM_ERROR,
            "invalid JSON-RPC response",
        ),
        (
            _respond(200, json=[{"jsonrpc": "2.0", "id": 1, "result": {}}]),
            ErrorCode.UPSTREAM_ERROR,
            "invalid JSON",
        ),
        (
            _respond(
                200,
                content=b'data: {"jsonrpc":"2.0","method":"x"}\n\n',
                headers={"content-type": "text/event-stream"},
            ),
            ErrorCode.UPSTREAM_ERROR,
            "without a response",
        ),
    ],
)
async def test_failure_mapping(handler: Any, code: ErrorCode, message: str) -> None:
    client = mock_client(handler)
    with pytest.raises(JsonRpcError) as info:
        await client.send(
            UP, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, response_id=1, headers={}
        )
    assert info.value.code == code
    assert message in info.value.message
    assert info.value.data["server"] == "demo"


@pytest.mark.anyio
async def test_jsonrpc_error_body_on_http_400_is_passed_through() -> None:
    body = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "bad"}}
    client = mock_client(_respond(400, json=body))
    reply = await client.send(
        UP, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, response_id=1, headers={}
    )
    assert reply.status == 400
    assert isinstance(reply.response, JsonRpcErrorResponse)


@pytest.mark.anyio
@pytest.mark.parametrize("content_type", ["application/json", "text/event-stream"])
async def test_response_size_cap(content_type: str) -> None:
    big = '{"jsonrpc":"2.0","id":1,"result":{"pad":"' + "x" * 5000 + '"}}'
    content = big if content_type == "application/json" else f"data: {big}\n\n"
    client = mock_client(
        _respond(200, content=content.encode(), headers={"content-type": content_type}),
        max_response_bytes=1000,
    )
    with pytest.raises(JsonRpcError, match="too large"):
        await client.send(
            UP, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, response_id=1, headers={}
        )


@pytest.mark.anyio
async def test_rejected_notification() -> None:
    client = mock_client(_respond(400))
    with pytest.raises(JsonRpcError, match="rejected"):
        await client.send(
            UP, {"jsonrpc": "2.0", "method": "notifications/x"}, response_id=None, headers={}
        )
