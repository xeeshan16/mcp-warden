from __future__ import annotations

from typing import Any

import pytest

from mcp_warden.jsonrpc import ErrorCode, JsonRpcError, JsonRpcRequest
from mcp_warden.jsonrpc.mcp import (
    LATEST_PROTOCOL_VERSION,
    CallToolResult,
    InitializeResult,
    Method,
    batching_allowed,
    negotiate_protocol_version,
    parse_call_tool,
    parse_initialize,
    parse_list_tools,
    parse_list_tools_result,
)


def _req(method: str, params: Any = None) -> JsonRpcRequest:
    data: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        data["params"] = params
    return JsonRpcRequest.model_validate(data)


def _invalid_params(fn: Any, request: JsonRpcRequest) -> str:
    with pytest.raises(JsonRpcError) as info:
        fn(request)
    assert info.value.code == ErrorCode.INVALID_PARAMS
    return info.value.message


def test_initialize_params() -> None:
    params = parse_initialize(
        _req(
            Method.INITIALIZE,
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {"roots": {"listChanged": True}},
                "clientInfo": {"name": "demo-agent", "version": "0.3.0"},
            },
        )
    )
    assert params.protocol_version == "2025-06-18"
    assert params.client_info.name == "demo-agent"
    assert params.capabilities == {"roots": {"listChanged": True}}


def test_initialize_requires_client_info() -> None:
    message = _invalid_params(parse_initialize, _req("initialize", {"protocolVersion": "x"}))
    assert "clientInfo" in message


def test_initialize_result_preserves_unknown_fields() -> None:
    result = InitializeResult.model_validate(
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake", "version": "1", "title": "Fake server"},
            "futureField": 1,
        }
    )
    dumped = result.model_dump(by_alias=True, exclude_unset=True)
    assert dumped["futureField"] == 1
    assert dumped["serverInfo"]["title"] == "Fake server"


def test_list_tools_params_cursor_is_optional() -> None:
    assert parse_list_tools(_req("tools/list")).cursor is None
    assert parse_list_tools(_req("tools/list", {"cursor": "c2"})).cursor == "c2"
    _invalid_params(parse_list_tools, _req("tools/list", {"cursor": 5}))


def test_list_tools_result() -> None:
    result = parse_list_tools_result(
        {
            "tools": [
                {"name": "get_issue", "description": "Read", "inputSchema": {"type": "object"}},
                {"name": "delete_repo", "inputSchema": {"type": "object"}, "annotations": {}},
            ],
            "nextCursor": "page-2",
        }
    )
    assert [t.name for t in result.tools] == ["get_issue", "delete_repo"]
    assert result.next_cursor == "page-2"


def test_list_tools_result_rejects_unsafe_tool_names() -> None:
    with pytest.raises(JsonRpcError):
        parse_list_tools_result({"tools": [{"name": "a b", "inputSchema": {}}]})


def test_call_tool_params() -> None:
    params = parse_call_tool(
        _req("tools/call", {"name": "get_issue", "arguments": {"number": 42}, "_meta": {}})
    )
    assert params.name == "get_issue"
    assert params.arguments == {"number": 42}


def test_call_tool_arguments_default_to_empty() -> None:
    assert parse_call_tool(_req("tools/call", {"name": "now"})).arguments == {}


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"name": ""},
        {"name": 7},
        {"name": "x", "arguments": [1]},
        {"name": "has space"},
        {"name": "x" * 201},
    ],
)
def test_call_tool_invalid_params(params: dict[str, Any]) -> None:
    _invalid_params(parse_call_tool, _req("tools/call", params))


def test_call_tool_rejects_array_params() -> None:
    _invalid_params(parse_call_tool, _req("tools/call", ["get_issue"]))


def test_call_tool_result_defaults() -> None:
    result = CallToolResult.model_validate({"content": [{"type": "text", "text": "ok"}]})
    assert result.is_error is False
    assert result.structured_content is None


def test_negotiate_protocol_version() -> None:
    assert negotiate_protocol_version("2025-06-18") == "2025-06-18"
    assert negotiate_protocol_version("2024-01-01") == LATEST_PROTOCOL_VERSION


@pytest.mark.parametrize(
    ("version", "allowed"),
    [(None, False), ("2025-03-26", True), ("2025-06-18", False), ("2025-11-25", False)],
)
def test_batching_allowed(version: str | None, allowed: bool) -> None:
    assert batching_allowed(version) is allowed
