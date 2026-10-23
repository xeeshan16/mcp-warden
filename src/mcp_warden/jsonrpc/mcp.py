"""Typed views of the MCP methods the gateway inspects.

Only the messages that carry policy-relevant information are modelled:
``initialize`` (who is the client, which protocol revision), the listings of
tools, prompts and resources (what the agent can see), and ``tools/call``,
``prompts/get``, ``resources/read`` / ``resources/subscribe`` and
``completion/complete`` (what it wants to use). Every other method is passed
through as an opaque JSON-RPC message.

Unlike the JSON-RPC envelope, these models allow unknown members: MCP adds
optional fields between revisions, and the gateway must forward them intact.
Fields the gateway relies on are validated strictly.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationError,
    field_validator,
)

from mcp_warden.jsonrpc.errors import ErrorCode, JsonRpcError
from mcp_warden.jsonrpc.messages import JsonRpcRequest

# Newest first. The 2025-06-18 revision removed JSON-RPC batching from MCP.
SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = ("2025-11-25", "2025-06-18", "2025-03-26")
LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]
_BATCHING_REMOVED_IN = "2025-06-18"

_OPEN = ConfigDict(extra="allow", frozen=True, populate_by_name=True)

_TOOL_NAME = r"^[A-Za-z0-9_.:/-]{1,200}$"
# MCP does not restrict prompt names; control characters are still refused.
_PROMPT_NAME = r"^[^\x00-\x1f\x7f]{1,200}$"
_MAX_URI = 2048
# A lowercase scheme, then no whitespace or control characters.
_URI = r"^[a-z][a-z0-9+.-]*:[^\x00-\x20\x7f]+$"
# Spellings that make one resource look like another to a glob: dot segments,
# percent-encoded dots, slashes and backslashes, and backslashes themselves.
_AMBIGUOUS_URI = re.compile(r"(^|/)\.{1,2}(/|$|[?#])|%2e|%2f|%5c|\\", re.IGNORECASE)


class Method(StrEnum):
    INITIALIZE = "initialize"
    INITIALIZED = "notifications/initialized"
    PING = "ping"
    TOOLS_LIST = "tools/list"
    TOOLS_CALL = "tools/call"
    TOOLS_LIST_CHANGED = "notifications/tools/list_changed"
    PROMPTS_LIST = "prompts/list"
    PROMPTS_GET = "prompts/get"
    RESOURCES_LIST = "resources/list"
    RESOURCES_READ = "resources/read"
    RESOURCES_SUBSCRIBE = "resources/subscribe"
    RESOURCES_UNSUBSCRIBE = "resources/unsubscribe"
    RESOURCE_TEMPLATES_LIST = "resources/templates/list"
    COMPLETE = "completion/complete"
    CANCELLED = "notifications/cancelled"


class Implementation(BaseModel):
    model_config = _OPEN

    name: StrictStr = Field(min_length=1, max_length=200)
    version: StrictStr = Field(max_length=100)


class InitializeParams(BaseModel):
    model_config = _OPEN

    protocol_version: StrictStr = Field(alias="protocolVersion", min_length=1, max_length=40)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    client_info: Implementation = Field(alias="clientInfo")


class InitializeResult(BaseModel):
    model_config = _OPEN

    protocol_version: StrictStr = Field(alias="protocolVersion")
    capabilities: dict[str, Any] = Field(default_factory=dict)
    server_info: Implementation = Field(alias="serverInfo")
    instructions: StrictStr | None = None


class ListToolsParams(BaseModel):
    model_config = _OPEN

    cursor: StrictStr | None = None


class Tool(BaseModel):
    model_config = _OPEN

    name: StrictStr = Field(pattern=_TOOL_NAME)
    description: StrictStr | None = None
    input_schema: dict[str, Any] = Field(alias="inputSchema")


class ListToolsResult(BaseModel):
    model_config = _OPEN

    tools: list[Tool]
    next_cursor: StrictStr | None = Field(default=None, alias="nextCursor")


class CallToolParams(BaseModel):
    model_config = _OPEN

    name: StrictStr = Field(pattern=_TOOL_NAME)
    arguments: dict[str, Any] = Field(default_factory=dict)


class CallToolResult(BaseModel):
    model_config = _OPEN

    content: list[dict[str, Any]] = Field(default_factory=list)
    is_error: bool = Field(default=False, alias="isError")
    structured_content: dict[str, Any] | None = Field(default=None, alias="structuredContent")


def _unambiguous_uri(value: str) -> str:
    if _AMBIGUOUS_URI.search(value):
        raise ValueError(
            "resource URI must not contain dot segments, backslashes or encoded '.', '/' or '\\'"
        )
    return value


class Prompt(BaseModel):
    model_config = _OPEN

    name: StrictStr = Field(pattern=_PROMPT_NAME)


class ListPromptsResult(BaseModel):
    model_config = _OPEN

    prompts: list[Prompt]
    next_cursor: StrictStr | None = Field(default=None, alias="nextCursor")


class GetPromptParams(BaseModel):
    model_config = _OPEN

    name: StrictStr = Field(pattern=_PROMPT_NAME)
    arguments: dict[str, Any] = Field(default_factory=dict)


class Resource(BaseModel):
    model_config = _OPEN

    # Listings are filtered, never rejected, for odd URIs: an upstream's URI
    # that a request could not use is simply hidden (see PolicyGuard).
    uri: StrictStr = Field(min_length=1, max_length=_MAX_URI)


class ListResourcesResult(BaseModel):
    model_config = _OPEN

    resources: list[Resource]
    next_cursor: StrictStr | None = Field(default=None, alias="nextCursor")


class ResourceParams(BaseModel):
    """Params of ``resources/read``, ``resources/subscribe`` and ``resources/unsubscribe``."""

    model_config = _OPEN

    uri: StrictStr = Field(max_length=_MAX_URI, pattern=_URI)

    @field_validator("uri")
    @classmethod
    def _check_uri(cls, value: str) -> str:
        return _unambiguous_uri(value)


class CompletionRef(BaseModel):
    model_config = _OPEN

    type: StrictStr
    name: StrictStr | None = None
    uri: StrictStr | None = None


class CompleteParams(BaseModel):
    model_config = _OPEN

    ref: CompletionRef


def is_valid_resource_uri(uri: str) -> bool:
    """Whether a request could use ``uri`` (see :class:`ResourceParams`)."""
    return (
        len(uri) <= _MAX_URI
        and re.fullmatch(_URI, uri) is not None
        and _AMBIGUOUS_URI.search(uri) is None
    )


def _validate[M: BaseModel](model: type[M], data: Any, what: str) -> M:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        err = exc.errors()[0]
        loc = ".".join(str(p) for p in err["loc"]) or "params"
        raise JsonRpcError(
            ErrorCode.INVALID_PARAMS, f"invalid {what} params: {loc}: {err['msg']}"
        ) from exc


def parse_initialize(request: JsonRpcRequest) -> InitializeParams:
    return _validate(InitializeParams, request.params_object(), Method.INITIALIZE)


def parse_list_tools(request: JsonRpcRequest) -> ListToolsParams:
    return _validate(ListToolsParams, request.params_object(), Method.TOOLS_LIST)


def parse_call_tool(request: JsonRpcRequest) -> CallToolParams:
    return _validate(CallToolParams, request.params_object(), Method.TOOLS_CALL)


def parse_list_tools_result(result: Any) -> ListToolsResult:
    return _validate(ListToolsResult, result, "tools/list result")


def parse_get_prompt(request: JsonRpcRequest) -> GetPromptParams:
    return _validate(GetPromptParams, request.params_object(), Method.PROMPTS_GET)


def parse_resource(request: JsonRpcRequest) -> ResourceParams:
    return _validate(ResourceParams, request.params_object(), request.method)


def parse_complete(request: JsonRpcRequest) -> CompleteParams:
    return _validate(CompleteParams, request.params_object(), Method.COMPLETE)


def parse_list_prompts_result(result: Any) -> ListPromptsResult:
    return _validate(ListPromptsResult, result, "prompts/list result")


def parse_list_resources_result(result: Any) -> ListResourcesResult:
    return _validate(ListResourcesResult, result, "resources/list result")


def negotiate_protocol_version(requested: str) -> str:
    """Pick the version to answer ``initialize`` with.

    Per MCP, a server that supports the requested revision echoes it; otherwise
    it answers with the latest revision it supports and lets the client decide
    whether to disconnect.
    """
    return requested if requested in SUPPORTED_PROTOCOL_VERSIONS else LATEST_PROTOCOL_VERSION


def batching_allowed(protocol_version: str | None) -> bool:
    """Whether JSON-RPC batches are valid for the negotiated MCP revision.

    Before a session is initialised the revision is unknown, so batches are
    refused: ``initialize`` must not be part of a batch anyway.
    """
    if protocol_version is None:
        return False
    # Revision strings are ISO dates, so lexical order is chronological order.
    return protocol_version < _BATCHING_REMOVED_IN
