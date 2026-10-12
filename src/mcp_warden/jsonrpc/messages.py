"""Typed JSON-RPC 2.0 envelopes.

The envelope models are strict (unknown members are rejected) because the
gateway re-serialises every message it forwards: a lenient model would let
extra members be silently dropped or, worse, interpreted differently by the
gateway and the upstream server.

Request ids are restricted to strings and integers. JSON-RPC 2.0 discourages
``null`` and fractional ids and MCP forbids ``null`` outright; booleans are
rejected explicitly because Python treats them as integers.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr

from mcp_warden.jsonrpc.errors import ErrorCode, JsonRpcError

JSONRPC_VERSION: Literal["2.0"] = "2.0"

RequestId = StrictInt | StrictStr
Params = dict[str, Any] | list[Any]

_STRICT = ConfigDict(extra="forbid", frozen=True)


class JsonRpcRequest(BaseModel):
    """A call that expects a response."""

    model_config = _STRICT

    jsonrpc: Literal["2.0"]
    id: RequestId
    method: StrictStr
    params: Params | None = None

    def params_object(self) -> dict[str, Any]:
        """Return params as an object, as MCP requires, or raise INVALID_PARAMS."""
        if self.params is None:
            return {}
        if isinstance(self.params, list):
            raise JsonRpcError(ErrorCode.INVALID_PARAMS, "params must be an object")
        return self.params


class JsonRpcNotification(BaseModel):
    """A one-way message: no ``id`` and never answered."""

    model_config = _STRICT

    jsonrpc: Literal["2.0"]
    method: StrictStr
    params: Params | None = None


class ErrorObject(BaseModel):
    model_config = _STRICT

    code: StrictInt
    message: StrictStr
    data: Any = None


class JsonRpcSuccess(BaseModel):
    model_config = _STRICT

    jsonrpc: Literal["2.0"]
    id: RequestId
    result: Any


class JsonRpcErrorResponse(BaseModel):
    """An error reply. ``id`` is ``None`` only when the request id was unreadable."""

    model_config = _STRICT

    jsonrpc: Literal["2.0"]
    id: RequestId | None
    error: ErrorObject


JsonRpcResponse = JsonRpcSuccess | JsonRpcErrorResponse
JsonRpcMessage = JsonRpcRequest | JsonRpcNotification | JsonRpcSuccess | JsonRpcErrorResponse


def error_response(
    request_id: RequestId | None,
    code: ErrorCode | int,
    message: str,
    data: Any = None,
) -> JsonRpcErrorResponse:
    error = (
        ErrorObject(code=int(code), message=message)
        if data is None
        else ErrorObject(code=int(code), message=message, data=data)
    )
    return JsonRpcErrorResponse(jsonrpc=JSONRPC_VERSION, id=request_id, error=error)


def error_response_from(exc: JsonRpcError, request_id: RequestId | None) -> JsonRpcErrorResponse:
    return error_response(request_id, exc.code, exc.message, exc.data)


def success_response(request_id: RequestId, result: Any) -> JsonRpcSuccess:
    return JsonRpcSuccess(jsonrpc=JSONRPC_VERSION, id=request_id, result=result)


def to_wire(message: JsonRpcMessage) -> dict[str, Any]:
    """Serialise one message to a JSON-compatible dict.

    Optional members that were never set are omitted (``params`` on a request
    without params), but ``result: null`` and ``error.data`` are preserved when
    they were set explicitly.
    """
    return message.model_dump(mode="json", exclude_unset=True)
