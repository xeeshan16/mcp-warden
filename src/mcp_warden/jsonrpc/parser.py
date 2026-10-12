"""Defensive parsing of untrusted JSON-RPC payloads.

The parser is the first thing that touches bytes sent by an agent, so it
enforces limits before and during decoding:

* a byte-size cap checked before any decoding work;
* strict UTF-8;
* no duplicate object keys (two parsers disagreeing on which ``name`` wins is
  a classic way to slip a call past a policy check);
* no ``NaN`` / ``Infinity`` literals, which are not valid JSON;
* a nesting-depth cap;
* a batch-size cap, or batches rejected entirely.

Whole-payload problems raise :class:`JsonRpcError` and should be answered with
a single error response whose id is ``null``. Problems with individual batch
entries do not fail the batch: each bad entry becomes an :class:`InvalidMessage`
carrying the error response that JSON-RPC requires for it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from mcp_warden.jsonrpc.errors import ErrorCode, JsonRpcError
from mcp_warden.jsonrpc.messages import (
    JsonRpcErrorResponse,
    JsonRpcMessage,
    JsonRpcNotification,
    JsonRpcRequest,
    JsonRpcSuccess,
    RequestId,
    error_response,
)


@dataclass(frozen=True, slots=True)
class ParseLimits:
    max_bytes: int = 1_000_000
    max_depth: int = 64
    max_batch_size: int = 50
    allow_batch: bool = True

    def __post_init__(self) -> None:
        if self.max_bytes < 1 or self.max_depth < 1 or self.max_batch_size < 1:
            raise ValueError("parse limits must be positive")


@dataclass(frozen=True, slots=True)
class InvalidMessage:
    """A batch entry (or single message) that could not be validated."""

    error: JsonRpcErrorResponse


ParsedItem = JsonRpcMessage | InvalidMessage


@dataclass(frozen=True, slots=True)
class ParseResult:
    items: tuple[ParsedItem, ...]
    is_batch: bool

    @property
    def messages(self) -> tuple[JsonRpcMessage, ...]:
        return tuple(i for i in self.items if not isinstance(i, InvalidMessage))

    @property
    def invalid(self) -> tuple[InvalidMessage, ...]:
        return tuple(i for i in self.items if isinstance(i, InvalidMessage))


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateKeyError(f"duplicate key {key!r}")
        obj[key] = value
    return obj


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _depth(value: Any) -> int:
    """Maximum container nesting depth, computed without recursion."""
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, level = stack.pop()
        if isinstance(node, dict):
            deepest = max(deepest, level)
            stack.extend((v, level + 1) for v in node.values())
        elif isinstance(node, list):
            deepest = max(deepest, level)
            stack.extend((v, level + 1) for v in node)
    return deepest


def decode_json(payload: bytes | str, limits: ParseLimits) -> Any:
    """Decode bytes into Python values, enforcing the size and syntax limits."""
    raw = payload.encode("utf-8") if isinstance(payload, str) else payload
    if len(raw) > limits.max_bytes:
        raise JsonRpcError(
            ErrorCode.PAYLOAD_TOO_LARGE,
            "payload too large",
            {"max_bytes": limits.max_bytes, "actual_bytes": len(raw)},
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JsonRpcError(ErrorCode.PARSE_ERROR, "payload is not valid UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except _DuplicateKeyError as exc:
        raise JsonRpcError(ErrorCode.PARSE_ERROR, f"parse error: {exc}") from exc
    except RecursionError as exc:
        raise JsonRpcError(ErrorCode.PARSE_ERROR, "parse error: nesting too deep") from exc
    except ValueError as exc:
        raise JsonRpcError(ErrorCode.PARSE_ERROR, "parse error: invalid JSON") from exc
    if _depth(value) > limits.max_depth:
        raise JsonRpcError(
            ErrorCode.PARSE_ERROR,
            "parse error: nesting too deep",
            {"max_depth": limits.max_depth},
        )
    return value


def _readable_id(obj: dict[str, Any]) -> RequestId | None:
    candidate = obj.get("id")
    if isinstance(candidate, bool):
        return None
    if isinstance(candidate, int | str):
        return candidate
    return None


def _first_error(exc: ValidationError) -> str:
    err = exc.errors()[0]
    loc = ".".join(str(part) for part in err["loc"]) or "message"
    return f"{loc}: {err['msg']}"


def parse_object(obj: Any) -> ParsedItem:
    """Validate one decoded JSON value as a JSON-RPC message.

    Classification follows the members present: ``method`` + ``id`` is a
    request, ``method`` alone a notification, ``result`` / ``error`` a response.
    """
    if not isinstance(obj, dict):
        return InvalidMessage(
            error_response(None, ErrorCode.INVALID_REQUEST, "message must be a JSON object")
        )
    model: type[JsonRpcMessage]
    if "method" in obj:
        model = JsonRpcRequest if "id" in obj else JsonRpcNotification
    elif "result" in obj and "error" in obj:
        return InvalidMessage(
            error_response(
                _readable_id(obj),
                ErrorCode.INVALID_REQUEST,
                "response must not contain both result and error",
            )
        )
    elif "result" in obj:
        model = JsonRpcSuccess
    elif "error" in obj:
        model = JsonRpcErrorResponse
    else:
        return InvalidMessage(
            error_response(
                _readable_id(obj),
                ErrorCode.INVALID_REQUEST,
                "message must contain method, result or error",
            )
        )
    try:
        return model.model_validate(obj)
    except ValidationError as exc:
        return InvalidMessage(
            error_response(
                _readable_id(obj),
                ErrorCode.INVALID_REQUEST,
                f"invalid request: {_first_error(exc)}",
            )
        )


def parse_payload(payload: bytes | str, limits: ParseLimits | None = None) -> ParseResult:
    """Parse a single message or a batch from raw bytes."""
    limits = limits or ParseLimits()
    value = decode_json(payload, limits)
    if isinstance(value, list):
        if not limits.allow_batch:
            raise JsonRpcError(ErrorCode.INVALID_REQUEST, "batch requests are not supported")
        if not value:
            raise JsonRpcError(ErrorCode.INVALID_REQUEST, "batch must not be empty")
        if len(value) > limits.max_batch_size:
            raise JsonRpcError(
                ErrorCode.INVALID_REQUEST,
                "batch too large",
                {"max_batch_size": limits.max_batch_size, "actual": len(value)},
            )
        return ParseResult(items=tuple(parse_object(v) for v in value), is_batch=True)
    return ParseResult(items=(parse_object(value),), is_batch=False)
