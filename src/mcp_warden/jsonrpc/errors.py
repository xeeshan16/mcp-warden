"""JSON-RPC 2.0 error codes and the exception used to raise them.

Codes -32768..-32000 are reserved by JSON-RPC. The spec leaves -32099..-32000
for implementation-defined server errors, which is where the warden's own
decisions (policy denial, rate limiting, ...) live so that clients can tell a
gateway refusal from an upstream tool failure.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any


class ErrorCode(IntEnum):
    # Standard JSON-RPC 2.0 codes.
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    # Warden-specific codes in the implementation-defined server error range.
    POLICY_DENIED = -32001
    APPROVAL_REQUIRED = -32002
    RATE_LIMITED = -32003
    BUDGET_EXHAUSTED = -32004
    UPSTREAM_ERROR = -32005
    UPSTREAM_TIMEOUT = -32006
    PAYLOAD_TOO_LARGE = -32007
    UNAUTHENTICATED = -32008


class JsonRpcError(Exception):
    """An error that maps directly onto a JSON-RPC ``error`` object."""

    def __init__(self, code: ErrorCode | int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = int(code)
        self.message = message
        self.data = data

    def __repr__(self) -> str:
        return f"JsonRpcError(code={self.code}, message={self.message!r})"
