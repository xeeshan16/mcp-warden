from __future__ import annotations

import json
from typing import Any

import pytest

from mcp_warden.config import Settings
from mcp_warden.jsonrpc import (
    ErrorCode,
    InvalidMessage,
    JsonRpcError,
    JsonRpcErrorResponse,
    JsonRpcNotification,
    JsonRpcRequest,
    JsonRpcSuccess,
    ParseLimits,
    error_response,
    error_response_from,
    parse_object,
    parse_payload,
    success_response,
    to_wire,
)


def _dumps(value: Any) -> bytes:
    return json.dumps(value).encode()


def _single(payload: Any) -> Any:
    result = parse_payload(_dumps(payload))
    assert not result.is_batch
    assert len(result.items) == 1
    return result.items[0]


def _invalid(payload: Any) -> JsonRpcErrorResponse:
    item = _single(payload)
    assert isinstance(item, InvalidMessage)
    return item.error


def _raises(payload: bytes | str, code: ErrorCode, limits: ParseLimits | None = None) -> None:
    with pytest.raises(JsonRpcError) as info:
        parse_payload(payload, limits)
    assert info.value.code == code


# --- classification -------------------------------------------------------


def test_request_with_object_params() -> None:
    msg = _single({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x"}})
    assert isinstance(msg, JsonRpcRequest)
    assert msg.id == 1
    assert msg.params_object() == {"name": "x"}


def test_request_with_string_id_and_no_params() -> None:
    msg = _single({"jsonrpc": "2.0", "id": "abc", "method": "ping"})
    assert isinstance(msg, JsonRpcRequest)
    assert msg.id == "abc"
    assert msg.params_object() == {}


def test_notification_has_no_id() -> None:
    msg = _single({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert isinstance(msg, JsonRpcNotification)


def test_success_response() -> None:
    msg = _single({"jsonrpc": "2.0", "id": 7, "result": {"tools": []}})
    assert isinstance(msg, JsonRpcSuccess)
    assert msg.result == {"tools": []}


def test_success_response_with_null_result() -> None:
    msg = _single({"jsonrpc": "2.0", "id": 7, "result": None})
    assert isinstance(msg, JsonRpcSuccess)
    assert to_wire(msg) == {"jsonrpc": "2.0", "id": 7, "result": None}


def test_error_response_with_null_id() -> None:
    msg = _single(
        {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
    )
    assert isinstance(msg, JsonRpcErrorResponse)
    assert msg.id is None
    assert msg.error.code == ErrorCode.PARSE_ERROR


# --- envelope validation --------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"jsonrpc": "1.0", "id": 1, "method": "ping"},
        {"id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "id": 1, "method": 5},
        {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": "nope"},
        {"jsonrpc": "2.0", "id": 1, "method": "ping", "extra": True},
        {"jsonrpc": "2.0", "id": True, "method": "ping"},
        {"jsonrpc": "2.0", "id": 1.5, "method": "ping"},
        {"jsonrpc": "2.0", "id": None, "method": "ping"},
        {"jsonrpc": "2.0", "id": [1], "method": "ping"},
    ],
)
def test_invalid_requests_are_rejected(payload: dict[str, Any]) -> None:
    err = _invalid(payload)
    assert err.error.code == ErrorCode.INVALID_REQUEST


def test_invalid_request_keeps_a_readable_id() -> None:
    err = _invalid({"jsonrpc": "1.0", "id": "req-9", "method": "ping"})
    assert err.id == "req-9"


def test_invalid_request_drops_an_unusable_id() -> None:
    err = _invalid({"jsonrpc": "2.0", "id": True, "method": "ping"})
    assert err.id is None


def test_response_with_result_and_error_is_invalid() -> None:
    err = _invalid({"jsonrpc": "2.0", "id": 1, "result": 1, "error": {"code": 1, "message": "x"}})
    assert "both result and error" in err.error.message


def test_message_without_method_or_result() -> None:
    err = _invalid({"jsonrpc": "2.0", "id": 3})
    assert err.id == 3
    assert err.error.code == ErrorCode.INVALID_REQUEST


def test_non_object_message() -> None:
    err = _invalid("hello")
    assert err.id is None


def test_array_params_are_valid_jsonrpc_but_not_mcp() -> None:
    msg = _single({"jsonrpc": "2.0", "id": 1, "method": "sum", "params": [1, 2]})
    assert isinstance(msg, JsonRpcRequest)
    with pytest.raises(JsonRpcError) as info:
        msg.params_object()
    assert info.value.code == ErrorCode.INVALID_PARAMS


def test_parse_object_accepts_already_decoded_values() -> None:
    assert isinstance(parse_object({"jsonrpc": "2.0", "method": "x"}), JsonRpcNotification)


# --- whole-payload failures -----------------------------------------------


def test_malformed_json() -> None:
    _raises(b'{"jsonrpc": "2.0",', ErrorCode.PARSE_ERROR)


def test_invalid_utf8() -> None:
    _raises(b'{"jsonrpc": "2.0", "method": "\xff"}', ErrorCode.PARSE_ERROR)


def test_duplicate_keys_are_rejected() -> None:
    # A policy check and the upstream server could otherwise read different names.
    payload = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}'
    with pytest.raises(JsonRpcError) as info:
        parse_payload(payload)
    assert info.value.code == ErrorCode.PARSE_ERROR
    assert "duplicate key 'name'" in info.value.message


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_non_standard_constants_are_rejected(literal: str) -> None:
    _raises('{"jsonrpc":"2.0","id":1,"result":' + literal + "}", ErrorCode.PARSE_ERROR)


def test_payload_size_limit_is_checked_before_decoding() -> None:
    limits = ParseLimits(max_bytes=10)
    with pytest.raises(JsonRpcError) as info:
        parse_payload(b"x" * 11, limits)
    assert info.value.code == ErrorCode.PAYLOAD_TOO_LARGE
    assert info.value.data == {"max_bytes": 10, "actual_bytes": 11}


def test_size_limit_counts_bytes_not_characters() -> None:
    limits = ParseLimits(max_bytes=40)
    text = '{"jsonrpc":"2.0","method":"' + "é" * 8 + '"}'
    assert len(text) <= 40 < len(text.encode())
    _raises(text, ErrorCode.PAYLOAD_TOO_LARGE, limits)


def test_depth_limit() -> None:
    nested: Any = "leaf"
    for _ in range(10):
        nested = {"a": nested}
    payload = _dumps({"jsonrpc": "2.0", "method": "x", "params": nested})
    assert parse_payload(payload, ParseLimits(max_depth=11)).messages
    _raises(payload, ErrorCode.PARSE_ERROR, ParseLimits(max_depth=10))


def test_pathological_nesting_does_not_crash() -> None:
    _raises(b"[" * 200_000 + b"]" * 200_000, ErrorCode.PARSE_ERROR, ParseLimits(max_bytes=10**6))


@pytest.mark.parametrize("bad", [{"max_bytes": 0}, {"max_depth": 0}, {"max_batch_size": 0}])
def test_limits_must_be_positive(bad: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        ParseLimits(**bad)


# --- batches ----------------------------------------------------------------


def test_batch_mixes_valid_and_invalid_entries() -> None:
    payload = _dumps(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2},
            7,
        ]
    )
    result = parse_payload(payload)
    assert result.is_batch
    assert len(result.items) == 4
    assert [type(m) for m in result.messages] == [JsonRpcRequest, JsonRpcNotification]
    assert [i.error.id for i in result.invalid] == [2, None]


def test_empty_batch_is_invalid() -> None:
    _raises(b"[]", ErrorCode.INVALID_REQUEST)


def test_batch_size_limit() -> None:
    batch = [{"jsonrpc": "2.0", "method": "n"}] * 3
    assert len(parse_payload(_dumps(batch), ParseLimits(max_batch_size=3)).items) == 3
    _raises(_dumps(batch), ErrorCode.INVALID_REQUEST, ParseLimits(max_batch_size=2))


def test_batches_can_be_disabled() -> None:
    _raises(
        _dumps([{"jsonrpc": "2.0", "method": "n"}]),
        ErrorCode.INVALID_REQUEST,
        ParseLimits(allow_batch=False),
    )


# --- building and serialising responses ------------------------------------


def test_error_response_omits_absent_data() -> None:
    resp = error_response(4, ErrorCode.POLICY_DENIED, "denied by policy")
    assert to_wire(resp) == {
        "jsonrpc": "2.0",
        "id": 4,
        "error": {"code": -32001, "message": "denied by policy"},
    }


def test_error_response_from_exception_keeps_data() -> None:
    exc = JsonRpcError(ErrorCode.RATE_LIMITED, "slow down", {"retry_after": 3})
    wire = to_wire(error_response_from(exc, "a"))
    assert wire["error"] == {"code": -32003, "message": "slow down", "data": {"retry_after": 3}}
    assert "RATE" not in repr(exc) and "-32003" in repr(exc)


def test_success_response_round_trips() -> None:
    resp = success_response(9, {"content": [{"type": "text", "text": "hi"}]})
    reparsed = _single(to_wire(resp))
    assert reparsed == resp


def test_request_without_params_serialises_without_params() -> None:
    msg = _single({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert to_wire(msg) == {"jsonrpc": "2.0", "id": 1, "method": "ping"}


def test_settings_build_parse_limits() -> None:
    settings = Settings(max_message_bytes=123, max_json_depth=5, max_batch_size=2)
    limits = settings.parse_limits(allow_batch=False)
    assert limits == ParseLimits(max_bytes=123, max_depth=5, max_batch_size=2, allow_batch=False)
