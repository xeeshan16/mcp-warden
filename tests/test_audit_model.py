from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import UTC, datetime, timedelta, timezone

import pytest

from mcp_warden.audit import (
    ArgumentHasher,
    AuditEvent,
    AuditQuery,
    Cursor,
    InvalidCursorError,
    Outcome,
    outcome_for_refusal,
)
from mcp_warden.jsonrpc import ErrorCode

T0 = datetime(2026, 10, 19, 9, 0, tzinfo=UTC)


def event(**overrides: object) -> AuditEvent:
    fields: dict[str, object] = {
        "occurred_at": T0,
        "agent": "bot",
        "server": "demo",
        "method": "tools/call",
        "outcome": Outcome.FORWARDED,
        "latency_ms": 1.5,
        "tool": "echo",
    }
    fields.update(overrides)
    return AuditEvent.create(**fields)  # type: ignore[arg-type]


def test_unkeyed_digest_is_sha256_of_canonical_json() -> None:
    digest, size = ArgumentHasher().digest({"b": 1, "a": "x"})
    canonical = b'{"a":"x","b":1}'
    assert digest == hashlib.sha256(canonical).hexdigest()
    assert size == len(canonical)


def test_key_order_and_whitespace_never_change_the_digest() -> None:
    hasher = ArgumentHasher(b"k" * 16)
    assert hasher.digest({"a": 1, "b": [1, 2]}) == hasher.digest({"b": [1, 2], "a": 1})


def test_keyed_digest_is_an_hmac() -> None:
    key = b"0123456789abcdef"
    digest, _ = ArgumentHasher(key).digest({"confirm": True})
    assert digest == hmac.new(key, b'{"confirm":true}', hashlib.sha256).hexdigest()
    assert digest != ArgumentHasher().digest({"confirm": True})[0]
    assert ArgumentHasher(key).keyed and not ArgumentHasher().keyed
    assert "0123" not in repr(ArgumentHasher(key))


def test_short_keys_are_rejected() -> None:
    with pytest.raises(ValueError, match="16 bytes"):
        ArgumentHasher(b"short")


def test_size_counts_utf8_bytes() -> None:
    _, size = ArgumentHasher().digest({"t": "é"})
    assert size == len('{"t":"é"}'.encode())


@pytest.mark.parametrize(
    ("code", "outcome"),
    [
        (ErrorCode.POLICY_DENIED, Outcome.DENIED),
        (ErrorCode.APPROVAL_REQUIRED, Outcome.APPROVAL_PENDING),
        (ErrorCode.RATE_LIMITED, Outcome.RATE_LIMITED),
        (ErrorCode.BUDGET_EXHAUSTED, Outcome.BUDGET_EXHAUSTED),
        (ErrorCode.UPSTREAM_ERROR, Outcome.UPSTREAM_ERROR),
        (ErrorCode.UPSTREAM_TIMEOUT, Outcome.UPSTREAM_ERROR),
        (ErrorCode.INVALID_PARAMS, Outcome.INVALID),
        (ErrorCode.INVALID_REQUEST, Outcome.INVALID),
        (ErrorCode.INTERNAL_ERROR, Outcome.ERROR),
        (-31999, Outcome.ERROR),
    ],
)
def test_refusal_codes_map_to_outcomes(code: int, outcome: Outcome) -> None:
    assert outcome_for_refusal(code) is outcome


def test_create_cuts_labels_and_normalises_time() -> None:
    e = event(
        agent="a" * 300,
        tool="t" * 300,
        method="m" * 300,
        rule_id="r" * 300,
        occurred_at=T0.astimezone(timezone(timedelta(hours=5))),
        latency_ms=-3.0,
    )
    assert len(e.agent) == 200 and len(e.tool or "") == 200
    assert len(e.method) == 100 and len(e.rule_id or "") == 100
    assert e.occurred_at == T0 and e.occurred_at.tzinfo is UTC
    assert e.latency_ms == 0.0
    assert e.id.startswith("evt_") and event().id != e.id


def test_create_requires_an_aware_time() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        event(occurred_at=datetime(2026, 10, 19, 9, 0))


def test_to_dict_has_metadata_only() -> None:
    data = event(arguments_digest="ab" * 32, arguments_size=12).to_dict()
    assert data["occurred_at"] == "2026-10-19T09:00:00.000000+00:00"
    assert data["outcome"] == "forwarded"
    assert set(data) == {
        "id", "occurred_at", "agent", "server", "method", "tool", "outcome", "effect",
        "rule_id", "approval_id", "error_code", "tool_error", "latency_ms",
        "arguments_digest", "arguments_size",
    }  # fmt: skip


def test_cursor_round_trips() -> None:
    cursor = Cursor(T0 + timedelta(microseconds=7), "evt_abc")
    assert Cursor.decode(cursor.encode()) == cursor
    assert "=" not in cursor.encode()


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not base64!",
        base64.urlsafe_b64encode(b"[]").decode(),
        base64.urlsafe_b64encode(b'{"t":"2026-10-19T09:00:00","id":"evt_x"}').decode(),
        base64.urlsafe_b64encode(b'{"t":"2026-10-19T09:00:00Z","id":"apr_x"}').decode(),
        base64.urlsafe_b64encode(b'{"t":"2026-10-19T09:00:00Z","id":5}').decode(),
        base64.urlsafe_b64encode(b'{"t":"yesterday","id":"evt_x"}').decode(),
        base64.urlsafe_b64encode(b'{"id":"evt_x"}').decode(),
    ],
)
def test_foreign_cursors_are_rejected(raw: str) -> None:
    with pytest.raises(InvalidCursorError):
        Cursor.decode(raw)


def test_query_validates_limit_and_times() -> None:
    with pytest.raises(ValueError, match="limit"):
        AuditQuery(limit=0)
    with pytest.raises(ValueError, match="limit"):
        AuditQuery(limit=1001)
    with pytest.raises(ValueError, match="timezone-aware"):
        AuditQuery(since=datetime(2026, 1, 1))


def test_query_matching() -> None:
    e = event()
    assert AuditQuery().matches(e)
    assert AuditQuery(agent="bot", server="demo", tool="echo", method="tools/call").matches(e)
    assert not AuditQuery(agent="other").matches(e)
    assert not AuditQuery(outcome=Outcome.DENIED).matches(e)
    assert AuditQuery(since=T0).matches(e)
    assert not AuditQuery(until=T0).matches(e)
    assert not AuditQuery(cursor=Cursor.after(e)).matches(e)
    assert AuditQuery(cursor=Cursor(T0 + timedelta(microseconds=1), "evt_0")).matches(e)
