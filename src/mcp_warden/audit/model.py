"""Audit events: what the gateway decided about each request, without payloads.

An event records who called what and what happened to it: the agent, the
upstream server, the JSON-RPC method, the tool for ``tools/call``, the
outcome, the policy effect and rule, the approval involved, the JSON-RPC
error code if the call failed, and how long the gateway took. Arguments are
represented only by their size and a digest; results, error messages and
anything else an agent or server wrote are never stored, because they are
where secrets and personal data live.

The digest lets an investigator check whether two calls had identical
arguments, or whether a call matches arguments they already hold, without
the log revealing them. A plain SHA-256 of a small argument object (say
``{"confirm": true}``) can be guessed by hashing candidates, so the digest is
an HMAC when an audit hash key is configured. Without a key it is a plain
SHA-256 and documented as such.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from mcp_warden.budget.estimator import canonical_json
from mcp_warden.jsonrpc import ErrorCode

# Column widths; values are cut to fit, the digest covers the full arguments.
LABEL_MAX = 200
METHOD_MAX = 100
RULE_MAX = 100


class Outcome(StrEnum):
    """What happened to one request, as far as the gateway is concerned."""

    # The upstream answered. Its answer may still be a JSON-RPC error or a
    # tool result with ``isError``; see ``error_code`` and ``tool_error``.
    FORWARDED = "forwarded"
    DENIED = "denied"
    APPROVAL_PENDING = "approval_pending"
    RATE_LIMITED = "rate_limited"
    BUDGET_EXHAUSTED = "budget_exhausted"
    UPSTREAM_ERROR = "upstream_error"
    INVALID = "invalid"
    ERROR = "error"


_OUTCOME_BY_CODE: dict[int, Outcome] = {
    ErrorCode.POLICY_DENIED: Outcome.DENIED,
    ErrorCode.APPROVAL_REQUIRED: Outcome.APPROVAL_PENDING,
    ErrorCode.RATE_LIMITED: Outcome.RATE_LIMITED,
    ErrorCode.BUDGET_EXHAUSTED: Outcome.BUDGET_EXHAUSTED,
    ErrorCode.UPSTREAM_ERROR: Outcome.UPSTREAM_ERROR,
    ErrorCode.UPSTREAM_TIMEOUT: Outcome.UPSTREAM_ERROR,
    ErrorCode.INVALID_PARAMS: Outcome.INVALID,
    ErrorCode.INVALID_REQUEST: Outcome.INVALID,
}


def outcome_for_refusal(code: int) -> Outcome:
    """The outcome of a request the gateway answered itself with ``code``."""
    return _OUTCOME_BY_CODE.get(code, Outcome.ERROR)


def new_event_id() -> str:
    return f"evt_{secrets.token_hex(12)}"


def _cut(value: str | None, width: int) -> str | None:
    return None if value is None else value[:width]


class ArgumentHasher:
    """Digest and size of tool arguments; keyed (HMAC-SHA-256) when a key is given."""

    def __init__(self, key: bytes | None = None) -> None:
        if key is not None and len(key) < 16:
            raise ValueError("the audit hash key must be at least 16 bytes")
        self._key = key

    @property
    def keyed(self) -> bool:
        return self._key is not None

    def digest(self, arguments: dict[str, Any]) -> tuple[str, int]:
        encoded = canonical_json(arguments).encode()
        if self._key is None:
            return hashlib.sha256(encoded).hexdigest(), len(encoded)
        return hmac.new(self._key, encoded, hashlib.sha256).hexdigest(), len(encoded)

    def __repr__(self) -> str:
        return f"ArgumentHasher(keyed={self.keyed})"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One request handled by the gateway. Holds metadata only, never payloads."""

    id: str
    occurred_at: datetime
    agent: str
    server: str
    method: str
    outcome: Outcome
    latency_ms: float
    tool: str | None = None
    effect: str | None = None
    rule_id: str | None = None
    approval_id: str | None = None
    error_code: int | None = None
    tool_error: bool | None = None
    arguments_digest: str | None = None
    arguments_size: int | None = None

    @classmethod
    def create(
        cls,
        *,
        occurred_at: datetime,
        agent: str,
        server: str,
        method: str,
        outcome: Outcome,
        latency_ms: float,
        tool: str | None = None,
        effect: str | None = None,
        rule_id: str | None = None,
        approval_id: str | None = None,
        error_code: int | None = None,
        tool_error: bool | None = None,
        arguments_digest: str | None = None,
        arguments_size: int | None = None,
    ) -> AuditEvent:
        """A new event with a fresh id and every label cut to its column width."""
        if occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        return cls(
            id=new_event_id(),
            occurred_at=occurred_at.astimezone(UTC),
            agent=agent[:LABEL_MAX],
            server=server[:LABEL_MAX],
            method=method[:METHOD_MAX],
            outcome=outcome,
            latency_ms=round(max(latency_ms, 0.0), 3),
            tool=_cut(tool, LABEL_MAX),
            effect=effect,
            rule_id=_cut(rule_id, RULE_MAX),
            approval_id=_cut(approval_id, 40),
            error_code=error_code,
            tool_error=tool_error,
            arguments_digest=arguments_digest,
            arguments_size=arguments_size,
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly view for the query API and the CLI."""
        return {
            "id": self.id,
            "occurred_at": self.occurred_at.astimezone(UTC).isoformat(timespec="microseconds"),
            "agent": self.agent,
            "server": self.server,
            "method": self.method,
            "tool": self.tool,
            "outcome": self.outcome.value,
            "effect": self.effect,
            "rule_id": self.rule_id,
            "approval_id": self.approval_id,
            "error_code": self.error_code,
            "tool_error": self.tool_error,
            "latency_ms": self.latency_ms,
            "arguments_digest": self.arguments_digest,
            "arguments_size": self.arguments_size,
        }


class InvalidCursorError(ValueError):
    """A pagination cursor that this gateway did not issue."""


@dataclass(frozen=True, slots=True)
class Cursor:
    """Position after the last event of a page, newest first: ``(occurred_at, id)``.

    Keyset pagination: a page is "events strictly older than the cursor", so
    events written while someone pages never shift or repeat entries, and
    every page costs one index range scan however deep it is.
    """

    occurred_at: datetime
    id: str

    def encode(self) -> str:
        raw = json.dumps(
            {"t": self.occurred_at.astimezone(UTC).isoformat(), "id": self.id},
            separators=(",", ":"),
        )
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    @classmethod
    def decode(cls, value: str) -> Cursor:
        try:
            padded = value + "=" * (-len(value) % 4)
            data = json.loads(base64.urlsafe_b64decode(padded.encode()))
            occurred_at = datetime.fromisoformat(data["t"])
            event_id = data["id"]
        except (ValueError, KeyError, TypeError, binascii.Error) as exc:
            raise InvalidCursorError("invalid cursor") from exc
        if (
            occurred_at.tzinfo is None
            or not isinstance(event_id, str)
            or not event_id.startswith("evt_")
            or len(event_id) > 40
        ):
            raise InvalidCursorError("invalid cursor")
        return cls(occurred_at.astimezone(UTC), event_id)

    @classmethod
    def after(cls, event: AuditEvent) -> Cursor:
        return cls(event.occurred_at, event.id)


@dataclass(frozen=True, slots=True)
class AuditQuery:
    """Filters for listing events; every given filter must match (AND)."""

    agent: str | None = None
    server: str | None = None
    tool: str | None = None
    method: str | None = None
    outcome: Outcome | None = None
    since: datetime | None = None  # inclusive
    until: datetime | None = None  # exclusive
    cursor: Cursor | None = None
    limit: int = 100

    def __post_init__(self) -> None:
        if not 1 <= self.limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        for ts in (self.since, self.until):
            if ts is not None and ts.tzinfo is None:
                raise ValueError("since and until must be timezone-aware")

    def matches(self, event: AuditEvent) -> bool:
        """Whether ``event`` passes the filters and lies past the cursor."""
        if self.agent is not None and event.agent != self.agent:
            return False
        if self.server is not None and event.server != self.server:
            return False
        if self.tool is not None and event.tool != self.tool:
            return False
        if self.method is not None and event.method != self.method:
            return False
        if self.outcome is not None and event.outcome is not self.outcome:
            return False
        if self.since is not None and event.occurred_at < self.since:
            return False
        if self.until is not None and event.occurred_at >= self.until:
            return False
        if self.cursor is not None:
            return (event.occurred_at, event.id) < (self.cursor.occurred_at, self.cursor.id)
        return True


@dataclass(frozen=True, slots=True)
class AuditPage:
    events: list[AuditEvent]
    next_cursor: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"events": [e.to_dict() for e in self.events], "next_cursor": self.next_cursor}


def page_from(events: list[AuditEvent], limit: int) -> AuditPage:
    """Build a page from up to ``limit + 1`` events fetched newest first."""
    has_more = len(events) > limit
    events = events[:limit]
    cursor = Cursor.after(events[-1]).encode() if has_more and events else None
    return AuditPage(events, cursor)
