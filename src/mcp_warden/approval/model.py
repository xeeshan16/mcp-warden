"""Approval requests: the records a human decides on.

A ``tools/call`` whose policy decision is ``require_approval`` is parked as
an approval request instead of being forwarded. The request is identified by
its *fingerprint*, the digest of the agent, server, tool and canonical
arguments, so an agent that repeats the exact same call finds the same
request rather than opening a new one, and an approval can never be spent on
a call with different arguments.

Lifecycle::

    pending ──approve──▶ approved ──call repeated──▶ executed
       │                    │
       ├──deny──▶ denied    └──decision window passes──▶ expired
       └──pending window passes──▶ expired

* ``pending`` waits for a reviewer until ``expires_at`` (the pending TTL).
* A decision is valid for the decision TTL: an ``approved`` request must be
  used within it, and a ``denied`` one answers repeats of the call with the
  denial for that long, so an agent cannot reopen a request it was just
  refused by retrying.
* ``executed`` and ``expired`` are final and release the fingerprint: the
  next identical call opens a fresh request.

Expiry is evaluated lazily against the clock (:meth:`ApprovalRequest.state`),
so no background job is needed for correctness. The stored arguments are what
the reviewer judges; they are dropped once a request reaches a final state or
is denied, leaving only their digest and size.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from mcp_warden.budget.estimator import canonical_json

# Columns hold readable labels; the fingerprint covers the full values.
LABEL_MAX = 200
NOTE_MAX = 500
REVIEWER_MAX = 100


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXECUTED = "executed"
    EXPIRED = "expired"

    @property
    def is_open(self) -> bool:
        """Open requests hold their fingerprint; final ones release it."""
        return self in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED, ApprovalStatus.DENIED)


class ApprovalError(ValueError):
    """A request to the approval store that cannot be satisfied."""


class ApprovalNotFoundError(ApprovalError):
    pass


class ApprovalConflictError(ApprovalError):
    """The request is no longer pending (decided, executed or expired)."""


def new_approval_id() -> str:
    return f"apr_{secrets.token_hex(12)}"


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def arguments_digest(arguments: dict[str, Any]) -> str:
    return _digest(arguments)


def fingerprint(agent: str, server: str, tool: str, arguments: dict[str, Any]) -> str:
    """Digest identifying one exact call; key order and whitespace never matter."""
    return _digest({"agent": agent, "server": server, "tool": tool, "arguments": arguments})


def label(value: str) -> str:
    return value[:LABEL_MAX]


@dataclass(frozen=True, slots=True)
class NewApproval:
    """What the gateway knows about a call that needs a human."""

    agent: str
    server: str
    tool: str
    arguments: dict[str, Any]
    rule_id: str | None
    reason: str

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.agent, self.server, self.tool, self.arguments)


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """A snapshot of one approval request."""

    id: str
    agent: str
    server: str
    tool: str
    rule_id: str | None
    reason: str
    arguments: dict[str, Any] | None
    arguments_digest: str
    arguments_size: int
    fingerprint: str
    status: ApprovalStatus
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None = None
    decided_by: str | None = None
    note: str | None = None
    executed_at: datetime | None = None

    def state(self, now: datetime) -> ApprovalStatus:
        """The status as of ``now``: open requests past ``expires_at`` have expired."""
        if self.status.is_open and self.expires_at <= now:
            return ApprovalStatus.EXPIRED
        return self.status

    def to_dict(self, now: datetime) -> dict[str, Any]:
        """JSON-friendly view for the admin API and the CLI."""
        return {
            "id": self.id,
            "status": self.state(now).value,
            "agent": self.agent,
            "server": self.server,
            "tool": self.tool,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "arguments": self.arguments,
            "arguments_digest": self.arguments_digest,
            "arguments_size": self.arguments_size,
            "created_at": iso(self.created_at),
            "expires_at": iso(self.expires_at),
            "decided_at": iso(self.decided_at),
            "decided_by": self.decided_by,
            "note": self.note,
            "executed_at": iso(self.executed_at),
        }


def iso(ts: datetime | None) -> str | None:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if ts is not None else None
