"""The approval store interface shared by the in-memory and database stores.

Stores are synchronous; the gateway runs them in a worker thread. Every
method takes ``now`` explicitly so that expiry is decided by one clock, the
caller's, which keeps tests deterministic and the two stores identical.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from mcp_warden.approval.model import (
    ApprovalError,
    ApprovalRequest,
    ApprovalStatus,
    NewApproval,
)


class TooManyPendingError(ApprovalError):
    """The agent already has the maximum number of requests waiting for a reviewer."""

    def __init__(self, agent: str, limit: int) -> None:
        super().__init__(f"agent {agent!r} already has {limit} pending approval requests")
        self.agent = agent
        self.limit = limit


@dataclass(frozen=True, slots=True)
class ApprovalTimings:
    """How long requests and decisions stay valid, and the per-agent queue cap."""

    pending_ttl: timedelta = timedelta(minutes=15)
    decision_ttl: timedelta = timedelta(minutes=10)
    max_pending_per_agent: int = 20

    def __post_init__(self) -> None:
        if self.pending_ttl <= timedelta(0) or self.decision_ttl <= timedelta(0):
            raise ValueError("approval TTLs must be positive")
        if self.max_pending_per_agent < 1:
            raise ValueError("max_pending_per_agent must be at least 1")


class ApprovalStore(Protocol):
    def open(self, new: NewApproval, now: datetime, timings: ApprovalTimings) -> ApprovalRequest:
        """The open request for this exact call, creating a pending one if there is none.

        Raises :class:`TooManyPendingError` instead of creating one past the cap.
        """
        ...

    def claim(self, approval_id: str, now: datetime) -> bool:
        """Spend an approval: ``approved`` and unexpired becomes ``executed``.

        Returns ``False`` if it was not claimable (already spent, expired, ...).
        Exactly one of several concurrent claims succeeds.
        """
        ...

    def decide(
        self,
        approval_id: str,
        *,
        approve: bool,
        reviewer: str,
        note: str | None,
        now: datetime,
        timings: ApprovalTimings,
    ) -> ApprovalRequest:
        """Approve or deny a pending request; raises if it is unknown or not pending."""
        ...

    def get(self, approval_id: str) -> ApprovalRequest:
        """Raises :class:`~mcp_warden.approval.model.ApprovalNotFoundError`."""
        ...

    def list(
        self,
        now: datetime,
        *,
        status: ApprovalStatus | None = None,
        agent: str | None = None,
        limit: int = 100,
    ) -> list[ApprovalRequest]:
        """Requests newest first, filtered by their status as of ``now``."""
        ...
