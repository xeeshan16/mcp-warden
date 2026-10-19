"""In-process approval store: for a single gateway, development and tests.

Requests live in process memory, so a restart forgets them and a reviewer
can only reach them through the gateway's admin API. Use the database store
to decide from the CLI or to run more than one gateway.

Memory is bounded: past ``max_requests``, the oldest requests in a final
state (executed, expired) are dropped first, then the oldest of any kind.
Open requests are already bounded per agent by the pending cap.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import replace
from datetime import datetime

from mcp_warden.approval.model import (
    ApprovalConflictError,
    ApprovalNotFoundError,
    ApprovalRequest,
    ApprovalStatus,
    NewApproval,
    arguments_digest,
    label,
    new_approval_id,
)
from mcp_warden.approval.store import ApprovalTimings, TooManyPendingError
from mcp_warden.budget.estimator import canonical_json

DEFAULT_MAX_REQUESTS = 10_000


class InMemoryApprovalStore:
    def __init__(self, max_requests: int = DEFAULT_MAX_REQUESTS) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be at least 1")
        self._max = max_requests
        self._requests: OrderedDict[str, ApprovalRequest] = OrderedDict()
        self._open: dict[str, str] = {}  # fingerprint -> id of its open request
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._requests)

    def open(self, new: NewApproval, now: datetime, timings: ApprovalTimings) -> ApprovalRequest:
        fp = new.fingerprint
        with self._lock:
            existing_id = self._open.get(fp)
            if existing_id is not None:
                existing = self._requests[existing_id]
                if existing.state(now) is not ApprovalStatus.EXPIRED:
                    return existing
                self._finish(existing, ApprovalStatus.EXPIRED)
            pending = sum(
                1
                for r in self._requests.values()
                if r.agent == label(new.agent) and r.state(now) is ApprovalStatus.PENDING
            )
            if pending >= timings.max_pending_per_agent:
                raise TooManyPendingError(new.agent, timings.max_pending_per_agent)
            request = ApprovalRequest(
                id=new_approval_id(),
                agent=label(new.agent),
                server=label(new.server),
                tool=label(new.tool),
                rule_id=new.rule_id,
                reason=new.reason[:500],
                arguments=new.arguments,
                arguments_digest=arguments_digest(new.arguments),
                arguments_size=len(canonical_json(new.arguments).encode()),
                fingerprint=fp,
                status=ApprovalStatus.PENDING,
                created_at=now,
                expires_at=now + timings.pending_ttl,
            )
            self._requests[request.id] = request
            self._open[fp] = request.id
            self._shrink(now)
            return request

    def claim(self, approval_id: str, now: datetime) -> bool:
        with self._lock:
            request = self._requests.get(approval_id)
            if request is None or request.state(now) is not ApprovalStatus.APPROVED:
                return False
            self._finish(request, ApprovalStatus.EXECUTED, executed_at=now)
            return True

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
        with self._lock:
            request = self._requests.get(approval_id)
            if request is None:
                raise ApprovalNotFoundError(f"no approval request {approval_id!r}")
            state = request.state(now)
            if state is not ApprovalStatus.PENDING:
                raise ApprovalConflictError(f"approval request {approval_id} is {state.value}")
            decided = replace(
                request,
                status=ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED,
                decided_at=now,
                decided_by=reviewer,
                note=note,
                expires_at=now + timings.decision_ttl,
                arguments=request.arguments if approve else None,
            )
            self._requests[approval_id] = decided
            return decided

    def get(self, approval_id: str) -> ApprovalRequest:
        with self._lock:
            request = self._requests.get(approval_id)
        if request is None:
            raise ApprovalNotFoundError(f"no approval request {approval_id!r}")
        return request

    def list(
        self,
        now: datetime,
        *,
        status: ApprovalStatus | None = None,
        agent: str | None = None,
        limit: int = 100,
    ) -> list[ApprovalRequest]:
        with self._lock:
            requests = list(self._requests.values())
        matches = [
            r
            for r in reversed(requests)
            if (status is None or r.state(now) is status) and (agent is None or r.agent == agent)
        ]
        return matches[:limit]

    def prune(self, before: datetime) -> int:
        with self._lock:
            finished = [r for r in self._requests.values() if _finished_at(r) < before]
            for request in finished:
                del self._requests[request.id]
                if self._open.get(request.fingerprint) == request.id:
                    del self._open[request.fingerprint]
            return len(finished)

    def _finish(
        self, request: ApprovalRequest, status: ApprovalStatus, executed_at: datetime | None = None
    ) -> None:
        self._requests[request.id] = replace(
            request, status=status, arguments=None, executed_at=executed_at
        )
        if self._open.get(request.fingerprint) == request.id:
            del self._open[request.fingerprint]

    def _shrink(self, now: datetime) -> None:
        if len(self._requests) <= self._max:
            return
        for request_id, request in list(self._requests.items()):
            if len(self._requests) <= self._max:
                return
            if not request.state(now).is_open:
                del self._requests[request_id]
        while len(self._requests) > self._max:
            _, dropped = self._requests.popitem(last=False)
            if self._open.get(dropped.fingerprint) == dropped.id:
                del self._open[dropped.fingerprint]


def _finished_at(request: ApprovalRequest) -> datetime:
    """When an executed request ran; for any other, when its window ends or ended."""
    if request.status is ApprovalStatus.EXECUTED and request.executed_at is not None:
        return request.executed_at
    return request.expires_at
