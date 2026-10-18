"""The approval step of the proxy pipeline.

For a ``tools/call`` the policy marks ``require_approval``, the gate opens
(or finds) the approval request for that exact call and then:

* **pending** → the agent gets ``APPROVAL_REQUIRED`` (``-32002``) with the
  request id, its expiry and a ``Retry-After`` hint. Repeating the identical
  call later is how the agent collects the decision, so any MCP client works
  unchanged. Optionally the gate first waits up to ``wait`` for a reviewer,
  in which case an approval arriving in time is answered with the tool's
  result in the same round trip;
* **approved** → the call proceeds through rate limits and budgets, and the
  approval is spent with :meth:`ApprovalGate.claim` just before forwarding,
  so a call refused by a limit keeps its approval for the retry;
* **denied** → ``POLICY_DENIED`` (``-32001``) naming the reviewer's note,
  for as long as the decision is valid.

An approval covers one execution of one exact call: same agent, server,
tool and arguments. A different argument value is a different request.
"""

from __future__ import annotations

import math
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio
import anyio.to_thread

from mcp_warden.approval.model import ApprovalRequest, ApprovalStatus, NewApproval, iso
from mcp_warden.approval.store import ApprovalStore, ApprovalTimings, TooManyPendingError
from mcp_warden.jsonrpc import ErrorCode, JsonRpcError, RetryAfterError
from mcp_warden.policy import Decision


class ApprovalPendingError(RetryAfterError):
    """``APPROVAL_REQUIRED``: the call waits for a reviewer."""

    def __init__(self, message: str, data: dict[str, Any], retry_after: int) -> None:
        super().__init__(ErrorCode.APPROVAL_REQUIRED, message, data, retry_after)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ApprovalGate:
    def __init__(
        self,
        store: ApprovalStore,
        timings: ApprovalTimings | None = None,
        *,
        wait: timedelta = timedelta(0),
        poll_interval: float = 1.0,
        retry_after: int = 5,
        clock: Callable[[], datetime] | None = None,
        sleep: Callable[[float], Awaitable[None]] = anyio.sleep,
    ) -> None:
        if wait < timedelta(0):
            raise ValueError("wait must not be negative")
        if poll_interval <= 0 or retry_after < 1:
            raise ValueError("poll_interval and retry_after must be positive")
        self.store = store
        self.timings = timings or ApprovalTimings()
        self.wait = wait
        self.poll_interval = poll_interval
        self.retry_after = retry_after
        self._clock = clock or _utcnow
        self._sleep = sleep

    def now(self) -> datetime:
        return self._clock()

    async def admit(
        self,
        agent: str,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        decision: Decision,
    ) -> str:
        """Return the id of an approval covering this call, or raise.

        The approval is not spent yet; call :meth:`claim` right before forwarding.
        """
        new = NewApproval(agent, server, tool, arguments, decision.rule_id, decision.reason)
        try:
            request = await anyio.to_thread.run_sync(
                self.store.open, new, self._clock(), self.timings
            )
        except TooManyPendingError as exc:
            raise RetryAfterError(
                ErrorCode.RATE_LIMITED,
                "too many approval requests waiting for a reviewer",
                {
                    "server": server,
                    "tool": tool,
                    "pending_limit": exc.limit,
                    "retry_after": self.retry_after,
                },
                self.retry_after,
            ) from exc

        polls = math.ceil(self.wait.total_seconds() / self.poll_interval)
        for _ in range(polls):
            if request.state(self._clock()) is not ApprovalStatus.PENDING:
                break
            await self._sleep(self.poll_interval)
            request = await anyio.to_thread.run_sync(self.store.get, request.id)
        return self._outcome(request, server, tool)

    async def claim(self, approval_id: str, server: str, tool: str) -> None:
        """Spend the approval; raise if another call spent it first or it expired."""
        claimed = await anyio.to_thread.run_sync(self.store.claim, approval_id, self._clock())
        if not claimed:
            raise JsonRpcError(
                ErrorCode.APPROVAL_REQUIRED,
                "approval was already used or has expired; repeat the call to request a new one",
                {"server": server, "tool": tool, "approval_id": approval_id},
            )

    def _outcome(self, request: ApprovalRequest, server: str, tool: str) -> str:
        state = request.state(self._clock())
        data: dict[str, Any] = {
            "server": server,
            "tool": tool,
            "effect": "require_approval",
            "rule_id": request.rule_id,
            "reason": request.reason,
            "approval_id": request.id,
            "status": state.value,
        }
        if state is ApprovalStatus.APPROVED:
            return request.id
        if state is ApprovalStatus.DENIED:
            data.update(decided_by=request.decided_by, note=request.note)
            raise JsonRpcError(
                ErrorCode.POLICY_DENIED, f"tool call denied by a reviewer: {tool}", data
            )
        # Pending, or (after waiting) expired before anyone decided: either way
        # the agent may repeat the call later.
        data.update(expires_at=iso(request.expires_at), retry_after=self.retry_after)
        raise ApprovalPendingError(
            f"tool call requires human approval: {tool}", data, self.retry_after
        )
