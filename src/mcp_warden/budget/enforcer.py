"""Applying the policy's ``budgets`` to ``tools/call``.

Each budget that matches a call contributes one charge: per agent
(``scope: agent``) or per agent, server and tool (``scope: tool``), in the
window that contains the current time. The enforcer reserves the call
against all of them before it is forwarded and settles the reply's tokens
afterwards.

Counters are keyed by the budget id, so editing a budget's numbers keeps the
usage booked so far in the window, while renaming it starts afresh.

A call that was forwarded counts even when the upstream then failed or timed
out: the tool may have run, and a budget that could be refunded by making
the upstream fail would not be a budget.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from mcp_warden.budget.estimator import TokenEstimator, canonical_json
from mcp_warden.budget.ledger import Charge, Refusal
from mcp_warden.budget.window import window_bounds
from mcp_warden.jsonrpc import ErrorCode, JsonRpcErrorResponse, JsonRpcSuccess, RetryAfterError
from mcp_warden.policy import LimitScope, PolicyEngine

logger = logging.getLogger(__name__)


class UsageStore(Protocol):
    async def reserve(self, charges: Sequence[Charge], tokens: int) -> Refusal | None: ...

    async def settle(self, charges: Sequence[Charge], tokens: int) -> None: ...


class BudgetObserver(Protocol):
    """Told what the enforcer booked and refused; used for metrics."""

    def booked(self, charges: Sequence[Charge], calls: int, tokens: int) -> None: ...

    def refused(self, refusal: Refusal) -> None: ...


class BudgetExhaustedError(RetryAfterError):
    """``BUDGET_EXHAUSTED``; ``retry_after`` is the time until the window resets."""

    def __init__(self, message: str, data: dict[str, object], retry_after: int) -> None:
        super().__init__(ErrorCode.BUDGET_EXHAUSTED, message, data, retry_after)


@dataclass(frozen=True, slots=True)
class Reservation:
    """A call booked against its budgets, waiting for the reply's tokens."""

    charges: tuple[Charge, ...]
    request_tokens: int


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class BudgetEnforcer:
    def __init__(
        self,
        engine: PolicyEngine,
        store: UsageStore,
        estimator: TokenEstimator,
        clock: Callable[[], datetime] | None = None,
        observer: BudgetObserver | None = None,
    ) -> None:
        self.engine = engine
        self.store = store
        self.estimator = estimator
        self._clock = clock or _utcnow
        self.observer = observer

    def charges_for(self, agent: str, server: str, tool: str, now: datetime) -> list[Charge]:
        charges = []
        for budget in self.engine.budgets_for(agent, server, tool):
            start, end = window_bounds(budget.window, now)
            per_tool = budget.scope is LimitScope.TOOL
            charges.append(
                Charge(
                    budget,
                    agent,
                    server if per_tool else None,
                    tool if per_tool else None,
                    start,
                    end,
                )
            )
        return charges

    def request_tokens(self, tool: str, arguments: Any) -> int:
        return self.estimator.count(canonical_json({"name": tool, "arguments": arguments}))

    def reply_tokens(self, response: JsonRpcSuccess | JsonRpcErrorResponse) -> int:
        if isinstance(response, JsonRpcSuccess):
            return self.estimator.count(canonical_json(response.result))
        return self.estimator.count(canonical_json(response.error.model_dump(exclude_none=True)))

    async def reserve(
        self, agent: str, server: str, tool: str, arguments: Any
    ) -> Reservation | None:
        """Book the call against every matching budget or raise ``BUDGET_EXHAUSTED``.

        Returns ``None`` when no budget applies, so there is nothing to settle.
        """
        now = self._clock()
        charges = self.charges_for(agent, server, tool, now)
        if not charges:
            return None
        tokens = self.request_tokens(tool, arguments)
        refusal = await self.store.reserve(charges, tokens)
        if refusal is not None:
            self._notify("refused", refusal)
            raise self._exhausted(refusal, server, tool, now)
        self._notify("booked", charges, 1, tokens)
        return Reservation(tuple(charges), tokens)

    async def settle(
        self, reservation: Reservation, response: JsonRpcSuccess | JsonRpcErrorResponse
    ) -> None:
        """Add the reply's tokens. Never fails the call: the tool has already run."""
        try:
            tokens = self.reply_tokens(response)
            await self.store.settle(reservation.charges, tokens)
        except Exception:
            logger.exception("could not record reply tokens for a budgeted call")
            return
        self._notify("booked", reservation.charges, 0, tokens)

    def _notify(self, event: str, *args: Any) -> None:
        if self.observer is None:
            return
        try:
            getattr(self.observer, event)(*args)
        except Exception:
            logger.exception("budget observer failed")

    def _exhausted(
        self, refusal: Refusal, server: str, tool: str, now: datetime
    ) -> BudgetExhaustedError:
        charge = refusal.charge
        budget = charge.budget
        retry_after = max(1, math.ceil((charge.window_end - now).total_seconds()))
        return BudgetExhaustedError(
            f"budget exhausted: {budget.id}",
            {
                "server": server,
                "tool": tool,
                "budget_id": budget.id,
                "scope": budget.scope.value,
                "window": budget.window.value,
                "exhausted": refusal.exhausted.value,
                "used": refusal.used,
                "limit": refusal.limit,
                "resets_at": _iso(charge.window_end),
                "retry_after": retry_after,
            },
            retry_after,
        )
