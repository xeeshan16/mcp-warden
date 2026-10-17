"""Budget charges and the pure decision whether a call fits.

A *charge* is one budget counter a call is booked against: the budget, who
it is kept for (the agent, or the agent, server and tool), and the window.
The usage ledger keeps one row of ``calls`` and ``tokens`` per counter and
window, so past windows remain as history until the retention job removes
them.

Booking is two-phase:

1. ``reserve`` happens before the call is forwarded. It is all-or-nothing
   across the call's charges: one call and the request's estimated tokens
   are added to every counter only if every budget has room. A refused call
   books nothing.
2. ``settle`` adds the tokens of the upstream's reply once it is known.

The reply's size is unknown in advance, so a token budget can end a window
slightly over its limit: the call that crosses the line completes, and every
later call in the window is refused. Refusing the crossing call would mean
refusing work after the tool already ran.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from mcp_warden.policy import Budget, LimitScope


class Exhausted(StrEnum):
    CALLS = "calls"
    TOKENS = "tokens"


@dataclass(frozen=True, slots=True)
class Charge:
    """One counter a call is booked against."""

    budget: Budget
    agent: str
    # ``None`` for ``scope: agent`` budgets, which count every matching call.
    server: str | None
    tool: str | None
    window_start: datetime
    window_end: datetime

    @property
    def key(self) -> str:
        parts = [self.budget.id, self.agent]
        if self.budget.scope is LimitScope.TOOL:
            parts += [self.server or "", self.tool or ""]
        # JSON keeps the key unambiguous whatever characters the names contain.
        return json.dumps(parts, separators=(",", ":"))

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.key.encode("utf-8")).hexdigest()

    @property
    def slot(self) -> tuple[str, datetime]:
        """Identifies the counter row: the key and the window it belongs to."""
        return (self.digest, self.window_start)


@dataclass(frozen=True, slots=True)
class Usage:
    calls: int = 0
    tokens: int = 0


@dataclass(frozen=True, slots=True)
class Refusal:
    """Why a call does not fit: the budget whose window resets last."""

    charge: Charge
    exhausted: Exhausted
    used: int
    limit: int


def unique_charges(charges: Sequence[Charge]) -> list[Charge]:
    """Drop repeated slots (first wins) and sort, giving every caller one lock order."""
    seen: dict[tuple[str, datetime], Charge] = {}
    for charge in charges:
        seen.setdefault(charge.slot, charge)
    return [seen[slot] for slot in sorted(seen)]


def _refusal(charge: Charge, usage: Usage, tokens: int) -> Refusal | None:
    budget = charge.budget
    if budget.max_calls is not None and usage.calls + 1 > budget.max_calls:
        return Refusal(charge, Exhausted.CALLS, usage.calls, budget.max_calls)
    if budget.max_tokens is not None and usage.tokens + tokens > budget.max_tokens:
        return Refusal(charge, Exhausted.TOKENS, usage.tokens, budget.max_tokens)
    return None


def decide(
    charges: Sequence[Charge], usage: Mapping[tuple[str, datetime], Usage], tokens: int
) -> Refusal | None:
    """``None`` if one call of ``tokens`` fits every charge, else the binding refusal.

    When several budgets are exhausted, the one that resets last is reported,
    because the call cannot pass before then.
    """
    if tokens < 0:
        raise ValueError("tokens must not be negative")
    refusals = [
        refusal
        for charge in charges
        if (refusal := _refusal(charge, usage.get(charge.slot, Usage()), tokens)) is not None
    ]
    if not refusals:
        return None
    return max(refusals, key=lambda r: r.charge.window_end)
