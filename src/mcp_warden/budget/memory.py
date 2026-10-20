"""In-process usage ledger: for one gateway, development and tests.

Usage lives in process memory, so it is lost on restart and each replica
counts only its own traffic. Daily, weekly and monthly budgets are usually
meant to survive both; use the database store for those.

Counters of past windows carry no information for enforcement and are swept
once the table grows past ``max_counters``. If that is not enough, the least
recently used counters are dropped, which resets them; this needs an unusual
spread of agents and tools and is the price of bounded memory.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from mcp_warden.budget.ledger import (
    Charge,
    Refusal,
    Usage,
    UsageRecord,
    decide,
    unique_charges,
)

DEFAULT_MAX_COUNTERS = 100_000


@dataclass(frozen=True, slots=True)
class _Entry:
    usage: Usage
    # The charge that created the counter: what reports show it as.
    charge: Charge

    @property
    def window_end(self) -> datetime:
        return self.charge.window_end


def _utcnow() -> datetime:
    return datetime.now(UTC)


class InMemoryUsageStore:
    def __init__(
        self,
        max_counters: int = DEFAULT_MAX_COUNTERS,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        if max_counters < 1:
            raise ValueError("max_counters must be at least 1")
        self._max = max_counters
        self._clock = clock
        self._entries: OrderedDict[tuple[str, datetime], _Entry] = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._entries)

    def usage(self, charge: Charge) -> Usage:
        with self._lock:
            entry = self._entries.get(charge.slot)
            return entry.usage if entry is not None else Usage()

    async def reserve(self, charges: Sequence[Charge], tokens: int) -> Refusal | None:
        return self.reserve_sync(charges, tokens)

    async def settle(self, charges: Sequence[Charge], tokens: int) -> None:
        self.settle_sync(charges, tokens)

    def reserve_sync(self, charges: Sequence[Charge], tokens: int) -> Refusal | None:
        charges = unique_charges(charges)
        if not charges:
            return None
        with self._lock:
            current = {
                c.slot: entry.usage
                for c in charges
                if (entry := self._entries.get(c.slot)) is not None
            }
            refusal = decide(charges, current, tokens)
            if refusal is not None:
                return refusal
            for charge in charges:
                used = current.get(charge.slot, Usage())
                self._entries[charge.slot] = _Entry(
                    Usage(used.calls + 1, used.tokens + tokens), charge
                )
                self._entries.move_to_end(charge.slot)
            if len(self._entries) > self._max:
                # Every window that ended before one of ours started is over.
                self._shrink(max(c.window_start for c in charges))
            return None

    def settle_sync(self, charges: Sequence[Charge], tokens: int) -> None:
        if tokens <= 0:
            return
        with self._lock:
            for charge in unique_charges(charges):
                entry = self._entries.get(charge.slot)
                if entry is None:
                    # Evicted since the reservation; nothing left to add to.
                    continue
                usage = entry.usage
                self._entries[charge.slot] = replace(
                    entry, usage=Usage(usage.calls, usage.tokens + tokens)
                )

    def records(
        self, *, agent: str | None = None, current_only: bool = True, limit: int = 100
    ) -> list[UsageRecord]:
        """Counters, newest window first; by default only windows still open."""
        now = self._clock()
        with self._lock:
            entries = list(self._entries.values())
        records = [
            UsageRecord.of(e.charge, e.usage)
            for e in entries
            if (agent is None or e.charge.agent == agent)
            and (not current_only or e.window_end > now)
        ]
        return sorted(records, key=UsageRecord.sort_key)[:limit]

    def prune(self, now: datetime) -> int:
        """Forget counters of windows that have ended; returns how many."""
        with self._lock:
            return self._prune(now)

    def _prune(self, now: datetime) -> int:
        ended = [slot for slot, entry in self._entries.items() if entry.window_end <= now]
        for slot in ended:
            del self._entries[slot]
        return len(ended)

    def _shrink(self, now: datetime) -> None:
        self._prune(now)
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)
