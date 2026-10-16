"""In-process bucket store: fast, exact, and per gateway instance.

Use it for a single gateway. With several replicas each instance enforces the
limits on its own share of the traffic; use the database store for limits
shared across instances.

Memory stays bounded: buckets that have refilled completely carry no
information and are swept once the table grows past ``max_buckets``. If that
is not enough, the least recently used buckets are dropped, which resets them
to full; this only happens under an unusually wide spread of agents and tools
and is the price of not letting callers grow memory without limit.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from mcp_warden.ratelimit.bucket import (
    ALLOWED,
    Acquisition,
    BucketSpec,
    BucketState,
    decide,
    full_at,
    level,
    unique_specs,
)

DEFAULT_MAX_BUCKETS = 100_000


@dataclass(frozen=True, slots=True)
class _Entry:
    state: BucketState
    full_at: float


class InMemoryBucketStore:
    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        max_buckets: int = DEFAULT_MAX_BUCKETS,
    ) -> None:
        if max_buckets < 1:
            raise ValueError("max_buckets must be at least 1")
        self._clock = clock
        self._max_buckets = max_buckets
        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._entries)

    async def acquire(self, specs: Sequence[BucketSpec], cost: float = 1.0) -> Acquisition:
        return self.acquire_sync(specs, cost)

    def acquire_sync(self, specs: Sequence[BucketSpec], cost: float = 1.0) -> Acquisition:
        specs = unique_specs(specs)
        if not specs:
            return ALLOWED
        with self._lock:
            now = self._clock()
            levels = {}
            for spec in specs:
                entry = self._entries.get(spec.key)
                levels[spec.key] = level(spec, entry.state if entry else None, now)
            result = decide(specs, levels, cost)
            if result.allowed:
                for spec in specs:
                    tokens = levels[spec.key] - cost
                    self._entries[spec.key] = _Entry(
                        BucketState(tokens, now), full_at(spec, tokens, now)
                    )
                    self._entries.move_to_end(spec.key)
                if len(self._entries) > self._max_buckets:
                    self._shrink(now)
            return result

    def prune(self) -> int:
        """Forget buckets that have refilled completely; returns how many."""
        with self._lock:
            return self._prune(self._clock())

    def _prune(self, now: float) -> int:
        full = [key for key, entry in self._entries.items() if entry.full_at <= now]
        for key in full:
            del self._entries[key]
        return len(full)

    def _shrink(self, now: float) -> None:
        self._prune(now)
        while len(self._entries) > self._max_buckets:
            self._entries.popitem(last=False)
