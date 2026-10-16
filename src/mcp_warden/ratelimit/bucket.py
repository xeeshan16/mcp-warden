"""Token-bucket arithmetic, free of storage and clocks.

A bucket holds up to ``capacity`` tokens and refills continuously at
``refill_per_second``. Instead of a timer, each stored bucket remembers its
level and when that level was recorded; the current level is derived on read.
A bucket that has never been used (or has been pruned) is full, so storage
only needs rows for buckets that are below capacity.

Acquiring is all-or-nothing across the buckets of one call: tokens are taken
from every bucket only if every bucket has enough. A refused call therefore
never drains a bucket, and after the reported ``retry_after`` every bucket
involved has refilled far enough for the call to pass, unless other calls took
the tokens first.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

# Absorbs floating-point error so a caller that waits exactly ``retry_after``
# seconds is not refused by a rounding residue.
_EPSILON = 1e-9


@dataclass(frozen=True, slots=True)
class BucketSpec:
    """One bucket a call must take a token from."""

    key: str
    capacity: float
    refill_per_second: float

    def __post_init__(self) -> None:
        if self.capacity <= 0 or self.refill_per_second <= 0:
            raise ValueError("capacity and refill rate must be positive")


@dataclass(frozen=True, slots=True)
class BucketState:
    """A bucket's level at ``updated_at`` (seconds on the store's clock)."""

    tokens: float
    updated_at: float


@dataclass(frozen=True, slots=True)
class Acquisition:
    """Outcome of trying to take tokens for one call."""

    allowed: bool
    # Seconds until every bucket of the call holds enough tokens; 0 if allowed.
    retry_after: float = 0.0
    # The bucket with the longest wait, when refused.
    limiting_key: str | None = None


ALLOWED = Acquisition(True)


def level(spec: BucketSpec, state: BucketState | None, now: float) -> float:
    """The bucket's level at ``now``. A clock that went backwards adds nothing."""
    if state is None:
        return spec.capacity
    elapsed = max(0.0, now - state.updated_at)
    return min(spec.capacity, state.tokens + elapsed * spec.refill_per_second)


def full_at(spec: BucketSpec, tokens: float, now: float) -> float:
    """When a bucket at ``tokens`` will be full again; it can be forgotten then."""
    return now + max(0.0, spec.capacity - tokens) / spec.refill_per_second


def decide(specs: Sequence[BucketSpec], levels: Mapping[str, float], cost: float) -> Acquisition:
    """Whether ``cost`` tokens can be taken from every bucket, and if not, how long to wait."""
    if cost <= 0:
        raise ValueError("cost must be positive")
    if any(cost > spec.capacity for spec in specs):
        raise ValueError("cost exceeds a bucket's capacity; the call could never pass")
    waits = {
        spec.key: (cost - levels[spec.key]) / spec.refill_per_second
        for spec in specs
        if levels[spec.key] + _EPSILON < cost
    }
    if not waits:
        return ALLOWED
    key = max(waits, key=lambda k: waits[k])
    return Acquisition(False, waits[key], key)


def unique_specs(specs: Sequence[BucketSpec]) -> list[BucketSpec]:
    """Drop repeated keys (first wins) and sort by key.

    Sorting gives every caller the same lock order in a database, which rules
    out deadlocks between two calls that share buckets.
    """
    seen: dict[str, BucketSpec] = {}
    for spec in specs:
        seen.setdefault(spec.key, spec)
    return [seen[key] for key in sorted(seen)]
