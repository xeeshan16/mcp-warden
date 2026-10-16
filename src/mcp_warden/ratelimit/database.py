"""Database-backed bucket store: limits shared by every gateway instance.

Each call runs one short transaction: lock the call's bucket rows
(``SELECT ... FOR UPDATE`` on PostgreSQL, in key order so two calls can never
deadlock), derive the current levels, and write the new levels only if the
call is allowed. A refused call writes nothing.

Rows only exist for buckets below capacity. A missing row is a full bucket,
so the first call for a bucket inserts it; if a concurrent call inserted the
same row first, the transaction is retried once and then finds the row.
``prune`` deletes rows whose bucket has refilled (``full_at`` has passed).

Bucket keys are stored as SHA-256 digests: agent, server and tool names make
keys of unbounded length, and the digest gives a fixed-width primary key.

Times are wall-clock epoch seconds, because several hosts must agree on them.
SQLite takes no row locks, so calls within one process are serialised with a
lock; across processes, use PostgreSQL.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager, nullcontext

import anyio.to_thread
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from mcp_warden.db.models import RateLimitBucket
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


def digest(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class DatabaseBucketStore:
    def __init__(
        self, sessions: sessionmaker[Session], clock: Callable[[], float] = time.time
    ) -> None:
        self._sessions = sessions
        self._clock = clock
        self._sqlite_lock = threading.Lock()

    async def acquire(self, specs: Sequence[BucketSpec], cost: float = 1.0) -> Acquisition:
        return await anyio.to_thread.run_sync(self.acquire_sync, specs, cost)

    def acquire_sync(self, specs: Sequence[BucketSpec], cost: float = 1.0) -> Acquisition:
        specs = unique_specs(specs)
        if not specs:
            return ALLOWED
        try:
            return self._attempt(specs, cost)
        except IntegrityError:
            # Another caller created one of our rows between our read and insert.
            return self._attempt(specs, cost)

    def prune(self) -> int:
        """Delete rows for buckets that have refilled; returns how many."""
        with self._serialised(), self._sessions.begin() as session:
            result = session.execute(
                delete(RateLimitBucket).where(RateLimitBucket.full_at <= self._clock())
            )
            return int(getattr(result, "rowcount", 0) or 0)

    def _serialised(self) -> AbstractContextManager[object]:
        bind = self._sessions.kw.get("bind")
        if bind is not None and bind.dialect.name == "sqlite":
            return self._sqlite_lock
        return nullcontext()

    def _attempt(self, specs: Sequence[BucketSpec], cost: float) -> Acquisition:
        # Rows are locked and inserted in digest order, the same for every caller.
        by_digest = {digest(spec.key): spec for spec in specs}
        by_digest = {key: by_digest[key] for key in sorted(by_digest)}
        with self._serialised(), self._sessions.begin() as session:
            rows = {
                row.key: row
                for row in session.scalars(
                    select(RateLimitBucket)
                    .where(RateLimitBucket.key.in_(list(by_digest)))
                    .order_by(RateLimitBucket.key)
                    .with_for_update()
                )
            }
            now = self._clock()
            levels: dict[str, float] = {}
            for key, spec in by_digest.items():
                row = rows.get(key)
                state = BucketState(row.tokens, row.updated_at) if row is not None else None
                levels[spec.key] = level(spec, state, now)
            result = decide(specs, levels, cost)
            if not result.allowed:
                return result
            for key, spec in by_digest.items():
                tokens = levels[spec.key] - cost
                row = rows.get(key)
                if row is None:
                    row = RateLimitBucket(key=key)
                    session.add(row)
                row.tokens = tokens
                row.updated_at = now
                row.full_at = full_at(spec, tokens, now)
            return result
