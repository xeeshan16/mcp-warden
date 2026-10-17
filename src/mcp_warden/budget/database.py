"""Database-backed usage ledger: budgets shared by every gateway instance.

``reserve`` runs one short transaction: lock the call's counter rows
(``SELECT ... FOR UPDATE`` on PostgreSQL, in one global order so two calls
can never deadlock), check every budget, and book the call only if all of
them have room. A refused call writes nothing. The first call of a window
inserts the counter row; if a concurrent call inserted it first, the
transaction is retried once and then finds the row.

``settle`` adds the reply's tokens with a single ``UPDATE ... SET tokens =
tokens + n``, which is atomic without an explicit lock.

SQLite takes no row locks, so calls within one process are serialised with a
lock; across processes, use PostgreSQL.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime

import anyio.to_thread
from sqlalchemy import and_, delete, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from mcp_warden.budget.ledger import Charge, Refusal, Usage, decide, unique_charges
from mcp_warden.db.models import UsageCounter

# Labels are for reports only (the digest identifies the counter), so long
# agent-supplied tool names are cut to fit the column rather than rejected.
_LABEL_MAX = 200


def _label(value: str | None) -> str | None:
    return None if value is None else value[:_LABEL_MAX]


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class UsageRecord:
    """One ledger row, for reports."""

    budget_id: str
    agent: str
    server: str | None
    tool: str | None
    window_start: datetime
    window_end: datetime
    calls: int
    tokens: int


class DatabaseUsageStore:
    def __init__(
        self, sessions: sessionmaker[Session], clock: Callable[[], datetime] = _utcnow
    ) -> None:
        self._sessions = sessions
        self._clock = clock
        self._sqlite_lock = threading.Lock()

    async def reserve(self, charges: Sequence[Charge], tokens: int) -> Refusal | None:
        return await anyio.to_thread.run_sync(self.reserve_sync, charges, tokens)

    async def settle(self, charges: Sequence[Charge], tokens: int) -> None:
        await anyio.to_thread.run_sync(self.settle_sync, charges, tokens)

    def reserve_sync(self, charges: Sequence[Charge], tokens: int) -> Refusal | None:
        charges = unique_charges(charges)
        if not charges:
            return None
        try:
            return self._attempt(charges, tokens)
        except IntegrityError:
            # Another caller created one of our rows between our read and insert.
            return self._attempt(charges, tokens)

    def settle_sync(self, charges: Sequence[Charge], tokens: int) -> None:
        if tokens <= 0:
            return
        now = self._clock()
        with self._serialised(), self._sessions.begin() as session:
            for charge in unique_charges(charges):
                session.execute(
                    update(UsageCounter)
                    .where(
                        UsageCounter.key == charge.digest,
                        UsageCounter.window_start == charge.window_start,
                    )
                    .values(tokens=UsageCounter.tokens + tokens, updated_at=now)
                )

    def usage(self, charge: Charge) -> Usage:
        with self._sessions() as session:
            row = session.get(UsageCounter, (charge.digest, charge.window_start))
            return Usage(row.calls, row.tokens) if row is not None else Usage()

    def records(
        self, *, agent: str | None = None, current_only: bool = True, limit: int = 100
    ) -> list[UsageRecord]:
        """Ledger rows, newest window first; by default only windows still open."""
        query = select(UsageCounter)
        if agent is not None:
            query = query.where(UsageCounter.agent == agent)
        if current_only:
            query = query.where(UsageCounter.window_end > self._clock())
        query = query.order_by(
            UsageCounter.window_start.desc(), UsageCounter.agent, UsageCounter.budget_id
        ).limit(limit)
        with self._sessions() as session:
            return [
                UsageRecord(
                    row.budget_id,
                    row.agent,
                    row.server,
                    row.tool,
                    row.window_start,
                    row.window_end,
                    row.calls,
                    row.tokens,
                )
                for row in session.scalars(query)
            ]

    def prune(self, before: datetime) -> int:
        """Delete counters of windows that ended at or before ``before``; returns how many."""
        with self._serialised(), self._sessions.begin() as session:
            result = session.execute(delete(UsageCounter).where(UsageCounter.window_end <= before))
            return int(getattr(result, "rowcount", 0) or 0)

    def _serialised(self) -> AbstractContextManager[object]:
        bind = self._sessions.kw.get("bind")
        if bind is not None and bind.dialect.name == "sqlite":
            return self._sqlite_lock
        return nullcontext()

    def _attempt(self, charges: Sequence[Charge], tokens: int) -> Refusal | None:
        slots = or_(
            *(
                and_(UsageCounter.key == c.digest, UsageCounter.window_start == c.window_start)
                for c in charges
            )
        )
        with self._serialised(), self._sessions.begin() as session:
            rows = {
                (row.key, row.window_start): row
                for row in session.scalars(
                    select(UsageCounter)
                    .where(slots)
                    .order_by(UsageCounter.key, UsageCounter.window_start)
                    .with_for_update()
                )
            }
            current = {slot: Usage(row.calls, row.tokens) for slot, row in rows.items()}
            refusal = decide(charges, current, tokens)
            if refusal is not None:
                return refusal
            now = self._clock()
            for charge in charges:
                row = rows.get(charge.slot)
                if row is None:
                    row = UsageCounter(
                        key=charge.digest,
                        window_start=charge.window_start,
                        window_end=charge.window_end,
                        budget_id=charge.budget.id,
                        agent=charge.agent[:_LABEL_MAX],
                        server=_label(charge.server),
                        tool=_label(charge.tool),
                        calls=0,
                        tokens=0,
                    )
                    session.add(row)
                row.calls += 1
                row.tokens += tokens
                row.updated_at = now
            return None
