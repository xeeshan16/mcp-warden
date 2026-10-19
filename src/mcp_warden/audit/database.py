"""Database-backed audit store: durable and shared by every gateway instance.

Events are append-only rows in ``audit_events``. Listing is keyset-paginated
on ``(occurred_at, id)``, served by a composite index, so deep pages cost the
same as the first one and concurrent writes never shift a page.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import Select, and_, delete, or_, select
from sqlalchemy.orm import Session, sessionmaker

from mcp_warden.audit.model import AuditEvent, AuditPage, AuditQuery, Outcome, page_from
from mcp_warden.db.models import AuditEventRow as Row


def _row(event: AuditEvent) -> Row:
    return Row(
        id=event.id,
        occurred_at=event.occurred_at,
        agent=event.agent,
        server=event.server,
        method=event.method,
        tool=event.tool,
        outcome=event.outcome.value,
        effect=event.effect,
        rule_id=event.rule_id,
        approval_id=event.approval_id,
        error_code=event.error_code,
        tool_error=event.tool_error,
        latency_ms=event.latency_ms,
        arguments_digest=event.arguments_digest,
        arguments_size=event.arguments_size,
    )


def _event(row: Row) -> AuditEvent:
    return AuditEvent(
        id=row.id,
        occurred_at=row.occurred_at,
        agent=row.agent,
        server=row.server,
        method=row.method,
        tool=row.tool,
        outcome=Outcome(row.outcome),
        effect=row.effect,
        rule_id=row.rule_id,
        approval_id=row.approval_id,
        error_code=row.error_code,
        tool_error=row.tool_error,
        latency_ms=row.latency_ms,
        arguments_digest=row.arguments_digest,
        arguments_size=row.arguments_size,
    )


def _filtered(query: AuditQuery) -> Select[Row]:
    stmt = select(Row)
    for column, value in (
        (Row.agent, query.agent),
        (Row.server, query.server),
        (Row.tool, query.tool),
        (Row.method, query.method),
    ):
        if value is not None:
            stmt = stmt.where(column == value)
    if query.outcome is not None:
        stmt = stmt.where(Row.outcome == query.outcome.value)
    if query.since is not None:
        stmt = stmt.where(Row.occurred_at >= query.since)
    if query.until is not None:
        stmt = stmt.where(Row.occurred_at < query.until)
    if query.cursor is not None:
        at, event_id = query.cursor.occurred_at, query.cursor.id
        # Written out rather than as a row-value comparison so that every
        # dialect can use the (occurred_at, id) index for it.
        stmt = stmt.where(or_(Row.occurred_at < at, and_(Row.occurred_at == at, Row.id < event_id)))
    return stmt


class DatabaseAuditStore:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def append(self, events: Sequence[AuditEvent]) -> None:
        if not events:
            return
        with self._sessions.begin() as session:
            session.add_all([_row(e) for e in events])

    def query(self, query: AuditQuery) -> AuditPage:
        stmt = (
            _filtered(query).order_by(Row.occurred_at.desc(), Row.id.desc()).limit(query.limit + 1)
        )
        with self._sessions() as session:
            events = [_event(row) for row in session.scalars(stmt)]
        return page_from(events, query.limit)

    def prune(self, before: datetime) -> int:
        with self._sessions.begin() as session:
            result = session.execute(delete(Row).where(Row.occurred_at < before))
            return int(getattr(result, "rowcount", 0) or 0)
