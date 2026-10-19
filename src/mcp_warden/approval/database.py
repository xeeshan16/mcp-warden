"""Database-backed approval store: shared by gateways, the CLI and reviewers.

Concurrency rests on two guarantees of the database rather than on locks
held across requests:

* ``open_key`` is unique, so two identical calls racing to open a request
  cannot both insert one; the loser's transaction fails and is retried once,
  finding the winner's row.
* ``claim`` and ``decide`` are single conditional ``UPDATE`` statements
  (``... WHERE status = 'approved' AND expires_at > now``), so exactly one of
  several concurrent claims spends an approval, and a request cannot be both
  approved and denied.

SQLite serialises writers itself; calls within one process additionally go
through a lock so the open-or-create read and insert stay together.
"""

from __future__ import annotations

import json
import threading
from contextlib import AbstractContextManager, nullcontext
from datetime import datetime
from typing import Any

from sqlalchemy import ColumnElement, and_, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

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
from mcp_warden.db.models import ApprovalRequestRow as Row

_OPEN_STATES = [s.value for s in ApprovalStatus if s.is_open]


def _snapshot(row: Row) -> ApprovalRequest:
    arguments: dict[str, Any] | None = (
        json.loads(row.arguments) if row.arguments is not None else None
    )
    return ApprovalRequest(
        id=row.id,
        agent=row.agent,
        server=row.server,
        tool=row.tool,
        rule_id=row.rule_id,
        reason=row.reason,
        arguments=arguments,
        arguments_digest=row.arguments_digest,
        arguments_size=row.arguments_size,
        fingerprint=row.fingerprint,
        status=ApprovalStatus(row.status),
        created_at=row.created_at,
        expires_at=row.expires_at,
        decided_at=row.decided_at,
        decided_by=row.decided_by,
        note=row.note,
        executed_at=row.executed_at,
    )


def _status_filter(status: ApprovalStatus, now: datetime) -> ColumnElement[bool]:
    if status.is_open:
        return and_(Row.status == status.value, Row.expires_at > now)
    if status is ApprovalStatus.EXPIRED:
        return or_(
            Row.status == status.value,
            and_(Row.status.in_(_OPEN_STATES), Row.expires_at <= now),
        )
    return Row.status == status.value


class DatabaseApprovalStore:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions
        self._sqlite_lock = threading.Lock()

    def open(self, new: NewApproval, now: datetime, timings: ApprovalTimings) -> ApprovalRequest:
        try:
            return self._open_once(new, now, timings)
        except IntegrityError:
            # An identical call opened the request between our read and insert.
            return self._open_once(new, now, timings)

    def claim(self, approval_id: str, now: datetime) -> bool:
        with self._serialised(), self._sessions.begin() as session:
            result = session.execute(
                update(Row)
                .where(
                    Row.id == approval_id,
                    Row.status == ApprovalStatus.APPROVED.value,
                    Row.expires_at > now,
                )
                .values(
                    status=ApprovalStatus.EXECUTED.value,
                    open_key=None,
                    arguments=None,
                    executed_at=now,
                )
            )
            return int(getattr(result, "rowcount", 0) or 0) == 1

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
        values: dict[str, Any] = {
            "status": (ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED).value,
            "decided_at": now,
            "decided_by": reviewer,
            "note": note,
            "expires_at": now + timings.decision_ttl,
        }
        if not approve:
            values["arguments"] = None
        with self._serialised(), self._sessions.begin() as session:
            result = session.execute(
                update(Row)
                .where(
                    Row.id == approval_id,
                    Row.status == ApprovalStatus.PENDING.value,
                    Row.expires_at > now,
                )
                .values(**values)
            )
            changed = int(getattr(result, "rowcount", 0) or 0) == 1
            row = session.get(Row, approval_id)
            if row is None:
                raise ApprovalNotFoundError(f"no approval request {approval_id!r}")
            request = _snapshot(row)
        if not changed:
            raise ApprovalConflictError(
                f"approval request {approval_id} is {request.state(now).value}"
            )
        return request

    def get(self, approval_id: str) -> ApprovalRequest:
        with self._sessions() as session:
            row = session.get(Row, approval_id)
            if row is None:
                raise ApprovalNotFoundError(f"no approval request {approval_id!r}")
            return _snapshot(row)

    def list(
        self,
        now: datetime,
        *,
        status: ApprovalStatus | None = None,
        agent: str | None = None,
        limit: int = 100,
    ) -> list[ApprovalRequest]:
        query = select(Row)
        if status is not None:
            query = query.where(_status_filter(status, now))
        if agent is not None:
            query = query.where(Row.agent == agent)
        query = query.order_by(Row.created_at.desc(), Row.id.desc()).limit(limit)
        with self._sessions() as session:
            return [_snapshot(row) for row in session.scalars(query)]

    def prune(self, before: datetime) -> int:
        executed = ApprovalStatus.EXECUTED.value
        with self._serialised(), self._sessions.begin() as session:
            result = session.execute(
                delete(Row).where(
                    or_(
                        and_(Row.status == executed, Row.executed_at < before),
                        and_(Row.status != executed, Row.expires_at < before),
                    )
                )
            )
            return int(getattr(result, "rowcount", 0) or 0)

    def _open_once(
        self, new: NewApproval, now: datetime, timings: ApprovalTimings
    ) -> ApprovalRequest:
        fp = new.fingerprint
        with self._serialised(), self._sessions.begin() as session:
            row = session.scalars(
                select(Row).where(Row.open_key == fp).with_for_update()
            ).one_or_none()
            if row is not None:
                existing = _snapshot(row)
                if existing.state(now) is not ApprovalStatus.EXPIRED:
                    return existing
                row.status = ApprovalStatus.EXPIRED.value
                row.open_key = None
                row.arguments = None
                session.flush()
            agent = label(new.agent)
            pending = session.scalar(
                select(func.count())
                .select_from(Row)
                .where(Row.agent == agent, _status_filter(ApprovalStatus.PENDING, now))
            )
            if (pending or 0) >= timings.max_pending_per_agent:
                raise TooManyPendingError(new.agent, timings.max_pending_per_agent)
            encoded = canonical_json(new.arguments)
            row = Row(
                id=new_approval_id(),
                open_key=fp,
                fingerprint=fp,
                agent=agent,
                server=label(new.server),
                tool=label(new.tool),
                rule_id=new.rule_id,
                reason=new.reason[:500],
                arguments=encoded,
                arguments_digest=arguments_digest(new.arguments),
                arguments_size=len(encoded.encode()),
                status=ApprovalStatus.PENDING.value,
                created_at=now,
                expires_at=now + timings.pending_ttl,
            )
            session.add(row)
            session.flush()
            return _snapshot(row)

    def _serialised(self) -> AbstractContextManager[object]:
        bind = self._sessions.kw.get("bind")
        if bind is not None and bind.dialect.name == "sqlite":
            return self._sqlite_lock
        return nullcontext()
