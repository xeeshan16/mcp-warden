"""Tables for agent identity and shared rate-limit state.

``agents`` holds the identities policies refer to; ``api_keys`` holds the
credentials an agent presents. A key row never contains the key itself, only
its public prefix (for lookup and display) and the SHA-256 digest of the full
key (see :mod:`mcp_warden.identity.keys`).

``usage_counters`` is the budget usage ledger: calls and estimated tokens per
budget counter and fixed window (see :mod:`mcp_warden.budget`). Rows of past
windows stay as history until the retention job removes them.

``approval_requests`` holds tool calls parked for a human decision (see
:mod:`mcp_warden.approval`). ``open_key`` carries the call's fingerprint while
the request is open and is cleared when it reaches a final state; its unique
constraint is what stops two concurrent identical calls from opening two
requests (both databases allow any number of nulls in a unique column).

``audit_events`` is the metadata-only audit log (see :mod:`mcp_warden.audit`):
one append-only row per request, listed newest first through the
``(occurred_at, id)`` index and removed by the retention job.

``rate_limit_buckets`` holds token buckets below capacity for the database
rate-limit store (see :mod:`mcp_warden.ratelimit.database`); its times are
epoch seconds because they feed arithmetic, not display.

Timestamps are timezone-aware UTC in Python. They are stored as naive UTC so
that SQLite (which has no timezone type) and PostgreSQL behave the same.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    TypeDecorator,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Deterministic constraint names keep migrations portable and diffable.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class UTCDateTime(TypeDecorator[datetime]):
    """A timezone-aware UTC ``datetime`` stored as naive UTC."""

    impl = DateTime(timezone=False)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetimes are ambiguous; pass a timezone-aware value")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        return None if value is None else value.replace(tzinfo=UTC)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # The id policies match on (``agents:`` patterns); unique and immutable.
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())

    keys: Mapped[list[ApiKey]] = relationship(
        back_populates="agent", cascade="all, delete-orphan", passive_deletes=True
    )


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    prefix: Mapped[str] = mapped_column(String(16), unique=True)
    key_hash: Mapped[str] = mapped_column(String(64))
    label: Mapped[str] = mapped_column(String(100), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    agent: Mapped[Agent] = relationship(back_populates="keys")


class RateLimitBucket(Base):
    __tablename__ = "rate_limit_buckets"

    # SHA-256 hex digest of the bucket key (limit id, agent, server, tool).
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    tokens: Mapped[float] = mapped_column(Float)
    updated_at: Mapped[float] = mapped_column(Float)
    # When the bucket is full again; past that the row can be deleted.
    full_at: Mapped[float] = mapped_column(Float, index=True)


class UsageCounter(Base):
    __tablename__ = "usage_counters"

    # SHA-256 hex digest of the counter key (budget id, agent, server, tool)
    # and the start of the window, together identifying one counter.
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(UTCDateTime(), primary_key=True)
    window_end: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    # Readable labels for reports; server and tool are null for agent-scoped budgets.
    budget_id: Mapped[str] = mapped_column(String(100))
    agent: Mapped[str] = mapped_column(String(200), index=True)
    server: Mapped[str | None] = mapped_column(String(200), nullable=True)
    tool: Mapped[str | None] = mapped_column(String(200), nullable=True)
    calls: Mapped[int] = mapped_column(BigInteger)
    tokens: Mapped[int] = mapped_column(BigInteger)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime())


class ApprovalRequestRow(Base):
    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    # The fingerprint while the request is open (pending, approved, denied), else null.
    open_key: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    agent: Mapped[str] = mapped_column(String(200), index=True)
    server: Mapped[str] = mapped_column(String(200))
    tool: Mapped[str] = mapped_column(String(200))
    rule_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    reason: Mapped[str] = mapped_column(String(500))
    # Canonical JSON of the arguments for the reviewer; dropped once no longer needed.
    arguments: Mapped[str | None] = mapped_column(Text, nullable=True)
    arguments_digest: Mapped[str] = mapped_column(String(64))
    arguments_size: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class AuditEventRow(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_occurred_at_id", "occurred_at", "id"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime())
    agent: Mapped[str] = mapped_column(String(200), index=True)
    server: Mapped[str] = mapped_column(String(200))
    method: Mapped[str] = mapped_column(String(100))
    tool: Mapped[str | None] = mapped_column(String(200), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), index=True)
    effect: Mapped[str | None] = mapped_column(String(32), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    approval_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    error_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tool_error: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    latency_ms: Mapped[float] = mapped_column(Float)
    # Digest (HMAC when keyed) and byte size of the canonical arguments; never the arguments.
    arguments_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    arguments_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
