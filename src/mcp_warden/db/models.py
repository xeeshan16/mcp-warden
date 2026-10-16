"""Tables for agent identity and shared rate-limit state.

``agents`` holds the identities policies refer to; ``api_keys`` holds the
credentials an agent presents. A key row never contains the key itself, only
its public prefix (for lookup and display) and the SHA-256 digest of the full
key (see :mod:`mcp_warden.identity.keys`).

``rate_limit_buckets`` holds token buckets below capacity for the database
rate-limit store (see :mod:`mcp_warden.ratelimit.database`); its times are
epoch seconds because they feed arithmetic, not display.

Timestamps are timezone-aware UTC in Python. They are stored as naive UTC so
that SQLite (which has no timezone type) and PostgreSQL behave the same.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    MetaData,
    String,
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
