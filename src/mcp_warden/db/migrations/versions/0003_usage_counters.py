"""Budget usage ledger.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-17
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "usage_counters",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("window_start", sa.DateTime(), nullable=False),
        sa.Column("window_end", sa.DateTime(), nullable=False),
        sa.Column("budget_id", sa.String(length=100), nullable=False),
        sa.Column("agent", sa.String(length=200), nullable=False),
        sa.Column("server", sa.String(length=200), nullable=True),
        sa.Column("tool", sa.String(length=200), nullable=True),
        sa.Column("calls", sa.BigInteger(), nullable=False),
        sa.Column("tokens", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("key", "window_start", name=op.f("pk_usage_counters")),
    )
    with op.batch_alter_table("usage_counters") as batch:
        batch.create_index(batch.f("ix_usage_counters_agent"), ["agent"], unique=False)
        batch.create_index(batch.f("ix_usage_counters_window_end"), ["window_end"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("usage_counters") as batch:
        batch.drop_index(batch.f("ix_usage_counters_window_end"))
        batch.drop_index(batch.f("ix_usage_counters_agent"))
    op.drop_table("usage_counters")
