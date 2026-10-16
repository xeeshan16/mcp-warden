"""Rate-limit buckets.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-16
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_buckets",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("tokens", sa.Float(), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
        sa.Column("full_at", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("key", name=op.f("pk_rate_limit_buckets")),
    )
    with op.batch_alter_table("rate_limit_buckets") as batch:
        batch.create_index(batch.f("ix_rate_limit_buckets_full_at"), ["full_at"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("rate_limit_buckets") as batch:
        batch.drop_index(batch.f("ix_rate_limit_buckets_full_at"))
    op.drop_table("rate_limit_buckets")
