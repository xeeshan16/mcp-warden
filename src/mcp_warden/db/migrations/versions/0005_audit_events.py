"""Audit events.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-19
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("agent", sa.String(length=200), nullable=False),
        sa.Column("server", sa.String(length=200), nullable=False),
        sa.Column("method", sa.String(length=100), nullable=False),
        sa.Column("tool", sa.String(length=200), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("effect", sa.String(length=32), nullable=True),
        sa.Column("rule_id", sa.String(length=100), nullable=True),
        sa.Column("approval_id", sa.String(length=40), nullable=True),
        sa.Column("error_code", sa.Integer(), nullable=True),
        sa.Column("tool_error", sa.Boolean(), nullable=True),
        sa.Column("latency_ms", sa.Float(), nullable=False),
        sa.Column("arguments_digest", sa.String(length=64), nullable=True),
        sa.Column("arguments_size", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    with op.batch_alter_table("audit_events") as batch:
        batch.create_index(batch.f("ix_audit_events_agent"), ["agent"], unique=False)
        batch.create_index(batch.f("ix_audit_events_outcome"), ["outcome"], unique=False)
        batch.create_index("ix_audit_events_occurred_at_id", ["occurred_at", "id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("audit_events") as batch:
        batch.drop_index("ix_audit_events_occurred_at_id")
        batch.drop_index(batch.f("ix_audit_events_outcome"))
        batch.drop_index(batch.f("ix_audit_events_agent"))
    op.drop_table("audit_events")
