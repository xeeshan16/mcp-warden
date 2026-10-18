"""Approval requests.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-18
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "approval_requests",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("open_key", sa.String(length=64), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("agent", sa.String(length=200), nullable=False),
        sa.Column("server", sa.String(length=200), nullable=False),
        sa.Column("tool", sa.String(length=200), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=True),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("arguments", sa.Text(), nullable=True),
        sa.Column("arguments_digest", sa.String(length=64), nullable=False),
        sa.Column("arguments_size", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        sa.Column("decided_by", sa.String(length=100), nullable=True),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.Column("executed_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_approval_requests")),
        sa.UniqueConstraint("open_key", name=op.f("uq_approval_requests_open_key")),
    )
    with op.batch_alter_table("approval_requests") as batch:
        batch.create_index(batch.f("ix_approval_requests_agent"), ["agent"], unique=False)
        batch.create_index(batch.f("ix_approval_requests_expires_at"), ["expires_at"], unique=False)
        batch.create_index(
            batch.f("ix_approval_requests_fingerprint"), ["fingerprint"], unique=False
        )
        batch.create_index(batch.f("ix_approval_requests_status"), ["status"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("approval_requests") as batch:
        batch.drop_index(batch.f("ix_approval_requests_status"))
        batch.drop_index(batch.f("ix_approval_requests_fingerprint"))
        batch.drop_index(batch.f("ix_approval_requests_expires_at"))
        batch.drop_index(batch.f("ix_approval_requests_agent"))
    op.drop_table("approval_requests")
