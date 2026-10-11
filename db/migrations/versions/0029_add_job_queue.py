"""add durable job queue + DB-backed token revocation (P2.3)

Creates two P2.3 infrastructure tables:

* ``jobs`` — the durable, restart-safe background-work queue the central service
  runs on (investigation dispatch now; P3/P4 later). No Redis, no broker.
* ``revoked_tokens`` — DB-backed JWT revocation so logout/revocation works with
  zero Redis on a single box.

Additive; nothing existing is altered. Mirrors ``Base.metadata.create_all`` on
the SQLite/CLI path from the single ORM definitions (``jobqueue/models.py`` and
``db/models.py``). Idempotent (inspect-before-create) like recent migrations.

Revision ID: 0029_add_job_queue
Revises: 0028_add_shared_provenance
Create Date: 2026-09-05
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0029_add_job_queue"
down_revision: Union[str, None] = "0028_add_shared_provenance"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing = set(inspector.get_table_names())

    if "jobs" not in existing:
        op.create_table(
            "jobs",
            sa.Column("id", sa.UUID(), nullable=False),
            sa.Column("task_type", sa.String(50), nullable=False),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="queued"),
            sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
            sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("dedup_key", sa.String(255), nullable=True),
            sa.Column("claimed_by", sa.String(100), nullable=True),
            sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_jobs_task_type", "jobs", ["task_type"])
        op.create_index("ix_jobs_status", "jobs", ["status"])
        op.create_index("ix_jobs_claim", "jobs", ["status", "available_at"])
        op.create_index("ix_jobs_lease", "jobs", ["lease_expires_at"])
        op.create_index("ix_jobs_dedup_key", "jobs", ["dedup_key"])

    if "revoked_tokens" not in existing:
        op.create_table(
            "revoked_tokens",
            sa.Column("jti", sa.String(64), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("jti"),
        )
        op.create_index("ix_revoked_tokens_expires_at", "revoked_tokens", ["expires_at"])


def downgrade() -> None:
    op.drop_table("revoked_tokens")
    op.drop_index("ix_jobs_dedup_key", table_name="jobs")
    op.drop_index("ix_jobs_lease", table_name="jobs")
    op.drop_index("ix_jobs_claim", table_name="jobs")
    op.drop_index("ix_jobs_status", table_name="jobs")
    op.drop_index("ix_jobs_task_type", table_name="jobs")
    op.drop_table("jobs")
