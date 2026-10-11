"""add ingest_keys + ingest_control (P4.3 cross-install ingest auth/control)

``ingest_keys`` — self-registered contributor keys (secret hash + authoritative
revocation status; the key's reputation lives in the shared-tier
``source_reputations`` keyed by key_id). ``ingest_control`` — single-row global
ingest kill-switch (fail-closed pause).

Additive, idempotent (inspect-before-create), mirrors ``Base.metadata.create_all``
on the SQLite/CLI path from the single ORM definition in ``ingest/models.py``.

Revision ID: 0033_add_ingest_tables
Revises: 0032_add_global_entity_source
Create Date: 2026-09-06
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0033_add_ingest_tables"
down_revision: Union[str, None] = "0032_add_global_entity_source"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = set(inspector.get_table_names())

    if "ingest_keys" not in tables:
        op.create_table(
            "ingest_keys",
            sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
            sa.Column("key_id", sa.String(length=64), nullable=False),
            sa.Column("secret_hash", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_ip", sa.String(length=64), nullable=True),
            sa.UniqueConstraint("key_id", name="uq_ingest_key_id"),
        )
        op.create_index("ix_ingest_keys_key_id", "ingest_keys", ["key_id"])

    if "ingest_control" not in tables:
        op.create_table(
            "ingest_control",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
            sa.Column("paused", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )


def downgrade() -> None:
    op.drop_table("ingest_control")
    op.drop_index("ix_ingest_keys_key_id", table_name="ingest_keys")
    op.drop_table("ingest_keys")
