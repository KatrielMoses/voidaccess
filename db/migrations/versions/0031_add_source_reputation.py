"""add source_reputations shared-tier table (P4.0 trust-gate reputation store)

The P4.0 trust gate downweights/blocks sources that repeatedly produce
contradicted or anomalous data. ``source_reputations`` is the durable home for
the per-source counters the gate emits (score, blocked, contributed,
corroborated, contradicted, anomalies) — a shared-tier table (a source's
reliability is corpus-wide, carrying no private framing).

The gate itself is pure and never touches this table; it consumes an in-memory
``CorpusState`` projected from these rows and emits deltas persisted by the P4.1
write path. P4.4 observability reads these columns.

Additive, idempotent (inspect-before-create), mirrors ``Base.metadata.create_all``
on the SQLite/CLI path from the single ORM definition in ``shared_corpus/models.py``.

Revision ID: 0031_add_source_reputation
Revises: 0030_add_onion_consecutive_dead
Create Date: 2026-09-06
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0031_add_source_reputation"
down_revision: Union[str, None] = "0030_add_onion_consecutive_dead"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if "source_reputations" in set(inspector.get_table_names()):
        return
    op.create_table(
        "source_reputations",
        sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(length=255), nullable=False),
        sa.Column("score", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column(
            "blocked", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("contributed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("corroborated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("contradicted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("anomalies", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("source", name="uq_source_reputation_source"),
    )
    op.create_index(
        "ix_source_reputations_source", "source_reputations", ["source"]
    )


def downgrade() -> None:
    op.drop_index("ix_source_reputations_source", table_name="source_reputations")
    op.drop_table("source_reputations")
