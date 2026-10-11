"""add global_entity_sources — corroboration source-set + queryable provenance (P4.1)

Each row records one (global entity, contributing source) observation. The
distinct count per entity is the trust gate's independent-source basis
(``uq_global_entity_source`` prevents a source inflating it by resubmission), and
the per-source ``first_seen`` + ``feed_hits`` make provenance queryable (spec 3.4).

Shared-tier table with an intra-tier FK to ``global_entities`` (CASCADE), so the
tier still relocates to a central service without a fork.

Additive, idempotent (inspect-before-create), mirrors ``Base.metadata.create_all``
on the SQLite/CLI path from the single ORM definition in ``shared_corpus/models.py``.

Revision ID: 0032_add_global_entity_source
Revises: 0031_add_source_reputation
Create Date: 2026-09-06
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0032_add_global_entity_source"
down_revision: Union[str, None] = "0031_add_source_reputation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if "global_entity_sources" in set(inspector.get_table_names()):
        return
    op.create_table(
        "global_entity_sources",
        sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "global_entity_id",
            sa.UUID(as_uuid=True),
            sa.ForeignKey("global_entities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(length=255), nullable=False),
        sa.Column("feed_hits", sa.JSON(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=True),
        sa.UniqueConstraint(
            "global_entity_id", "source", name="uq_global_entity_source"
        ),
    )
    op.create_index(
        "ix_global_entity_sources_entity", "global_entity_sources", ["global_entity_id"]
    )
    op.create_index(
        "ix_global_entity_sources_source", "global_entity_sources", ["source"]
    )


def downgrade() -> None:
    op.drop_index("ix_global_entity_sources_source", table_name="global_entity_sources")
    op.drop_index("ix_global_entity_sources_entity", table_name="global_entity_sources")
    op.drop_table("global_entity_sources")
