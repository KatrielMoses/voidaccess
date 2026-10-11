"""add global_entity_sources.contributor (P4.4 reputation-gaming defense)

Corroboration now requires >= M distinct CONTRIBUTORS in addition to >= N distinct
origins, so a single (even trusted) contributor claiming one IOC across many
fabricated origins cannot self-promote. The contributor is persisted alongside the
origin so the distinct-contributor set survives a reload.

Additive, nullable (pre-P4.4 rows fall back to the origin), idempotent, mirrors
``Base.metadata.create_all`` from ``shared_corpus/models.py``.

Revision ID: 0035_add_ges_contributor
Revises: 0034_add_global_entity_disposition
Create Date: 2026-09-06
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0035_add_ges_contributor"
down_revision: Union[str, None] = "0034_add_global_entity_disposition"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if "global_entity_sources" not in set(inspector.get_table_names()):
        return
    cols = {c["name"] for c in inspector.get_columns("global_entity_sources")}
    if "contributor" not in cols:
        op.add_column(
            "global_entity_sources",
            sa.Column("contributor", sa.String(length=255), nullable=True),
        )


def downgrade() -> None:
    op.drop_column("global_entity_sources", "contributor")
