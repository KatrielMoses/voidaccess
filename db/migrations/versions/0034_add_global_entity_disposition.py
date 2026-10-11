"""add global_entities.disposition (P4.1 contradiction seam, wired in P4.3)

The trust gate's contradiction check needs an established disposition baseline per
entity. ``disposition`` is set once an entity reaches a promoted tier; a later
external claim (P4.3 ingest) that conflicts with it downweights the contributor's
reputation.

Additive, nullable, idempotent (inspect-before-add), mirrors
``Base.metadata.create_all`` on the SQLite/CLI path from ``shared_corpus/models.py``.

Revision ID: 0034_add_global_entity_disposition
Revises: 0033_add_ingest_tables
Create Date: 2026-09-06
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0034_add_global_entity_disposition"
down_revision: Union[str, None] = "0033_add_ingest_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if "global_entities" not in set(inspector.get_table_names()):
        return
    cols = {c["name"] for c in inspector.get_columns("global_entities")}
    if "disposition" not in cols:
        op.add_column(
            "global_entities", sa.Column("disposition", sa.String(length=64), nullable=True)
        )


def downgrade() -> None:
    op.drop_column("global_entities", "disposition")
