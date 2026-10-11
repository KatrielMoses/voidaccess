"""add provenance stamp to shared-tier tables (P2.2)

Adds a nullable ``provenance`` JSON column to the three shared-corpus tables so
every shared artifact can carry its origin stamp ({source, captured_at,
scraper_version} — 3.2 step 3 / 3.4). Additive and nullable, so existing rows
and the existing pipeline are unaffected.

Mirrors ``Base.metadata.create_all`` on the SQLite/CLI path from the single ORM
definition in ``shared_corpus/models.py``.

Revision ID: 0028_add_shared_provenance
Revises: 0027_add_shared_corpus_tier
Create Date: 2026-09-05
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0028_add_shared_provenance"
down_revision: Union[str, None] = "0027_add_shared_corpus_tier"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLES = ("discovered_onions", "page_snapshots", "global_entities")


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    for table in _TABLES:
        if table not in inspector.get_table_names():
            continue
        existing = {c["name"] for c in inspector.get_columns(table)}
        if "provenance" not in existing:
            op.add_column(table, sa.Column("provenance", sa.JSON(), nullable=True))


def downgrade() -> None:
    for table in _TABLES:
        op.drop_column(table, "provenance")
