"""add shared-corpus tier (P2.0)

Creates the three shared-tier tables — ``discovered_onions``, ``page_snapshots``,
``global_entities`` — that formalize the private/shared split in the schema.

These tables are additive: nothing on the existing private tier
(``investigations`` / ``entities`` / …) is altered, so current investigations
keep loading and running end-to-end. The load-bearing change is the DB-level
``UniqueConstraint(entity_type, canonical_value)`` on ``global_entities`` (via
``uq_global_entity_type_canonical``), which — together with the collision-safe
upsert in ``shared_corpus.access`` — replaces the old non-unique-index +
SELECT-then-INSERT dedup that could race concurrent writers.

The same tables are created by ``Base.metadata.create_all`` on the SQLite/CLI
path from a single ORM definition (``shared_corpus/models.py``); this migration
is the PostgreSQL mirror. ``sa.UUID`` renders as native ``uuid`` on PostgreSQL
and ``CHAR(32)`` on SQLite, matching the rest of the schema.

Revision ID: 0027_add_shared_corpus_tier
Revises: 0026_add_entity_investigation_count
Create Date: 2026-09-05
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0027_add_shared_corpus_tier"
down_revision: Union[str, None] = "0026_add_entity_investigation_count"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    # ------------------------------------------------------------------
    # discovered_onions — shared onion registry (user-agnostic)
    # ------------------------------------------------------------------
    if "discovered_onions" not in existing_tables:
        op.create_table(
            "discovered_onions",
            sa.Column("id", sa.UUID(), nullable=False),
            sa.Column("onion_address", sa.String(255), nullable=False),
            sa.Column("discovery_source", sa.String(30), nullable=True),
            sa.Column("status", sa.String(20), nullable=False, server_default="unknown"),
            sa.Column("title", sa.Text(), nullable=True),
            sa.Column("category", sa.String(50), nullable=True),
            sa.Column("language", sa.String(10), nullable=True),
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("onion_address", name="uq_discovered_onion_address"),
        )
        op.create_index(
            "ix_discovered_onions_onion_address",
            "discovered_onions",
            ["onion_address"],
        )

    # ------------------------------------------------------------------
    # page_snapshots — content-cache refs, deduped by content_hash
    # ------------------------------------------------------------------
    if "page_snapshots" not in existing_tables:
        op.create_table(
            "page_snapshots",
            sa.Column("id", sa.UUID(), nullable=False),
            sa.Column("content_hash", sa.String(64), nullable=False),
            sa.Column(
                "onion_id",
                sa.UUID(),
                sa.ForeignKey("discovered_onions.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("url", sa.Text(), nullable=False),
            sa.Column("storage_ref", sa.Text(), nullable=True),
            sa.Column("byte_size", sa.Integer(), nullable=True),
            sa.Column("language", sa.String(10), nullable=True),
            sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("content_hash", name="uq_page_snapshot_content_hash"),
        )
        op.create_index(
            "ix_page_snapshots_content_hash", "page_snapshots", ["content_hash"]
        )
        op.create_index("ix_page_snapshots_onion_id", "page_snapshots", ["onion_id"])
        op.create_index("ix_page_snapshots_url", "page_snapshots", ["url"])

    # ------------------------------------------------------------------
    # global_entities — first-class shared canonical entities / IOCs.
    # The UniqueConstraint here is the audit fix: one row per canonical entity,
    # enforced by the DB, so the trust gate's corroboration counting (P4) can
    # rely on it.
    # ------------------------------------------------------------------
    if "global_entities" not in existing_tables:
        op.create_table(
            "global_entities",
            sa.Column("id", sa.UUID(), nullable=False),
            sa.Column("entity_type", sa.String(50), nullable=False),
            sa.Column("canonical_value", sa.String(1024), nullable=False),
            sa.Column("display_value", sa.Text(), nullable=True),
            sa.Column(
                "confidence_tier",
                sa.String(20),
                nullable=False,
                server_default="unconfirmed",
            ),
            sa.Column(
                "corroboration_count",
                sa.Integer(),
                nullable=False,
                server_default="1",
            ),
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "entity_type",
                "canonical_value",
                name="uq_global_entity_type_canonical",
            ),
        )


def downgrade() -> None:
    op.drop_table("global_entities")
    op.drop_index("ix_page_snapshots_url", table_name="page_snapshots")
    op.drop_index("ix_page_snapshots_onion_id", table_name="page_snapshots")
    op.drop_index("ix_page_snapshots_content_hash", table_name="page_snapshots")
    op.drop_table("page_snapshots")
    op.drop_index(
        "ix_discovered_onions_onion_address", table_name="discovered_onions"
    )
    op.drop_table("discovered_onions")
