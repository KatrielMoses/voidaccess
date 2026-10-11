"""add discovered_onions.consecutive_dead (P3.3 freshness dead→drop counter)

The P3.3 freshness loop re-crawls previously-seen onions for liveness. A
repeatedly-dead onion must eventually stop surfacing and stop burning re-crawl
budget: ``consecutive_dead`` counts consecutive dead re-crawls (reset to 0 on any
live re-crawl); at the drop threshold the onion's ``status`` becomes ``dropped``.

Additive, idempotent (inspect-before-add), mirrors ``Base.metadata.create_all``
on the SQLite/CLI path from the single ORM definition in ``shared_corpus/models.py``.

Revision ID: 0030_add_onion_consecutive_dead
Revises: 0029_add_job_queue
Create Date: 2026-09-06
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0030_add_onion_consecutive_dead"
down_revision: Union[str, None] = "0029_add_job_queue"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if "discovered_onions" not in set(inspector.get_table_names()):
        return
    cols = {c["name"] for c in inspector.get_columns("discovered_onions")}
    if "consecutive_dead" not in cols:
        op.add_column(
            "discovered_onions",
            sa.Column(
                "consecutive_dead",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
        )


def downgrade() -> None:
    op.drop_column("discovered_onions", "consecutive_dead")
