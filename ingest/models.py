"""
ingest/models.py — DB-backed stores for the cross-install ingest API (P4.3).

Two tables, both on the main service DB (not the relocatable shared-corpus tier —
these are central-service *auth/control*, not corpus observations):

* ``IngestKey`` — a self-registered contributor key. Holds only a **hash** of the
  secret (never the plaintext), plus the authoritative revocation ``status``. The
  key's *reputation* is not here — it lives in the shared-tier
  ``SourceReputation`` store keyed by the ``key_id`` (the contributor id), so the
  trust gate's two-layer reputation reads it through the normal load path.
* ``IngestControl`` — a single-row global kill-switch (``paused``). Authoritative
  and **fail-closed**: if this store can't be read, ingest is refused.

Registered on ``db.models.Base`` (bottom-of-file import in ``db.models``) so a
single ``Base.metadata`` drives both create_all (SQLite/CLI/tests) and Alembic
(PostgreSQL) — no hand-written DDL to drift.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from db.models import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IngestKeyStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class IngestKey(Base):
    """A self-registered ingest contributor key (auth + revocation only)."""

    __tablename__ = "ingest_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Public identifier sent on every request (opaque token). The secret is never
    # stored — only its SHA-256 hash, verified in constant time.
    key_id: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)
    secret_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        sa.String(20), nullable=False,
        default=IngestKeyStatus.ACTIVE.value, server_default=IngestKeyStatus.ACTIVE.value,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    # Recorded for anti-key-farming / abuse forensics (not a user identity).
    created_ip: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)

    __table_args__ = (
        sa.UniqueConstraint("key_id", name="uq_ingest_key_id"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<IngestKey {self.key_id[:8]}… status={self.status!r}>"


class IngestControl(Base):
    """Single-row global ingest kill-switch (authoritative, fail-closed)."""

    __tablename__ = "ingest_control"

    # Fixed sentinel primary key — there is exactly one control row.
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=False)
    paused: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False, server_default=sa.false()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow
    )

    #: The one row's id.
    SINGLETON_ID = 1

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<IngestControl paused={self.paused}>"
