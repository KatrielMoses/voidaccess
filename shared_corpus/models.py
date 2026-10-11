"""
shared_corpus/models.py — the SHARED tier of VoidAccess's two-tier data model.

Two tiers, one boundary
-----------------------
VoidAccess persists two kinds of data with two very different lifecycles:

* **Private tier** (``db.models``: ``Investigation``, its ``query`` /
  ``refined_query`` / ``summary``, and ``user_id`` linkage). Owned by one user,
  access-controlled, and **never** exposed to another user or copied into the
  shared corpus.
* **Shared tier** (this module): the *observed artifacts* — which onions exist,
  what page content was captured (by content hash), and which canonical
  entities/IOCs were seen. These are stripped of user identity and query
  framing so they can accelerate the *next* investigation (cache hits, seed
  expansion, pre-extracted entities) without leaking who searched for what.

The boundary is made *structural*, not conventional: the tables defined here
carry **no** ``user_id`` / ``investigation_id`` / ``query`` / ``refined_query``
/ ``summary`` columns, and ``shared_corpus.access`` enforces that invariant at
import time (adding such a column makes the package fail to import, and the
test-suite red). That is the P2.0 acceptance goal — "impossible to cross by
accident."

One ORM definition, both schema paths
-------------------------------------
These models are declared on the *same* ``db.models.Base`` as the private tier.
That means they materialize identically on both of VoidAccess's schema paths
with a single definition:

* ``Base.metadata.create_all(engine)`` — the SQLite/CLI/test path
  (``voidaccess_cli.adapters.sqlite.init_db`` and ``tests/conftest.py``); and
* Alembic — the PostgreSQL path (migration ``0027_add_shared_corpus_tier``).

No hand-written ``CREATE TABLE`` mirrors these anywhere, so the shared tier is
**not** born into the Alembic-vs-raw-SQL drift the audit flagged. Registration
on ``Base.metadata`` happens via a bottom-of-file import in ``db.models`` (so
``create_all`` sees them regardless of import order) and via ``db.migrations.env``
(so Alembic autogenerate sees them).

Conventions (inherited from ``db.models``)
------------------------------------------
* UUID4 primary keys, generated in Python (``default=uuid.uuid4``).
* Timezone-aware UTC ``DateTime(timezone=True)`` everywhere.
* Enums are ``str, enum.Enum`` stored as ``VARCHAR`` (``native_enum=False`` by
  virtue of using ``sa.String`` columns) for PostgreSQL/SQLite portability.

Future central-service split
----------------------------
Because the shared tier owns no foreign key *into* the private tier (all its
inter-table FKs stay within the shared tier and are nullable ``SET NULL``), the
three tables here can be relocated to a different database — the central shared
corpus service — without a schema fork. The private tier keeps working
standalone on the local install.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

# The shared tier lives on the SAME declarative Base as the private tier so a
# single Base.metadata drives both create_all and Alembic. Importing Base here
# is what ties the two tiers to one metadata object.
from db.models import Base


def _utcnow() -> datetime:
    """Timezone-aware UTC now — the project-wide default for DateTime columns."""
    return datetime.now(timezone.utc)


class ConfidenceTier(str, enum.Enum):
    """Trust level of a shared artifact (stored as VARCHAR).

    New artifacts enter ``UNCONFIRMED`` and are only promoted by the automated
    trust gate (Epic 3 / P4) once corroborated by independent sources or
    cross-validated against a trusted feed. P2.0 only *models* the column and
    its default; the promotion machinery is out of scope here.
    """

    UNCONFIRMED = "unconfirmed"
    CORROBORATED = "corroborated"
    FEED_VALIDATED = "feed_validated"


class DiscoveredOnion(Base):
    """A ``.onion`` address observed by any investigation — the shared registry.

    This is the shared-tier, user-agnostic view of "which onions exist and are
    they alive." It is deliberately distinct from the private-tier
    ``investigation_sources`` junction (which records *which user's
    investigation* touched a source): a ``DiscoveredOnion`` records only the
    address and its liveness/classification, never who searched for it.

    Today onion discovery is scattered across ``sources.seed_manager`` (a JSON
    file) and the private ``sources`` table; P4 will wire discovery to write
    here. P2.0 establishes the table and its dedup key.
    """

    __tablename__ = "discovered_onions"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    onion_address: Mapped[str] = mapped_column(
        sa.String(255), nullable=False, index=True
    )
    # How the onion first came to our attention ("seed", "crawl", "search",
    # "enrichment"). NOT a user/query field — it is a provenance class, kept so
    # the corpus can weight seeds vs. live discoveries. Stored as VARCHAR.
    discovery_source: Mapped[Optional[str]] = mapped_column(
        sa.String(30), nullable=True
    )
    # Liveness lifecycle (set by the P3.3 freshness loop):
    #   "unknown" (seeded, never crawled) → "alive" / "dead" (last re-crawl) →
    #   "dropped" (terminal: N consecutive dead re-crawls; excluded from active
    #   retrieval AND from further re-crawl scheduling).
    status: Mapped[str] = mapped_column(
        sa.String(20), nullable=False, default="unknown", server_default="unknown"
    )
    # Count of consecutive dead re-crawls — the dead→drop policy counter (P3.3).
    # Reset to 0 on any live re-crawl; at the drop threshold the onion is marked
    # "dropped" so it stops surfacing and stops burning re-crawl budget.
    consecutive_dead: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    title: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    category: Mapped[Optional[str]] = mapped_column(sa.String(50), nullable=True)
    language: Mapped[Optional[str]] = mapped_column(sa.String(10), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow
    )
    # Provenance stamp (P2.2 / 3.2 step 3): {source, captured_at, scraper_version}.
    provenance: Mapped[Optional[dict[str, Any]]] = mapped_column(sa.JSON, nullable=True)

    snapshots: Mapped[list["PageSnapshot"]] = relationship(
        "PageSnapshot", back_populates="onion", lazy="select"
    )

    __table_args__ = (
        sa.UniqueConstraint("onion_address", name="uq_discovered_onion_address"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<DiscoveredOnion {self.onion_address!r} status={self.status!r}>"


class PageSnapshot(Base):
    """A content snapshot of a captured page, deduplicated by content hash.

    The snapshot *bytes* live in object storage (Cloudflare R2 — P2.1); this
    row holds only the **reference**: the ``content_hash`` (the dedup key and,
    later, the R2 object key derivation) plus lightweight metadata. P2.0 models
    the ref column ``storage_ref``; the R2 wiring itself is explicitly out of
    scope.

    Dedup is by ``content_hash``: two different URLs (or the same URL captured
    twice) that yield byte-identical content collapse to one snapshot, which is
    what lets a second investigation reuse the first's capture. The ``url`` is
    retained as representative metadata, not as the identity.
    """

    __tablename__ = "page_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    content_hash: Mapped[str] = mapped_column(
        sa.String(64), nullable=False, index=True
    )
    onion_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.UUID(as_uuid=True),
        sa.ForeignKey("discovered_onions.id", ondelete="SET NULL"),
        nullable=True,
    )
    url: Mapped[str] = mapped_column(sa.Text, nullable=False)
    # Reference into object storage (R2 object key / URI). Modeled here; the
    # store itself is wired in P2.1. Nullable so a snapshot ref can be recorded
    # before/without the object being uploaded in local/$0 mode.
    storage_ref: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    byte_size: Mapped[Optional[int]] = mapped_column(sa.Integer, nullable=True)
    language: Mapped[Optional[str]] = mapped_column(sa.String(10), nullable=True)
    captured_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow
    )
    first_seen: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow
    )
    # Provenance stamp (P2.2 / 3.2 step 3): {source, captured_at, scraper_version}.
    provenance: Mapped[Optional[dict[str, Any]]] = mapped_column(sa.JSON, nullable=True)

    onion: Mapped[Optional["DiscoveredOnion"]] = relationship(
        "DiscoveredOnion", back_populates="snapshots"
    )

    __table_args__ = (
        sa.UniqueConstraint("content_hash", name="uq_page_snapshot_content_hash"),
        sa.Index("ix_page_snapshots_onion_id", "onion_id"),
        sa.Index("ix_page_snapshots_url", "url"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<PageSnapshot {self.content_hash[:12]}… url={self.url!r}>"


class GlobalEntity(Base):
    """The canonical, cross-investigation form of an entity / IOC — one row per
    ``(entity_type, canonical_value)`` across the entire corpus.

    This is the first-class *shared* entity, deliberately distinct from the
    per-investigation ``db.models.Entity`` observation rows. An ``Entity`` row
    records "this investigation saw this value on this page"; a ``GlobalEntity``
    row records "this canonical thing exists in the corpus" and is the anchor
    the trust gate's corroboration counting (P4) hangs off of.

    The dedup key is enforced by a **DB-level** ``UniqueConstraint`` (not just a
    non-unique index + application SELECT-then-INSERT, which the audit flagged
    as a race). Identity is computed exclusively through
    ``extractor.identity.entity_canonical_id`` — the single identity path — so
    there is no second canonicalization here to drift from it. See
    ``shared_corpus.access.upsert_global_entity`` for the collision-safe writer.
    """

    __tablename__ = "global_entities"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    entity_type: Mapped[str] = mapped_column(sa.String(50), nullable=False)
    # Canonical, dedup-safe value — produced by extractor.identity, never
    # re-derived here. Part of the unique key, so it is NOT nullable (unlike the
    # legacy per-investigation entities.canonical_value).
    canonical_value: Mapped[str] = mapped_column(sa.String(1024), nullable=False)
    # Human-facing value, casing preserved. Metadata only — never an identity.
    display_value: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    # Established disposition (e.g. "malicious"/"benign"), set once the entity
    # reaches a promoted tier. The trust gate reads this as the contradiction
    # baseline (P4.1 seam, wired in P4.3): a later external claim that conflicts
    # with it downweights the contributor's reputation. First promoted claim wins.
    disposition: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)
    confidence_tier: Mapped[str] = mapped_column(
        sa.String(20),
        nullable=False,
        default=ConfidenceTier.UNCONFIRMED.value,
        server_default=ConfidenceTier.UNCONFIRMED.value,
    )
    # How many independent corroborations promoted this row. P2.0 seeds it at 1
    # on first insert; the promotion arithmetic is P4.
    corroboration_count: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=1, server_default="1"
    )
    first_seen: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow
    )
    # Provenance stamp (P2.2 / 3.2 step 3): {source, captured_at, scraper_version}
    # of the first contribution. Multi-source corroboration is P4.
    provenance: Mapped[Optional[dict[str, Any]]] = mapped_column(sa.JSON, nullable=True)

    __table_args__ = (
        # The load-bearing constraint: one row per canonical entity, enforced by
        # the database so concurrent writers cannot double-insert.
        sa.UniqueConstraint(
            "entity_type", "canonical_value", name="uq_global_entity_type_canonical"
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<GlobalEntity {self.entity_type!r} "
            f"canonical={self.canonical_value!r} tier={self.confidence_tier!r}>"
        )


class SourceReputation(Base):
    """Per-source reliability score — the trust gate's source-reputation store (P4.0).

    A ``source`` is whatever contributed an artifact: a ``.onion`` address, a feed
    name, or an ingest API key. This is the durable home for the counters the
    trust gate emits (``trust_gate`` steps 6–7): every source starts neutral and
    is downweighted as it accrues *contradictions* (data that conflicts with the
    established/feed-validated disposition) and *anomalies* (flood / entity-stuffing
    / templated / mass-identical submissions). When its ``score`` falls below the
    block threshold the source is ``blocked`` and its contributions no longer count
    toward corroboration.

    It is a *shared-tier* table — a source's reliability is a corpus-wide property,
    not tied to any one user or investigation, so it carries no private framing
    (enforced by ``shared_corpus.access._enforce_tier_separation``). The trust gate
    itself is **pure**: it never reads or writes this table. It consumes an
    in-memory ``CorpusState`` (projected from these rows by the P4.1 write path) and
    *emits* the updated counters; persistence of the emitted deltas back to this
    table is P4.1 wiring, and observability reads (P4.4) hang off these columns.

    Dedup key: one row per ``source`` (DB-level unique constraint), mirroring the
    collision-safe pattern the other shared writers use.
    """

    __tablename__ = "source_reputations"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # The contributing source identity: onion address / feed name / ingest key.
    # NOT a user id — a source is a corpus-wide provenance origin (the tier-
    # separation invariant would reject a user_id column here).
    source: Mapped[str] = mapped_column(sa.String(255), nullable=False, index=True)
    # Reliability score in [0, 1]; starts neutral (config TRUST_GATE_REPUTATION_START),
    # decays on contradiction/anomaly. Below the block threshold → blocked.
    score: Mapped[float] = mapped_column(
        sa.Float, nullable=False, default=1.0, server_default="1.0"
    )
    blocked: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False, server_default=sa.false()
    )
    # Emitted counters (read by P4.4 observability).
    contributed: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    corroborated: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    contradicted: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    anomalies: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    first_seen: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow
    )

    __table_args__ = (
        sa.UniqueConstraint("source", name="uq_source_reputation_source"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<SourceReputation {self.source!r} score={self.score:.3f} "
            f"blocked={self.blocked}>"
        )


class GlobalEntitySource(Base):
    """One (global entity, contributing source) observation — the corroboration
    source-set and the queryable-provenance backbone (P4.1 / spec 3.4).

    A ``GlobalEntity`` records "this canonical thing exists"; each row here records
    "*this source* contributed it, first seen *then*". The **distinct count of
    these rows per entity is the independent-source basis** the trust gate scores
    on — enforced by the ``uq_global_entity_source`` unique constraint, so the same
    source re-observing an entity collapses to one row and can never inflate the
    corroboration count. It is also what makes provenance queryable: a shared
    record traces to its sources + per-source first_seen + (via ``feed_hits``)
    which contributions were trusted-feed cross-hits.

    Shared-tier: the intra-tier FK to ``global_entities`` stays within the shared
    tier, so the whole tier still relocates to a central service without a fork.
    """

    __tablename__ = "global_entity_sources"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    global_entity_id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True),
        sa.ForeignKey("global_entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    # The ORIGIN: the onion/host the artifact was observed on — the corroboration
    # independence unit. (Column name kept ``source`` for back-compat.)
    source: Mapped[str] = mapped_column(sa.String(255), nullable=False, index=True)
    # The CONTRIBUTOR that attested this origin (ingest key / "local"): the second
    # independence axis. Corroboration needs >= M distinct contributors, so this is
    # persisted to survive reload. Nullable for rows written before P4.4 (they fall
    # back to the origin, which for P4.1-local equals the contributor).
    contributor: Mapped[Optional[str]] = mapped_column(sa.String(255), nullable=True)
    # Trusted-feed ids this contribution cross-hit (platform-derived, never user
    # input). Persisted so a re-promotion knows the entity was feed-validated.
    feed_hits: Mapped[Optional[list]] = mapped_column(sa.JSON, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=_utcnow
    )
    # Per-source provenance stamp (P2.2): {source, captured_at, scraper_version}.
    provenance: Mapped[Optional[dict[str, Any]]] = mapped_column(sa.JSON, nullable=True)

    __table_args__ = (
        sa.UniqueConstraint(
            "global_entity_id", "source", name="uq_global_entity_source"
        ),
        sa.Index("ix_global_entity_sources_entity", "global_entity_id"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<GlobalEntitySource entity={self.global_entity_id} source={self.source!r}>"
