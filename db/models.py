"""
SQLAlchemy ORM models for VoidAccess's persistent storage layer.

Tables
------
investigations       — one record per pipeline run
sources              — canonical .onion domain registry (global, deduped by address)
investigation_sources — many-to-many: which sources appeared in which investigation
pages                — individual scraped pages (URL-level, one per unique URL)
entities             — structured intelligence artifacts extracted from pages
entity_relationships — directed edges between two entities

Design notes
------------
- Primary keys are UUID4, generated in Python so they're globally unique and safe
  to produce offline before insertion.
- All enum columns use native_enum=False (stored as VARCHAR) for portability between
  PostgreSQL (production) and SQLite (tests) and to avoid DDL-level ENUM management.
- DateTime columns are timezone-aware (UTC throughout).
- Soft cascade rules: deleting a Page cascades to its Entities and their Relationships.
  Deleting an Investigation does NOT delete its Sources (they are global).
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.schema import UniqueConstraint


# ---------------------------------------------------------------------------
# Enums (application-level validation; stored as VARCHAR in the DB)
# ---------------------------------------------------------------------------

class SourceStatus(str, enum.Enum):
    ACTIVE = "active"
    DOWN = "down"
    UNKNOWN = "unknown"


class SourceType(str, enum.Enum):
    SEARCH_RESULT = "search_result"
    CRAWLED = "crawled"
    SEED = "seed"
    TELEGRAM = "telegram"


class EntityType(str, enum.Enum):
    """Entity types stored as VARCHAR in the DB."""
    CRYPTO_WALLET = "crypto_wallet"
    EMAIL = "email"
    PGP_KEY = "pgp_key"
    ONION_URL = "onion_url"
    CVE = "cve"
    IP_ADDRESS = "ip_address"
    PHONE = "phone"
    HANDLE = "handle"
    MALWARE = "malware"
    RANSOMWARE_GROUP = "ransomware_group"
    DOMAIN = "domain"
    OTHER = "other"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    MITRE_TECHNIQUE = "mitre_technique"


class RelationshipType(str, enum.Enum):
    """Edge types for the entity graph (Phase 3 will query these)."""
    CO_APPEARED_ON = "CO_APPEARED_ON"
    POSTED_BY = "POSTED_BY"
    LINKED_TO = "LINKED_TO"
    PAID_TO = "PAID_TO"
    MEMBER_OF = "MEMBER_OF"
    USES = "USES"
    CLAIMED = "CLAIMED"
    LIKELY_SAME_ACTOR = "LIKELY_SAME_ACTOR"
    CONFIRMED_SAME_ACTOR = "CONFIRMED_SAME_ACTOR"
    FUNDED_BY = "FUNDED_BY"
    POSSIBLE_SAME_AUTHOR = "POSSIBLE_SAME_AUTHOR"
    # Typed relationships extracted by the LLM relationship-extraction pass
    # (extractor/relationship_extract.py).  These carry a claim-specific
    # confidence separate from the confidence of the two entities they connect.
    # The vocabulary is deliberately bounded — the LLM may only emit one of
    # these; anything it cannot map cleanly falls back to CO_APPEARED_ON.
    DROPS = "DROPS"                     # malware drops another payload
    CONTROLS = "CONTROLS"               # actor controls a wallet/infrastructure
    TARGETS = "TARGETS"                 # actor/campaign targeted an organization
    EXPLOITS = "EXPLOITS"               # malware/actor exploits a vulnerability
    COMMUNICATES_WITH = "COMMUNICATES_WITH"  # host/malware C2 communication


# ---------------------------------------------------------------------------
# Declarative base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Junction table: Investigation <-> Source  (many-to-many)
# ---------------------------------------------------------------------------

investigation_sources = sa.Table(
    "investigation_sources",
    Base.metadata,
    sa.Column(
        "investigation_id",
        sa.UUID(as_uuid=True),
        sa.ForeignKey("investigations.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    sa.Column(
        "source_id",
        sa.UUID(as_uuid=True),
        sa.ForeignKey("sources.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    sa.Column(
        "added_at",
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    ),
)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Investigation(Base):
    """
    One row per pipeline run.  Stores the query, parameters, and final summary.
    """
    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), unique=True, nullable=False, default=uuid.uuid4,
        index=True,
    )
    query: Mapped[str] = mapped_column(sa.Text, nullable=False)
    refined_query: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    model_used: Mapped[Optional[str]] = mapped_column(sa.String(100), nullable=True)
    preset: Mapped[Optional[str]] = mapped_column(sa.String(50), nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    status: Mapped[str] = mapped_column(
        sa.String(20), nullable=False, default="pending", server_default="pending"
    )
    cancellation_requested: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False, server_default="false"
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    is_seed: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False, server_default="false"
    )
    graph_status: Mapped[str] = mapped_column(
        sa.String(20), nullable=False, default="pending", server_default="pending"
    )
    current_step: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    current_step_label: Mapped[str] = mapped_column(
        sa.String(200), nullable=False, default="", server_default=""
    )
    entity_count: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    page_count: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    user_id: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        sa.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # Free-form JSON metadata bag for per-investigation artifacts that don't
    # deserve their own column.  Used by Phase 6.1 to persist:
    #   - sources_used:        per-source status dict (previously only in
    #                          module-level memory cache).
    #   - infrastructure_clusters: DNS co-location clusters (previously only
    #                          in module-level memory cache).
    # Default {} via server_default keeps the column non-null on PostgreSQL
    # and SQLite alike so callers can `metadata.get("...")` without a None
    # guard.  Backfilled in migration 0023.
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        "metadata",  # DB column name (Python attr is metadata_json to avoid
                     # colliding with SQLAlchemy's Base.metadata)
        sa.JSON,
        nullable=True,
        default=None,
    )

    sources: Mapped[List["Source"]] = relationship(
        "Source",
        secondary=investigation_sources,
        back_populates="investigations",
        lazy="select",
    )

    def __repr__(self) -> str:
        return f"<Investigation {self.id} query={self.query!r}>"


class InvestigationStepMetric(Base):
    """Persisted timing and work counters for one pipeline step/run."""

    __tablename__ = "investigation_step_metrics"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), sa.ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    step_name: Mapped[str] = mapped_column(sa.String(50), nullable=False)
    duration_ms: Mapped[float] = mapped_column(sa.Float, nullable=False, default=0.0)
    llm_calls: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    extraction_llm_pages: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    extraction_cache_hits: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    pages_attempted: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    pages_fetched: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    pages_failed: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    pages_cache_hits: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    pages_fresh: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    recorded_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        sa.UniqueConstraint("investigation_id", "step_name", name="uq_investigation_step_metric"),
    )



class MonitorAlertSeverity(str, enum.Enum):
    """Stored as VARCHAR in ``monitor_alerts.severity``."""

    info = "info"
    warning = "warning"
    critical = "critical"


class MonitorAlert(Base):
    """
    Persisted record of every alert fired by the monitoring system.
    Created whenever a monitor detects a change significant enough to alert.
    """

    __tablename__ = "monitor_alerts"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    monitor_name: Mapped[str] = mapped_column(sa.String, nullable=False, index=True)
    triggered_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    change_type: Mapped[str] = mapped_column(sa.String(50), nullable=False)
    summary: Mapped[str] = mapped_column(sa.Text, nullable=False, default="")
    diff_data: Mapped[Optional[dict[str, Any]]] = mapped_column(sa.JSON, nullable=True)
    severity: Mapped[str] = mapped_column(
        sa.String(20),
        nullable=False,
        default=MonitorAlertSeverity.info.value,
    )
    entity_count_delta: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0
    )
    delivered: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    delivery_channels: Mapped[Optional[List[Any]]] = mapped_column(sa.JSON, nullable=True)
    acknowledged: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False
    )
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        sa.Index("ix_monitor_alerts_monitor_triggered", "monitor_name", "triggered_at"),
    )


class InvestigationEntityLink(Base):
    """
    Links an entity to additional investigations beyond its origin.
    Enables cross-investigation deduplication without moving entity ownership.
    """
    __tablename__ = "investigation_entity_links"
    
    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    entity_id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=False
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    linked_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    
    __table_args__ = (
        sa.UniqueConstraint("entity_id", "investigation_id"),
    )


class ActorStyleProfile(Base):
    """
    Stores aggregated writing style fingerprints for unique actors.
    Updated incrementally as new text samples are discovered.
    """
    __tablename__ = "actor_style_profiles"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    canonical_value: Mapped[str] = mapped_column(sa.String, nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(sa.String, nullable=False)
    style_vector: Mapped[dict[str, Any]] = mapped_column(sa.JSON, nullable=False)
    sample_count: Mapped[int] = mapped_column(sa.Integer, default=0, server_default="0")
    total_chars: Mapped[int] = mapped_column(sa.Integer, default=0, server_default="0")
    last_updated: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        UniqueConstraint("canonical_value", "entity_type"),
    )

class User(Base):
    """
    VoidAccess system user.  Handles authentication and access control.
    """
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(sa.String(255), nullable=False, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(sa.String, nullable=False)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)

    # Forces password reset on next login
    # Set to True for the default admin account
    must_reset_password: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<User {self.email!r}>"


class UserApiKey(Base):
    """
    Per-user encrypted API key storage.
    Keys are encrypted at rest using Fernet (AES-128) with a key derived from JWT_SECRET.
    """
    __tablename__ = "user_api_keys"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        sa.Integer,
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    key_name: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    encrypted_value: Mapped[str] = mapped_column(sa.Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )

    __table_args__ = (
        sa.UniqueConstraint("user_id", "key_name"),
    )


class ContentSafetyEvent(Base):
    """
    Audit log for content safety block events.
    Never stores actual prohibited content — only event metadata and a hash
    prefix for correlation.
    """
    __tablename__ = "content_safety_events"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(
        sa.String(50), nullable=False
    )  # "query_blocked", "url_blocked", "content_blocked"
    user_id: Mapped[Optional[int]] = mapped_column(sa.Integer, nullable=True)
    # Hash prefix for correlation — never the actual content
    content_hash: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
    )


class Entity(Base):
    """
    Structured intelligence artifacts extracted from pages.
    """
    __tablename__ = "entities"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    page_id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True),
        sa.ForeignKey("pages.id", ondelete="CASCADE"),
        nullable=False,
    )
    investigation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.UUID(as_uuid=True),
        sa.ForeignKey("investigations.id", ondelete="SET NULL"),
        nullable=True,
    )
    entity_type: Mapped[str] = mapped_column(sa.String(50), nullable=False)
    value: Mapped[str] = mapped_column(sa.Text, nullable=False)
    confidence: Mapped[float] = mapped_column(
        sa.Float(), nullable=False, server_default="1.0"
    )
    # DB column is context_snippet; `context` is a backward-compat Python alias
    context_snippet: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    canonical_value: Mapped[Optional[str]] = mapped_column(
        sa.String, nullable=True, index=True
    )
    historical_context: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    extraction_method: Mapped[Optional[str]] = mapped_column(
        sa.String(10), nullable=True
    )
    first_seen: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_seen: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    source_count: Mapped[int] = mapped_column(
        sa.Integer, server_default="1", default=1
    )
    # Distinct investigations that independently surfaced this canonical
    # entity. This is separate from enrichment-feed provenance below.
    investigation_count: Mapped[int] = mapped_column(
        sa.Integer, server_default="1", default=1
    )
    corroborating_sources: Mapped[Optional[str]] = mapped_column(
        sa.Text, nullable=True
    )
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=True,
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=True,
    )

    @property
    def context(self) -> Optional[str]:
        """Backward-compat alias for context_snippet (AGENTS.md: do not remove)."""
        return self.context_snippet

    @context.setter
    def context(self, value: Optional[str]) -> None:
        self.context_snippet = value

    __table_args__ = (
        sa.Index("ix_entities_page_id", "page_id"),
        sa.Index("ix_entities_investigation_id", "investigation_id"),
        sa.Index("ix_entities_entity_type", "entity_type"),
        sa.Index("ix_entity_canonical", "entity_type", "canonical_value"),
    )

    page: Mapped["Page"] = relationship("Page", back_populates="entities")
    relationships_as_entity_a: Mapped[List["EntityRelationship"]] = relationship(
        "EntityRelationship",
        foreign_keys="EntityRelationship.entity_a_id",
        back_populates="entity_a",
        cascade="all, delete-orphan",
    )
    relationships_as_entity_b: Mapped[List["EntityRelationship"]] = relationship(
        "EntityRelationship",
        foreign_keys="EntityRelationship.entity_b_id",
        back_populates="entity_b",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Entity {self.entity_type!r} value={self.value!r}>"



class Page(Base):
    """
    Individual scraped page from a source.
    """
    __tablename__ = "pages"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    source_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.UUID(as_uuid=True),
        sa.ForeignKey("sources.id", ondelete="SET NULL"),
        nullable=True,
    )
    url: Mapped[str] = mapped_column(sa.Text, nullable=False)
    raw_content_hash: Mapped[Optional[str]] = mapped_column(sa.String(64), nullable=True)
    cleaned_text: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    scrape_timestamp: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    language: Mapped[Optional[str]] = mapped_column(sa.String(10), nullable=True)
    byte_size: Mapped[Optional[int]] = mapped_column(sa.Integer, nullable=True)
    posted_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        sa.UniqueConstraint("url"),
        sa.Index("ix_pages_source_id", "source_id"),
        sa.Index("ix_pages_raw_content_hash", "raw_content_hash"),
        sa.Index("ix_pages_posted_at", "posted_at"),
    )

    source: Mapped[Optional["Source"]] = relationship(
        "Source", back_populates="pages"
    )
    entities: Mapped[List["Entity"]] = relationship(
        "Entity", back_populates="page", cascade="all, delete-orphan"
    )
    relationships_as_source: Mapped[List["EntityRelationship"]] = relationship(
        "EntityRelationship",
        foreign_keys="EntityRelationship.source_page_id",
        back_populates="source_page",
    )


class Source(Base):
    """
    Canonical .onion domain registry.
    """
    __tablename__ = "sources"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    onion_address: Mapped[str] = mapped_column(sa.String(255), nullable=False, unique=True)
    first_seen: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_seen: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    status: Mapped[str] = mapped_column(
        sa.String(20), nullable=False, default="unknown", server_default="unknown"
    )
    source_type: Mapped[str] = mapped_column(
        sa.String(30),
        nullable=False,
        default="search_result",
        server_default="search_result",
    )

    __table_args__ = (
        sa.Index("ix_sources_onion_address", "onion_address"),
    )

    pages: Mapped[List["Page"]] = relationship(
        "Page", back_populates="source", cascade="all, delete-orphan"
    )
    investigations: Mapped[List["Investigation"]] = relationship(
        "Investigation",
        secondary=investigation_sources,
        back_populates="sources",
        lazy="select",
    )

    def __repr__(self) -> str:
        return f"<Source {self.onion_address!r}>"


class EntityRelationship(Base):
    """
    Directed edge between two entities.
    """
    __tablename__ = "entity_relationships"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    entity_a_id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True),
        sa.ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    entity_b_id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True),
        sa.ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    relationship_type: Mapped[str] = mapped_column(sa.String(50), nullable=False)
    source_page_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.UUID(as_uuid=True),
        sa.ForeignKey("pages.id", ondelete="SET NULL"),
        nullable=True,
    )
    confidence: Mapped[float] = mapped_column(
        sa.Float(), nullable=False, server_default="1.0"
    )
    first_seen: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    investigation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.UUID(as_uuid=True),
        sa.ForeignKey("investigations.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        sa.Index(
            "ix_entity_relationships_lookup",
            "entity_a_id",
            "entity_b_id",
            "relationship_type",
        ),
        sa.Index("ix_entity_relationships_investigation_id", "investigation_id"),
        sa.Index("ix_entity_relationships_source_target", "entity_a_id", "entity_b_id"),
    )

    entity_a: Mapped["Entity"] = relationship(
        "Entity",
        foreign_keys=[entity_a_id],
        back_populates="relationships_as_entity_a",
    )
    entity_b: Mapped["Entity"] = relationship(
        "Entity",
        foreign_keys=[entity_b_id],
        back_populates="relationships_as_entity_b",
    )
    source_page: Mapped[Optional["Page"]] = relationship(
        "Page",
        foreign_keys=[source_page_id],
        back_populates="relationships_as_source",
    )


# ---------------------------------------------------------------------------
# Actor profiles (Phase 7 — persistent actor aggregates)
# ---------------------------------------------------------------------------
#
# These tables are the source of truth for cross-investigation actor data.
# Unlike the Entity table (which is per-investigation, per-page), these rows
# survive across restarts and dedupe by canonical handle.  One row per
# unique actor handle; aliases and infrastructure are joined rows.


class ActorProfile(Base):
    """
    Persistent profile for a unique threat actor / handle.

    One row per *canonical_handle* (lowercased, whitespace-stripped, no
    leading '@').  When the same handle is seen in N different
    investigations, `investigation_count` tracks how many distinct
    investigations surfaced it.  This is the table the
    ``/actors/{handle}`` and ``voidaccess actor`` commands read from.
    """

    __tablename__ = "actor_profiles"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    canonical_handle: Mapped[str] = mapped_column(
        sa.String(255), unique=True, nullable=False, index=True
    )
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True), nullable=True, index=True
    )
    investigation_count: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    confidence: Mapped[float] = mapped_column(
        sa.Float, nullable=False, default=0.85, server_default="0.85"
    )
    notes: Mapped[Optional[str]] = mapped_column(sa.Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    aliases: Mapped[List["ActorAlias"]] = relationship(
        "ActorAlias",
        back_populates="actor",
        cascade="all, delete-orphan",
        lazy="select",
    )
    infrastructure: Mapped[List["ActorInfrastructure"]] = relationship(
        "ActorInfrastructure",
        back_populates="actor",
        cascade="all, delete-orphan",
        lazy="select",
    )


class ActorAlias(Base):
    """
    An alternate spelling / variant handle linked to an actor profile.

    Examples: forum_handle (raw @lockbit), pgp_fingerprint (long hex),
    email (lockbit@protonmail.com), wallet (bc1q...), domain
    (lockbit-leaks.example).  ``alias_type`` is a free-form label so the
    CLI/API can render it appropriately without enum churn.
    """

    __tablename__ = "actor_aliases"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    actor_id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True),
        sa.ForeignKey("actor_profiles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alias_value: Mapped[str] = mapped_column(
        sa.String(500), nullable=False
    )
    alias_type: Mapped[Optional[str]] = mapped_column(
        sa.String(50), nullable=True
    )
    source_investigation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.UUID(as_uuid=True), nullable=True
    )
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    confidence: Mapped[Optional[float]] = mapped_column(sa.Float, nullable=True)

    __table_args__ = (
        sa.UniqueConstraint("actor_id", "alias_value"),
    )

    actor: Mapped["ActorProfile"] = relationship(
        "ActorProfile", back_populates="aliases"
    )


class ActorInfrastructure(Base):
    """
    Infrastructure (IP, domain, onion URL, wallet, etc.) linked to an actor.

    Distinct from ``Entity`` because one IP can be linked to multiple
    actors (shared hosting) and we want a persistent, cross-investigation
    view.  ``UNIQUE(actor_id, entity_type, entity_value)`` so the same
    IOC linked twice to the same actor does not create a duplicate row.
    """

    __tablename__ = "actor_infrastructure"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    actor_id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True),
        sa.ForeignKey("actor_profiles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    entity_type: Mapped[str] = mapped_column(sa.String(50), nullable=False)
    entity_value: Mapped[str] = mapped_column(sa.String(500), nullable=False)
    source_investigation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.UUID(as_uuid=True), nullable=True
    )
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    confidence: Mapped[Optional[float]] = mapped_column(sa.Float, nullable=True)

    __table_args__ = (
        sa.UniqueConstraint("actor_id", "entity_type", "entity_value"),
        sa.Index("ix_actor_infra_actor", "actor_id"),
        sa.Index("ix_actor_infra_type_value", "entity_type", "entity_value"),
    )

    actor: Mapped["ActorProfile"] = relationship(
        "ActorProfile", back_populates="infrastructure"
    )


class RevokedToken(Base):
    """DB-backed JWT revocation entry (P2.3).

    Lets token revocation (logout) work with **zero Redis** on a single box: a
    revoked token's ``jti`` is recorded here with its natural expiry, and the
    auth dependency checks membership on each request. Expired rows are pruned
    opportunistically. See ``auth/token_blacklist.py``.
    """

    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(sa.String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, index=True
    )
    revoked_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Shared tier (P2.0) + job queue (P2.3) — register these tables on this same
# Base so a single Base.metadata drives BOTH schema paths (create_all for
# SQLite/CLI/tests and Alembic for PostgreSQL). These bottom-of-file imports run
# after Base and all core models are defined, so the submodules can safely
# ``from db.models import Base`` without a circular-import problem. Keeping the
# imports here (rather than only in the create_all call sites) guarantees the
# tables are on the metadata regardless of which module is imported first.
# ---------------------------------------------------------------------------
import shared_corpus.models  # noqa: E402,F401  (side-effect: table registration)
import jobqueue.models  # noqa: E402,F401  (side-effect: table registration)
import ingest.models  # noqa: E402,F401  (P4.3 ingest-key + control tables)
