"""
shared_corpus — the SHARED tier of VoidAccess's two-tier persistence model.

The shared tier holds *observed artifacts* — discovered onions, page-content
snapshot refs, and canonical entities/IOCs — stripped of user identity and query
framing, so one investigation's observations accelerate the next without leaking
who searched for what. The private tier (investigations, queries, reports, user
linkage) stays in ``db.models`` and is access-controlled to its owner.

See ``shared_corpus/README.md`` for the design, and ``shared_corpus.access`` for
the enforced tier boundary and the collision-safe writers.
"""

from shared_corpus.models import (
    ConfidenceTier,
    DiscoveredOnion,
    GlobalEntity,
    GlobalEntitySource,
    PageSnapshot,
    SourceReputation,
)
from shared_corpus.access import (
    PRIVATE_FRAMING_COLUMNS,
    SHARED_MODELS,
    entity_provenance,
    fetch_entity_sources,
    fetch_global_entities,
    fetch_source_reputations,
    filter_investigations_for_user,
    owned_investigation_ids,
    record_discovered_onion,
    record_global_entity_source,
    record_page_snapshot,
    to_shared_dict,
    upsert_global_entity,
    upsert_source_reputation,
)
from shared_corpus.consent import contribution_enabled

__all__ = [
    "ConfidenceTier",
    "DiscoveredOnion",
    "GlobalEntity",
    "GlobalEntitySource",
    "PageSnapshot",
    "SourceReputation",
    "PRIVATE_FRAMING_COLUMNS",
    "SHARED_MODELS",
    "contribution_enabled",
    "entity_provenance",
    "fetch_entity_sources",
    "fetch_global_entities",
    "fetch_source_reputations",
    "filter_investigations_for_user",
    "owned_investigation_ids",
    "record_discovered_onion",
    "record_global_entity_source",
    "record_page_snapshot",
    "to_shared_dict",
    "upsert_global_entity",
    "upsert_source_reputation",
]
