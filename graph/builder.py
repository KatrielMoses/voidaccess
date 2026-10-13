"""
graph/builder.py — Builds and updates the NetworkX relationship graph from DB entities.

The graph is a NetworkX MultiDiGraph (directed, allows multiple edges between the
same node pair).  All public functions accept and return nx.MultiDiGraph so callers
can chain operations.

Public interface
----------------
build_graph_from_db(investigation_id, since)           → nx.MultiDiGraph
add_entity_to_graph(graph, entity)                     → nx.MultiDiGraph
add_relationship(graph, source_id, target_id, ...)     → nx.MultiDiGraph
infer_relationships(graph)                             → nx.MultiDiGraph
detect_communities(graph)                              → dict[str, int]
find_shortest_path(graph, source, target, max_hops)    → list[str] | None
"""

from __future__ import annotations

import itertools
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional
import uuid
from urllib.parse import urlparse

import networkx as nx
import sqlalchemy as sa

from types import SimpleNamespace

from extractor.identity import entity_graph_id
from extractor.normalizer import NormalizedEntity
from graph.model import EDGE_TYPES, NODE_TYPES

logger = logging.getLogger(__name__)

_CO_OCCURRENCE_MAX_ENTITIES_PER_PAGE = 40
_CO_OCCURRENCE_MAX_EDGES_PER_PAGE = 120

# ORGANIZATION_NAME is deliberately absent from both sets below, even though it
# is the largest (or second-largest) bucket in most real runs.  These sets were
# introduced by v1.7.2, the same release that filtered "ORGANIZATION_NAME NER
# noise ... generic security/programming vocabulary false positives" — the
# exclusion is that fix, not an oversight.  The bucket is still ~25-45% junk on
# measured runs (values like POST, JavaScript, HTML, HTTPS, IP, SCADA, EDR sit
# alongside genuine orgs), so admitting it here would attach hundreds of
# meaningless edges to every real hub and drown the signal the semantic filter
# exists to preserve.
#
# Dependency, not a TODO: genuinely-real organizations *should* eventually be
# able to participate in co-occurrence edges.  That is gated on Phase 2's
# noise-reduction work actually improving what lands in this bucket — do not
# widen eligibility before then, and re-measure the bucket's noise rate rather
# than assuming Phase 2 fixed it.
_CO_OCCURRENCE_HUB_TYPES = frozenset({
    "THREAT_ACTOR_HANDLE",
    "RANSOMWARE_GROUP",
    "MALWARE_FAMILY",
    "CVE_NUMBER",
    "CVE",
})
_CO_OCCURRENCE_IOC_TYPES = frozenset({
    "IP_ADDRESS",
    "IPV6_ADDRESS",
    "DOMAIN",
    "ONION_URL",
    "EMAIL_ADDRESS",
    "BITCOIN_ADDRESS",
    "ETHEREUM_ADDRESS",
    "MONERO_ADDRESS",
    "LITECOIN_ADDRESS",
    "ZCASH_ADDRESS",
    "DOGECOIN_ADDRESS",
    "XRP_ADDRESS",
    "SOLANA_ADDRESS",
    "TRON_ADDRESS",
    "BITCOIN_CASH_ADDRESS",
    "DASH_ADDRESS",
    "FILE_HASH_MD5",
    "FILE_HASH_SHA1",
    "FILE_HASH_SHA256",
    "MITRE_TECHNIQUE",
    "EXPLOIT_DB_ID",
    "YARA_RULE",
    "NUCLEI_TEMPLATE",
})

# ---------------------------------------------------------------------------
# Mapping: extractor entity_type → graph node_type
# ---------------------------------------------------------------------------

_ENTITY_TYPE_TO_NODE_TYPE: dict[str, str] = {
    "THREAT_ACTOR_HANDLE":   NODE_TYPES.THREAT_ACTOR,
    "BITCOIN_ADDRESS":       NODE_TYPES.CRYPTO_WALLET,
    "ETHEREUM_ADDRESS":      NODE_TYPES.CRYPTO_WALLET,
    "MONERO_ADDRESS":        NODE_TYPES.CRYPTO_WALLET,
    "LITECOIN_ADDRESS":      NODE_TYPES.CRYPTO_WALLET,
    "ZCASH_ADDRESS":         NODE_TYPES.CRYPTO_WALLET,
    "DOGECOIN_ADDRESS":      NODE_TYPES.CRYPTO_WALLET,
    "XRP_ADDRESS":           NODE_TYPES.CRYPTO_WALLET,
    "SOLANA_ADDRESS":        NODE_TYPES.CRYPTO_WALLET,
    "TRON_ADDRESS":          NODE_TYPES.CRYPTO_WALLET,
    "BITCOIN_CASH_ADDRESS":  NODE_TYPES.CRYPTO_WALLET,
    "DASH_ADDRESS":          NODE_TYPES.CRYPTO_WALLET,
    "ENS_DOMAIN":            NODE_TYPES.DOMAIN,
    "DOMAIN":                NODE_TYPES.DOMAIN,
    "ONION_URL":             NODE_TYPES.ONION_URL,
    "EMAIL_ADDRESS":         NODE_TYPES.EMAIL_ADDRESS,
    "PGP_KEY_BLOCK":         NODE_TYPES.PGP_KEY,
    "CVE_NUMBER":            NODE_TYPES.CVE,
    "CVE":                   "vulnerability",
    "PASTE_URL":             NODE_TYPES.PASTE,
    "MALWARE_FAMILY":        NODE_TYPES.MALWARE_FAMILY,
    "RANSOMWARE_GROUP":      NODE_TYPES.RANSOMWARE_GROUP,
    "IP_ADDRESS":            NODE_TYPES.IP_ADDRESS,
    "IPV6_ADDRESS":          "network",  # reuse the IP_ADDRESS node type
    "MAC_ADDRESS":           NODE_TYPES.NETWORK_INDICATOR,
    "IPFS_CID":              "file_hash",  # reuse the file_hash node type
    "COMBO_LIST_ENTRY":      NODE_TYPES.CONTENT_INDICATOR,
    "YARA_RULE":             NODE_TYPES.MALWARE_INDICATOR,
    "MITRE_TACTIC":          "technique",  # reuse the MITRE_TECHNIQUE node type
    "EXPLOIT_DB_ID":         "vulnerability",  # reuse the CVE node type
    "NUCLEI_TEMPLATE":       NODE_TYPES.MALWARE_INDICATOR,
    "CRYPTO_SEED_PHRASE":    NODE_TYPES.CONTENT_INDICATOR,
    "PHONE_NUMBER":          NODE_TYPES.PHONE_NUMBER,
    "ORGANIZATION_NAME":     NODE_TYPES.ORGANIZATION,
    "DATE":                  NODE_TYPES.DATE,
    "FILE_HASH_MD5":         "file_hash",
    "FILE_HASH_SHA1":        "file_hash",
    "FILE_HASH_SHA256":      "file_hash",
    "MITRE_TECHNIQUE":       "technique",
    # Credential / token entity types — all collapse to the single
    # Credential node type.  This keeps the graph compact and makes
    # credential-based queries (which credential appears next to which
    # actor / paste / wallet) trivial.
    "AWS_ACCESS_KEY":        NODE_TYPES.CREDENTIAL,
    "AWS_SECRET_KEY":        NODE_TYPES.CREDENTIAL,
    "GITHUB_TOKEN":          NODE_TYPES.CREDENTIAL,
    "SLACK_TOKEN":           NODE_TYPES.CREDENTIAL,
    "DISCORD_TOKEN":         NODE_TYPES.CREDENTIAL,
    "JWT_TOKEN":             NODE_TYPES.CREDENTIAL,
    "GOOGLE_API_KEY":        NODE_TYPES.CREDENTIAL,
    "STRIPE_KEY":            NODE_TYPES.CREDENTIAL,
    "STEALER_LOG_ENTRY":     NODE_TYPES.CREDENTIAL,
    "API_KEY":               NODE_TYPES.CREDENTIAL,
    # Messaging / identity handle entity types — all collapse to the
    # single MESSAGING_HANDLE node type.  This is the communication IOC
    # family (purple in the visualization); original subtype is preserved
    # in node metadata["messaging_kind"] so a query can still distinguish
    # a Telegram handle from a Tox ID even though they share a node type.
    "TELEGRAM_HANDLE":       NODE_TYPES.MESSAGING_HANDLE,
    "DISCORD_HANDLE":        NODE_TYPES.MESSAGING_HANDLE,
    "XMPP_JID":              NODE_TYPES.MESSAGING_HANDLE,
    "TOX_ID":                NODE_TYPES.MESSAGING_HANDLE,
    "SESSION_ID":            NODE_TYPES.MESSAGING_HANDLE,
    "MATRIX_HANDLE":         NODE_TYPES.MESSAGING_HANDLE,
    "WIRE_HANDLE":           NODE_TYPES.MESSAGING_HANDLE,
    "ICQ_NUMBER":            NODE_TYPES.MESSAGING_HANDLE,
    "WICKR_ID":              NODE_TYPES.MESSAGING_HANDLE,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_domain(url: str) -> str:
    """Extract the netloc (hostname) from a URL, or empty string on failure."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or ""
    except Exception:
        return ""


def _make_node_id(entity_type: str, value: str, source_url: str) -> str:
    """
    Derive a stable node_id for an entity.

    ThreatActor handles are disambiguated by forum domain so that the same
    handle on two different forums produces two distinct nodes (enabling the
    LIKELY_SAME_ACTOR inference pass).  All other entity types are globally
    unique by canonical value.

    This is now a thin wrapper that delegates entirely to
    ``extractor.identity.entity_graph_id`` — the single source of truth for
    graph node identity.  Every consumer (STIX/MISP/Sigma/IOC exporters, the
    entity API) resolves graph nodes through that same function, so a graph
    node id and an exporter's lookup key can no longer silently diverge (the
    STIX threat-actor relationship-drop bug class).  Kept as a primitive-arg
    name because other modules still import and call it directly.
    """
    return entity_graph_id(
        SimpleNamespace(entity_type=entity_type, value=value, source_url=source_url)
    )


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _cooccurrence_entity_rank(ent) -> tuple[int, float, str]:
    etype = (getattr(ent, "entity_type", "") or "").upper()
    confidence = float(getattr(ent, "confidence", 0.0) or 0.0)
    if etype in _CO_OCCURRENCE_HUB_TYPES:
        priority = 0
    elif etype in _CO_OCCURRENCE_IOC_TYPES:
        priority = 1
    else:
        priority = 2
    return (priority, -confidence, str(getattr(ent, "id", "")))


def _iter_semantic_cooccurrence_pairs(page_entities: list) -> list[tuple]:
    """
    Return bounded, analyst-useful co-occurrence pairs for one page.

    We avoid the old all-pairs cartesian behavior. Edges are only emitted
    between high-signal actor/malware/CVE hubs and technical IOCs; if a page
    has no hub, we keep a small set of high-confidence technical IOC pairs.
    """
    unique: dict[tuple[str, str], object] = {}
    for ent in page_entities:
        etype = (getattr(ent, "entity_type", "") or "").upper()
        value = str(getattr(ent, "value", "") or "").strip().lower()
        if not etype or not value:
            continue
        key = (etype, value)
        existing = unique.get(key)
        if existing is None or _cooccurrence_entity_rank(ent) < _cooccurrence_entity_rank(existing):
            unique[key] = ent

    ranked = sorted(unique.values(), key=_cooccurrence_entity_rank)[:_CO_OCCURRENCE_MAX_ENTITIES_PER_PAGE]
    hubs = [e for e in ranked if (getattr(e, "entity_type", "") or "").upper() in _CO_OCCURRENCE_HUB_TYPES]
    iocs = [e for e in ranked if (getattr(e, "entity_type", "") or "").upper() in _CO_OCCURRENCE_IOC_TYPES]

    pairs: list[tuple] = []
    if hubs:
        for hub in hubs[:12]:
            for ioc in iocs[:25]:
                if getattr(hub, "id", None) == getattr(ioc, "id", None):
                    continue
                pairs.append((hub, ioc))
                if len(pairs) >= _CO_OCCURRENCE_MAX_EDGES_PER_PAGE:
                    return pairs
        return pairs

    for ent_a, ent_b in itertools.combinations(iocs[:16], 2):
        pairs.append((ent_a, ent_b))
        if len(pairs) >= _CO_OCCURRENCE_MAX_EDGES_PER_PAGE:
            break
    return pairs


def _is_semantic_cooccurrence_pair(ent_a, ent_b) -> bool:
    etype_a = (getattr(ent_a, "entity_type", "") or "").upper()
    etype_b = (getattr(ent_b, "entity_type", "") or "").upper()
    if not etype_a or not etype_b or getattr(ent_a, "id", None) == getattr(ent_b, "id", None):
        return False
    if etype_a in _CO_OCCURRENCE_HUB_TYPES and etype_b in _CO_OCCURRENCE_IOC_TYPES:
        return True
    if etype_b in _CO_OCCURRENCE_HUB_TYPES and etype_a in _CO_OCCURRENCE_IOC_TYPES:
        return True
    return False


def _coerce_uuid_or_none(value) -> uuid.UUID | None:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Public: add_entity_to_graph
# ---------------------------------------------------------------------------


def add_entity_to_graph(
    graph: nx.MultiDiGraph,
    entity: NormalizedEntity,
) -> nx.MultiDiGraph:
    """
    Upsert a single NormalizedEntity as a node in *graph*.

    - If the node does not exist: create it with all fields from *entity*.
    - If the node already exists:
        * update last_seen if entity's source timestamp is later
        * append source_url if not already present
    Returns the modified graph.
    """
    node_type = _ENTITY_TYPE_TO_NODE_TYPE.get(entity.entity_type)
    if node_type is None:
        return graph  # entity type has no graph representation

    node_id = _make_node_id(entity.entity_type, entity.value, entity.source_url)
    now = _now_utc()

    if graph.has_node(node_id):
        data = graph.nodes[node_id]
        # Update last_seen to now (we just re-observed this entity)
        data["last_seen"] = now
        # Append source URL if not already recorded
        if entity.source_url and entity.source_url not in data["source_urls"]:
            data["source_urls"] = data["source_urls"] + [entity.source_url]
    else:
        metadata: dict = {}
        if node_type == NODE_TYPES.THREAT_ACTOR:
            metadata["handle"] = entity.value
            domain = _extract_domain(entity.source_url)
            if domain:
                metadata["forum"] = domain
        if node_type == NODE_TYPES.CREDENTIAL:
            # Preserve the original credential subtype so a graph query
            # can still distinguish AWS keys from GitHub tokens even
            # though they collapse to the same node_type.
            metadata["credential_kind"] = entity.entity_type
        if node_type == NODE_TYPES.MESSAGING_HANDLE:
            # Preserve the original messaging subtype (Telegram vs Discord
            # vs Tox vs ...) so a graph query can filter by platform even
            # though they collapse to the same node_type.  Purple in the
            # visualization.
            metadata["messaging_kind"] = entity.entity_type
        if node_type == NODE_TYPES.NETWORK_INDICATOR:
            # Preserve the original subtype (MAC_ADDRESS vs the
            # future-added ones that map to NETWORK_INDICATOR) so a
            # query can still distinguish a MAC from another network
            # indicator type that shares this node_type.
            metadata["network_kind"] = entity.entity_type
        if node_type == NODE_TYPES.MALWARE_INDICATOR:
            # Preserve the original subtype (YARA_RULE vs NUCLEI_TEMPLATE
            # vs future additions) so a query can filter by detector.
            metadata["malware_kind"] = entity.entity_type
        if node_type == NODE_TYPES.CONTENT_INDICATOR:
            # Preserve the original subtype (IPFS_CID vs COMBO_LIST_ENTRY
            # vs CRYPTO_SEED_PHRASE) so a query can still distinguish
            # between the three content-indicator families.
            metadata["content_kind"] = entity.entity_type
        graph.add_node(
            node_id,
            node_type=node_type,
            first_seen=now,
            last_seen=now,
            source_urls=[entity.source_url] if entity.source_url else [],
            metadata=metadata,
        )

    return graph


# ---------------------------------------------------------------------------
# Public: add_relationship
# ---------------------------------------------------------------------------


def add_relationship(
    graph: nx.MultiDiGraph,
    source_id: str,
    target_id: str,
    edge_type: str,
    confidence: float,
    source_url: str,
    metadata: Optional[dict] = None,
) -> nx.MultiDiGraph:
    """
    Add a directed edge from *source_id* to *target_id*.

    Nodes referenced by source_id / target_id are auto-created as stubs if
    they do not exist (so the graph stays consistent).
    Returns the modified graph.
    """
    now = _now_utc()
    for nid in (source_id, target_id):
        if not graph.has_node(nid):
            graph.add_node(
                nid,
                node_type="",
                first_seen=now,
                last_seen=now,
                source_urls=[],
                metadata={},
                confidence=0.0,
            )

    graph.add_edge(
        source_id,
        target_id,
        edge_type=edge_type,
        confidence=confidence,
        source_url=source_url,
        timestamp=now,
        metadata=metadata or {},
    )
    return graph


# ---------------------------------------------------------------------------
# Public: infer_relationships
# ---------------------------------------------------------------------------


def infer_relationships(graph: nx.MultiDiGraph) -> nx.MultiDiGraph:
    """
    Run inference passes over the existing graph to add derived edges.

    Pass 1 — PGP key reuse:
        If a PGPKey node is directly connected (any edge direction) to 2+
        ThreatActor nodes → those actors likely share an identity → add a
        CONFIRMED_SAME_ACTOR edge (confidence=0.95).

    Pass 2 — Handle similarity:
        If two ThreatActor nodes have the same metadata["handle"] value
        (case-insensitive) but originate from different forums
        (metadata["forum"] differs) → add LIKELY_SAME_ACTOR (confidence=0.6).

    Returns the modified graph (inferred edges appended in-place).
    """
    now = _now_utc()

    # --- Pass 1: PGP key reuse ---
    for pgp_id, data in list(graph.nodes(data=True)):
        if data.get("node_type") != NODE_TYPES.PGP_KEY:
            continue

        # Collect all ThreatActor nodes directly adjacent (either direction)
        adjacent = set(graph.successors(pgp_id)) | set(graph.predecessors(pgp_id))
        actors = [
            n for n in adjacent
            if graph.nodes[n].get("node_type") == NODE_TYPES.THREAT_ACTOR
        ]

        for actor_a, actor_b in itertools.combinations(actors, 2):
            # Skip if a CONFIRMED_SAME_ACTOR edge already exists in either direction
            existing_types = {
                d.get("edge_type")
                for _, _, d in graph.edges(actor_a, data=True)
            } | {
                d.get("edge_type")
                for _, _, d in graph.edges(actor_b, data=True)
            }
            if EDGE_TYPES.CONFIRMED_SAME_ACTOR in existing_types:
                continue
            graph.add_edge(
                actor_a,
                actor_b,
                edge_type=EDGE_TYPES.CONFIRMED_SAME_ACTOR,
                confidence=0.95,
                source_url="",
                timestamp=now,
                metadata={"inferred_from_pgp": pgp_id},
            )

    # --- Pass 2: Handle similarity across forums ---
    # Group ThreatActor nodes by their normalised handle value
    handle_groups: dict[str, list[str]] = defaultdict(list)
    for nid, data in graph.nodes(data=True):
        if data.get("node_type") != NODE_TYPES.THREAT_ACTOR:
            continue
        handle = data.get("metadata", {}).get("handle", "")
        if handle:
            handle_groups[handle.lower().strip()].append(nid)

    for _handle, node_ids in handle_groups.items():
        if len(node_ids) < 2:
            continue
        for nid_a, nid_b in itertools.combinations(node_ids, 2):
            forum_a = graph.nodes[nid_a].get("metadata", {}).get("forum", "")
            forum_b = graph.nodes[nid_b].get("metadata", {}).get("forum", "")
            # Only infer when forums differ (same forum + same handle = same node
            # by construction, but guard anyway)
            if forum_a == forum_b:
                continue
            # Skip if already connected by a same-actor edge
            existing_types = {
                d.get("edge_type")
                for _, _, d in graph.edges(nid_a, data=True)
            } | {
                d.get("edge_type")
                for _, _, d in graph.edges(nid_b, data=True)
            }
            if (
                EDGE_TYPES.LIKELY_SAME_ACTOR in existing_types
                or EDGE_TYPES.CONFIRMED_SAME_ACTOR in existing_types
            ):
                continue
            graph.add_edge(
                nid_a,
                nid_b,
                edge_type=EDGE_TYPES.LIKELY_SAME_ACTOR,
                confidence=0.6,
                source_url="",
                timestamp=now,
                metadata={"inferred_from_handle": _handle},
            )

    return graph


# ---------------------------------------------------------------------------
# Public: detect_communities
# ---------------------------------------------------------------------------


def detect_communities(G: "nx.Graph | nx.DiGraph | nx.MultiDiGraph") -> dict:
    """
    Detect communities in *G* using the Clauset-Newman-Moore greedy modularity
    algorithm (built into NetworkX — no extra dependency required).

    Why greedy_modularity_communities (instead of python-louvain)?
        networkx==3.4.2 is already a hard requirement of the project, so we
        avoid pulling in python-louvain and stay zero-new-dep.  The algorithm
        is deterministic (no random seed), so identical graphs always produce
        identical community assignments — which is the whole point of moving
        this out of the browser.

    Returns
    -------
    dict[node_id, int]
        Mapping from node id → community index (0..N-1).

    Edge cases
    ----------
    * Empty graph            → ``{}``
    * 1 or 2 nodes           → all nodes assigned community 0 (too small for
                               meaningful partition)
    * Disconnected components → each component gets its own community indices
                               (community numbers are global, just not
                               contiguous per component)
    * Algorithm raises       → ``{n: 0 for n in G.nodes}`` (logged warning).
                               We never fail loudly — community colouring is a
                               visualisation aid, not a correctness feature.
    """
    if G is None or len(G.nodes) == 0:
        return {}
    if len(G.nodes) < 3:
        # Clauset-Newman-Moore refuses graphs with <3 nodes
        return {n: 0 for n in G.nodes}

    try:
        from networkx.algorithms.community import (
            greedy_modularity_communities,
        )

        # The algorithm requires an undirected graph — convert if needed.
        G_undirected = G.to_undirected() if G.is_directed() else G

        communities_iter = greedy_modularity_communities(G_undirected)
        partition: dict = {}
        for idx, community in enumerate(communities_iter):
            for node in community:
                partition[node] = idx
        return partition

    except Exception as exc:
        logger.warning(
            "detect_communities failed (%s); falling back to single-community", exc
        )
        return {n: 0 for n in G.nodes}


# ---------------------------------------------------------------------------
# Public: find_shortest_path
# ---------------------------------------------------------------------------


def find_shortest_path(
    G: nx.DiGraph,
    source_id: str,
    target_id: str,
    max_hops: int = 6,
) -> "list[str] | None":
    """
    Find the shortest path between two nodes in a directed graph.

    Strategy:
        1. Try the directed graph as-is (preserves relationship directionality).
        2. If no directed path exists within ``max_hops``, retry on the
           undirected projection — relationship direction shouldn't prevent
           finding *a* connection between two entities (analysts care about
           association, not necessarily causality).

    Parameters
    ----------
    G : nx.DiGraph | nx.MultiDiGraph
        The relationship graph.  Multi-edges are flattened — we only need
        reachability, not which specific edge is traversed.
    source_id, target_id : str
        Node ids (canonical_value / node_id strings, not entity UUIDs).
    max_hops : int, default 6
        Maximum number of edges allowed in the returned path.  Default 6 is
        enough for any realistic investigation subgraph and prevents infinite
        search on dense graphs.

    Returns
    -------
    list[str] | None
        Ordered list of node ids from ``source_id`` to ``target_id`` (both
        endpoints included), or ``None`` if:
        - either node is missing from the graph
        - no path exists within ``max_hops`` in either directed or
          undirected view.

    Notes
    -----
    * For ``MultiDiGraph`` input, ``shortest_path`` flattens parallel edges
      transparently — that's the correct semantics here (we want reachability,
      not "is there an edge from A to B in any one parallel slot").
    * The directed attempt always runs first; the undirected fallback only
      kicks in when directed reachability fails.
    * This function never raises — all NetworkX exceptions are caught and
      converted to ``None`` so callers can rely on a single ``None`` check
      for "no path".
    """
    if G is None or source_id not in G or target_id not in G:
        return None

    # Try directed first.
    try:
        path = nx.shortest_path(G, source_id, target_id)
        if len(path) - 1 <= max_hops:
            return path
        return None  # directed path exists but exceeds max_hops
    except nx.NetworkXNoPath:
        pass
    except nx.NodeNotFound:
        return None

    # Fall back to undirected — ignore relationship direction.
    try:
        path = nx.shortest_path(G.to_undirected(), source_id, target_id)
        if len(path) - 1 <= max_hops:
            return path
        return None
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None


def _link_cross_page_entities(
    G: nx.MultiDiGraph,
    entities: list,
    investigation_id: Optional[uuid.UUID]
) -> int:
    """
    Second pass: link entities from different pages that share investigation context.
    
    Strategy:
    1. Find entities that appear on multiple pages (high-value bridge nodes)
       → Increase their node size/weight
    2. Find pairs of entities from different pages that share a common
       co-occurring entity → Add CROSS_PAGE_LINKED edge
    3. Find entity clusters from different pages that are densely connected
       internally → Add inter-cluster edges for the most connected nodes
    
    Returns: count of new edges added
    """
    if not entities:
        return 0

    edges_added = 0
    
    # Step 1: Build page→entities map
    page_entity_map: dict[str, list] = defaultdict(list)
    entity_page_map: dict[str, list] = defaultdict(list)  # node_id → page_urls
    
    for ent in entities:
        page_url = ent.page.url if ent.page else f"unknown_{ent.id}"
        node_id = _make_node_id(ent.entity_type, ent.value, page_url)
        page_entity_map[page_url].append(node_id)
        if page_url not in entity_page_map[node_id]:
            entity_page_map[node_id].append(page_url)
    
    # Step 2: Boost multi-page entities (appear on 2+ pages = high significance)
    for node_id, pages in entity_page_map.items():
        if len(pages) > 1 and G.has_node(node_id):
            current_size = G.nodes[node_id].get("size", 10)
            # Each additional page appearance adds 5 to node size (up to 40 max)
            boost = min(len(pages) * 5, 40)
            G.nodes[node_id]["size"] = min(current_size + boost, 40)
            G.nodes[node_id]["page_count"] = len(pages)
            logger.debug(f"Boosted node {node_id}: appears on {len(pages)} pages")
    
    # Step 3: Link entities from different pages via shared co-occurrence
    # Build inverted index: entity_id → set of pages containing it (O(entities))
    # Then for each entity, connect all page pairs (O(entities × avg_pages²))
    # This reduces O(pages²) to O(entities × avg_pages²_per_entity)
    entity_to_pages: dict[str, set] = defaultdict(set)
    for node_id, pages_list in entity_page_map.items():
        for page_url in pages_list:
            entity_to_pages[node_id].add(page_url)

    for node_id, page_set in entity_to_pages.items():
        if len(page_set) < 2:
            continue
        page_list = list(page_set)
        for i, page_a in enumerate(page_list):
            for page_b in page_list[i + 1:]:
                entities_a = page_entity_map.get(page_a, [])
                entities_b = page_entity_map.get(page_b, [])

                if not entities_a or not entities_b:
                    continue

                entities_a_set = set(entities_a)
                entities_b_set = set(entities_b)
                shared_entities = entities_a_set & entities_b_set

                if shared_entities:
                    unique_to_a = entities_a_set - entities_b_set
                    unique_to_b = entities_b_set - entities_a_set

                    for bridge_node in shared_entities:
                        unique_list_a = list(unique_to_a)[:3]
                        unique_list_b = list(unique_to_b)[:3]
                        for entity_a in unique_list_a:
                            for entity_b in unique_list_b:
                                if G.has_node(entity_a) and G.has_node(entity_b):
                                    if not G.has_edge(entity_a, entity_b):
                                        G.add_edge(
                                            entity_a, entity_b,
                                            edge_type=EDGE_TYPES.CO_INVESTIGATION,
                                            confidence=0.3,
                                            via=bridge_node,
                                            label="co-investigation",
                                            timestamp=_now_utc()
                                        )
                                        edges_added += 1
    
    # Step 4: Direct cross-page linking for same-type high-confidence entities
    # If two THREAT_ACTOR entities appear in the same investigation across different
    # pages, they're likely part of the same ecosystem → link them
    actor_nodes = [
        node for node, data in G.nodes(data=True)
        if data.get("node_type") == NODE_TYPES.THREAT_ACTOR
        # Confidence might be in metadata or root; check both
        and (data.get("metadata", {}).get("confidence", 0) >= 0.85 
             or data.get("confidence", 0.85) >= 0.85) # default 0.85 for TA
    ]
    
    # Link threat actors that appear across 2+ pages (they're ecosystem-level nodes)
    multi_page_actors = [
        node for node in actor_nodes
        if len(entity_page_map.get(node, [])) >= 2
    ]
    
    for i, actor_a in enumerate(multi_page_actors):
        for actor_b in multi_page_actors[i + 1:]:
            if not G.has_edge(actor_a, actor_b):
                G.add_edge(
                    actor_a, actor_b,
                    edge_type=EDGE_TYPES.CO_INVESTIGATION,
                    confidence=0.4,
                    label="co-investigation",
                    timestamp=_now_utc()
                )
                edges_added += 1
    
    return edges_added



# ---------------------------------------------------------------------------
# Public: build_graph_from_db
# ---------------------------------------------------------------------------


def build_graph_from_db(
    investigation_id: Optional[uuid.UUID] = None,
    since: Optional[datetime] = None,
) -> nx.MultiDiGraph:
    """
    Build a fresh graph by loading entity records from the database.

    Filters:
        investigation_id — if given, only load entities for that investigation.
        since            — if given, only load entities where first_seen >= since.

    For every page that has 2+ entities, CO_APPEARED_ON edges are created
    between all pairs of entities on that page.

    If DATABASE_URL is not set, returns an empty graph without raising.
    Never raises on DB errors (logs a warning and returns the partial graph).
    """
    graph: nx.MultiDiGraph = nx.MultiDiGraph()

    if not os.getenv("DATABASE_URL"):
        return graph

    try:
        from db.session import get_session  # noqa: PLC0415
        from db.models import Entity, EntityRelationship  # noqa: PLC0415
        from sqlalchemy.orm import joinedload  # noqa: PLC0415

        with get_session() as session:
            from db.models import InvestigationEntityLink  # noqa: PLC0415

            if investigation_id is not None:
                query = (
                    session.query(Entity)
                    .join(
                        InvestigationEntityLink,
                        InvestigationEntityLink.entity_id == Entity.id,
                        isouter=True,
                    )
                    .filter(
                        (Entity.investigation_id == investigation_id)
                        | (InvestigationEntityLink.investigation_id == investigation_id)
                    )
                    .options(joinedload(Entity.page))
                )
            else:
                query = session.query(Entity).options(joinedload(Entity.page))

            if since is not None:
                query = query.filter(Entity.first_seen >= since)

            matching_entities_count = query.count()

            total_investigation = (
                session.query(Entity)
                .filter(Entity.investigation_id == investigation_id)
                .count()
                if investigation_id is not None
                else session.query(Entity).count()
            )
            null_inv_count = (
                session.query(Entity)
                .filter(Entity.investigation_id.is_(None))
                .count()
            )

            logger.warning(
                "build_graph_from_db: investigation_id=%s entity_rows_loaded=%s "
                "count_matching_investigation_filter=%s global_entities_with_null_investigation_id=%s",
                investigation_id,
                matching_entities_count,
                total_investigation,
                null_inv_count,
            )

            # Entity rows must be processed while the session is open: after close,
            # lazy loads on ent.page raise (joinedload data is expired).
            skipped_unmapped = 0
            page_entity_map: dict[str, list[Entity]] = defaultdict(list)
            all_entities: list[Entity] = []

            entity_rows = list(query.yield_per(2000))
            if investigation_id is not None and entity_rows:
                from db.entity_views import entity_views
                entity_rows = entity_views(session, entity_rows, investigation_id=investigation_id)
            if not entity_rows and not isinstance(matching_entities_count, int):
                fallback_rows = query.all()
                entity_rows = (
                    list(fallback_rows)
                    if isinstance(fallback_rows, (list, tuple))
                    else []
                )
            if not entity_rows and not isinstance(matching_entities_count, int):
                fallback_rows = session.query(Entity).all()
                entity_rows = (
                    list(fallback_rows)
                    if isinstance(fallback_rows, (list, tuple))
                    else []
                )

            for ent in entity_rows:
                all_entities.append(ent)
                page_url = ent.page.url if ent.page else ""
                node_type = _ENTITY_TYPE_TO_NODE_TYPE.get(ent.entity_type)
                if node_type is None:
                    skipped_unmapped += 1
                    continue  # skip unmapped types

                node_id = _make_node_id(ent.entity_type, ent.value, page_url)

                if graph.has_node(node_id):
                    data = graph.nodes[node_id]
                    if ent.last_seen and (
                        not data.get("last_seen") or ent.last_seen > data["last_seen"]
                    ):
                        data["last_seen"] = ent.last_seen
                    if page_url and page_url not in data["source_urls"]:
                        data["source_urls"] = data["source_urls"] + [page_url]
                else:
                    meta: dict = {}
                    if node_type == NODE_TYPES.THREAT_ACTOR:
                        meta["handle"] = ent.value
                        domain = _extract_domain(page_url)
                        if domain:
                            meta["forum"] = domain
                    if node_type == NODE_TYPES.CREDENTIAL:
                        meta["credential_kind"] = ent.entity_type
                    if node_type == NODE_TYPES.MESSAGING_HANDLE:
                        # Preserve the messaging subtype on reload.
                        meta["messaging_kind"] = ent.entity_type
                    if node_type == NODE_TYPES.NETWORK_INDICATOR:
                        meta["network_kind"] = ent.entity_type
                    if node_type == NODE_TYPES.MALWARE_INDICATOR:
                        meta["malware_kind"] = ent.entity_type
                    if node_type == NODE_TYPES.CONTENT_INDICATOR:
                        meta["content_kind"] = ent.entity_type
                    graph.add_node(
                        node_id,
                        node_type=node_type,
                        first_seen=ent.first_seen or _now_utc(),
                        last_seen=ent.last_seen or _now_utc(),
                        source_urls=[page_url] if page_url else [],
                        metadata=meta,
                        confidence=ent.confidence,
                    )

                if ent.page_id:
                    page_entity_map[str(ent.page_id)].append(ent)

            intra_page_edges = 0
            for _page_id, page_entities in page_entity_map.items():
                if len(page_entities) < 2:
                    continue
                for ent_a, ent_b in _iter_semantic_cooccurrence_pairs(page_entities):
                    page_url_a = ent_a.page.url if ent_a.page else ""
                    node_id_a = _make_node_id(ent_a.entity_type, ent_a.value, page_url_a)
                    node_id_b = _make_node_id(ent_b.entity_type, ent_b.value, page_url_a)

                    if not graph.has_node(node_id_a) or not graph.has_node(node_id_b):
                        continue

                    graph.add_edge(
                        node_id_a,
                        node_id_b,
                        edge_type=EDGE_TYPES.CO_APPEARED_ON,
                        confidence=1.0,
                        source_url=page_url_a,
                        timestamp=_now_utc(),
                        metadata={},
                    )
                    intra_page_edges += 1

            # Second pass: cross-page entity linking
            cross_page_edges = _link_cross_page_entities(graph, all_entities, investigation_id)

            # Third pass: Load persistent relationships from DB
            persisted_edges = 0
            try:
                # Get all entities in the graph so we can filter relationships
                graph_entity_ids = [ent.id for ent in all_entities]
                if graph_entity_ids:
                    if investigation_id is not None:
                        relationships = (
                            session.query(EntityRelationship)
                            .filter(
                                EntityRelationship.investigation_id == investigation_id
                            )
                            .yield_per(500)
                            .all()
                        )
                    else:
                        relationships = session.query(EntityRelationship).filter(
                            (EntityRelationship.entity_a_id.in_(graph_entity_ids)) |
                            (EntityRelationship.entity_b_id.in_(graph_entity_ids))
                        ).all()

                    # Create a map of entity_id -> node_id for easy lookup
                    # Since one entity can appear on multiple pages, we use the first one found or a stable mapping
                    entity_to_node = {}
                    entity_by_id = {}
                    for ent in all_entities:
                        page_url = ent.page.url if ent.page else ""
                        node_id = _make_node_id(ent.entity_type, ent.value, page_url)
                        if str(ent.id) not in entity_to_node:
                            entity_to_node[str(ent.id)] = node_id
                            entity_by_id[str(ent.id)] = ent

                    all_missing_ids = set()
                    for rel in relationships:
                        src_uuid = _coerce_uuid_or_none(rel.entity_a_id)
                        tgt_uuid = _coerce_uuid_or_none(rel.entity_b_id)
                        if src_uuid is None or tgt_uuid is None:
                            logger.debug("Skipping relationship with non-UUID endpoints: %s", rel.id)
                            continue
                        src = str(src_uuid)
                        tgt = str(tgt_uuid)
                        if src not in entity_to_node:
                            all_missing_ids.add(src_uuid)
                        if tgt not in entity_to_node:
                            all_missing_ids.add(tgt_uuid)

                    if all_missing_ids:
                        from db.models import Entity as EntityModel

                        (
                            session.query(EntityModel)
                            .options(joinedload(EntityModel.page))
                            .filter(EntityModel.id.in_(all_missing_ids))
                        )
                        missing_entities = (
                            session.query(EntityModel)
                            .options(joinedload(EntityModel.page))
                            .filter(EntityModel.id.in_(all_missing_ids))
                            .all()
                        )
                        if investigation_id is not None:
                            from db.entity_views import entity_views
                            missing_entities = entity_views(session, missing_entities, investigation_id=investigation_id)
                        for me in missing_entities:
                            me_page_url = me.page.url if me.page else ""
                            me_node_id = _make_node_id(me.entity_type, me.value, me_page_url)
                            entity_to_node[str(me.id)] = me_node_id
                            entity_by_id[str(me.id)] = me
                            if not graph.has_node(me_node_id):
                                graph.add_node(
                                    me_node_id,
                                    node_type=_ENTITY_TYPE_TO_NODE_TYPE.get(me.entity_type, ""),
                                    first_seen=me.first_seen or _now_utc(),
                                    last_seen=me.last_seen or _now_utc(),
                                    source_urls=[me_page_url] if me_page_url else [],
                                    metadata={}
                                )

                    for rel in relationships:
                        source_id = _coerce_uuid_or_none(rel.entity_a_id)
                        target_id = _coerce_uuid_or_none(rel.entity_b_id)
                        if source_id is None or target_id is None:
                            continue
                        rel_type = str(rel.relationship_type or "")
                        if rel_type == EDGE_TYPES.CO_APPEARED_ON:
                            ent_a = entity_by_id.get(str(source_id))
                            ent_b = entity_by_id.get(str(target_id))
                            if ent_a is None or ent_b is None:
                                continue
                            if not _is_semantic_cooccurrence_pair(ent_a, ent_b):
                                continue
                        source_node = entity_to_node.get(str(source_id))
                        target_node = entity_to_node.get(str(target_id))

                        if source_node and target_node:
                            # Add the persisted relationship edge
                            if not graph.has_edge(source_node, target_node, key=f"persisted_{rel.id}"):
                                graph.add_edge(
                                    source_node,
                                    target_node,
                                    key=f"persisted_{rel.id}",
                                    edge_type=rel_type,
                                    confidence=rel.confidence,
                                    source_url="",
                                    timestamp=rel.first_seen or _now_utc(),
                                    metadata={}
                                )
                                persisted_edges += 1
            except Exception as e:
                logger.warning(f"Failed to load persistent relationships: {e}")


            logger.warning(
                "build_graph_from_db: investigation_id=%s "
                "nodes=%s "
                "intra_page_edges=%s "
                "cross_page_edges=%s "
                "total_edges=%s "
                "skipped_unmapped_entity_types=%s",
                investigation_id,
                len(graph.nodes()),
                intra_page_edges,
                cross_page_edges,
                len(graph.edges()),
                skipped_unmapped,
            )

    except Exception as exc:
        logger.warning("build_graph_from_db failed: %s", exc)

    return graph


def persist_graph_edges(
    G: nx.MultiDiGraph,
    investigation_id: uuid.UUID,
    session,
) -> dict:
    """
    Write all edges from the NetworkX graph to entity_relationships table.

    Called once after build_graph_from_db() completes.
    Uses upsert logic — safe to call multiple times.

    Edge cap rules:
    - If edge count > 50,000: skip all edges, return {"status": "skipped_overflow", "edges_written": 0}
    - If edge count between 10,000 and 50,000: prune edges where BOTH entities have confidence < 0.85
    - Otherwise: write all edges

    Returns: dict with keys:
      - status: "written" | "skipped_overflow" | "pruned"
      - edges_written: int
      - original_count: int (for pruned status)
    """
    from db.models import Entity, EntityRelationship

    from sqlalchemy.orm import joinedload  # noqa: PLC0415

    entity_to_node = {}
    node_to_entity = {}
    entity_confidence: dict[uuid.UUID, float] = {}

    from db.models import InvestigationEntityLink  # noqa: PLC0415
    # Phase 0 fix: use a JOIN for linked entities and avoid ORM coercion
    # warnings on SQLAlchemy 2.x.
    entities = (
        session.query(Entity)
        .options(joinedload(Entity.page))
        .outerjoin(
            InvestigationEntityLink,
            InvestigationEntityLink.entity_id == Entity.id,
        )
        .filter(
            (Entity.investigation_id == investigation_id)
            | (InvestigationEntityLink.investigation_id == investigation_id)
        )
        .yield_per(2000)
    )
    for ent in entities:
        page_url = ent.page.url if ent.page else ""
        node_id = _make_node_id(ent.entity_type, ent.value, page_url)
        entity_to_node[str(ent.id)] = node_id
        node_to_entity[node_id] = ent.id
        entity_confidence[ent.id] = ent.confidence

    edges_to_update: list[tuple[uuid.UUID, uuid.UUID, str, float]] = []
    edge_keys: set[tuple] = set()

    potential_edges: list[tuple] = []
    for source_node, target_node, edge_data in G.edges(data=True):
        source_entity_id = node_to_entity.get(source_node)
        target_entity_id = node_to_entity.get(target_node)

        if not source_entity_id or not target_entity_id:
            continue

        if source_entity_id == target_entity_id:
            continue

        relationship_type = edge_data.get("edge_type", "CO_APPEARED_ON")
        confidence = float(edge_data.get("confidence", 0.5))
        key = (source_entity_id, target_entity_id, relationship_type)
        if key not in edge_keys:
            edge_keys.add(key)
            potential_edges.append((source_entity_id, target_entity_id, relationship_type, confidence))

    if not potential_edges:
        return {"status": "written", "edges_written": 0, "original_count": 0}

    edge_count = len(potential_edges)

    # Edge explosion check: > 50,000 edges
    if edge_count > 50000:
        logger.error(
            f"Edge explosion detected: {edge_count} edges for investigation {investigation_id}. "
            f"Graph construction skipped. Reduce entity count first."
        )
        return {"status": "skipped_overflow", "edges_written": 0, "original_count": edge_count}

    # Edge pruning: between 10,000 and 50,000 - keep only edges where BOTH entities have confidence >= 0.85
    pruned_count = 0
    if edge_count > 10000:
        pruned_edges = []
        for source_eid, target_eid, rel_type, conf in potential_edges:
            src_conf = entity_confidence.get(source_eid, 0)
            tgt_conf = entity_confidence.get(target_eid, 0)
            if src_conf >= 0.85 and tgt_conf >= 0.85:
                pruned_edges.append((source_eid, target_eid, rel_type, conf))
            else:
                pruned_count += 1
        potential_edges = pruned_edges
        if pruned_count:
            logger.warning(
                f"Edge pruning applied: {pruned_count}/{edge_count} edges removed "
                f"(both entity confidences must be >= 0.85). "
                f"Remaining: {len(potential_edges)} edges."
            )

    if not potential_edges:
        return {"status": "pruned", "edges_written": 0, "original_count": edge_count}

    source_ids = list({e[0] for e in potential_edges})
    target_ids = list({e[1] for e in potential_edges})
    all_entity_ids = list(set(source_ids + target_ids))
    rel_types = list({e[2] for e in potential_edges})

    existing_rels = (
        session.query(EntityRelationship)
        .filter(
            sa.or_(
                EntityRelationship.entity_a_id.in_(all_entity_ids),
                EntityRelationship.entity_b_id.in_(all_entity_ids),
            ),
            EntityRelationship.relationship_type.in_(rel_types),
        )
        .all()
    )

    existing_edge_set: set[tuple] = set()
    existing_confidence_map: dict[tuple, float] = {}
    for rel in existing_rels:
        key = (rel.entity_a_id, rel.entity_b_id, rel.relationship_type)
        existing_edge_set.add(key)
        existing_confidence_map[key] = rel.confidence

    edges_written = 0
    for source_entity_id, target_entity_id, relationship_type, confidence in potential_edges:
        key = (source_entity_id, target_entity_id, relationship_type)
        if key in existing_edge_set:
            existing_conf = existing_confidence_map.get(key, 0)
            if confidence > existing_conf:
                edges_to_update.append((source_entity_id, target_entity_id, relationship_type, confidence))
            continue

        rel = EntityRelationship(
            entity_a_id=source_entity_id,
            entity_b_id=target_entity_id,
            relationship_type=relationship_type,
            confidence=confidence,
            source_page_id=None,
            investigation_id=investigation_id,
        )
        session.add(rel)
        edges_written += 1

    session.commit()

    status = "pruned" if pruned_count > 0 else "written"
    logger.warning(
        f"persist_graph_edges: investigation={investigation_id} "
        f"status={status} edges_written={edges_written}, edges_skipped={len(potential_edges) - edges_written}"
    )
    return {"status": status, "edges_written": edges_written, "original_count": edge_count}


def build_graph_from_db_cached(investigation_id: uuid.UUID) -> nx.MultiDiGraph:
    """
    Build NetworkX graph from persisted entity_relationships rows.
    Faster than full recompute — reads pre-computed edges from DB.
    """
    from db.models import Entity, EntityRelationship
    from db.session import get_session
    from sqlalchemy.orm import joinedload

    G: nx.MultiDiGraph = nx.MultiDiGraph()

    with get_session() as session:
        from db.models import InvestigationEntityLink  # noqa: PLC0415
        entities = (
            session.query(Entity)
            .join(
                InvestigationEntityLink,
                InvestigationEntityLink.entity_id == Entity.id,
                isouter=True,
            )
            .filter(
                (Entity.investigation_id == investigation_id)
                | (InvestigationEntityLink.investigation_id == investigation_id)
            )
            .options(joinedload(Entity.page))
            .yield_per(500)
        )

        entity_to_node = {}
        for ent in entities:
            page_url = ent.page.url if ent.page else ""
            node_id = _make_node_id(ent.entity_type, ent.value, page_url)
            G.add_node(
                node_id,
                node_type=_ENTITY_TYPE_TO_NODE_TYPE.get(ent.entity_type, ""),
                first_seen=ent.first_seen or _now_utc(),
                last_seen=ent.last_seen or _now_utc(),
                source_urls=[page_url] if page_url else [],
                metadata={},
                confidence=ent.confidence,
            )
            entity_to_node[str(ent.id)] = node_id

        relationships = (
            session.query(EntityRelationship)
            .filter(EntityRelationship.investigation_id == investigation_id)
            .yield_per(2000)
        )

        for rel in relationships:
            source_node = entity_to_node.get(str(rel.entity_a_id))
            target_node = entity_to_node.get(str(rel.entity_b_id))

            if source_node and target_node and G.has_node(source_node) and G.has_node(target_node):
                G.add_edge(
                    source_node,
                    target_node,
                    edge_type=rel.relationship_type,
                    confidence=rel.confidence,
                    source_url="",
                    timestamp=rel.first_seen or _now_utc(),
                    metadata={},
                )

    return G
