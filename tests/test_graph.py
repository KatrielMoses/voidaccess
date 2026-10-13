"""
tests/test_graph.py — Comprehensive tests for the Phase 3 graph module.

Test classes
------------
TestModel          — graph/model.py
TestBuilder        — graph/builder.py
TestQueries        — graph/queries.py
TestExport         — graph/export.py
TestVisualize      — graph/visualize.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import networkx as nx

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path regardless of how pytest is invoked
# ---------------------------------------------------------------------------
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------

def _utc(offset_hours: int = 0) -> datetime:
    return datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc) + timedelta(hours=offset_hours)


def _make_graph_with_nodes() -> nx.MultiDiGraph:
    """Return a small graph with a variety of node types for query tests."""
    g = nx.MultiDiGraph()
    now = _utc()

    g.add_node("actor1", node_type="ThreatActor", first_seen=_utc(-10),
               last_seen=now, source_urls=["http://forum1.onion/page"], metadata={"handle": "h1", "forum": "forum1.onion"})
    g.add_node("actor2", node_type="ThreatActor", first_seen=_utc(-5),
               last_seen=now, source_urls=["http://forum2.onion/page"], metadata={"handle": "h2", "forum": "forum2.onion"})
    g.add_node("wallet1", node_type="CryptoWallet", first_seen=_utc(-8),
               last_seen=now, source_urls=["http://forum1.onion/page"], metadata={})
    g.add_node("wallet2", node_type="CryptoWallet", first_seen=_utc(-2),
               last_seen=now, source_urls=["http://forum2.onion/page"], metadata={})
    g.add_node("malware1", node_type="MalwareFamily", first_seen=_utc(-12),
               last_seen=now, source_urls=[], metadata={})
    g.add_node("forum1", node_type="Forum", first_seen=_utc(-20),
               last_seen=now, source_urls=[], metadata={})
    g.add_node("pgp1", node_type="PGPKey", first_seen=_utc(-7),
               last_seen=now, source_urls=[], metadata={"fingerprint": "DEAD1234"})

    # Edges
    g.add_edge("actor1", "wallet1", edge_type="CO_APPEARED_ON", confidence=1.0,
               source_url="http://forum1.onion/page", timestamp=now, metadata={})
    g.add_edge("actor1", "malware1", edge_type="USES", confidence=0.9,
               source_url="http://forum1.onion/page", timestamp=now, metadata={})
    g.add_edge("actor1", "forum1", edge_type="MEMBER_OF", confidence=1.0,
               source_url="", timestamp=now, metadata={})
    g.add_edge("actor2", "wallet2", edge_type="CO_APPEARED_ON", confidence=1.0,
               source_url="http://forum2.onion/page", timestamp=now, metadata={})
    g.add_edge("wallet1", "wallet2", edge_type="CO_APPEARED_ON", confidence=0.8,
               source_url="http://forum1.onion/page", timestamp=now, metadata={})

    return g


# ===========================================================================
# TestModel
# ===========================================================================


class TestModel(unittest.TestCase):

    def setUp(self):
        from graph import model as m
        self.m = m

    def test_graphnode_instantiation(self):
        node = self.m.GraphNode(
            node_id="wallet123",
            node_type=self.m.NODE_TYPES.CRYPTO_WALLET,
            first_seen=_utc(),
            last_seen=_utc(),
            source_urls=["http://example.onion"],
            metadata={"coin": "BTC"},
        )
        self.assertEqual(node.node_id, "wallet123")
        self.assertEqual(node.node_type, "CryptoWallet")
        self.assertIsInstance(node.source_urls, list)
        self.assertIsInstance(node.metadata, dict)

    def test_graphedge_instantiation(self):
        edge = self.m.GraphEdge(
            source_id="a",
            target_id="b",
            edge_type=self.m.EDGE_TYPES.CO_APPEARED_ON,
            confidence=0.95,
            source_url="http://forum.onion/page",
            timestamp=_utc(),
            metadata={"note": "test"},
        )
        self.assertEqual(edge.source_id, "a")
        self.assertEqual(edge.target_id, "b")
        self.assertEqual(edge.confidence, 0.95)

    def test_node_types_are_strings(self):
        nt = self.m.NODE_TYPES
        for attr in ("THREAT_ACTOR", "CRYPTO_WALLET", "ONION_URL", "FORUM",
                     "MALWARE_FAMILY", "RANSOMWARE_GROUP", "PGP_KEY",
                     "EMAIL_ADDRESS", "CVE", "PASTE"):
            self.assertIsInstance(getattr(nt, attr), str, msg=f"NODE_TYPES.{attr} is not str")

    def test_edge_types_are_strings(self):
        et = self.m.EDGE_TYPES
        for attr in ("CO_APPEARED_ON", "POSTED_BY", "LINKED_TO", "MEMBER_OF",
                     "USES", "CLAIMED", "LIKELY_SAME_ACTOR", "CONFIRMED_SAME_ACTOR"):
            self.assertIsInstance(getattr(et, attr), str, msg=f"EDGE_TYPES.{attr} is not str")

    def test_node_types_no_duplicates(self):
        nt = self.m.NODE_TYPES
        values = [
            nt.THREAT_ACTOR, nt.CRYPTO_WALLET, nt.ONION_URL, nt.FORUM,
            nt.MALWARE_FAMILY, nt.RANSOMWARE_GROUP, nt.PGP_KEY,
            nt.EMAIL_ADDRESS, nt.CVE, nt.PASTE,
        ]
        self.assertEqual(len(values), len(set(values)), "Duplicate NODE_TYPES values detected")

    def test_edge_types_no_duplicates(self):
        et = self.m.EDGE_TYPES
        values = [
            et.CO_APPEARED_ON, et.POSTED_BY, et.LINKED_TO, et.MEMBER_OF,
            et.USES, et.CLAIMED, et.LIKELY_SAME_ACTOR, et.CONFIRMED_SAME_ACTOR,
        ]
        self.assertEqual(len(values), len(set(values)), "Duplicate EDGE_TYPES values detected")


# ===========================================================================
# TestBuilder
# ===========================================================================


class TestBuilder(unittest.TestCase):

    def _make_entity(
        self,
        entity_type: str = "THREAT_ACTOR_HANDLE",
        value: str = "darkking99",
        source_url: str = "http://forum1.onion/thread/1",
        confidence: float = 0.8,
    ):
        from extractor.normalizer import NormalizedEntity
        return NormalizedEntity(
            entity_type=entity_type,
            value=value,
            confidence=confidence,
            source_url=source_url,
            page_id=None,
            context_snippet="",
        )

    # --- build_graph_from_db ---

    @patch.dict(os.environ, {}, clear=True)
    def test_build_graph_no_database_url(self):
        """Returns an empty graph when DATABASE_URL is not set."""
        # Remove DATABASE_URL if somehow present
        os.environ.pop("DATABASE_URL", None)
        from graph.builder import build_graph_from_db
        graph = build_graph_from_db()
        self.assertIsInstance(graph, nx.MultiDiGraph)
        self.assertEqual(graph.number_of_nodes(), 0)
        self.assertEqual(graph.number_of_edges(), 0)

    # --- add_entity_to_graph ---

    def test_add_entity_adds_node(self):
        """add_entity_to_graph adds a node with correct type and metadata."""
        from graph.builder import add_entity_to_graph
        entity = self._make_entity(
            entity_type="BITCOIN_ADDRESS",
            value="bc1qabc123",
            source_url="http://market.onion/listing/99",
        )
        g = nx.MultiDiGraph()
        g = add_entity_to_graph(g, entity)
        self.assertIn("bc1qabc123", g.nodes)
        data = g.nodes["bc1qabc123"]
        self.assertEqual(data["node_type"], "CryptoWallet")
        self.assertIn("http://market.onion/listing/99", data["source_urls"])

    def test_add_entity_upserts_existing_node(self):
        """add_entity_to_graph on existing node updates last_seen and appends source_url."""
        from graph.builder import add_entity_to_graph
        entity1 = self._make_entity(
            entity_type="BITCOIN_ADDRESS",
            value="bc1qabc123",
            source_url="http://market.onion/page1",
        )
        entity2 = self._make_entity(
            entity_type="BITCOIN_ADDRESS",
            value="bc1qabc123",
            source_url="http://market.onion/page2",
        )
        g = nx.MultiDiGraph()
        g = add_entity_to_graph(g, entity1)
        first_seen_before = g.nodes["bc1qabc123"]["first_seen"]
        g = add_entity_to_graph(g, entity2)

        data = g.nodes["bc1qabc123"]
        # first_seen must not change; source_urls must contain both
        self.assertEqual(data["first_seen"], first_seen_before)
        self.assertIn("http://market.onion/page1", data["source_urls"])
        self.assertIn("http://market.onion/page2", data["source_urls"])

    def test_add_entity_threat_actor_stores_handle_metadata(self):
        """ThreatActor nodes get metadata["handle"] and metadata["forum"] set."""
        from graph.builder import add_entity_to_graph
        entity = self._make_entity(
            entity_type="THREAT_ACTOR_HANDLE",
            value="hacker99",
            source_url="http://darkforum.onion/u/hacker99",
        )
        g = nx.MultiDiGraph()
        g = add_entity_to_graph(g, entity)
        node_id = "hacker99@darkforum.onion"
        self.assertIn(node_id, g.nodes)
        meta = g.nodes[node_id]["metadata"]
        self.assertEqual(meta.get("handle"), "hacker99")
        self.assertEqual(meta.get("forum"), "darkforum.onion")

    def test_add_entity_disambiguates_same_handle_by_forum(self):
        """Real NormalizedEntity inputs keep same-named forum handles distinct."""
        from graph.builder import add_entity_to_graph
        first = self._make_entity(source_url="https://forum-one.example/thread/1")
        second = self._make_entity(source_url="https://forum-two.example/thread/9")
        graph = nx.MultiDiGraph()
        add_entity_to_graph(graph, first)
        add_entity_to_graph(graph, second)
        self.assertEqual(graph.number_of_nodes(), 2)
        self.assertEqual(set(graph.nodes), {
            "darkking99@forum-one.example", "darkking99@forum-two.example",
        })

    def test_add_entity_canonicalizes_mixed_case_real_entity(self):
        """Real NormalizedEntity inputs use canonical graph identity."""
        from graph.builder import add_entity_to_graph
        first = self._make_entity(entity_type="MALWARE_FAMILY", value="LockBit")
        second = self._make_entity(entity_type="MALWARE_FAMILY", value="lockbit")
        graph = nx.MultiDiGraph()
        add_entity_to_graph(graph, first)
        add_entity_to_graph(graph, second)
        self.assertEqual(list(graph.nodes), ["lockbit"])

    # --- add_relationship ---

    def test_add_relationship_adds_directed_edge(self):
        """add_relationship adds a directed edge with correct attributes."""
        from graph.builder import add_relationship
        g = nx.MultiDiGraph()
        g = add_relationship(
            g,
            source_id="actor1",
            target_id="wallet1",
            edge_type="CO_APPEARED_ON",
            confidence=0.95,
            source_url="http://forum.onion/page",
            metadata={"extra": "info"},
        )
        self.assertTrue(g.has_edge("actor1", "wallet1"))
        edges = list(g.get_edge_data("actor1", "wallet1").values())
        self.assertTrue(any(e.get("edge_type") == "CO_APPEARED_ON" for e in edges))
        edge_data = edges[0]
        self.assertEqual(edge_data["confidence"], 0.95)
        self.assertEqual(edge_data["source_url"], "http://forum.onion/page")
        self.assertEqual(edge_data["metadata"]["extra"], "info")

    # --- build_graph_from_db with CO_APPEARED_ON ---

    @patch.dict(os.environ, {"DATABASE_URL": "sqlite:///test.db"})
    def test_co_appeared_on_edge_from_db(self):
        """
        When two entities appear on the same page, build_graph_from_db creates
        a CO_APPEARED_ON edge between them.
        """
        import uuid
        from graph.builder import build_graph_from_db

        page_id = uuid.uuid4()
        page_url = "http://forum.onion/page/1"

        mock_page = MagicMock()
        mock_page.url = page_url
        mock_page.id = page_id

        def _make_ent(etype, value):
            e = MagicMock()
            e.entity_type = etype
            e.value = value
            e.page_id = page_id
            e.page = mock_page
            e.first_seen = _utc()
            e.last_seen = _utc()
            e.investigation_id = None
            return e

        entity_a = _make_ent("BITCOIN_ADDRESS", "bc1qabc")
        entity_b = _make_ent("EMAIL_ADDRESS", "user@example.com")

        mock_session = MagicMock()
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)

        mock_query = MagicMock()
        mock_query.options.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [entity_a, entity_b]
        mock_session.query.return_value = mock_query

        with patch("db.session.get_session", return_value=mock_session):
            graph = build_graph_from_db()

        self.assertEqual(graph.number_of_nodes(), 2)
        self.assertEqual(graph.number_of_edges(), 1)
        edges = list(graph.edges(data=True))
        self.assertEqual(edges[0][2]["edge_type"], "CO_APPEARED_ON")

    def test_cross_page_linking_adds_edges(self):
        """Entities from different pages should be linked in the graph"""
        import uuid
        from graph.builder import build_graph_from_db
        inv_id = uuid.uuid4()

        def _make_ent(page_id, url, etype, value):
            e = MagicMock()
            e.id = uuid.uuid4()
            e.page_id = page_id
            e.page = MagicMock()
            e.page.url = url
            e.entity_type = etype
            e.value = value
            e.first_seen = _utc()
            e.last_seen = _utc()
            e.investigation_id = inv_id
            return e

        p1_id, p1_url = uuid.uuid4(), "p1"
        p2_id, p2_url = uuid.uuid4(), "p2"

        # Shared entity (bridge)
        e_shared_p1 = _make_ent(p1_id, p1_url, "EMAIL_ADDRESS", "bridge@test.com")
        e_shared_p2 = _make_ent(p2_id, p2_url, "EMAIL_ADDRESS", "bridge@test.com")

        # Unique entities
        e_p1 = _make_ent(p1_id, p1_url, "BITCOIN_ADDRESS", "bc1_p1")
        e_p2 = _make_ent(p2_id, p2_url, "BITCOIN_ADDRESS", "bc1_p2")

        mock_session = MagicMock()
        mock_session.__enter__.return_value = mock_session
        mock_query = MagicMock()
        mock_query.options.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [e_shared_p1, e_shared_p2, e_p1, e_p2]
        mock_session.query.return_value = mock_query

        with patch("db.session.get_session", return_value=mock_session), \
             patch.dict(os.environ, {"DATABASE_URL": "sqlite://"}):
            graph = build_graph_from_db(investigation_id=inv_id)

        # Should have CO_INVESTIGATION edges between e_p1 and e_p2
        # (directed, so likely two edges or one depending on order)
        cross_edges = [d for _, _, d in graph.edges(data=True) if d["edge_type"] == "CO_INVESTIGATION"]
        self.assertGreater(len(cross_edges), 0)
        self.assertEqual(cross_edges[0]["label"], "co-investigation")

    def test_multi_page_node_boost(self):
        """Nodes appearing on multiple pages should have larger size"""
        import uuid
        from graph.builder import build_graph_from_db
        inv_id = uuid.uuid4()

        def _make_ent(page_id, url, value):
            e = MagicMock()
            e.id = uuid.uuid4()
            e.page_id = page_id
            e.page = MagicMock()
            e.page.url = url
            e.entity_type = "EMAIL_ADDRESS"
            e.value = value
            e.first_seen = _utc()
            e.last_seen = _utc()
            e.investigation_id = inv_id
            return e

        # Appears on 3 pages
        e_multi = [
            _make_ent(uuid.uuid4(), f"p{i}", "shared@test.com") for i in range(3)
        ]
        # Appears on 1 page
        e_single = [_make_ent(uuid.uuid4(), "px", "single@test.com")]

        mock_session = MagicMock()
        mock_session.__enter__.return_value = mock_session
        mock_query = MagicMock()
        mock_query.options.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = e_multi + e_single
        mock_session.query.return_value = mock_query

        with patch("db.session.get_session", return_value=mock_session), \
             patch.dict(os.environ, {"DATABASE_URL": "sqlite://"}):
            graph = build_graph_from_db(investigation_id=inv_id)

        self.assertIn("shared@test.com", graph.nodes)
        self.assertIn("single@test.com", graph.nodes)
        
        multi_size = graph.nodes["shared@test.com"].get("size", 10)
        single_size = graph.nodes["single@test.com"].get("size", 10)
        
        self.assertGreater(multi_size, single_size)

    def test_cross_page_edges_weaker_than_intra(self):
        """CO_INVESTIGATION edges should have lower strength/confidence than CO_APPEARED_ON"""
        import uuid
        from graph.builder import build_graph_from_db
        inv_id = uuid.uuid4()

        def _make_ent(page_id, url, etype, value):
            e = MagicMock()
            e.id = uuid.uuid4()
            e.page_id = page_id
            e.page = MagicMock()
            e.page.url = url
            e.entity_type = etype
            e.value = value
            e.first_seen = _utc()
            e.last_seen = _utc()
            e.investigation_id = inv_id
            return e

        p1_id, p1_url = uuid.uuid4(), "p1"
        p2_id, p2_url = uuid.uuid4(), "p2"

        # Shared bridge
        e1 = _make_ent(p1_id, p1_url, "EMAIL_ADDRESS", "b")
        e2 = _make_ent(p2_id, p2_url, "EMAIL_ADDRESS", "b")
        # Intra-page pair
        e3 = _make_ent(p1_id, p1_url, "EMAIL_ADDRESS", "x")
        # Unique on p2
        e4 = _make_ent(p2_id, p2_url, "EMAIL_ADDRESS", "y")

        mock_session = MagicMock()
        mock_session.__enter__.return_value = mock_session
        mock_query = MagicMock()
        mock_query.options.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.all.return_value = [e1, e2, e3, e4]
        mock_session.query.return_value = mock_query

        with patch("db.session.get_session", return_value=mock_session), \
             patch.dict(os.environ, {"DATABASE_URL": "sqlite://"}):
            graph = build_graph_from_db(investigation_id=inv_id)

        intra_edges = [d for _, _, d in graph.edges(data=True) if d["edge_type"] == "CO_APPEARED_ON"]
        cross_edges = [d for _, _, d in graph.edges(data=True) if d["edge_type"] == "CO_INVESTIGATION"]
        
        self.assertGreater(len(intra_edges), 0)
        self.assertGreater(len(cross_edges), 0)

        
        # Intra-page (CO_APPEARED_ON) should be 1.0 confidence
        # Cross-page (CO_INVESTIGATION) should be <= 0.4
        self.assertEqual(intra_edges[0]["confidence"], 1.0)
        self.assertLessEqual(cross_edges[0]["confidence"], 0.4)

    def test_graph_scoped_to_investigation(self):
        """
        Graph for investigation A must not include entities or edges from investigation B.
        Regression test for the global-entity-table leak: previously the entity query used
        Entity.investigation_id OR InvestigationEntityLink, pulling in globally-merged rows.
        """
        import uuid
        from graph.builder import build_graph_from_db

        inv1_id = uuid.uuid4()
        inv2_id = uuid.uuid4()

        def _make_ent(inv_id, idx):
            e = MagicMock()
            e.id = uuid.uuid4()
            e.page_id = uuid.uuid4()
            e.page = MagicMock()
            e.page.url = f"http://inv{str(inv_id)[:8]}.onion/{idx}"
            e.entity_type = "EMAIL_ADDRESS"
            e.value = f"user{idx}@inv{str(inv_id)[:8]}.test"
            e.first_seen = _utc()
            e.last_seen = _utc()
            e.investigation_id = inv_id
            e.confidence = 0.9
            return e

        inv1_entities = [_make_ent(inv1_id, i) for i in range(5)]
        inv2_entities = [_make_ent(inv2_id, i) for i in range(5)]

        mock_query = MagicMock()
        mock_query.join.return_value = mock_query
        mock_query.filter.return_value = mock_query
        mock_query.options.return_value = mock_query
        mock_query.subquery.return_value = mock_query
        mock_query.count.return_value = 5
        # yield_per must return self so the for-loop iterates over mock_query
        mock_query.yield_per.return_value = mock_query
        # Provide a fresh iterator each time __iter__ is called
        mock_query.__iter__ = MagicMock(side_effect=lambda: iter(inv1_entities))
        # Relationship query uses .all(); return empty — no cross-investigation edges
        mock_query.all.return_value = []

        mock_session = MagicMock()
        mock_session.__enter__.return_value = mock_session
        mock_session.__exit__.return_value = False
        mock_session.query.return_value = mock_query

        with patch("db.session.get_session", return_value=mock_session), \
             patch.dict(os.environ, {"DATABASE_URL": "sqlite://"}):
            with patch("db.entity_views.entity_views", side_effect=lambda session, entities, **kwargs: entities):
                graph = build_graph_from_db(investigation_id=inv1_id)

        inv2_node_ids = {e.value for e in inv2_entities}

        self.assertEqual(
            graph.number_of_nodes(), 5,
            f"Expected 5 nodes for investigation 1, got {graph.number_of_nodes()} "
            f"— entities from other investigations may have leaked in",
        )
        for node_id in inv2_node_ids:
            self.assertNotIn(
                node_id, graph.nodes,
                f"Entity '{node_id}' from investigation 2 appeared in investigation 1 graph",
            )

    @patch.dict(os.environ, {"JWT_SECRET": "test_secret_for_benchmark_only_not_for_production"})
    def test_link_cross_page_entities_performance(self):
        """
        Benchmark: 500 pages, 1000 entities (avg 3 pages per entity).
        _link_cross_page_entities should complete in under 2 seconds.
        """
        import time
        import uuid
        from unittest.mock import MagicMock
        from graph.builder import _link_cross_page_entities
        from graph.model import EDGE_TYPES, NODE_TYPES

        num_pages = 500
        num_entities = 1000
        avg_pages_per_entity = 3

        G = nx.MultiDiGraph()
        now = _utc()

        for i in range(num_entities):
            node_id = f"entity_{i}"
            G.add_node(
                node_id,
                node_type=NODE_TYPES.EMAIL_ADDRESS,
                first_seen=now,
                last_seen=now,
                source_urls=[],
                metadata={},
            )

        mock_entities = []
        for entity_idx in range(num_entities):
            page_count = avg_pages_per_entity if entity_idx < num_entities - 100 else 2
            for page_idx in range(page_count):
                page_url = f"http://page{(entity_idx + page_idx) % num_pages}.onion"
                e = MagicMock()
                e.id = uuid.uuid4()
                e.entity_type = "EMAIL_ADDRESS"
                e.value = f"entity_{entity_idx}"
                e.page_id = uuid.uuid4()
                e.page = MagicMock()
                e.page.url = page_url
                e.first_seen = now
                e.last_seen = now
                e.investigation_id = uuid.uuid4()
                mock_entities.append(e)

        start_time = time.perf_counter()
        result = _link_cross_page_entities(G, mock_entities, None)
        elapsed_time = time.perf_counter() - start_time

        self.assertLess(elapsed_time, 2.0,
            f"Cross-page linking took {elapsed_time:.2f}s, expected < 2.0s")


    # --- infer_relationships: PGP key ---

    def test_infer_pgp_key_confirmed_same_actor(self):
        """
        PGP key shared between 2 ThreatActors → CONFIRMED_SAME_ACTOR edge
        with confidence=0.95.
        """
        from graph.builder import infer_relationships
        g = nx.MultiDiGraph()
        now = _utc()

        g.add_node("actor_a", node_type="ThreatActor", first_seen=now, last_seen=now,
                   source_urls=[], metadata={"handle": "alpha"})
        g.add_node("actor_b", node_type="ThreatActor", first_seen=now, last_seen=now,
                   source_urls=[], metadata={"handle": "beta"})
        g.add_node("pgp_key", node_type="PGPKey", first_seen=now, last_seen=now,
                   source_urls=[], metadata={"fingerprint": "ABCD1234"})

        # Both actors appeared on the same page as this PGP key
        g.add_edge("actor_a", "pgp_key", edge_type="CO_APPEARED_ON", confidence=1.0,
                   source_url="", timestamp=now, metadata={})
        g.add_edge("actor_b", "pgp_key", edge_type="CO_APPEARED_ON", confidence=1.0,
                   source_url="", timestamp=now, metadata={})

        result = infer_relationships(g)

        # Should have added CONFIRMED_SAME_ACTOR between actor_a and actor_b
        confirmed_edges = [
            (u, v, d)
            for u, v, d in result.edges(data=True)
            if d.get("edge_type") == "CONFIRMED_SAME_ACTOR"
        ]
        self.assertEqual(len(confirmed_edges), 1)
        actors = {confirmed_edges[0][0], confirmed_edges[0][1]}
        self.assertEqual(actors, {"actor_a", "actor_b"})
        self.assertAlmostEqual(confirmed_edges[0][2]["confidence"], 0.95)

    # --- infer_relationships: handle similarity ---

    def test_infer_handle_similarity_likely_same_actor(self):
        """
        Same handle on different forums → LIKELY_SAME_ACTOR edge with confidence=0.6.
        """
        from graph.builder import infer_relationships
        g = nx.MultiDiGraph()
        now = _utc()

        g.add_node("handle@forum1.onion", node_type="ThreatActor",
                   first_seen=now, last_seen=now, source_urls=[],
                   metadata={"handle": "darkking99", "forum": "forum1.onion"})
        g.add_node("handle@forum2.onion", node_type="ThreatActor",
                   first_seen=now, last_seen=now, source_urls=[],
                   metadata={"handle": "darkking99", "forum": "forum2.onion"})

        result = infer_relationships(g)

        likely_edges = [
            (u, v, d)
            for u, v, d in result.edges(data=True)
            if d.get("edge_type") == "LIKELY_SAME_ACTOR"
        ]
        self.assertEqual(len(likely_edges), 1)
        self.assertAlmostEqual(likely_edges[0][2]["confidence"], 0.6)

    # --- infer_relationships: no false positives ---

    def test_infer_no_false_positives(self):
        """
        Unrelated nodes with different types and handles do not get
        spurious inference edges.
        """
        from graph.builder import infer_relationships
        g = nx.MultiDiGraph()
        now = _utc()

        g.add_node("actor_x", node_type="ThreatActor", first_seen=now, last_seen=now,
                   source_urls=[], metadata={"handle": "alice", "forum": "forum1.onion"})
        g.add_node("actor_y", node_type="ThreatActor", first_seen=now, last_seen=now,
                   source_urls=[], metadata={"handle": "bob", "forum": "forum1.onion"})
        g.add_node("wallet_z", node_type="CryptoWallet", first_seen=now, last_seen=now,
                   source_urls=[], metadata={})

        result = infer_relationships(g)

        # No same-actor edges at all (different handles, no shared PGP key)
        same_actor_edges = [
            d
            for _, _, d in result.edges(data=True)
            if d.get("edge_type") in ("LIKELY_SAME_ACTOR", "CONFIRMED_SAME_ACTOR")
        ]
        self.assertEqual(len(same_actor_edges), 0)


# ===========================================================================
# TestQueries
# ===========================================================================


class TestQueries(unittest.TestCase):

    def setUp(self):
        self.graph = _make_graph_with_nodes()

    # --- get_neighbors ---

    def test_get_neighbors_hop1_and_hop2(self):
        """get_neighbors returns correct nodes at hop 1 and hop 2."""
        from graph.queries import get_neighbors
        result = get_neighbors(self.graph, "actor1", hops=2)

        # Hop 1: wallet1, malware1, forum1
        hop1_ids = {n.node_id for n in result.get("1", [])}
        self.assertIn("wallet1", hop1_ids)
        self.assertIn("malware1", hop1_ids)
        self.assertIn("forum1", hop1_ids)

        # Hop 2: wallet2 (via wallet1 → wallet2 CO_APPEARED_ON edge)
        hop2_ids = {n.node_id for n in result.get("2", [])}
        self.assertIn("wallet2", hop2_ids)

    def test_get_neighbors_edge_type_filter(self):
        """get_neighbors with edge_type filter only traverses matching edges."""
        from graph.queries import get_neighbors
        result = get_neighbors(self.graph, "actor1", hops=2, edge_types=["USES"])

        # Only malware1 should be reachable via USES edge
        hop1_ids = {n.node_id for n in result.get("1", [])}
        self.assertIn("malware1", hop1_ids)
        # wallet1 should NOT be in hop 1 (it's connected via CO_APPEARED_ON)
        self.assertNotIn("wallet1", hop1_ids)
        self.assertNotIn("forum1", hop1_ids)

    # --- find_nodes_by_type ---

    def test_find_nodes_by_type_returns_correct_type(self):
        """find_nodes_by_type returns only nodes of the given type."""
        from graph.queries import find_nodes_by_type
        wallets = find_nodes_by_type(self.graph, "CryptoWallet")
        wallet_ids = {n.node_id for n in wallets}
        self.assertEqual(wallet_ids, {"wallet1", "wallet2"})
        for w in wallets:
            self.assertEqual(w.node_type, "CryptoWallet")

    def test_find_nodes_by_type_no_match(self):
        """find_nodes_by_type returns empty list for a type not in graph."""
        from graph.queries import find_nodes_by_type
        result = find_nodes_by_type(self.graph, "Paste")
        self.assertEqual(result, [])

    # --- find_co_occurring_entities ---

    def test_find_co_occurring_entities_counts_and_order(self):
        """find_co_occurring_entities returns sorted (node, count) pairs."""
        from graph.queries import find_co_occurring_entities
        # wallet1 co-appears with actor1 (1 edge) and wallet2 (1 edge)
        result = find_co_occurring_entities(self.graph, "wallet1")
        self.assertTrue(len(result) >= 1)
        # Must be sorted descending by count
        counts = [c for _, c in result]
        self.assertEqual(counts, sorted(counts, reverse=True))
        node_ids = {n.node_id for n, _ in result}
        self.assertIn("actor1", node_ids)

    def test_find_co_occurring_entities_unknown_node(self):
        """Returns empty list for a node not in the graph."""
        from graph.queries import find_co_occurring_entities
        result = find_co_occurring_entities(self.graph, "nonexistent_node")
        self.assertEqual(result, [])

    # --- get_new_nodes_since ---

    def test_get_new_nodes_since_filters_correctly(self):
        """get_new_nodes_since returns only nodes with first_seen >= cutoff."""
        from graph.queries import get_new_nodes_since
        cutoff = _utc(-4)  # 4 hours before the reference time
        result = get_new_nodes_since(self.graph, cutoff)
        # actor2 has first_seen = _utc(-5); wallet2 = _utc(-2)
        # wallet2 should be in result; actor1 (_utc(-10)) should NOT
        node_ids = {n.node_id for n in result}
        self.assertIn("wallet2", node_ids)
        self.assertNotIn("actor1", node_ids)

    # --- find_high_degree_nodes ---

    def test_find_high_degree_nodes_returns_top_n(self):
        """find_high_degree_nodes returns at most top_n nodes sorted by degree."""
        from graph.queries import find_high_degree_nodes
        result = find_high_degree_nodes(self.graph, top_n=3)
        self.assertLessEqual(len(result), 3)
        degrees = [deg for _, deg in result]
        self.assertEqual(degrees, sorted(degrees, reverse=True))

    def test_find_high_degree_nodes_with_type_filter(self):
        """find_high_degree_nodes with node_type filter only includes matching nodes."""
        from graph.queries import find_high_degree_nodes
        result = find_high_degree_nodes(self.graph, top_n=10, node_type="CryptoWallet")
        for node, _deg in result:
            self.assertEqual(node.node_type, "CryptoWallet")

    # --- get_shortest_path ---

    def test_get_shortest_path_connected(self):
        """get_shortest_path returns a valid path between connected nodes."""
        from graph.queries import get_shortest_path
        path = get_shortest_path(self.graph, "actor1", "wallet2")
        self.assertIsNotNone(path)
        self.assertIsInstance(path, list)
        self.assertEqual(path[0].node_id, "actor1")
        self.assertEqual(path[-1].node_id, "wallet2")
        self.assertGreater(len(path), 1)

    def test_get_shortest_path_disconnected(self):
        """get_shortest_path returns None when no path exists."""
        from graph.queries import get_shortest_path
        # pgp1 has no edges → disconnected from actor1
        path = get_shortest_path(self.graph, "actor1", "pgp1")
        self.assertIsNone(path)

    def test_get_shortest_path_missing_node(self):
        """get_shortest_path returns None when a node doesn't exist."""
        from graph.queries import get_shortest_path
        path = get_shortest_path(self.graph, "actor1", "no_such_node")
        self.assertIsNone(path)

    # --- get_actor_profile ---

    def test_get_actor_profile_complete(self):
        """get_actor_profile returns a complete profile dict for a known actor."""
        from graph.queries import get_actor_profile
        profile = get_actor_profile(self.graph, "actor1")

        self.assertIn("node", profile)
        self.assertIn("connected_wallets", profile)
        self.assertIn("connected_malware", profile)
        self.assertIn("connected_forums", profile)
        self.assertIn("co_actors", profile)
        self.assertIn("total_pages_appeared", profile)
        self.assertIn("first_seen", profile)
        self.assertIn("last_seen", profile)

        self.assertEqual(profile["node"].node_id, "actor1")

        wallet_ids = {n.node_id for n in profile["connected_wallets"]}
        self.assertIn("wallet1", wallet_ids)

        malware_ids = {n.node_id for n in profile["connected_malware"]}
        self.assertIn("malware1", malware_ids)

        forum_ids = {n.node_id for n in profile["connected_forums"]}
        self.assertIn("forum1", forum_ids)

        self.assertIsInstance(profile["total_pages_appeared"], int)

    def test_get_actor_profile_missing_node(self):
        """get_actor_profile returns empty dict for a node not in the graph."""
        from graph.queries import get_actor_profile
        profile = get_actor_profile(self.graph, "no_such_actor")
        self.assertEqual(profile, {})


# ===========================================================================
# TestExport
# ===========================================================================


class TestExport(unittest.TestCase):

    def setUp(self):
        self.graph = _make_graph_with_nodes()

    # --- to_json ---

    def test_to_json_node_and_edge_counts(self):
        """to_json returns correct node and edge counts."""
        from graph.export import to_json
        data = to_json(self.graph)
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertEqual(len(data["nodes"]), self.graph.number_of_nodes())
        self.assertEqual(len(data["edges"]), self.graph.number_of_edges())

    def test_to_json_datetimes_are_iso_strings(self):
        """to_json serialises all datetime values as ISO 8601 strings."""
        import json as _json
        from graph.export import to_json
        data = to_json(self.graph)
        # Must be JSON-serialisable (no datetime objects)
        serialised = _json.dumps(data)  # raises TypeError if any non-serialisable object
        self.assertIsInstance(serialised, str)

        # Verify first_seen values are strings, not datetime objects
        for node in data["nodes"]:
            fs = node.get("first_seen")
            if fs is not None:
                self.assertIsInstance(fs, str, msg="first_seen should be ISO string")

    # --- summary_stats ---

    def test_summary_stats_correct_totals(self):
        """summary_stats returns correct total_nodes and total_edges."""
        from graph.export import summary_stats
        stats = summary_stats(self.graph)
        self.assertEqual(stats["total_nodes"], self.graph.number_of_nodes())
        self.assertEqual(stats["total_edges"], self.graph.number_of_edges())

    def test_summary_stats_type_breakdown(self):
        """summary_stats nodes_by_type and edges_by_type count correctly."""
        from graph.export import summary_stats
        stats = summary_stats(self.graph)
        # 2 ThreatActor nodes in the test graph
        self.assertEqual(stats["nodes_by_type"].get("ThreatActor", 0), 2)
        # There are CO_APPEARED_ON edges
        self.assertGreater(stats["edges_by_type"].get("CO_APPEARED_ON", 0), 0)
        # most_connected is a non-empty list
        self.assertIsInstance(stats["most_connected"], list)
        self.assertGreater(len(stats["most_connected"]), 0)

    # --- to_graphml ---

    def test_to_graphml_writes_nonempty_file(self):
        """to_graphml writes a file that exists and is non-empty."""
        from graph.export import to_graphml
        with tempfile.NamedTemporaryFile(suffix=".graphml", delete=False) as f:
            tmp_path = f.name
        try:
            to_graphml(self.graph, tmp_path)
            self.assertTrue(os.path.exists(tmp_path))
            self.assertGreater(os.path.getsize(tmp_path), 0)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


# ===========================================================================
# TestVisualize
# ===========================================================================


class TestVisualize(unittest.TestCase):

    def setUp(self):
        self.graph = _make_graph_with_nodes()

    # --- build_pyvis_network with pyvis missing ---

    def test_build_pyvis_network_returns_none_without_pyvis(self):
        """build_pyvis_network returns None when pyvis is not installed."""
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "pyvis" or name.startswith("pyvis."):
                raise ImportError("No module named 'pyvis'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            # Need to reload to trigger the mocked import path
            from graph import visualize as viz
            with patch.object(viz, "build_pyvis_network", wraps=viz.build_pyvis_network):
                # Re-trigger the import-time check by calling directly
                pass

        # Direct test: mock pyvis import inside the function
        with patch.dict(sys.modules, {"pyvis": None, "pyvis.network": None}):
            import importlib
            import graph.visualize as viz_mod
            importlib.reload(viz_mod)
            result = viz_mod.build_pyvis_network(self.graph)

        self.assertIsNone(result)

    def test_get_html_string_returns_empty_without_pyvis(self):
        """get_html_string returns empty string when pyvis is not installed."""
        from graph.visualize import get_html_string
        result = get_html_string(None)
        self.assertEqual(result, "")

    # --- build_pyvis_network with mocked pyvis ---

    def test_node_colors_by_type_with_mock_pyvis(self):
        """build_pyvis_network assigns correct node colors based on node type."""
        mock_network_instance = MagicMock()
        mock_network_class = MagicMock(return_value=mock_network_instance)
        mock_network_instance.force_atlas_2based = MagicMock()

        mock_pyvis_module = types.ModuleType("pyvis")
        mock_pyvis_network_module = types.ModuleType("pyvis.network")
        mock_pyvis_network_module.Network = mock_network_class
        mock_pyvis_module.network = mock_pyvis_network_module

        with patch.dict(sys.modules, {
            "pyvis": mock_pyvis_module,
            "pyvis.network": mock_pyvis_network_module,
        }):
            import importlib
            import graph.visualize as viz_mod
            importlib.reload(viz_mod)

            result = viz_mod.build_pyvis_network(self.graph)

        # The Network was instantiated
        mock_network_class.assert_called_once()
        # add_node was called for each node in the graph
        self.assertEqual(
            mock_network_instance.add_node.call_count,
            self.graph.number_of_nodes(),
        )

        # Check that ThreatActor gets red color
        all_calls = mock_network_instance.add_node.call_args_list
        actor_calls = [
            call for call in all_calls
            if call.args and call.args[0] in ("actor1", "actor2")
        ]
        for call in actor_calls:
            kwargs = call.kwargs
            color = kwargs.get("color")
            if isinstance(color, dict):
                self.assertEqual(color.get("background"), "#e74c3c")
            else:
                self.assertEqual(color, "#e74c3c")

    def test_max_nodes_limit_is_respected(self):
        """build_pyvis_network trims to max_nodes highest-degree nodes."""
        mock_network_instance = MagicMock()
        mock_network_class = MagicMock(return_value=mock_network_instance)
        mock_network_instance.force_atlas_2based = MagicMock()

        mock_pyvis_module = types.ModuleType("pyvis")
        mock_pyvis_network_module = types.ModuleType("pyvis.network")
        mock_pyvis_network_module.Network = mock_network_class
        mock_pyvis_module.network = mock_pyvis_network_module

        with patch.dict(sys.modules, {
            "pyvis": mock_pyvis_module,
            "pyvis.network": mock_pyvis_network_module,
        }):
            import importlib
            import graph.visualize as viz_mod
            importlib.reload(viz_mod)
            # Request only 3 nodes from a graph that has 7
            viz_mod.build_pyvis_network(self.graph, max_nodes=3)

        self.assertEqual(mock_network_instance.add_node.call_count, 3)


if __name__ == "__main__":
    unittest.main()
