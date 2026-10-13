from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import networkx as nx

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _make_result():
    return SimpleNamespace(
        page_url="https://example.com",
        entity_count=1,
        entities=[SimpleNamespace(entity_type="THREAT_ACTOR_HANDLE", value="alpha", confidence=0.9, source_url="https://example.com")],
        entities_by_type={"THREAT_ACTOR_HANDLE": 1},
        entity_ids=[],
        errors=[],
    )


class TestGraphIntegration(unittest.TestCase):
    def test_pipeline_build_graph_trigger(self):
        from extractor import pipeline as p

        fake_graph = nx.MultiDiGraph()
        fake_graph.add_node("alpha", node_type="ThreatActor", first_seen=None, last_seen=None, source_urls=["https://example.com"], metadata={}, confidence=0.9)
        fake_graph.add_node("beta", node_type="Forum", first_seen=None, last_seen=None, source_urls=["https://example.com"], metadata={}, confidence=0.9)
        fake_graph.add_edge("alpha", "beta", edge_type="CO_APPEARED_ON", confidence=1.0, source_url="https://example.com", timestamp=None, metadata={})

        with patch.object(p, "_merge_db", return_value=["entity-1"]), \
            patch.object(p, "extract_entities_from_page", return_value=_make_result()), \
            patch("graph.builder.build_graph_from_db", return_value=fake_graph), \
            patch("graph.builder.infer_relationships", side_effect=lambda g: g) as infer_mock, \
            patch("graph.builder.persist_graph_edges", return_value={"status": "written", "edges_written": 1}) as persist_mock, \
            patch("db.session.get_session") as session_mock:
            session = MagicMock()
            session.get.return_value = SimpleNamespace(graph_status="pending")
            session_mock.return_value.__enter__.return_value = session
            session_mock.return_value.__exit__.return_value = False
            results = self._run_async(
                p.extract_entities_from_pages(
                    [{"url": "https://example.com", "text": "alpha"}],
                    investigation_id="00000000-0000-0000-0000-000000000001",
                    build_graph_on_complete=True,
                )
            )

        self.assertEqual(len(results), 1)
        infer_mock.assert_called_once()
        persist_mock.assert_called_once()

    def test_pipeline_can_skip_graph(self):
        from extractor import pipeline as p

        with patch.object(p, "_merge_db", return_value=["entity-1"]), \
            patch.object(p, "extract_entities_from_page", return_value=_make_result()), \
            patch("graph.builder.build_graph_from_db") as build_mock:
            results = self._run_async(
                p.extract_entities_from_pages(
                    [{"url": "https://example.com", "text": "alpha"}],
                    investigation_id="00000000-0000-0000-0000-000000000001",
                    build_graph_on_complete=False,
                )
            )

        self.assertEqual(len(results), 1)
        build_mock.assert_not_called()

    def test_api_graph_endpoints(self):
        from api.main import app
        from api.ownership import require_resource_owner
        session_patch = patch("db.session.get_session")
        session_patch.start()
        self.addCleanup(session_patch.stop)
        app.dependency_overrides[require_resource_owner] = lambda: None
        from api.auth import get_current_user

        mock_user = MagicMock()
        mock_user.user.id = 1

        app.dependency_overrides[get_current_user] = lambda: mock_user

        from fastapi.testclient import TestClient
        client = TestClient(app, raise_server_exceptions=False)
        fake_graph = nx.MultiDiGraph()
        fake_graph.add_node("alpha", node_type="ThreatActor", first_seen=None, last_seen=None, source_urls=["https://example.com"], metadata={}, confidence=0.9)
        fake_graph.add_node("beta", node_type="Forum", first_seen=None, last_seen=None, source_urls=["https://example.com"], metadata={}, confidence=0.9)
        fake_graph.add_edge("alpha", "beta", edge_type="CO_APPEARED_ON", confidence=1.0, source_url="https://example.com", timestamp=None, metadata={})

        inv = SimpleNamespace(id="00000000-0000-0000-0000-000000000001", user_id=1, graph_status="complete")

        with patch("db.queries.get_investigation_by_id_or_run", return_value=inv), \
            patch("graph.build_graph_from_db_cached", return_value=fake_graph), \
            patch("graph.build_graph_from_db", return_value=fake_graph), \
            patch("graph.summary_stats", return_value={"total_nodes": 2, "total_edges": 1, "nodes_by_type": {"ThreatActor": 1}, "edges_by_type": {"CO_APPEARED_ON": 1}, "most_connected": [{"node_id": "alpha", "degree": 1}] }), \
            patch("graph.build_pyvis_network", return_value=None), \
            patch("graph.get_html_string", return_value=None), \
            patch("graph.get_actor_profile", return_value={"node": {"node_id": "alpha"}}):
            resp = client.get("/investigations/00000000-0000-0000-0000-000000000001/graph?include_viz=true")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["status"], "complete")

            stats = client.get("/investigations/00000000-0000-0000-0000-000000000001/graph/stats")
            self.assertEqual(stats.status_code, 200)
            self.assertEqual(stats.json()["status"], "complete")

            actor = client.get("/investigations/00000000-0000-0000-0000-000000000001/graph/actor/alpha")
            self.assertEqual(actor.status_code, 200)

            path = client.get("/investigations/00000000-0000-0000-0000-000000000001/graph/path?source=alpha&target=beta")
            self.assertEqual(path.status_code, 200)
            self.assertIsNotNone(path.json()["path"])

    def test_pending_and_missing_node(self):
        from api.main import app
        from api.ownership import require_resource_owner
        session_patch = patch("db.session.get_session")
        session_patch.start()
        self.addCleanup(session_patch.stop)
        app.dependency_overrides[require_resource_owner] = lambda: None
        from api.auth import get_current_user

        mock_user = MagicMock()
        mock_user.user.id = 1
        app.dependency_overrides[get_current_user] = lambda: mock_user
        from fastapi.testclient import TestClient
        client = TestClient(app, raise_server_exceptions=False)

        pending_inv = SimpleNamespace(id="00000000-0000-0000-0000-000000000001", user_id=1, graph_status="pending")
        with patch("db.queries.get_investigation_by_id_or_run", return_value=pending_inv):
            resp = client.get("/investigations/00000000-0000-0000-0000-000000000001/graph")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["status"], "pending")

        complete_inv = SimpleNamespace(id="00000000-0000-0000-0000-000000000001", user_id=1, graph_status="complete")
        with patch("db.queries.get_investigation_by_id_or_run", return_value=complete_inv), \
            patch("graph.build_graph_from_db_cached", return_value=nx.MultiDiGraph()), \
            patch("graph.get_html_string", return_value=None), \
            patch("graph.build_pyvis_network", return_value=None):
            resp = client.get("/investigations/00000000-0000-0000-0000-000000000001/graph/actor/missing")
            self.assertEqual(resp.status_code, 404)

    def _run_async(self, coro):
        import asyncio
        return asyncio.run(coro)
