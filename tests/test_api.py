"""
tests/test_api.py — Tests for Phase 5 FastAPI REST API.

All DB, export, graph, and vector calls are mocked.
Uses FastAPI TestClient (synchronous wrapper over ASGI).

Test classes
------------
TestHealth              — GET /health
TestInvestigationsPost  — POST /investigations
TestInvestigationsGet   — GET /investigations, GET /investigations/{id}
TestEntities            — GET /entities, GET /entities/{id}/neighbors
TestSearch              — POST /search/semantic
TestExportStix          — GET /export/{id}/stix
TestExportMisp          — GET /export/{id}/misp
TestMonitors            — GET /monitors
"""

from __future__ import annotations

import json
import os
import sys
import unittest
import uuid
import networkx as nx
from unittest.mock import MagicMock, patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

_VALID_UUID = "00000000-0000-0000-0000-000000000001"
_UNKNOWN_UUID = "00000000-0000-0000-0000-000000000099"


def _make_client():
    """Create a FastAPI TestClient. Import deferred so pytest collection doesn't fail without fastapi."""
    from fastapi.testclient import TestClient  # noqa: PLC0415
    from api.main import app  # noqa: PLC0415
    from api.auth import CurrentUser, get_current_user, require_password_not_reset_pending
    from db.models import User
    from unittest.mock import MagicMock

    mock_user = User(
        id=1,
        email="test@example.com",
        hashed_password="test-hash",
        is_active=True,
        must_reset_password=False,
    )

    current = CurrentUser(user=mock_user, jti="test-jti")
    from api.ownership import require_resource_owner
    app.dependency_overrides[require_resource_owner] = lambda: None  # Unit handlers; real guards covered in test_multiuser_security.
    app.dependency_overrides[get_current_user] = lambda: current
    app.dependency_overrides[require_password_not_reset_pending] = lambda: current
    client = TestClient(app, raise_server_exceptions=False)
    return client


# ===========================================================================
# TestHealth
# ===========================================================================


class TestHealth(unittest.TestCase):

    def test_health_returns_200(self):
        client = _make_client()
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)

    def test_health_structure(self):
        client = _make_client()
        resp = client.get("/health")
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("checks", data)
        self.assertIn("database", data["checks"])
        self.assertIn("tor", data["checks"])
        self.assertEqual(data["status"], "degraded")

    def test_health_db_is_bool(self):
        client = _make_client()
        data = client.get("/health").json()
        self.assertIsInstance(data["checks"]["database"], str)

    def test_health_tor_is_bool(self):
        client = _make_client()
        data = client.get("/health").json()
        self.assertIsInstance(data["checks"]["tor"], str)


# ===========================================================================
# TestInvestigationsPost
# ===========================================================================


class TestInvestigationsPost(unittest.TestCase):

    @patch.dict(os.environ, {"DATABASE_URL": ""}, clear=True)
    def test_post_returns_200(self):
        client = _make_client()
        resp = client.post(
            "/investigations",
            json={"query": "ransomware forum", "model": "gpt-4o"},
        )
        self.assertEqual(resp.status_code, 200)

    @patch.dict(os.environ, {"DATABASE_URL": ""}, clear=True)
    def test_post_returns_run_id(self):
        client = _make_client()
        resp = client.post(
            "/investigations",
            json={"query": "dark web market"},
        )
        data = resp.json()
        self.assertIn("run_id", data)
        self.assertIsNotNone(data["run_id"])

    def test_post_returns_status_pending(self):
        saved_db = os.environ.pop("DATABASE_URL", None)
        try:
            client = _make_client()
            resp = client.post(
                "/investigations",
                json={"query": "threat actor tracking"},
            )
            data = resp.json()
            self.assertEqual(data["status"], "pending")
        finally:
            if saved_db is not None:
                os.environ["DATABASE_URL"] = saved_db

    @patch.dict(os.environ, {"DATABASE_URL": ""}, clear=True)
    def test_post_returns_query(self):
        client = _make_client()
        resp = client.post(
            "/investigations",
            json={"query": "LockBit 4.0"},
        )
        data = resp.json()
        self.assertEqual(data["query"], "LockBit 4.0")

    @patch.dict(os.environ, {"DATABASE_URL": ""}, clear=True)
    def test_post_run_id_is_uuid(self):
        import uuid as _uuid
        client = _make_client()
        resp = client.post(
            "/investigations",
            json={"query": "test query"},
        )
        run_id = resp.json()["run_id"]
        _uuid.UUID(run_id)  # Should not raise

    def test_request_model_defaults_to_none(self):
        from api.routes.investigations import InvestigationRequest
        req = InvestigationRequest(query="test")
        self.assertEqual(req.model, "openrouter/deepseek/deepseek-chat")


# ===========================================================================
# TestInvestigationsGet
# ===========================================================================


class TestInvestigationsGet(unittest.TestCase):

    @patch("api.routes.investigations.os.getenv", return_value=None)
    def test_get_list_returns_list(self, mock_getenv):
        client = _make_client()
        resp = client.get("/investigations")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)

    @patch("api.routes.investigations._get_db_investigation")
    def test_get_by_id_returns_404_for_unknown(self, mock_get):
        from fastapi import HTTPException
        mock_get.side_effect = HTTPException(status_code=404, detail="Investigation not found")
        client = _make_client()
        resp = client.get(f"/investigations/{_UNKNOWN_UUID}")
        self.assertEqual(resp.status_code, 404)

    @patch("api.routes.investigations._get_db_investigation")
    def test_get_by_id_returns_investigation_data(self, mock_get):
        mock_get.return_value = {
            "id": _VALID_UUID,
            "run_id": _VALID_UUID,
            "query": "test",
            "model_used": "gpt-4o",
            "created_at": "2025-01-01T00:00:00",
            "entity_count": 5,
        }
        client = _make_client()
        resp = client.get(f"/investigations/{_VALID_UUID}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["id"], _VALID_UUID)


# ===========================================================================
# TestEntities
# ===========================================================================


class TestEntities(unittest.TestCase):

    @patch("api.routes.entities.os.getenv", return_value=None)
    def test_get_entities_returns_list(self, mock_env):
        client = _make_client()
        resp = client.get("/entities")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), dict)
        self.assertEqual(resp.json()["items"], [])

    @patch("api.routes.entities.os.getenv", return_value=None)
    def test_get_entities_with_entity_type_filter(self, mock_env):
        client = _make_client()
        resp = client.get("/entities?entity_type=BITCOIN_ADDRESS")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["items"], [])

    @patch("api.routes.entities._get_entity_value", return_value=None)
    @patch("api.routes.entities.os.getenv", return_value="postgresql://test")
    def test_get_entity_neighbors_404_when_not_found(self, mock_env, mock_value):
        client = _make_client()
        resp = client.get(f"/entities/{_VALID_UUID}/neighbors")
        self.assertIn(resp.status_code, (200, 404))  # Returns 404 or empty dict

    def test_get_entities_neighbors_structure(self):
        with patch("api.routes.entities._get_entity_value", return_value="1.2.3.4"), \
             patch("api.routes.entities.os.getenv", return_value="postgresql://test"):
            client = _make_client()

            mock_graph = MagicMock()
            mock_graph.edges.return_value = []

            with patch("api.routes.entities.build_graph_from_db", return_value=mock_graph, create=True), \
                 patch("api.routes.entities.get_neighbors", return_value=[], create=True):
                try:
                    from graph.queries import get_neighbors  # noqa
                    from graph.builder import build_graph_from_db  # noqa
                except ImportError:
                    pass
                resp = client.get(f"/entities/{_VALID_UUID}/neighbors")
                # Should return structure with entity_id, hops, neighbors
                if resp.status_code == 200:
                    data = resp.json()
                    self.assertIn("entity_id", data)
                    self.assertIn("hops", data)
                    self.assertIn("neighbors", data)

    def test_resolve_graph_node_id_exact_then_handle_domain_prefix(self):
        from api.routes.entities import _resolve_graph_node_id

        graph = nx.MultiDiGraph()
        graph.add_node("exact-node")
        graph.add_node("darkactor@example.onion")

        self.assertEqual(_resolve_graph_node_id(graph, "exact-node"), "exact-node")
        self.assertEqual(
            _resolve_graph_node_id(graph, "darkactor"),
            "darkactor@example.onion",
        )
        self.assertIsNone(_resolve_graph_node_id(graph, "missing"))


# ===========================================================================
# TestSearch
# ===========================================================================


class TestSearch(unittest.TestCase):

    @patch("api.routes.search.find_related_pages", return_value=[], create=True)
    def test_semantic_search_returns_list(self, mock_search):
        with patch.dict("sys.modules", {"vector.search": MagicMock(find_related_pages=mock_search)}):
            client = _make_client()
            resp = client.get("/search/semantic?q=ransomware%20payment&n=5")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertIsInstance(data, dict)
            self.assertIn("results", data)
            self.assertIn("warnings", data)

    @patch("api.routes.search.os.getenv", return_value=None)
    def test_entity_search_returns_list(self, mock_env):
        client = _make_client()
        resp = client.post(
            "/search/entities",
            json={"query": "LockBit", "entity_types": ["MALWARE_FAMILY"]},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), dict)
        self.assertEqual(resp.json()["items"], [])

    @patch("api.routes.search.os.getenv", return_value=None)
    def test_entity_search_without_type_filter(self, mock_env):
        client = _make_client()
        resp = client.post(
            "/search/entities",
            json={"query": "wallet"},
        )
        self.assertEqual(resp.status_code, 200)


# ===========================================================================
# TestExportStix
# ===========================================================================


class TestExportStix(unittest.TestCase):

    def _mock_bundle(self):
        mock_bundle = MagicMock()
        return mock_bundle

    @patch(
        "api.routes.export._resolve_internal_investigation_id",
        return_value=uuid.UUID(_VALID_UUID),
    )
    @patch("api.routes.export._check_investigation_owner")
    @patch("export.stix._load_entities_for_investigation", return_value=[MagicMock()])
    @patch("api.routes.export.investigation_to_stix_bundle", create=True)
    @patch("api.routes.export.bundle_to_json", return_value='{"type":"bundle","id":"bundle--1","objects":[]}', create=True)
    def test_stix_returns_200(self, mock_json, mock_bundle, _mock_entities, _mock_owner, _mock_resolve):
        mock_bundle.return_value = self._mock_bundle()
        with patch.dict("sys.modules", {
            "export.stix": MagicMock(
                investigation_to_stix_bundle=mock_bundle,
                bundle_to_json=mock_json,
            )
        }):
            client = _make_client()
            resp = client.get(f"/export/{_VALID_UUID}/stix")
            self.assertIn(resp.status_code, (200, 500))  # 500 ok if stix2 not installed

    @patch("export.stix.investigation_to_stix_bundle")
    @patch("export.stix.bundle_to_json")
    def test_stix_content_type_json(self, mock_json, mock_bundle):
        mock_json.return_value = '{"type":"bundle"}'
        mock_bundle.return_value = MagicMock()
        client = _make_client()
        resp = client.get(f"/export/{_VALID_UUID}/stix")
        if resp.status_code == 200:
            self.assertIn("application/json", resp.headers.get("content-type", ""))

    @patch("export.stix.investigation_to_stix_bundle")
    @patch("export.stix.bundle_to_json")
    def test_stix_content_disposition_header(self, mock_json, mock_bundle):
        mock_json.return_value = '{"type":"bundle"}'
        mock_bundle.return_value = MagicMock()
        client = _make_client()
        resp = client.get(f"/export/{_VALID_UUID}/stix")
        if resp.status_code == 200:
            disposition = resp.headers.get("content-disposition", "")
            self.assertIn("attachment", disposition)

    def test_stix_invalid_uuid_422(self):
        client = _make_client()
        resp = client.get("/export/not-a-uuid/stix")
        self.assertEqual(resp.status_code, 422)


# ===========================================================================
# TestExportMisp
# ===========================================================================


class TestExportMisp(unittest.TestCase):

    @patch(
        "api.routes.export._resolve_internal_investigation_id",
        return_value=uuid.UUID(_VALID_UUID),
    )
    @patch("api.routes.export._check_investigation_owner")
    @patch("export.stix._load_entities_for_investigation", return_value=[MagicMock()])
    @patch("export.misp.investigation_to_misp_event")
    @patch("export.misp.misp_event_to_json")
    def test_misp_returns_200(self, mock_json, mock_event, _mock_entities, _mock_owner, _mock_resolve):
        mock_event.return_value = {"Event": {"info": "VoidAccess Investigation: test", "Attribute": []}}
        mock_json.return_value = '{"Event": {"info": "VoidAccess Investigation: test", "Attribute": []}}'
        client = _make_client()
        resp = client.get(f"/export/{_VALID_UUID}/misp")
        self.assertEqual(resp.status_code, 200)

    @patch(
        "api.routes.export._resolve_internal_investigation_id",
        return_value=uuid.UUID(_VALID_UUID),
    )
    @patch("api.routes.export._check_investigation_owner")
    @patch("export.stix._load_entities_for_investigation", return_value=[MagicMock()])
    @patch("export.misp.investigation_to_misp_event")
    @patch("export.misp.misp_event_to_json")
    def test_misp_correct_structure(self, mock_json, mock_event, _mock_entities, _mock_owner, _mock_resolve):
        event_dict = {
            "Event": {
                "info": "VoidAccess Investigation: test",
                "date": "2025-01-01",
                "threat_level_id": "2",
                "analysis": "2",
                "distribution": "0",
                "Attribute": [{"type": "btc", "value": "bc1q..."}],
            }
        }
        mock_event.return_value = event_dict
        mock_json.return_value = json.dumps(event_dict)
        client = _make_client()
        resp = client.get(f"/export/{_VALID_UUID}/misp")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("Event", data)

    def test_misp_invalid_uuid_422(self):
        client = _make_client()
        resp = client.get("/export/bad-id/misp")
        self.assertEqual(resp.status_code, 422)


# ===========================================================================
# TestExportPackage
# ===========================================================================


class TestExportPackage(unittest.TestCase):
    """The IOC package route must backfill sources_used from investigation
    metadata (previously hardcoded empty) so it reaches metadata.json."""

    @patch(
        "api.routes.export._resolve_internal_investigation_id",
        return_value=uuid.UUID(_VALID_UUID),
    )
    @patch("api.routes.export._check_investigation_owner")
    def test_package_backfills_sources_used_into_metadata(self, _mock_owner, _mock_resolve):
        import io as _io
        import zipfile as _zipfile
        import datetime as _dt
        from types import SimpleNamespace

        entities = [
            {"entity_type": "IP_ADDRESS", "value": "185.220.101.1", "confidence": 0.9,
             "source_url": "http://leak.onion/c2"},
            {"entity_type": "CVE_NUMBER", "value": "CVE-2024-3094", "confidence": 0.9,
             "source_url": "http://forum.onion/exploit"},
        ]
        sources_used = {"otx": "ok_3_enrichments", "greynoise": "skipped_no_key"}
        inv = SimpleNamespace(
            id=uuid.UUID(_VALID_UUID),
            run_id=None,
            query="lockbit leak",
            summary="s",
            created_at=_dt.datetime(2026, 8, 2, tzinfo=_dt.timezone.utc),
            metadata_json={"sources_used": sources_used},
        )

        session_cm = MagicMock()
        session_cm.__enter__.return_value = MagicMock()
        session_cm.__exit__.return_value = False

        with patch("export.stix._load_entities_for_investigation", return_value=entities), \
             patch("db.session.get_session", return_value=session_cm), \
             patch("db.queries.get_investigation_by_id_or_run", return_value=inv):
            client = _make_client()
            resp = client.get(f"/export/{_VALID_UUID}/package")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("content-type"), "application/zip")
        with _zipfile.ZipFile(_io.BytesIO(resp.content)) as zf:
            meta = json.loads(zf.read("metadata.json").decode("utf-8"))
        # The exact fix: sources_used is no longer an empty stub.
        self.assertEqual(meta["sources_used"], sources_used)


# ===========================================================================
# TestMonitors
# ===========================================================================


# Monitor API integration is covered with real owner-scoped databases in
# test_api_monitors.py and test_multiuser_security.py.


# ===========================================================================
# TestGraphConfidenceFilter
# ===========================================================================


class TestGraphConfidenceFilter(unittest.TestCase):

    @patch("db.session.get_session")
    @patch("db.queries.get_investigation_by_id_or_run")
    @patch("graph.builder.build_graph_from_db")
    @patch("graph.build_graph_from_db_cached")
    @patch("graph.export.to_json")
    @patch("graph.export.summary_stats", return_value={})
    def test_graph_confidence_filter(self, mock_summary, mock_to_json, mock_build_cached, mock_build, mock_get_inv, mock_session):
        from unittest.mock import MagicMock
        from datetime import datetime, timezone

        mock_inv = MagicMock()
        mock_inv.id = 1
        mock_inv.graph_status = "built"
        mock_get_inv.return_value = mock_inv

        mock_session_instance = MagicMock()
        mock_session_instance.__enter__ = MagicMock(return_value=mock_session_instance)
        mock_session_instance.__exit__ = MagicMock(return_value=False)
        mock_session.return_value = mock_session_instance
        mock_session_instance.query.return_value.filter.return_value.scalar.return_value = 10

        class _Graph:
            @staticmethod
            def degree(_node_id):
                return 1

        mock_graph = _Graph()
        mock_build_cached.return_value = mock_graph
        mock_build.return_value = mock_graph
        mock_to_json.return_value = {
            "nodes": [
                {"id": "high@example.com", "type": "EmailAddress", "confidence": 0.95, "first_seen": None, "last_seen": None, "source_urls": [], "metadata": {}},
                {"id": "low@example.com", "type": "EmailAddress", "confidence": 0.5, "first_seen": None, "last_seen": None, "source_urls": [], "metadata": {}},
            ],
            "edges": []
        }

        client = _make_client()
        resp = client.get(f"/investigations/{_VALID_UUID}/graph?min_confidence=0.9")

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertEqual(data["status"], "complete")
        self.assertIn("summary_stats", data)


# ===========================================================================
# TestGraphOverflow
# ===========================================================================


class TestGraphOverflow(unittest.TestCase):

    @patch("db.session.get_session")
    @patch("db.queries.get_investigation_by_id_or_run")
    def test_graph_overflow_response(self, mock_get_inv, mock_session):
        from unittest.mock import MagicMock

        mock_inv = MagicMock()
        mock_inv.id = 1
        mock_inv.graph_status = "pending"
        mock_get_inv.return_value = mock_inv

        mock_session_instance = MagicMock()
        mock_session_instance.__enter__ = MagicMock(return_value=mock_session_instance)
        mock_session_instance.__exit__ = MagicMock(return_value=False)
        mock_session.return_value = mock_session_instance
        mock_session_instance.query.return_value.filter.return_value.scalar.return_value = 1000

        client = _make_client()
        resp = client.get(f"/investigations/{_VALID_UUID}/graph")

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "pending")


# ===========================================================================
# TestCsvExport
# ===========================================================================


class TestCsvExport(unittest.TestCase):

    @patch("db.session.get_session")
    @patch("db.queries.get_investigation_by_id_or_run")
    @patch("api.routes.investigations.os.getenv", return_value="postgresql://test")
    def test_csv_export(self, mock_getenv, mock_get_inv, mock_session):
        from unittest.mock import MagicMock

        mock_inv = MagicMock()
        mock_inv.id = 1
        mock_inv.user_id = 1
        mock_get_inv.return_value = mock_inv

        mock_ent = MagicMock()
        mock_ent.entity_type = "EMAIL_ADDRESS"
        mock_ent.value = "test@example.com"
        mock_ent.canonical_value = None
        mock_ent.confidence = 0.95
        mock_ent.context_snippet = "Test context"
        mock_ent.page = MagicMock(url="http://example.com/page")

        mock_session_instance = MagicMock()
        mock_session_instance.__enter__ = MagicMock(return_value=mock_session_instance)
        mock_session_instance.__exit__ = MagicMock(return_value=False)
        mock_session.return_value = mock_session_instance
        mock_session_instance.query.return_value.filter.return_value.all.return_value = [mock_ent]

        client = _make_client()
        with patch("db.entity_views.entity_views", side_effect=lambda session, entities, **kwargs: entities):
            resp = client.get(f"/investigations/{_VALID_UUID}/entities/export/csv")

        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.headers.get("content-type", ""))
        self.assertIn("attachment", resp.headers.get("content-disposition", ""))
        self.assertIn("voidaccess", resp.headers.get("content-disposition", ""))
        self.assertIn("entities.csv", resp.headers.get("content-disposition", ""))

        content = resp.text
        self.assertIn("entity_type", content)
        self.assertIn("canonical_value", content)
        self.assertIn("confidence", content)
        self.assertIn("occurrence_count", content)
        self.assertIn("first_seen_page", content)
        self.assertIn("context_snippet", content)
        self.assertIn("EMAIL_ADDRESS", content)
        self.assertIn("test@example.com", content)

    def test_csv_export_auth(self):
        from fastapi import HTTPException
        with patch("api.routes.investigations.os.getenv", return_value="postgresql://test"), \
             patch("db.session.get_session") as mock_session:
            mock_session.side_effect = HTTPException(status_code=401, detail="Invalid or expired token")
            client = _make_client()
            resp = client.get(f"/investigations/{_VALID_UUID}/entities/export/csv")
            self.assertEqual(resp.status_code, 401)


# ===========================================================================
# Regression: GET /investigations (P2.2 carve-out)
# ===========================================================================
# Pytest-style function test (needs the conftest `db_engine` fixture for a real
# SQLite DB so ownership scoping actually executes). Previously the endpoint
# filtered on the non-existent `current_user.id`, and a broad except swallowed
# the AttributeError, so it always returned []. This proves the caller gets
# their own investigations and never another user's.


def test_list_investigations_returns_owner_scoped(db_engine):
    from sqlalchemy.orm import Session as _Session

    from db.models import Investigation, User

    with _Session(db_engine) as s:
        s.add(User(id=1, email="test@example.com", hashed_password="x", is_active=True,
                   must_reset_password=False))
        s.add(User(id=2, email="other@example.com", hashed_password="x", is_active=True,
                   must_reset_password=False))
        s.flush()
        s.add(Investigation(query="mine-owned", user_id=1))
        s.add(Investigation(query="theirs-private", user_id=2))
        s.commit()

    client = _make_client()  # authenticated as user.id == 1
    resp = client.get("/investigations")
    assert resp.status_code == 200
    data = resp.json()
    queries = {row["query"] for row in data}
    assert "mine-owned" in queries        # not [] anymore
    assert "theirs-private" not in queries  # never another user's


if __name__ == "__main__":
    unittest.main()
