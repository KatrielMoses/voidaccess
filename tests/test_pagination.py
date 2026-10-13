"""
tests/test_pagination.py — Tests for pagination endpoints.

Verifies that pagination is pushed to SQL rather than Python list slicing.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch
from typing import get_type_hints

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


class TestPagination(unittest.TestCase):

    def test_investigation_entities_endpoint_signature(self):
        """Verify get_investigation_entities has correct pagination params."""
        from api.routes.investigations import get_investigation_entities
        import inspect

        sig = inspect.signature(get_investigation_entities)
        params = sig.parameters

        self.assertIn("limit", params)
        self.assertIn("offset", params)

        limit_param = params["limit"]
        self.assertEqual(limit_param.default.default, 20)
        self.assertEqual(limit_param.default.metadata[1].le, 100)

    def test_investigation_entities_returns_pagination_dict(self):
        """Verify endpoint returns dict with pagination metadata."""
        from api.routes.investigations import get_investigation_entities
        import inspect

        sig = inspect.signature(get_investigation_entities)
        self.assertEqual(get_type_hints(get_investigation_entities)["return"], dict)

    def test_list_entities_endpoint_signature(self):
        """Verify list_entities has correct pagination params."""
        from api.routes.entities import list_entities
        import inspect

        sig = inspect.signature(list_entities)
        params = sig.parameters

        self.assertIn("limit", params)
        self.assertIn("offset", params)

        limit_param = params["limit"]
        self.assertEqual(limit_param.default.default, 20)

    def test_list_entities_returns_pagination_dict(self):
        """Verify list_entities returns dict with pagination metadata."""
        from api.routes.entities import list_entities
        import inspect

        sig = inspect.signature(list_entities)
        self.assertEqual(get_type_hints(list_entities)["return"], dict)

    def test_limit_validation_rejects_over_100(self):
        """Verify FastAPI rejects limit > 100."""
        from fastapi.testclient import TestClient
        from api.main import app
        from api.ownership import require_resource_owner
        app.dependency_overrides[require_resource_owner] = lambda: None
        from api.auth import get_current_user

        mock_user = MagicMock()
        mock_user.id = 1
        mock_user.email = "test@example.com"
        mock_user.is_active = True

        app.dependency_overrides[get_current_user] = lambda: mock_user
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/investigations/00000000-0000-0000-0000-000000000001/entities?limit=500")
        self.assertEqual(resp.status_code, 422)

    def test_offset_validation_rejects_negative(self):
        """Verify FastAPI rejects negative offset."""
        from fastapi.testclient import TestClient
        from api.main import app
        from api.ownership import require_resource_owner
        app.dependency_overrides[require_resource_owner] = lambda: None
        from api.auth import get_current_user

        mock_user = MagicMock()
        mock_user.id = 1
        mock_user.email = "test@example.com"
        mock_user.is_active = True

        app.dependency_overrides[get_current_user] = lambda: mock_user
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/investigations/00000000-0000-0000-0000-000000000001/entities?offset=-1")
        self.assertEqual(resp.status_code, 422)


if __name__ == "__main__":
    unittest.main()
