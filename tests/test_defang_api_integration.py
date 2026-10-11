"""RV-F4a (integration) — the defang legal line at the real API boundary.

Seeds URL / PASTE_URL / BITCOIN_ADDRESS entities and hits the actual
``GET /investigations/{id}/entities`` route with ``defang=true``, asserting:

  * URL and PASTE_URL come back defanged (``hxxp``/``hxxps``, ``[.]``);
  * ``defanged:true`` appears ONLY on rows whose value actually changed;
  * a wallet (non-network) comes back raw with ``defanged:false``.

This drives ``api/routes/investigations.py`` (the :3101 serialization site)
end-to-end. The live-crawl portion — a real ``.onion`` surfacing these URLs —
is operator-driven; this proves the serialization + honesty path a live run
flows through.
"""
import uuid
from datetime import datetime, timezone

from db.models import User, Investigation, Page, Entity
from sqlalchemy.orm import Session


def _client_for(user_id: int):
    from fastapi.testclient import TestClient
    from api.main import app
    from api.auth import (
        CurrentUser,
        get_current_user,
        require_password_not_reset_pending,
    )

    u = User(
        id=user_id,
        email="gate@example.com",
        hashed_password="x",
        is_active=True,
        must_reset_password=False,
    )
    cur = CurrentUser(user=u, jti="gate-jti")
    app.dependency_overrides[get_current_user] = lambda: cur
    app.dependency_overrides[require_password_not_reset_pending] = lambda: cur
    return TestClient(app, raise_server_exceptions=False)


def test_rv_f4a_api_defang_and_flag_honesty(db_engine):
    now = datetime.now(timezone.utc)
    inv_id = uuid.uuid4()
    page_id = uuid.uuid4()
    user_id = 1

    with Session(db_engine) as s:
        s.add(User(
            id=user_id, email="gate@example.com", hashed_password="x",
            is_active=True, must_reset_password=False, created_at=now,
        ))
        s.add(Investigation(
            id=inv_id, run_id=uuid.uuid4(), user_id=user_id,
            query="lockbit leak site url", status="completed",
            cancellation_requested=False, created_at=now, is_seed=False,
            graph_status="none", current_step=13, current_step_label="done",
            entity_count=3, page_count=1,
        ))
        s.add(Page(id=page_id, url="http://seed.onion"))
        rows = [
            ("URL", "http://evil.example.com/login"),
            ("PASTE_URL", "https://pastebin.com/raw/abcd"),
            ("BITCOIN_ADDRESS", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
        ]
        for etype, val in rows:
            s.add(Entity(
                id=uuid.uuid4(), page_id=page_id, investigation_id=inv_id,
                entity_type=etype, value=val, confidence=0.95,
                first_seen=now, last_seen=now, created_at=now,
                source_count=1, investigation_count=1,
            ))
        s.commit()

    client = _client_for(user_id)
    r = client.get(
        f"/investigations/{inv_id}/entities",
        params={
            "defang": "true", "min_confidence": 0,
            "include_suppressed": "true", "limit": 100,
        },
    )
    assert r.status_code == 200, r.text
    items = {i["entity_type"]: i for i in r.json()["items"]}
    assert set(items) == {"URL", "PASTE_URL", "BITCOIN_ADDRESS"}

    url = items["URL"]
    assert url["value"] == "hxxp://evil[.]example[.]com/login"
    assert url["defanged"] is True

    paste = items["PASTE_URL"]
    assert paste["value"] == "hxxps://pastebin[.]com/raw/abcd"
    assert paste["defanged"] is True

    # Non-network value is untouched and must NOT be labeled defanged (flag honesty).
    btc = items["BITCOIN_ADDRESS"]
    assert btc["value"] == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert btc["defanged"] is False

    # The legal invariant across every returned row.
    for it in r.json()["items"]:
        if it["defanged"]:
            assert "http://" not in it["value"] and "https://" not in it["value"]
