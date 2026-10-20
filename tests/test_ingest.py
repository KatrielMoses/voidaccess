"""
tests/test_ingest.py — P4.3 cross-install ingest + Sybil-resistance acceptance.

Drives the real HTTP boundary (a FastAPI app mounting ``ingest.router`` with an
overridden DB session) plus the fail-closed stores directly. Proves:

* self-registration with no manual approval; unauthenticated ingest rejected;
* ingested artifacts land unconfirmed by default via the ONE write path;
* the **Sybil red-team**: many self-registered keys / many fabricated origins
  flooding false IOCs move nothing to scoring (fresh keys are low-rep; origin,
  not key, is the independence unit);
* submitted (forged) feed_hits are discarded and re-derived server-side;
* per-key rate limits + payload caps enforce; malformed input rejected;
* authoritative fail-closed kill-switch: revoked key + global pause reject,
  including when the control/key store is unreachable;
* a contradicted external claim downweights the contributor (the P4.1 seam).
"""

from __future__ import annotations

import uuid

import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import config
import ratelimit
from db.models import Base
from db.session import get_db
from ingest import IngestAuthError, is_paused, revoke_key, set_paused, verify_key
from shared_corpus import GlobalEntity, entity_provenance
from shared_corpus.models import SourceReputation

HEADERS = lambda k, s: {"X-Ingest-Key-Id": k, "X-Ingest-Secret": s}
IP = "185.220.101.5"


async def _no_feed_matches(entities):
    return {}


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "PRIVATE_MODE", False)
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'ingest.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    def _override_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    app = FastAPI()
    from api.routes import ingest as ingest_route

    app.include_router(ingest_route.router)
    app.dependency_overrides[get_db] = _override_db

    # Default: server-side feed matcher finds nothing (so forged hits die).
    monkeypatch.setattr("feeds.derive_feed_hits", _no_feed_matches)
    ratelimit.reset()

    client = TestClient(app)
    yield client, Session
    engine.dispose()


def _register(client):
    r = client.post("/ingest/register")
    assert r.status_code == 200, r.text
    body = r.json()
    return body["key_id"], body["secret"]


def _submit(client, key, secret, artifacts):
    return client.post(
        "/ingest/observations", json={"artifacts": artifacts}, headers=HEADERS(key, secret)
    )


def _artifact(value=IP, origin="abc.onion", disposition=None, feed_hits=None):
    a = {"entity_type": "IP_ADDRESS", "value": value, "origin": origin}
    if disposition:
        a["disposition"] = disposition
    if feed_hits:
        a["feed_hits"] = feed_hits
    return a


# ---------------------------------------------------------------------------
# Registration + auth
# ---------------------------------------------------------------------------

def test_self_register_and_unauthenticated_is_rejected(ctx):
    client, _ = ctx
    key, secret = _register(client)
    assert key and secret

    # No credentials → 401.
    r = client.post("/ingest/observations", json={"artifacts": [_artifact()]})
    assert r.status_code == 401
    # Bad secret → 401.
    r = _submit(client, key, "wrong-secret", [_artifact()])
    assert r.status_code == 401


def test_ingested_artifact_lands_unconfirmed(ctx):
    client, Session = ctx
    key, secret = _register(client)
    r = _submit(client, key, secret, [_artifact()])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["considered"] == 1
    # Fresh low-rep key → its origin does not count → unconfirmed.
    s = Session()
    try:
        prov = entity_provenance(s, "IP_ADDRESS", IP)
        assert prov is not None
        assert prov["confidence_tier"] == "unconfirmed"
    finally:
        s.close()


# ---------------------------------------------------------------------------
# The Sybil red-team (headline)
# ---------------------------------------------------------------------------

def test_sybil_many_keys_many_origins_move_nothing(ctx):
    client, Session = ctx
    # Attacker self-registers 6 keys and floods the SAME false IOC, each from a
    # DIFFERENT fabricated origin, trying to manufacture independent corroboration.
    for i in range(6):
        key, secret = _register(client)
        r = _submit(client, key, secret, [_artifact(origin=f"evil{i}.onion")])
        assert r.status_code == 200
        body = r.json()
        assert body["corroborated"] == 0
        assert body["feed_validated"] == 0

    s = Session()
    try:
        prov = entity_provenance(s, "IP_ADDRESS", IP)
        # Stored (visible) but never promoted; NO origin ever counted.
        assert prov["confidence_tier"] == "unconfirmed"
        assert prov["sources"] == []  # no counted origins despite 6 keys × 6 origins
    finally:
        s.close()


def test_single_key_many_fabricated_origins_move_nothing(ctx):
    client, Session = ctx
    key, secret = _register(client)
    # One key claiming the same IOC on 10 fabricated origins in one request.
    arts = [_artifact(origin=f"fake{i}.onion") for i in range(10)]
    r = _submit(client, key, secret, arts)
    assert r.status_code == 200
    assert r.json()["corroborated"] == 0

    s = Session()
    try:
        prov = entity_provenance(s, "IP_ADDRESS", IP)
        # Caught as a templated batch (rejected → not stored) or held unconfirmed
        # with zero counted origins — either way it never reaches a promoted tier.
        if prov is not None:
            assert prov["confidence_tier"] == "unconfirmed"
            assert prov["sources"] == []
    finally:
        s.close()


# ---------------------------------------------------------------------------
# feed_hits re-derived server-side
# ---------------------------------------------------------------------------

def test_forged_feed_hits_are_discarded(ctx):
    client, Session = ctx
    key, secret = _register(client)
    # Submitter forges a trusted-feed hit; server re-derivation (default) finds none.
    r = _submit(client, key, secret, [_artifact(feed_hits=["kev", "sslbl"])])
    assert r.status_code == 200
    assert r.json()["feed_validated"] == 0
    s = Session()
    try:
        assert entity_provenance(s, "IP_ADDRESS", IP)["confidence_tier"] == "unconfirmed"
    finally:
        s.close()


def test_genuine_server_derived_feed_hit_promotes(ctx, monkeypatch):
    client, Session = ctx

    async def _matcher(entities):
        return {("IP_ADDRESS", IP): frozenset({"kev"})}

    monkeypatch.setattr("feeds.derive_feed_hits", _matcher)
    key, secret = _register(client)
    r = _submit(client, key, secret, [_artifact()])
    assert r.status_code == 200
    assert r.json()["feed_validated"] == 1
    s = Session()
    try:
        assert entity_provenance(s, "IP_ADDRESS", IP)["confidence_tier"] == "feed_validated"
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Kill-switch — authoritative + fail-closed
# ---------------------------------------------------------------------------

def test_revoked_key_is_rejected(ctx):
    client, Session = ctx
    key, secret = _register(client)
    s = Session()
    try:
        assert revoke_key(s, key) is True
        s.commit()
    finally:
        s.close()
    r = _submit(client, key, secret, [_artifact()])
    assert r.status_code == 401


def test_global_pause_rejects(ctx):
    client, Session = ctx
    key, secret = _register(client)
    s = Session()
    try:
        set_paused(s, True)
        s.commit()
    finally:
        s.close()
    r = _submit(client, key, secret, [_artifact()])
    assert r.status_code == 503


def test_stores_fail_closed_when_unreachable():
    """A control/key store that raises is treated as paused / auth-failed."""

    class _BrokenSession:
        def execute(self, *a, **k):
            raise RuntimeError("db down")

    assert is_paused(_BrokenSession()) is True  # fail-closed: unreadable → paused
    with pytest.raises(IngestAuthError):
        verify_key(_BrokenSession(), "kid", "secret")  # fail-closed: unreadable → reject


# ---------------------------------------------------------------------------
# Rate limits + payload caps (CC-2)
# ---------------------------------------------------------------------------

def test_per_key_rate_limit_429(ctx, monkeypatch):
    client, _ = ctx
    monkeypatch.setenv("DISABLE_RATE_LIMIT", "false")
    monkeypatch.setattr(config, "INGEST_RATE_LIMIT", 2)
    ratelimit.reset()
    key, secret = _register(client)
    codes = [_submit(client, key, secret, [_artifact()]).status_code for _ in range(4)]
    assert 429 in codes  # the burst trips the per-key limit
    monkeypatch.setenv("DISABLE_RATE_LIMIT", "true")
    ratelimit.reset()


def test_payload_cap_rejected(ctx, monkeypatch):
    client, _ = ctx
    monkeypatch.setattr(config, "INGEST_MAX_ARTIFACTS_PER_REQUEST", 3)
    key, secret = _register(client)
    r = _submit(client, key, secret, [_artifact(value=f"185.220.101.{i}") for i in range(5)])
    assert r.status_code == 413


def test_malformed_input_rejected(ctx):
    client, _ = ctx
    key, secret = _register(client)
    # Missing 'value' → 422 at the boundary.
    r = client.post(
        "/ingest/observations",
        json={"artifacts": [{"entity_type": "IP_ADDRESS"}]},
        headers=HEADERS(key, secret),
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Only-one-write-path + contradiction seam
# ---------------------------------------------------------------------------

def test_no_second_write_path():
    """Ingest never writes global_entities directly — only via promote_entities."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    service = (root / "ingest" / "service.py").read_text(encoding="utf-8")
    route = (root / "api" / "routes" / "ingest.py").read_text(encoding="utf-8")
    for src in (service, route):
        # No direct global-entity write *calls* (prose mentions are fine).
        assert "upsert_global_entity(" not in src
        assert "record_global_entity_source(" not in src
    assert "promote_entities(" in service  # the one write path


def test_contradiction_downweights_contributor(ctx, monkeypatch):
    client, Session = ctx

    # Establish IP as feed_validated malicious (server-derived feed hit).
    async def _matcher(entities):
        return {("IP_ADDRESS", IP): frozenset({"kev"})}

    monkeypatch.setattr("feeds.derive_feed_hits", _matcher)
    k1, s1 = _register(client)
    assert _submit(client, k1, s1, [_artifact(disposition="malicious")]).status_code == 200

    # A different key now claims the SAME IOC is benign → contradiction.
    k2, s2 = _register(client)
    assert _submit(client, k2, s2, [_artifact(disposition="benign")]).status_code == 200

    s = Session()
    try:
        rep = s.execute(
            sa.select(SourceReputation).where(SourceReputation.source == k2)
        ).scalar_one()
        assert rep.contradicted >= 1
        assert rep.score < config.TRUST_GATE_CONTRIBUTOR_START_REPUTATION
    finally:
        s.close()
