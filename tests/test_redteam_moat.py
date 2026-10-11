"""
tests/test_redteam_moat.py — P4.4 full live red-team: the moat holds end-to-end.

The definitive anti-poisoning acceptance. A comprehensive adversarial suite driven
through the REAL ingest HTTP boundary (FastAPI + the live gate + the promote path),
unifying the P4.0 gate red-team and the P4.3 ingest red-team into one pass over the
whole attack taxonomy:

    single-source flood · Sybil key-farming · fabricated origins · forged feed_hits
    · contradicted claims · templated / mass-identical injection · reputation-gaming

Every attack must fail to move scoring. A positive control proves the gate still
promotes genuine evidence (so the moat isn't just "block everything"). Finally, the
observability view must *reflect* an in-progress attack — the owner can see it.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import config
import ratelimit
from db.models import Base
from db.session import get_db
from observability import corpus_health
from shared_corpus import entity_provenance
from shared_corpus.models import SourceReputation

# Values the (patched) server-side feed matcher treats as genuine trusted-feed hits.
_FEED_VALID: set[str] = set()


async def _feed_matcher(entities):
    return {
        ("IP_ADDRESS", e["value"]): frozenset({"kev"})
        for e in entities
        if e.get("value") in _FEED_VALID
    }


@pytest.fixture
def moat(tmp_path, monkeypatch):
    _FEED_VALID.clear()
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'moat.db').as_posix()}",
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
    monkeypatch.setattr("feeds.derive_feed_hits", _feed_matcher)
    ratelimit.reset()

    yield TestClient(app), Session
    engine.dispose()


def _register(client):
    r = client.post("/ingest/register")
    assert r.status_code == 200
    b = r.json()
    return b["key_id"], b["secret"]


def _submit(client, key, secret, artifacts):
    return client.post(
        "/ingest/observations",
        json={"artifacts": artifacts},
        headers={"X-Ingest-Key-Id": key, "X-Ingest-Secret": secret},
    )


def _art(value, origin="o.onion", disposition=None, feed_hits=None):
    a = {"entity_type": "IP_ADDRESS", "value": value, "origin": origin}
    if disposition:
        a["disposition"] = disposition
    if feed_hits:
        a["feed_hits"] = feed_hits
    return a


def _tier(Session, value):
    s = Session()
    try:
        prov = entity_provenance(s, "IP_ADDRESS", value)
        return prov["confidence_tier"] if prov else None
    finally:
        s.close()


# ---------------------------------------------------------------------------
# The attack taxonomy — each must fail to move scoring
# ---------------------------------------------------------------------------

def test_single_source_flood_is_rate_limited(moat, monkeypatch):
    client, Session = moat
    monkeypatch.setenv("DISABLE_RATE_LIMIT", "false")
    monkeypatch.setattr(config, "INGEST_RATE_LIMIT", 3)
    ratelimit.reset()
    key, secret = _register(client)
    codes = [_submit(client, key, secret, [_art(f"5.5.5.{i}")]).status_code for i in range(8)]
    assert 429 in codes  # the burst is throttled at the boundary
    # Nothing the flood managed to submit was promoted.
    for i in range(8):
        assert _tier(Session, f"5.5.5.{i}") in (None, "unconfirmed")
    monkeypatch.setenv("DISABLE_RATE_LIMIT", "true")
    ratelimit.reset()


def test_sybil_key_farming_moves_nothing(moat):
    client, Session = moat
    for i in range(8):
        k, s = _register(client)
        assert _submit(client, k, s, [_art("6.6.6.6", origin=f"evil{i}.onion")]).status_code == 200
    assert _tier(Session, "6.6.6.6") == "unconfirmed"


def test_fabricated_origins_move_nothing(moat):
    client, Session = moat
    k, s = _register(client)
    assert _submit(client, k, s, [_art("6.6.6.7", origin=f"fake{i}.onion") for i in range(10)]).status_code == 200
    # Caught either as a templated batch (rejected) or by the single-contributor
    # rule (quarantined) — either way it never reaches a promoted tier.
    assert _tier(Session, "6.6.6.7") in (None, "unconfirmed")


def test_forged_feed_hits_moves_nothing(moat):
    client, Session = moat
    # 6.6.6.8 is NOT in _FEED_VALID → server re-derivation finds nothing.
    k, s = _register(client)
    assert _submit(client, k, s, [_art("6.6.6.8", feed_hits=["kev", "sslbl"])]).status_code == 200
    assert _tier(Session, "6.6.6.8") == "unconfirmed"


def test_contradicted_claim_downweights_attacker(moat):
    client, Session = moat
    _FEED_VALID.add("7.7.7.7")  # genuinely feed-validated as malicious
    k1, s1 = _register(client)
    _submit(client, k1, s1, [_art("7.7.7.7", disposition="malicious")])
    k2, s2 = _register(client)
    _submit(client, k2, s2, [_art("7.7.7.7", disposition="benign")])  # contradiction
    s = Session()
    try:
        rep = s.query(SourceReputation).filter_by(source=k2).one()
        assert rep.contradicted >= 1
        assert rep.score < config.TRUST_GATE_CONTRIBUTOR_START_REPUTATION
    finally:
        s.close()
    # The feed's verdict is authoritative and unchanged.
    assert _tier(Session, "7.7.7.7") == "feed_validated"


def test_templated_mass_identical_batch_rejected(moat):
    client, Session = moat
    k, s = _register(client)
    r = _submit(client, k, s, [_art("6.6.6.9", origin=f"x{i}.onion") for i in range(10)])
    assert r.status_code == 200
    assert r.json()["rejected"] >= 5  # templated batch → rejected
    assert _tier(Session, "6.6.6.9") is None  # nothing stored
    chk = Session()
    try:
        rep = chk.query(SourceReputation).filter_by(source=k).one()
        assert rep.anomalies >= 1  # attacker flagged
    finally:
        chk.close()


def test_reputation_gaming_single_key_cannot_defect(moat):
    """A key earns trust on real feed data, then defects — and still promotes nothing."""
    client, Session = moat
    _FEED_VALID.update({"9.9.9.9", "9.9.9.10", "9.9.9.11"})
    k, s = _register(client)
    # Earn reputation by agreeing with the feed several times (score climbs past
    # the corroborate threshold).
    for v in ("9.9.9.9", "9.9.9.10", "9.9.9.11"):
        assert _submit(client, k, s, [_art(v)]).status_code == 200
    chk = Session()
    try:
        rep = chk.query(SourceReputation).filter_by(source=k).one()
        assert rep.score >= config.TRUST_GATE_REPUTATION_MIN_TO_CORROBORATE  # now "trusted"
    finally:
        chk.close()
    # Defect: claim a false IOC on many fabricated origins from this one trusted key.
    _submit(client, k, s, [_art("6.6.6.66", origin=f"lie{i}.onion") for i in range(5)])
    # Blocked by the >=2-distinct-contributors rule — one key is one contributor.
    assert _tier(Session, "6.6.6.66") == "unconfirmed"


# ---------------------------------------------------------------------------
# Positive control — genuine evidence still promotes
# ---------------------------------------------------------------------------

def test_genuine_feed_hit_still_promotes(moat):
    client, Session = moat
    _FEED_VALID.add("8.8.8.8")
    k, s = _register(client)
    r = _submit(client, k, s, [_art("8.8.8.8")])
    assert r.json()["feed_validated"] == 1
    assert _tier(Session, "8.8.8.8") == "feed_validated"


# ---------------------------------------------------------------------------
# Close the loop — the attack is VISIBLE in the observability view
# ---------------------------------------------------------------------------

def test_observability_reflects_an_attack_in_progress(moat):
    client, Session = moat
    # Sybil flood: many keys, many distinct false IOCs → pile up as unconfirmed.
    for i in range(12):
        k, s = _register(client)
        _submit(client, k, s, [_art(f"66.66.0.{i}", origin=f"a{i}.onion")])
    # A templated batch from one contributor → flags it with anomalies.
    kf, sf = _register(client)
    _submit(client, kf, sf, [_art("66.66.1.1", origin=f"t{i}.onion") for i in range(10)])

    s = Session()
    try:
        health = corpus_health(s, now=None)
    finally:
        s.close()

    # The primary poisoning signal is lit: almost everything is quarantined.
    assert health["tiers"]["quarantine_ratio"] >= 0.8
    # The flooding contributor is visible as flagged, and abuse is aggregated.
    assert health["reputation"]["total_anomalies"] >= 1
    flagged_sources = {f["source"] for f in health["reputation"]["flagged"]}
    assert kf in flagged_sources
