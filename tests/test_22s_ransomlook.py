"""22S-2: RansomLook in the cloud profile. Licence verdict in the cloud
allowlist, the query-side group-name gate (ordinary-word group names need a
threat cue) and the leak-site seed cap. Synthetic group data, no network."""

from __future__ import annotations

import asyncio
import re

import pytest
from aioresponses import aioresponses

import sources.enrichment as en
from sources.enrichment_allowlist import CLOUD_ENRICHMENT_SOURCES

RL = "https://www.ransomlook.io/api"


def test_cloud_value_enables_ransomlook_not_ransomware_live():
    ids = CLOUD_ENRICHMENT_SOURCES.split(",")
    assert "ransomlook" in ids
    assert "ransomware_live" not in ids


@pytest.mark.parametrize("name, query, expected", [
    ("lockbit3", "LockBit ransomware leak", True),     # versioned stem, not a word
    ("akira", "Akira", True),                          # not a dictionary word
    ("telegram", "Telegram channel selling credentials", False),
    ("play", "play store account dump", False),
    ("play", "Play ransomware victims", True),         # cue next to the name
    ("hive", "Hive group leak", True),
    ("root", "root access vpn", False),
    ("global", "global corp breach", False),
    ("blockbit", "LockBit ransomware", False),         # whole word only
])
def test_group_matches_query(name, query, expected):
    assert en._group_matches_query(name, query) is expected


def test_group_matches_query_trusts_the_query_intent(monkeypatch):
    """A bare ordinary-word name matches when the run's intent is that threat."""
    from voidaccess import relevance
    from voidaccess.query_intent import QueryIntent

    intent = QueryIntent(kind="named_threat", terms=["medusa"], display="Medusa",
                         original="Medusa", aliases=["medusa"])
    assert not en._group_matches_query("medusa", "Medusa")
    relevance.set_current_intent(intent)
    try:
        assert en._group_matches_query("medusa", "Medusa")
    finally:
        relevance.set_current_intent(None)


def _locations(n: int) -> list[dict]:
    letters = "abcdefghijklmnopqrstuvwxyz234567"
    out = []
    for i in range(n):
        label = (letters[i % 32] * 55) + letters[(i // 32) % 32]
        out.append({"fqdn": f"{label}.onion", "available": i % 2 == 0})
    return out


def test_fetch_ransomlook_caps_seeds_and_skips_ordinary_word_groups(monkeypatch):
    monkeypatch.setenv("VOIDACCESS_ENRICHMENT_SOURCES", "ransomlook")
    with aioresponses() as m:
        m.get(f"{RL}/groups", payload=["lockbit3", "telegram", "blockbit"])
        m.get(f"{RL}/group/lockbit3", payload=[{"meta": "synthetic", "locations": _locations(40),
                                                "profile": []}])
        m.get(f"{RL}/recent", payload=[])
        groups = asyncio.run(en.fetch_ransomlook("telegram channel dumps about LockBit"))
        detail_calls = [k for k in m.requests if re.search(r"/group/", str(k[1]))]
    assert [g["group"] for g in groups] == ["lockbit3"]
    assert len(detail_calls) == 1  # "telegram" (no cue next to it) and "blockbit" never fetched
    onions = groups[0]["onion_urls"]
    assert len(onions) == en.RANSOMLOOK_MAX_ONIONS_PER_GROUP
    pages = en.ransomlook_to_pages(groups)
    seeds = [p for p in pages if p.get("_scrape_seed")]
    assert len(seeds) == en.RANSOMLOOK_MAX_ONIONS_PER_GROUP
    summary = [p for p in pages if not p.get("_scrape_seed")][0]
    assert "CC BY 4.0" in summary["text"]  # attribution travels with the data


def test_fetch_ransomlook_off_without_allowlist_entry(monkeypatch):
    monkeypatch.setenv("VOIDACCESS_ENRICHMENT_SOURCES", "rdap")
    with aioresponses() as m:
        assert asyncio.run(en.fetch_ransomlook("LockBit")) == []
        assert not m.requests
