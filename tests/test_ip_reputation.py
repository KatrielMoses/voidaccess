"""
Tests for sources/ip_reputation.py

Covers: feed parsing, reputation checks, suppression logic,
confidence calculation, cache TTL, private IP filtering, and concurrency.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import sources.ip_reputation as ipr
from sources.ip_reputation import (
    _parse_feodo_csv,
    _parse_c2_txt,
    check_ip_reputation,
    enrich_ip_entities,
    is_private_ip,
    _feed_cache,
)

_REAL_LOAD_NETAPI_FEED = ipr.load_netapi_feed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_cache():
    """Zero out the in-memory feed cache between tests."""
    _feed_cache["feodo"]["ips"] = {}
    _feed_cache["feodo"]["loaded_at"] = 0.0
    _feed_cache["c2feeds"]["ips"] = {}
    _feed_cache["c2feeds"]["loaded_at"] = 0.0
    _feed_cache["netapi"]["ips"] = set()
    _feed_cache["netapi"]["loaded_at"] = 0.0


@pytest.fixture(autouse=True)
def _no_live_netapi_feed(monkeypatch):
    """Keep the NetAPI feed offline unless a test patches it explicitly."""
    monkeypatch.setattr(ipr, "load_netapi_feed", AsyncMock(return_value=set()))


def _make_entity(ip: str, confidence: float = 1.0):
    e = MagicMock()
    e.entity_type = "IP_ADDRESS"
    e.value = ip
    e.confidence = confidence
    return e


def _make_result(entities: list):
    r = MagicMock()
    r.entities = list(entities)
    r.entity_count = len(entities)
    return r


# ---------------------------------------------------------------------------
# 1. Feodo CSV parsing
# ---------------------------------------------------------------------------

def test_feodo_csv_parsing_returns_correct_ips():
    csv_text = """\
# Feodo Tracker
# Generated: 2024-01-01
# Columns: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
2024-01-01 00:00:00,10.0.0.1,443,online,2024-01-01,Emotet
2024-01-01 00:00:00,10.0.0.2,8080,offline,2023-12-31,QakBot
"""
    result = _parse_feodo_csv(csv_text)
    assert result["10.0.0.1"] == "Emotet"
    assert result["10.0.0.2"] == "QakBot"
    assert len(result) == 2


def test_feodo_csv_skips_comment_lines():
    csv_text = """\
# comment line
# another comment
first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
2024-01-01 00:00:00,1.2.3.4,443,online,2024-01-01,Dridex
"""
    result = _parse_feodo_csv(csv_text)
    assert "1.2.3.4" in result
    assert result["1.2.3.4"] == "Dridex"


# ---------------------------------------------------------------------------
# 2. C2Feed text file parsing
# ---------------------------------------------------------------------------

def test_c2feed_txt_parsing_returns_correct_ips():
    text = """\
1.2.3.4
5.6.7.8
# comment
9.10.11.12
"""
    result = _parse_c2_txt(text)
    assert result == {"1.2.3.4", "5.6.7.8", "9.10.11.12"}


def test_c2feed_txt_strips_port_suffix():
    text = "1.2.3.4:8080\n5.6.7.8:443\n"
    result = _parse_c2_txt(text)
    assert "1.2.3.4" in result
    assert "5.6.7.8" in result


def test_c2feed_txt_strips_cidr():
    text = "1.2.3.4/32\n5.6.7.8/24\n"
    result = _parse_c2_txt(text)
    assert "1.2.3.4" in result
    assert "5.6.7.8" in result


# ---------------------------------------------------------------------------
# 3. Feodo hit → confirmed_c2 tag + confidence boost
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_feodo_hit_adds_confirmed_c2_tag_and_boosts_confidence():
    _reset_cache()
    ip = "1.2.3.4"

    with patch.object(ipr, "load_feodo_feed", new=AsyncMock(return_value={ip: "Emotet"})), \
         patch.object(ipr, "load_c2_feeds", new=AsyncMock(return_value={})), \
         patch.dict(os.environ, {}, clear=False):
        # Remove optional keys so AbuseIPDB/GreyNoise are skipped
        env = {k: v for k, v in os.environ.items() if k not in ("ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY")}
        env.pop("ABUSEIPDB_API_KEY", None)
        env.pop("GREYNOISE_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            result = await check_ip_reputation(ip, base_confidence=0.8)

    assert result["feodo_hit"] is True
    assert result["feodo_malware"] == "Emotet"
    assert "confirmed_c2" in result["tags"]
    assert "confirmed_c2_emotet" in result["tags"]
    assert result["threat_confidence"] == pytest.approx(0.8 + 0.15)
    assert result["suppress"] is False


# ---------------------------------------------------------------------------
# 4. C2Feed hit → framework-specific tag
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_c2feed_hit_adds_framework_tag():
    _reset_cache()
    ip = "5.6.7.8"

    with patch.object(ipr, "load_feodo_feed", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_c2_feeds", new=AsyncMock(return_value={"cobalt_strike": {ip}})):
        env = {k: v for k, v in os.environ.items()}
        env.pop("ABUSEIPDB_API_KEY", None)
        env.pop("GREYNOISE_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            result = await check_ip_reputation(ip, base_confidence=0.9)

    assert result["c2feed_hit"] is True
    assert result["c2feed_framework"] == "cobalt_strike"
    assert "confirmed_c2" in result["tags"]
    assert "confirmed_c2_cobalt_strike" in result["tags"]
    assert result["threat_confidence"] == pytest.approx(min(0.9 + 0.15, 1.0))
    assert result["suppress"] is False


# ---------------------------------------------------------------------------
# 5. GreyNoise benign → suppress=True
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_greynoise_benign_sets_suppress():
    _reset_cache()
    ip = "8.8.8.8"

    with patch.object(ipr, "load_feodo_feed", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_c2_feeds", new=AsyncMock(return_value={})), \
         patch.object(ipr, "_check_greynoise", new=AsyncMock(return_value={"classification": "benign"})), \
         patch.dict(os.environ, {"GREYNOISE_API_KEY": "test-key"}, clear=False):
        env = dict(os.environ)
        env.pop("ABUSEIPDB_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            result = await check_ip_reputation(ip)

    assert result["suppress"] is True
    assert result["greynoise_classification"] == "benign"


# ---------------------------------------------------------------------------
# 6. GreyNoise malicious → tag added, no suppression
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_greynoise_malicious_adds_tag_no_suppress():
    _reset_cache()
    ip = "1.1.1.2"

    with patch.object(ipr, "load_feodo_feed", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_c2_feeds", new=AsyncMock(return_value={})), \
         patch.object(ipr, "_check_greynoise", new=AsyncMock(return_value={
             "classification": "malicious",
             "tags": ["Mirai", "brute_force"],
         })), \
         patch.dict(os.environ, {"GREYNOISE_API_KEY": "test-key"}, clear=False):
        env = dict(os.environ)
        env.pop("ABUSEIPDB_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            result = await check_ip_reputation(ip, base_confidence=0.8)

    assert result["suppress"] is False
    assert result["greynoise_classification"] == "malicious"
    assert "greynoise_malicious" in result["tags"]
    assert result["threat_confidence"] == pytest.approx(min(0.8 + 0.10, 1.0))


# ---------------------------------------------------------------------------
# 7. GreyNoise unknown → entity passes through unchanged
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_greynoise_unknown_passes_through():
    _reset_cache()
    ip = "1.1.1.3"

    with patch.object(ipr, "load_feodo_feed", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_c2_feeds", new=AsyncMock(return_value={})), \
         patch.object(ipr, "_check_greynoise", new=AsyncMock(return_value={"classification": "unknown"})), \
         patch.dict(os.environ, {"GREYNOISE_API_KEY": "test-key"}, clear=False):
        env = dict(os.environ)
        env.pop("ABUSEIPDB_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            result = await check_ip_reputation(ip, base_confidence=0.9)

    assert result["suppress"] is False
    assert result["greynoise_classification"] == "unknown"
    assert "greynoise_malicious" not in result["tags"]
    assert result["threat_confidence"] == pytest.approx(0.9)


# ---------------------------------------------------------------------------
# 8. AbuseIPDB score > 80 → confidence boost
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_abuseipdb_score_above_80_boosts_confidence():
    _reset_cache()
    ip = "2.2.2.2"

    abuse_resp = {"data": {"abuseConfidenceScore": 85, "usageType": "Data Center/Web Hosting/Transit"}}

    with patch.object(ipr, "load_feodo_feed", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_c2_feeds", new=AsyncMock(return_value={})), \
         patch.object(ipr, "_check_abuseipdb", new=AsyncMock(return_value=abuse_resp)), \
         patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}, clear=False):
        env = dict(os.environ)
        env.pop("GREYNOISE_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            result = await check_ip_reputation(ip, base_confidence=0.8)

    assert result["abuseipdb_score"] == 85
    assert "abuse_confirmed" in result["tags"]
    assert result["threat_confidence"] == pytest.approx(0.8 + 0.10)


# ---------------------------------------------------------------------------
# 9. AbuseIPDB score < 50 → no tag, no confidence boost
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_abuseipdb_score_below_50_adds_no_tag():
    _reset_cache()
    ip = "3.3.3.3"

    abuse_resp = {"data": {"abuseConfidenceScore": 30, "usageType": "ISP"}}

    with patch.object(ipr, "load_feodo_feed", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_c2_feeds", new=AsyncMock(return_value={})), \
         patch.object(ipr, "_check_abuseipdb", new=AsyncMock(return_value=abuse_resp)), \
         patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"}, clear=False):
        env = dict(os.environ)
        env.pop("GREYNOISE_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            result = await check_ip_reputation(ip, base_confidence=0.8)

    assert result["abuseipdb_score"] == 30
    assert "abuse_confirmed" not in result["tags"]
    assert result["threat_confidence"] == pytest.approx(0.8)


# ---------------------------------------------------------------------------
# 10. No API keys → AbuseIPDB/GreyNoise skipped; Feodo/C2 still work
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_api_keys_skips_external_checks_but_runs_feeds():
    _reset_cache()
    ip = "4.4.4.4"

    feodo_mock = AsyncMock(return_value={ip: "IcedID"})
    c2_mock = AsyncMock(return_value={})
    abuse_mock = AsyncMock(return_value={"data": {"abuseConfidenceScore": 99}})
    gn_mock = AsyncMock(return_value={"classification": "benign"})

    with patch.object(ipr, "load_feodo_feed", new=feodo_mock), \
         patch.object(ipr, "load_c2_feeds", new=c2_mock), \
         patch.object(ipr, "_check_abuseipdb", new=abuse_mock), \
         patch.object(ipr, "_check_greynoise", new=gn_mock):
        env = {k: v for k, v in os.environ.items()}
        env.pop("ABUSEIPDB_API_KEY", None)
        env.pop("GREYNOISE_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            result = await check_ip_reputation(ip, base_confidence=0.7)

    # Feeds ran and found the IP
    assert result["feodo_hit"] is True
    assert result["feodo_malware"] == "IcedID"
    # But neither external API was called (no key)
    abuse_mock.assert_not_called()
    gn_mock.assert_not_called()
    # Not suppressed because GreyNoise was never queried
    assert result["suppress"] is False


# ---------------------------------------------------------------------------
# 11. threat_confidence capped at 1.0
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_threat_confidence_capped_at_1():
    _reset_cache()
    ip = "5.5.5.5"

    abuse_resp = {"data": {"abuseConfidenceScore": 95, "usageType": "Hosting"}}

    with patch.object(ipr, "load_feodo_feed", new=AsyncMock(return_value={ip: "Emotet"})), \
         patch.object(ipr, "load_c2_feeds", new=AsyncMock(return_value={"cobalt_strike": {ip}})), \
         patch.object(ipr, "_check_abuseipdb", new=AsyncMock(return_value=abuse_resp)), \
         patch.object(ipr, "_check_greynoise", new=AsyncMock(return_value={"classification": "malicious"})), \
         patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "k", "GREYNOISE_API_KEY": "k"}, clear=False):
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "k", "GREYNOISE_API_KEY": "k"}):
            result = await check_ip_reputation(ip, base_confidence=0.9)

    # 0.9 + 0.15 (feodo) + 0.15 (c2feed) + 0.10 (abuse>80) + 0.10 (gn malicious) = 1.40 → capped
    assert result["threat_confidence"] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# 12. Private IPs skipped entirely
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_private_ip_skipped():
    _reset_cache()

    feodo_mock = AsyncMock(return_value={"192.168.1.1": "Emotet"})
    c2_mock = AsyncMock(return_value={})

    with patch.object(ipr, "load_feodo_feed", new=feodo_mock), \
         patch.object(ipr, "load_c2_feeds", new=c2_mock):
        result = await check_ip_reputation("192.168.1.1", base_confidence=0.9)

    assert result["feodo_hit"] is False
    assert result["suppress"] is False
    assert result["tags"] == []
    assert result["threat_confidence"] == pytest.approx(0.9)
    # Feeds should not have been loaded (short-circuit before gather)
    feodo_mock.assert_not_called()


def test_is_private_ip_loopback():
    assert is_private_ip("127.0.0.1") is True


def test_is_private_ip_rfc1918():
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("192.168.0.1") is True


def test_is_private_ip_public():
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False


# ---------------------------------------------------------------------------
# 13. Cache TTL respected — feeds not re-fetched within TTL window
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cache_ttl_prevents_refetch():
    _reset_cache()

    # Prime the cache manually
    _feed_cache["feodo"]["ips"] = {"9.9.9.9": "TrickBot"}
    _feed_cache["feodo"]["loaded_at"] = time.time()  # just loaded

    fetch_called = []

    async def _fake_fetch(url, **kwargs):
        fetch_called.append(url)
        resp = AsyncMock()
        resp.status = 200
        resp.text = AsyncMock(return_value="")
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)
        return resp

    with patch("aiohttp.ClientSession") as mock_session_cls:
        mock_session = AsyncMock()
        mock_session.get = _fake_fetch
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session_cls.return_value = mock_session

        # Load feed — should use cache, not make HTTP call
        result = await ipr.load_feodo_feed()

    assert result == {"9.9.9.9": "TrickBot"}
    assert fetch_called == [], "HTTP fetch should not be called when cache is fresh"


# ---------------------------------------------------------------------------
# 14. Concurrent enrichment of 10 IPs completes without errors
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_enrichment_of_10_ips():
    _reset_cache()

    ips = [f"10.0.0.{i}" for i in range(1, 11)]  # 10 IPs
    entities = [_make_entity(ip) for ip in ips]
    results = [_make_result(entities)]  # all in one result

    with patch.object(ipr, "load_feodo_feed", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_c2_feeds", new=AsyncMock(return_value={})), \
         patch.object(ipr, "_suppress_entities_in_db", return_value=None), \
         patch.object(ipr, "_update_entity_reputations", return_value=None):
        env = {k: v for k, v in os.environ.items()}
        env.pop("ABUSEIPDB_API_KEY", None)
        env.pop("GREYNOISE_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            filtered, stats = await enrich_ip_entities(results, "test-investigation-id")

    assert stats["checked"] == 10
    assert stats["suppressed"] == 0
    # All private IPs (10.x.x.x) return immediately, no tags
    assert len(filtered[0].entities) == 10


# ---------------------------------------------------------------------------
# 15. NetAPI honeypot list: parsing, hit tags, confidence, gate, stats
# ---------------------------------------------------------------------------

class _FakeResp:
    def __init__(self, status: int, body: str):
        self.status = status
        self._body = body

    async def text(self) -> str:
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    def __init__(self, status: int, body: str):
        self.urls: list[str] = []
        self._status = status
        self._body = body

    def get(self, url, **kwargs):
        self.urls.append(url)
        return _FakeResp(self._status, self._body)


def _install_session(monkeypatch, session):
    @contextlib.asynccontextmanager
    async def _cm():
        yield session

    monkeypatch.setattr(ipr.http_pool, "clearnet_session", _cm)


@pytest.mark.asyncio
async def test_netapi_feed_loads_plain_list(monkeypatch):
    _reset_cache()
    monkeypatch.setattr(ipr, "load_netapi_feed", _REAL_LOAD_NETAPI_FEED)
    session = _FakeSession(200, "1.2.3.4\n5.6.7.8\n\n# comment\n5.6.7.8\n")
    _install_session(monkeypatch, session)

    result = await ipr.load_netapi_feed()

    assert result == {"1.2.3.4", "5.6.7.8"}
    assert session.urls == [ipr.NETAPI_IP_URL]
    assert _feed_cache["netapi"]["ips"] == {"1.2.3.4", "5.6.7.8"}

    # Second call within the TTL is served from the cache
    again = await ipr.load_netapi_feed()
    assert again == result
    assert len(session.urls) == 1


@pytest.mark.asyncio
async def test_netapi_feed_http_error_keeps_previous_list(monkeypatch):
    _reset_cache()
    monkeypatch.setattr(ipr, "load_netapi_feed", _REAL_LOAD_NETAPI_FEED)
    _feed_cache["netapi"]["ips"] = {"9.9.9.9"}
    _feed_cache["netapi"]["loaded_at"] = 0.0  # stale, forces a refresh
    _install_session(monkeypatch, _FakeSession(503, ""))

    result = await ipr.load_netapi_feed()

    assert result == {"9.9.9.9"}


@pytest.mark.asyncio
async def test_netapi_hit_adds_honeypot_tags_and_boosts_confidence():
    _reset_cache()
    ip = "45.33.32.156"

    with patch.object(ipr, "load_feodo_feed", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_c2_feeds", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_netapi_feed", new=AsyncMock(return_value={ip})):
        env = {k: v for k, v in os.environ.items()}
        env.pop("ABUSEIPDB_API_KEY", None)
        env.pop("GREYNOISE_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            result = await check_ip_reputation(ip, base_confidence=0.8)

    assert result["netapi_hit"] is True
    assert "honeypot_attacker" in result["tags"]
    assert "honeypot_attacker_netapi" in result["tags"]
    assert "confirmed_c2" not in result["tags"]
    assert result["threat_confidence"] == pytest.approx(0.8 + 0.10)


@pytest.mark.asyncio
async def test_netapi_miss_leaves_result_unchanged():
    _reset_cache()

    with patch.object(ipr, "load_feodo_feed", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_c2_feeds", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_netapi_feed", new=AsyncMock(return_value={"1.1.1.2"})):
        env = {k: v for k, v in os.environ.items()}
        env.pop("ABUSEIPDB_API_KEY", None)
        env.pop("GREYNOISE_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            result = await check_ip_reputation("8.8.4.4", base_confidence=0.8)

    assert result["netapi_hit"] is False
    assert result["tags"] == []
    assert result["threat_confidence"] == pytest.approx(0.8)


@pytest.mark.asyncio
async def test_netapi_disabled_by_allowlist_is_not_loaded(monkeypatch):
    _reset_cache()
    netapi_mock = AsyncMock(return_value={"45.33.32.156"})
    monkeypatch.setenv("VOIDACCESS_ENRICHMENT_SOURCES", "feodo_tracker,c2_tracker")

    with patch.object(ipr, "load_feodo_feed", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_c2_feeds", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_netapi_feed", new=netapi_mock):
        result = await check_ip_reputation("45.33.32.156", base_confidence=0.8)

    netapi_mock.assert_not_called()
    assert result["netapi_hit"] is False


@pytest.mark.asyncio
async def test_enrich_counts_honeypot_attackers():
    _reset_cache()
    ips = ["45.33.32.156", "45.33.32.157"]
    results = [_make_result([_make_entity(ip, 0.8) for ip in ips])]

    with patch.object(ipr, "load_feodo_feed", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_c2_feeds", new=AsyncMock(return_value={})), \
         patch.object(ipr, "load_netapi_feed", new=AsyncMock(return_value={ips[0]})), \
         patch.object(ipr, "_suppress_entities_in_db", return_value=None), \
         patch.object(ipr, "_update_entity_reputations", return_value=None):
        env = {k: v for k, v in os.environ.items()}
        env.pop("ABUSEIPDB_API_KEY", None)
        env.pop("GREYNOISE_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            _, stats = await enrich_ip_entities(results, "test-investigation-id")

    assert stats["checked"] == 2
    assert stats["honeypot_attackers"] == 1
    assert stats["c2_confirmed"] == 0
