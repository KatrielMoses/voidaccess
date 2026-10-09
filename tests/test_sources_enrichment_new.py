"""
tests/test_sources_enrichment_new.py — Tests for the 4 new enrichment sources:
  sources/cisa.py
  sources/shodan.py
  sources/virustotal.py
  sources/historical_intel.py
  sources/cache.py

Run with:
    pytest tests/test_sources_enrichment_new.py -v
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ---------------------------------------------------------------------------
# Mock aiohttp session helpers
# ---------------------------------------------------------------------------


def _json_response(data, status: int = 200) -> MagicMock:
    r = MagicMock()
    r.status = status
    r.__aenter__ = AsyncMock(return_value=r)
    r.__aexit__ = AsyncMock(return_value=False)
    r.json = AsyncMock(return_value=data)
    return r


def _text_response(text: str, status: int = 200) -> MagicMock:
    r = MagicMock()
    r.status = status
    r.__aenter__ = AsyncMock(return_value=r)
    r.__aexit__ = AsyncMock(return_value=False)
    r.text = AsyncMock(return_value=text)
    return r


# ===========================================================================
# TestCachedFeed
# ===========================================================================


class TestCachedFeed(unittest.TestCase):
    # <category> exercises the tags mapping; note the live CISA all.xml feed
    # (checked 2026-10-09) emits no categories, so tags are [] in production.
    _RSS = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel><title>All CISA Advisories</title>
<item>
  <title>Siemens SIMATIC</title>
  <link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-01</link>
  <pubDate>Thu, 08 Oct 2026 12:00:00 +0000</pubDate>
  <category>ICS</category>
</item>
</channel></rss>"""

    def test_parse_feed_body_rss_normalizes_entries(self):
        """RSS bodies (CISA advisories, DOJ press) flatten to dicts with JSON-era keys."""
        from sources.cache import _parse_feed_body

        entries = _parse_feed_body(self._RSS, "application/rss+xml; charset=utf-8")
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e["title"], "Siemens SIMATIC")
        self.assertEqual(e["url"], e["link"])
        self.assertTrue(e["link"].endswith("icsa-26-281-01"))
        self.assertEqual(e["datePublished"], e["published"])
        self.assertEqual(e["published"], "2026-10-08T12:00:00+00:00")
        self.assertEqual(e["tags"], ["ICS"])

    def test_parse_feed_body_atom_updated_fallback(self):
        """Atom entries that carry only <updated> still get a timestamp."""
        from sources.cache import _parse_feed_body

        atom = (
            '<feed xmlns="http://www.w3.org/2005/Atom"><title>t</title>'
            '<entry><title>e</title><link href="https://example.com/e"/>'
            "<updated>2026-10-08T12:00:00Z</updated></entry></feed>"
        )
        e = _parse_feed_body(atom, "application/atom+xml")[0]
        self.assertEqual(e["published"], "2026-10-08T12:00:00+00:00")
        self.assertEqual(e["url"], "https://example.com/e")

    def test_parse_feed_body_two_digit_year_normalized(self):
        """The live CISA feed emits RFC-822 dates with a 2-digit year; they must come out as ISO."""
        from sources.cache import _parse_feed_body

        rss = self._RSS.replace("Thu, 08 Oct 2026 12:00:00 +0000", "Thu, 08 Oct 26 12:00:00 +0000")
        self.assertEqual(_parse_feed_body(rss, "application/rss+xml")[0]["published"], "2026-10-08T12:00:00+00:00")

    def test_parse_feed_body_empty_but_valid_feed_returns_empty_list(self):
        from sources.cache import _parse_feed_body

        rss = '<?xml version="1.0"?><rss version="2.0"><channel><title>Empty</title></channel></rss>'
        self.assertEqual(_parse_feed_body(rss, "application/rss+xml"), [])

    def test_parse_feed_body_html_error_page_raises(self):
        """An HTTP-200 HTML page (WAF challenge, maintenance page) must not be cached as an empty feed."""
        from sources.cache import _parse_feed_body

        html = "<!DOCTYPE html><html><head><title>Access Denied</title></head><body>blocked</body></html>"
        with self.assertRaises(ValueError):
            _parse_feed_body(html, "text/html; charset=utf-8")
        with self.assertRaises(ValueError):
            _parse_feed_body(html, "")
        with self.assertRaises(ValueError):
            _parse_feed_body(html, "application/xml")

    def test_cached_feed_html_200_falls_back_to_stale_cache(self):
        """End-to-end: a 200 HTML body leaves the stale disk cache intact and returns it."""
        import sources.cache as cache_mod

        with tempfile.TemporaryDirectory() as tmpdir:
            stale_file = os.path.join(tmpdir, "stale.json")
            stale_payload = {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}
            with open(stale_file, "w") as f:
                json.dump(stale_payload, f)
            old_mtime = time.time() - 2000
            os.utime(stale_file, (old_mtime, old_mtime))

            feed = cache_mod.CachedFeed(url="https://example.com/html-200.json", cache_path=stale_file, ttl_seconds=300)

            resp = _text_response("<!DOCTYPE html><html><body>Access Denied</body></html>")
            resp.headers = {"Content-Type": "text/html"}
            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.get = MagicMock(return_value=resp)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                result = asyncio.run(feed.fetch())

            self.assertEqual(result, stale_payload)
            with open(stale_file) as f:
                self.assertEqual(json.load(f), stale_payload)

    def test_parse_feed_body_json_passthrough(self):
        from sources.cache import _parse_feed_body

        data = _parse_feed_body('{"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}', "application/json")
        self.assertEqual(data["vulnerabilities"][0]["cveID"], "CVE-2021-44228")

    def test_parse_feed_body_detects_xml_without_content_type(self):
        from sources.cache import _parse_feed_body

        entries = _parse_feed_body(self._RSS, "")
        self.assertEqual(entries[0]["title"], "Siemens SIMATIC")

    def test_fresh_cache_returns_cached_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = os.path.join(tmpdir, "feed.json")
            feed = MagicMock()
            feed._is_fresh = MagicMock(return_value=True)
            feed.cache_path = Path(cache_path)

            import builtins
            with patch("builtins.open", MagicMock()):
                result = feed._is_fresh()
                self.assertTrue(result)


# ===========================================================================
# TestCISA
# ===========================================================================


class TestCISA(unittest.TestCase):
    def test_enrich_cisa_kev_lookup_hit(self):
        """CVE present in KEV returns is_actively_exploited = True."""
        from sources.cisa import enrich_cisa_cve

        mock_kev_data = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache Software Foundation",
                    "product": "Log4j",
                    "vulnerabilityName": "Apache Log4j Remote Code Execution",
                    "dateAdded": "2021-12-10",
                    "shortDescription": "Apache Log4j2 vulnerability...",
                }
            ]
        }

        async def run():
            with patch("sources.cache.CachedFeed.fetch", new=AsyncMock(return_value=mock_kev_data)):
                result = await enrich_cisa_cve("CVE-2021-44228")
            return result

        result = asyncio.run(run())
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["is_actively_exploited"])
        self.assertEqual(result[0]["vendor_project"], "Apache Software Foundation")
        self.assertEqual(result[0]["product"], "Log4j")

    def test_enrich_cisa_kev_miss(self):
        """CVE not in KEV returns empty without error."""
        from sources.cisa import enrich_cisa_cve

        mock_kev_data = {"vulnerabilities": []}

        async def run():
            with patch("sources.cache.CachedFeed.fetch", new=AsyncMock(return_value=mock_kev_data)):
                result = await enrich_cisa_cve("CVE-2021-99999")
            return result

        result = asyncio.run(run())
        self.assertEqual(result, [])

    def test_enrich_cisa_cve_handles_fetch_error(self):
        """KEV fetch failure returns empty, does not raise."""
        from sources.cisa import enrich_cisa_cve

        async def run():
            with patch("sources.cache.CachedFeed.fetch", new=AsyncMock(return_value=None)):
                result = await enrich_cisa_cve("CVE-2021-44228")
            return result

        result = asyncio.run(run())
        self.assertEqual(result, [])


# ===========================================================================
# TestShodan
# ===========================================================================


class TestShodan(unittest.TestCase):
    def test_shodan_c2_detection(self):
        """Shodan tags containing 'cobalt-strike' sets high_confidence_c2 = True."""
        from sources.shodan import enrich_shodan_ip

        mock_internetdb = {
            "ip": "1.2.3.4",
            "ports": [50050, 8080],
            "tags": ["cobalt-strike", "tor"],
            "hostnames": ["evil.example.com"],
            "vulns": {"CVE-2021-44228": {}},
        }

        async def run():
            with patch("aiohttp.ClientSession") as MockSession:
                mock_session = MagicMock()
                mock_resp = _json_response(mock_internetdb)
                mock_session.get = MagicMock(return_value=mock_resp)
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=False)
                MockSession.return_value = mock_session

                result = await enrich_shodan_ip("1.2.3.4", {"CVE-2021-44228"})
            return result

        result = asyncio.run(run())
        self.assertIsNotNone(result)
        self.assertTrue(result["high_confidence_c2"])
        self.assertEqual(result["open_ports"], [50050, 8080])
        self.assertIn("CVE-2021-44228", result["correlated_cves"])

    def test_shodan_rate_limit_cap(self):
        """60 IP entities results in only 50 Shodan requests (max cap enforced)."""
        from sources.shodan import enrich_shodan

        entities = [{"type": "IP_ADDRESS", "value": f"1.2.3.{i}"} for i in range(60)]

        call_count = 0

        async def mock_ip(ip, cves):
            nonlocal call_count
            call_count += 1
            return None

        async def run():
            with patch("sources.shodan.enrich_shodan_ip", new=mock_ip):
                await enrich_shodan(entities)
            return call_count

        call_count = asyncio.run(run())
        self.assertEqual(call_count, 50)

    def test_shodan_ip_not_found_returns_none(self):
        """404 from InternetDB returns None without error."""
        from sources.shodan import enrich_shodan_ip

        async def run():
            with patch("aiohttp.ClientSession") as MockSession:
                mock_session = MagicMock()
                mock_resp = _json_response({}, status=404)
                mock_session.get = MagicMock(return_value=mock_resp)
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=False)
                MockSession.return_value = mock_session

                result = await enrich_shodan_ip("99.99.99.99", set())
            return result

        result = asyncio.run(run())
        self.assertIsNone(result)


# ===========================================================================
# TestVirusTotal
# ===========================================================================


class TestVirusTotal(unittest.TestCase):
    def test_virustotal_disabled_gracefully(self):
        """With no VT_API_KEY, source returns [] without raising."""
        from sources import virustotal as vt

        async def run():
            with patch.object(vt, "VT_API_KEY", ""):
                result = await vt.enrich_virustotal([])
            return result

        result = asyncio.run(run())
        self.assertEqual(result, [])

    def test_virustotal_confirmed_malicious(self):
        """50/72 detections sets confirmed_malicious = True and detection_ratio ~0.69."""
        from sources import virustotal as vt

        mock_vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 50,
                        "suspicious": 5,
                        "undetected": 17,
                        "harmless": 0,
                    },
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.cobaltloader/win"
                    },
                    "creation_date": "2021-01-01",
                    "last_analysis_date": "2024-01-01",
                }
            }
        }

        async def run():
            with patch.object(vt, "VT_API_KEY", "test_key_123"), \
                 patch("aiohttp.ClientSession") as MockSession:
                mock_session = MagicMock()
                mock_resp = _json_response(mock_vt_response)
                mock_session.get = MagicMock(return_value=mock_resp)
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=False)
                MockSession.return_value = mock_session

                entities = [{"type": "FILE_HASH_SHA256", "value": "a" * 64}]
                result = await vt.enrich_virustotal(entities)
            return result

        result = asyncio.run(run())
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["confirmed_malicious"])
        self.assertAlmostEqual(result[0]["detection_ratio"], 50 / 72, places=2)
        self.assertEqual(result[0]["suggested_threat_label"], "trojan.cobaltloader/win")


# ===========================================================================
# TestHistoricalIntel
# ===========================================================================


class TestHistoricalIntel(unittest.TestCase):
    def test_historical_fallback_only_runs_for_empty_entities(self):
        """Fallback ONLY activates when other sources returned 0 results for THREAT_ACTOR."""
        from sources.historical_intel import enrich_historical

        async def run():
            result = await enrich_historical({
                "THREAT_ACTOR": [{"type": "THREAT_ACTOR", "value": "REvil"}],
                "RANSOMWARE_GROUP": [],
                "MALWARE_FAMILY": [],
            })
            return result

        result = asyncio.run(run())
        self.assertIsInstance(result, list)

    def test_historical_returns_empty_for_non_actor_entities(self):
        """Non THREAT_ACTOR/RANSOMWARE_GROUP/MALWARE_FAMILY types return empty."""
        from sources.historical_intel import enrich_historical

        async def run():
            result = await enrich_historical({
                "CVE_NUMBER": [{"type": "CVE_NUMBER", "value": "CVE-2021-44228"}],
            })
            return result

        result = asyncio.run(run())
        self.assertEqual(result, [])


# ===========================================================================
# TestCache
# ===========================================================================


class TestCacheStaleFallback(unittest.TestCase):
    def test_cached_feed_stale_fallback(self):
        """Failed HTTP fetch with stale cache present returns stale cache + warning."""
        import sources.cache as cache_mod

        with tempfile.TemporaryDirectory() as tmpdir:
            stale_file = os.path.join(tmpdir, "stale.json")
            with open(stale_file, "w") as f:
                json.dump({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}, f)

            old_mtime = time.time() - 2000
            os.utime(stale_file, (old_mtime, old_mtime))

            feed = cache_mod.CachedFeed(
                url="https://example.com/feed.json",
                cache_path=stale_file,
                ttl_seconds=300,
            )

            async def run():
                return await feed.fetch()

            with patch("aiohttp.ClientSession") as MockSession:
                mock_session = MagicMock()
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=False)

                async def raise_exc(*a, **kw):
                    raise Exception("network error")

                mock_get = MagicMock(side_effect=raise_exc)
                mock_session.get = mock_get
                MockSession.return_value = mock_session

                result = asyncio.run(run())

            self.assertIsNotNone(result)
            self.assertEqual(result["vulnerabilities"][0]["cveID"], "CVE-2021-44228")


# ===========================================================================
# TestNewSourcesWiredInEnrichment
# ===========================================================================


class TestNewSourcesWiredInEnrichment(unittest.TestCase):
    def test_enrich_investigation_accepts_entities_param(self):
        """enrich_investigation signature accepts optional entities list."""
        from sources.enrichment import enrich_investigation
        import inspect

        sig = inspect.signature(enrich_investigation)
        self.assertIn("entities", sig.parameters)

    def test_new_sources_in_gather(self):
        """_enrich_new_sources runs CISA, Shodan, and VT concurrently."""
        from sources import enrichment as enr

        with patch("sources.cisa.enrich_cisa", new=AsyncMock(return_value=[])), \
             patch("sources.shodan.enrich_shodan", new=AsyncMock(return_value=[])), \
             patch("sources.virustotal.enrich_virustotal", new=AsyncMock(return_value=[])), \
             patch("aiohttp.ClientSession"):
            async def run():
                return await enr._enrich_new_sources("test query", [])
            result = asyncio.run(run())
            self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
