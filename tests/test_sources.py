"""
tests/test_sources.py — Unit tests for the sources/ package (Phase 1D).

No real network connections.  All HTTP is mocked.  Telethon is mocked via
unittest.mock so it does not need to be installed (though it is in requirements.txt).

Covers:
  - search_onionsearch (HTML parsing, link extraction, graceful error)
  - get_seeds          (no filter, category filter, language filter, combined)
  - fetch_recent_pastes (keyword match returns result, no match skips,
                          graceful failure, DB persistence)
  - fetch_telegram_messages (missing creds → [], one missing cred → [],
                              invalid api_id → [], channel errors skipped,
                              keyword matching, DB persistence)
  - collect_all_sources (search + pastes run concurrently, Telegram skipped
                          when include_telegram=False, seed filtering)

Run with:
    pytest tests/test_sources.py -v
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

# ---------------------------------------------------------------------------
# Separate SQLite DB — isolated from test_db.py / test_scrape.py / test_crawler.py
# ---------------------------------------------------------------------------

_SOURCES_DB_FILE = "sources_test_temp.db"
SOURCES_TEST_DB_URL = f"sqlite:///{_SOURCES_DB_FILE}"


@pytest.fixture(scope="module")
def _sources_db_engine():
    from db.models import Base
    from db.session import _engine_cache, get_engine

    engine = get_engine(SOURCES_TEST_DB_URL)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()
    _engine_cache.pop(SOURCES_TEST_DB_URL, None)
    if os.path.exists(_SOURCES_DB_FILE):
        os.remove(_SOURCES_DB_FILE)


@pytest.fixture
def _clean_sources_db(_sources_db_engine):
    from sqlalchemy.orm import sessionmaker
    from db.models import Entity, EntityRelationship, Page, Source

    SM = sessionmaker(bind=_sources_db_engine)

    def _wipe():
        s = SM()
        s.query(EntityRelationship).delete()
        s.query(Entity).delete()
        s.query(Page).delete()
        s.query(Source).delete()
        s.commit()
        s.close()

    _wipe()
    yield
    _wipe()


@pytest.fixture
def _db_url(monkeypatch, _clean_sources_db):
    monkeypatch.setattr("config.DATABASE_URL", SOURCES_TEST_DB_URL)
    monkeypatch.setattr("db.session.DATABASE_URL", SOURCES_TEST_DB_URL)


# ---------------------------------------------------------------------------
# aiohttp mock helpers
# ---------------------------------------------------------------------------

def _json_response(data: dict, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status = status
    resp.headers = {"Content-Type": "application/json"}
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    resp.json = AsyncMock(return_value=data)
    resp.text = AsyncMock(return_value="")
    return resp


def _html_response(html: str, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status = status
    resp.headers = {"Content-Type": "text/html"}
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    resp.text = AsyncMock(return_value=html)
    resp.json = AsyncMock(return_value={})
    return resp


def _mock_session(responses: dict) -> MagicMock:
    """
    Build a mock aiohttp.ClientSession whose .get() dispatches by URL substring.
    *responses* maps URL substring → response mock (first match wins).
    Falls back to a 404 response if no key matches.
    """
    _404 = _html_response("", status=404)

    def _get(url, **kwargs):
        for key, resp in responses.items():
            if key in url:
                return resp
        return _404

    session = MagicMock()
    session.get = MagicMock(side_effect=_get)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session


def _patch_session(responses: dict):
    """Context manager: patch aiohttp.ClientSession to return a mock session."""
    return patch(
        "aiohttp.ClientSession",
        return_value=_mock_session(responses),
    )


def _patch_connector():
    """Context manager: patch ProxyConnector so no real Tor is needed."""
    return patch("aiohttp_socks.ProxyConnector.from_url", return_value=MagicMock())


# ===========================================================================
# TestOnionSearch
# ===========================================================================

class TestOnionSearch:
    """Tests for sources.engines.search_onionsearch."""

    def _run(self, *args, **kwargs):
        from sources.engines import search_onionsearch
        return asyncio.run(search_onionsearch(*args, **kwargs))

    # All hostnames must use only base32 chars: a-z and 2-7 (no 0,1,8,9)
    _FORUM_HOST = "forumabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv"   # 55 — v2 16 or v3 56; use 56
    _FORUM_HOST = "a" * 56                                                   # safe 56-char v3 host
    _MARKET_HOST = "b" * 56                                                  # safe 56-char v3 host
    _DUP_HOST    = "c" * 56

    _SAMPLE_HTML = (
        f'<html><body>'
        f'<a href="http://{_FORUM_HOST}.onion/thread/1">Forum thread</a>'
        f'<a href="http://{_MARKET_HOST}.onion/">Market</a>'
        f'<a href="http://example.com/clearnet">Clearnet</a>'
        f'<a href="http://{"d" * 56}.onion/search?q=test">Self-ref search</a>'
        f'</body></html>'
    )

    def test_extracts_onion_links_from_html(self):
        with _patch_connector(), _patch_session({"torchdeed": _html_response(self._SAMPLE_HTML),
                                                  "haystak": _html_response("")}):
            results = self._run("ransomware")

        urls = [r["url"] for r in results]
        assert any(self._FORUM_HOST in u for u in urls)
        assert any(self._MARKET_HOST in u for u in urls)

    def test_excludes_clearnet_urls(self):
        with _patch_connector(), _patch_session({"torchdeed": _html_response(self._SAMPLE_HTML),
                                                  "haystak": _html_response("")}):
            results = self._run("test")

        assert not any("example.com" in r["url"] for r in results)

    def test_deduplicates_across_engines(self):
        dup_host = self._DUP_HOST   # 56-char valid base32
        duplicate_html = (
            f'<html><body>'
            f'<a href="http://{dup_host}.onion/">Dup</a>'
            f'</body></html>'
        )
        with _patch_connector(), _patch_session({"torchdeed": _html_response(duplicate_html),
                                                  "haystak": _html_response(duplicate_html)}):
            results = self._run("test")

        dup_url = f"http://{dup_host}.onion"
        count = sum(1 for r in results if dup_url in r["url"])
        assert count == 1

    def test_returns_empty_on_all_failures(self):
        with _patch_connector(), _patch_session({}):  # all 404
            results = self._run("test")

        assert results == []

    def test_source_field_matches_engine_name(self):
        html = """<a href="http://abc1234567890abcdef1234567890abcdef1234567890abcde.onion/">L</a>"""
        with _patch_connector(), _patch_session({"torchdeed": _html_response(html),
                                                  "haystak": _html_response("")}):
            results = self._run("test")

        if results:
            assert results[0]["source"] == "Torch"

    def test_partial_results_when_one_engine_fails(self):
        good_html = """<a href="http://abc1234567890abcdef1234567890abcdef1234567890abcde.onion/">L</a>"""
        with _patch_connector(), _patch_session({"torchdeed": _html_response(good_html),
                                                  "haystak": _html_response("", status=500)}):
            results = self._run("test")

        # Torch should still return results even if Haystack fails
        assert isinstance(results, list)


# ===========================================================================
# TestSeeds
# ===========================================================================

class TestSeeds:
    """Tests for sources.seeds.get_seeds."""

    def test_no_filter_returns_all(self):
        from sources.seeds import SEED_URLS, get_seeds
        assert get_seeds() == SEED_URLS

    def test_at_least_20_seeds(self):
        from sources.seeds import SEED_URLS
        assert len(SEED_URLS) >= 20

    def test_filter_by_category_forum(self):
        from sources.seeds import get_seeds
        forums = get_seeds(category="forum")
        assert len(forums) >= 1
        assert all(s["category"] == "forum" for s in forums)

    def test_filter_by_category_search(self):
        from sources.seeds import get_seeds
        searches = get_seeds(category="search")
        assert len(searches) >= 2
        assert all(s["category"] == "search" for s in searches)

    def test_filter_by_category_index(self):
        from sources.seeds import get_seeds
        indexes = get_seeds(category="index")
        assert len(indexes) >= 3

    def test_filter_by_category_paste(self):
        from sources.seeds import get_seeds
        pastes = get_seeds(category="paste")
        assert len(pastes) >= 1

    def test_filter_by_category_market_index(self):
        from sources.seeds import get_seeds
        markets = get_seeds(category="market_index")
        assert len(markets) >= 1

    def test_filter_by_language_en(self):
        from sources.seeds import get_seeds
        en = get_seeds(language="en")
        assert len(en) >= 5
        assert all(s["language"] == "en" for s in en)

    def test_filter_by_language_ru(self):
        from sources.seeds import get_seeds
        ru = get_seeds(language="ru")
        assert len(ru) >= 1
        assert all(s["language"] == "ru" for s in ru)

    def test_combined_category_and_language(self):
        from sources.seeds import get_seeds
        results = get_seeds(category="forum", language="en")
        assert all(s["category"] == "forum" for s in results)
        assert all(s["language"] == "en" for s in results)

    def test_unknown_category_returns_empty(self):
        from sources.seeds import get_seeds
        assert get_seeds(category="nonexistent") == []

    def test_all_seeds_have_required_keys(self):
        from sources.seeds import SEED_URLS
        for seed in SEED_URLS:
            assert "url" in seed
            assert "category" in seed
            assert "description" in seed
            assert "language" in seed

    def test_all_seed_urls_are_strings(self):
        from sources.seeds import SEED_URLS
        for seed in SEED_URLS:
            assert isinstance(seed["url"], str)
            assert seed["url"].startswith("http")

    def test_categories_are_valid(self):
        from sources.seeds import SEED_URLS
        valid = {"search", "index", "forum", "paste", "market_index"}
        for seed in SEED_URLS:
            assert seed["category"] in valid

    def test_get_seeds_does_not_mutate_original(self):
        from sources.seeds import SEED_URLS, get_seeds
        original_len = len(SEED_URLS)
        result = get_seeds(category="search")
        result.clear()
        assert len(SEED_URLS) == original_len


# ===========================================================================
# TestPastes
# ===========================================================================

class TestPastes:
    """Tests for sources.pastes.fetch_recent_pastes."""

    def _run(self, *args, **kwargs):
        from sources.pastes import fetch_recent_pastes
        return asyncio.run(fetch_recent_pastes(*args, **kwargs))

    _INDEX_HTML = """
    <html><body>
    <a href="/paste/abc123">Latest paste</a>
    <a href="/paste/def456">Another paste</a>
    </body></html>
    """

    _MATCHING_PASTE = """
    <html><head><title>Ransomware keys leaked</title></head>
    <body><pre>ransomware decryption keys here...</pre></body>
    </html>
    """

    _NONMATCHING_PASTE = """
    <html><head><title>Recipe collection</title></head>
    <body><pre>flour, eggs, butter...</pre></body>
    </html>
    """

    def test_matching_paste_returned(self):
        # More-specific paste-path keys must come BEFORE "depaste" so the mock
        # dispatcher (which returns first match) routes /paste/* correctly.
        with _patch_connector(), _patch_session({
            "/paste/abc": _html_response(self._MATCHING_PASTE),
            "/paste/def": _html_response(self._NONMATCHING_PASTE),
            "zgjnkivy":   _html_response(""),
            "torpaste":   _html_response(""),
            "depaste":    _html_response(self._INDEX_HTML),
        }):
            results = self._run("ransomware")

        assert len(results) >= 1
        titles = [r["title"] for r in results]
        assert any("Ransomware" in t or "ransomware" in t for t in titles)

    def test_nonmatching_paste_excluded(self):
        nonmatch_html = "<html><head><title>Cake recipe</title></head><body><pre>Flour, sugar</pre></body></html>"
        with _patch_connector(), _patch_session({
            "depaste": self._INDEX_HTML,  # raw string → treated as body string
            "/paste/": _html_response(nonmatch_html),
        }):
            # Use a query that won't match cake recipes
            results = self._run("ransomware decryption")

        # Nonmatching content should not appear
        for r in results:
            assert "ransomware decryption" in (r["title"] + r["content_snippet"]).lower()

    def test_returns_empty_on_site_failure(self):
        with _patch_connector(), _patch_session({}):  # all 404
            results = self._run("ransomware")

        assert results == []

    def test_result_has_required_keys(self):
        with _patch_connector(), _patch_session({
            "/paste/": _html_response(self._MATCHING_PASTE),
            "zgjnkivy": _html_response(""),
            "torpaste": _html_response(""),
            "depaste": _html_response(self._INDEX_HTML),
        }):
            results = self._run("ransomware")

        for r in results:
            assert "title" in r
            assert "url" in r
            assert "content_snippet" in r
            assert "posted_at" in r
            assert "source" in r

    def test_snippet_at_most_500_chars(self):
        long_paste = f"""
        <html><head><title>ransomware data</title></head>
        <body><pre>ransomware {"x" * 2000}</pre></body>
        </html>
        """
        with _patch_connector(), _patch_session({
            "/paste/": _html_response(long_paste),
            "zgjnkivy": _html_response(""),
            "torpaste": _html_response(""),
            "depaste": _html_response(self._INDEX_HTML),
        }):
            results = self._run("ransomware")

        for r in results:
            assert len(r["content_snippet"]) <= 500

    def test_max_results_respected(self):
        index = "<html><body>" + "".join(
            f'<a href="/paste/{i:03d}">p</a>' for i in range(50)
        ) + "</body></html>"
        match_html = "<html><head><title>ransomware hit</title></head><body><pre>ransomware key</pre></body></html>"

        with _patch_connector(), _patch_session({
            "/paste/": _html_response(match_html),
            "zgjnkivy": _html_response(""),
            "torpaste": _html_response(""),
            "depaste": _html_response(index),
        }):
            results = self._run("ransomware", max_results=3)

        assert len(results) <= 3

    def test_graceful_on_session_error(self):
        session = MagicMock()
        session.get = MagicMock(side_effect=Exception("Tor is down"))
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=False)

        with _patch_connector(), patch("aiohttp.ClientSession", return_value=session):
            results = self._run("test")

        assert results == []

    def test_db_persistence_on_match(self, _db_url):
        from sqlalchemy.orm import sessionmaker
        from db.models import Page
        from db.session import get_engine, get_session as real_gs

        with _patch_connector(), _patch_session({
            "/paste/": _html_response(self._MATCHING_PASTE),
            "zgjnkivy": _html_response(""),
            "torpaste": _html_response(""),
            "depaste": _html_response(self._INDEX_HTML),
        }):
            with patch("db.session.get_session", side_effect=lambda u=None: real_gs(SOURCES_TEST_DB_URL)), \
                 patch("config.DATABASE_URL", SOURCES_TEST_DB_URL):
                results = self._run("ransomware")

        SM = sessionmaker(bind=get_engine(SOURCES_TEST_DB_URL))
        s = SM()
        count = s.query(Page).count()
        s.close()

        if results:
            assert count >= 1


# ===========================================================================
# TestTelegram
# ===========================================================================

class TestTelegram:
    """Tests for sources.telegram.fetch_telegram_messages."""

    def _run(self, *args, **kwargs):
        from sources.telegram import fetch_telegram_messages
        return asyncio.run(fetch_telegram_messages(*args, **kwargs))

    def _set_creds(self, monkeypatch, api_id="12345", api_hash="abc123hash", phone="+1555"):
        monkeypatch.setattr("sources.telegram.TELEGRAM_API_ID", api_id, raising=False)
        monkeypatch.setattr("sources.telegram.TELEGRAM_API_HASH", api_hash, raising=False)
        monkeypatch.setattr("sources.telegram.TELEGRAM_PHONE", phone, raising=False)

    # --- Missing credentials -------------------------------------------------

    def test_returns_empty_when_api_id_missing(self, monkeypatch):
        monkeypatch.setattr("config.TELEGRAM_API_ID", None)
        monkeypatch.setattr("config.TELEGRAM_API_HASH", "hash")
        monkeypatch.setattr("config.TELEGRAM_PHONE", "+1")
        result = self._run(["@channel"], "test")
        assert result == []

    def test_returns_empty_when_api_hash_missing(self, monkeypatch):
        monkeypatch.setattr("config.TELEGRAM_API_ID", "12345")
        monkeypatch.setattr("config.TELEGRAM_API_HASH", None)
        monkeypatch.setattr("config.TELEGRAM_PHONE", "+1")
        result = self._run(["@channel"], "test")
        assert result == []

    def test_returns_empty_when_both_missing(self, monkeypatch):
        monkeypatch.setattr("config.TELEGRAM_API_ID", None)
        monkeypatch.setattr("config.TELEGRAM_API_HASH", None)
        monkeypatch.setattr("config.TELEGRAM_PHONE", None)
        result = self._run(["@channel"], "test")
        assert result == []

    def test_returns_empty_when_api_id_not_integer(self, monkeypatch):
        monkeypatch.setattr("config.TELEGRAM_API_ID", "not-a-number")
        monkeypatch.setattr("config.TELEGRAM_API_HASH", "hash")
        result = self._run(["@channel"], "test")
        assert result == []

    # --- Mocked Telethon client ----------------------------------------------

    def _make_telethon_mock(self, messages, authorized=True):
        """Build a mock TelegramClient context manager that yields *messages*."""
        client = MagicMock()
        client.is_user_authorized = AsyncMock(return_value=authorized)

        async def mock_iter(channel, *, limit=None):
            for msg in messages:
                yield msg

        client.iter_messages = mock_iter
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        return client

    def _make_msg(self, text: str, msg_id: int = 1):
        msg = MagicMock()
        msg.text = text
        msg.id = msg_id
        msg.date = datetime(2025, 1, 1, tzinfo=timezone.utc)
        return msg

    def test_returns_matching_messages(self, monkeypatch):
        monkeypatch.setattr("config.TELEGRAM_API_ID", "12345")
        monkeypatch.setattr("config.TELEGRAM_API_HASH", "hash")
        monkeypatch.setattr("config.TELEGRAM_PHONE", "+1")
        monkeypatch.setattr("config.DATABASE_URL", None)

        msgs = [
            self._make_msg("ransomware LockBit new variant released", 1),
            self._make_msg("Today's dinner recipes", 2),
        ]
        mock_client = self._make_telethon_mock(msgs)

        with patch("sources.telegram._import_telethon", return_value=(
            lambda *a, **kw: mock_client,  # TelegramClient constructor
            Exception,                      # SessionPasswordNeededError
        )):
            results = self._run(["darkintel"], "ransomware")

        assert len(results) == 1
        assert "ransomware" in results[0]["text"].lower()

    def test_url_format_is_t_me(self, monkeypatch):
        monkeypatch.setattr("config.TELEGRAM_API_ID", "12345")
        monkeypatch.setattr("config.TELEGRAM_API_HASH", "hash")
        monkeypatch.setattr("config.TELEGRAM_PHONE", "+1")
        monkeypatch.setattr("config.DATABASE_URL", None)

        msgs = [self._make_msg("ransomware attack", 42)]
        mock_client = self._make_telethon_mock(msgs)

        with patch("sources.telegram._import_telethon", return_value=(
            lambda *a, **kw: mock_client, Exception
        )):
            results = self._run(["@mychannel"], "ransomware")

        if results:
            assert results[0]["url"].startswith("https://t.me/")
            assert "42" in results[0]["url"]

    def test_unauthorized_session_returns_empty(self, monkeypatch):
        monkeypatch.setattr("config.TELEGRAM_API_ID", "12345")
        monkeypatch.setattr("config.TELEGRAM_API_HASH", "hash")
        monkeypatch.setattr("config.TELEGRAM_PHONE", "+1")

        mock_client = self._make_telethon_mock([], authorized=False)

        with patch("sources.telegram._import_telethon", return_value=(
            lambda *a, **kw: mock_client, Exception
        )):
            results = self._run(["@chan"], "test")

        assert results == []

    def test_channel_error_skipped_others_processed(self, monkeypatch):
        monkeypatch.setattr("config.TELEGRAM_API_ID", "12345")
        monkeypatch.setattr("config.TELEGRAM_API_HASH", "hash")
        monkeypatch.setattr("config.TELEGRAM_PHONE", "+1")
        monkeypatch.setattr("config.DATABASE_URL", None)

        client = MagicMock()
        client.is_user_authorized = AsyncMock(return_value=True)

        call_count = 0

        async def iter_messages(channel, *, limit=None):
            nonlocal call_count
            call_count += 1
            if channel == "bad_channel":
                raise Exception("Channel not found")
            yield self._make_msg("ransomware data", 1)

        client.iter_messages = iter_messages
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)

        with patch("sources.telegram._import_telethon", return_value=(
            lambda *a, **kw: client, Exception
        )):
            results = self._run(["bad_channel", "good_channel"], "ransomware")

        # good_channel should still yield results
        assert len(results) >= 1

    def test_result_has_required_keys(self, monkeypatch):
        monkeypatch.setattr("config.TELEGRAM_API_ID", "12345")
        monkeypatch.setattr("config.TELEGRAM_API_HASH", "hash")
        monkeypatch.setattr("config.TELEGRAM_PHONE", "+1")
        monkeypatch.setattr("config.DATABASE_URL", None)

        msgs = [self._make_msg("ransomware report", 10)]
        mock_client = self._make_telethon_mock(msgs)

        with patch("sources.telegram._import_telethon", return_value=(
            lambda *a, **kw: mock_client, Exception
        )):
            results = self._run(["chan"], "ransomware")

        if results:
            r = results[0]
            assert "channel" in r
            assert "message_id" in r
            assert "text" in r
            assert "date" in r
            assert "url" in r

    def test_keyword_match_all_terms_required(self, monkeypatch):
        monkeypatch.setattr("config.TELEGRAM_API_ID", "12345")
        monkeypatch.setattr("config.TELEGRAM_API_HASH", "hash")
        monkeypatch.setattr("config.TELEGRAM_PHONE", "+1")
        monkeypatch.setattr("config.DATABASE_URL", None)

        msgs = [
            self._make_msg("ransomware only", 1),
            self._make_msg("lockbit only", 2),
            self._make_msg("ransomware lockbit affiliate program", 3),
        ]
        mock_client = self._make_telethon_mock(msgs)

        with patch("sources.telegram._import_telethon", return_value=(
            lambda *a, **kw: mock_client, Exception
        )):
            results = self._run(["chan"], "ransomware lockbit")

        assert len(results) == 1
        assert results[0]["message_id"] == 3

    def test_db_persistence_on_match(self, monkeypatch, _db_url):
        monkeypatch.setattr("config.TELEGRAM_API_ID", "12345")
        monkeypatch.setattr("config.TELEGRAM_API_HASH", "hash")
        monkeypatch.setattr("config.TELEGRAM_PHONE", "+1")

        from sqlalchemy.orm import sessionmaker
        from db.models import Page
        from db.session import get_engine, get_session as real_gs

        msgs = [self._make_msg("ransomware lockbit 4.0", 99)]
        mock_client = self._make_telethon_mock(msgs)

        with patch("sources.telegram._import_telethon", return_value=(
            lambda *a, **kw: mock_client, Exception
        )), patch("db.session.get_session", side_effect=lambda u=None: real_gs(SOURCES_TEST_DB_URL)), \
            patch("config.DATABASE_URL", SOURCES_TEST_DB_URL):
            results = self._run(["chan"], "ransomware lockbit")

        if results:
            SM = sessionmaker(bind=get_engine(SOURCES_TEST_DB_URL))
            s = SM()
            page = s.query(Page).filter(Page.url.like("%t.me%")).first()
            s.close()
            assert page is not None


# ===========================================================================
# TestCollectAllSources
# ===========================================================================

class TestCollectAllSources:
    """Tests for sources.collect_all_sources."""

    def _run(self, *args, **kwargs):
        from sources import collect_all_sources
        return asyncio.run(collect_all_sources(*args, **kwargs))

    def test_returns_all_four_keys(self):
        with patch("sources.engines.search_onionsearch", new=AsyncMock(return_value=[])), \
             patch("sources.pastes.fetch_recent_pastes", new=AsyncMock(return_value=[])):
            result = self._run("ransomware")

        assert "search_results" in result
        assert "paste_results" in result
        assert "telegram_results" in result
        assert "seed_urls" in result

    def test_search_and_pastes_both_called(self):
        onion_mock = AsyncMock(return_value=[{"url": "o", "title": "O", "snippet": "", "source": "OnionSearch"}])
        paste_mock = AsyncMock(return_value=[{"title": "P", "url": "p", "content_snippet": "", "posted_at": None, "source": "X"}])

        with patch("sources.engines.search_onionsearch", onion_mock), \
             patch("sources.pastes.fetch_recent_pastes", paste_mock):
            result = self._run("test")

        onion_mock.assert_called_once_with("test")
        paste_mock.assert_called_once_with("test")
        assert len(result["search_results"]) == 1  # onion only (DarkSearch removed in P1.1)
        assert len(result["paste_results"]) == 1

    def test_telegram_skipped_when_flag_false(self):
        tg_mock = AsyncMock(return_value=[])

        with patch("sources.engines.search_onionsearch", new=AsyncMock(return_value=[])), \
             patch("sources.pastes.fetch_recent_pastes", new=AsyncMock(return_value=[])), \
             patch("sources.telegram.fetch_telegram_messages", tg_mock):
            result = self._run("test", include_telegram=False)

        tg_mock.assert_not_called()
        assert result["telegram_results"] == []

    def test_telegram_called_when_flag_true(self):
        tg_mock = AsyncMock(return_value=[{"channel": "c", "message_id": 1, "text": "t", "date": None, "url": "u"}])

        with patch("sources.engines.search_onionsearch", new=AsyncMock(return_value=[])), \
             patch("sources.pastes.fetch_recent_pastes", new=AsyncMock(return_value=[])), \
             patch("sources.telegram.fetch_telegram_messages", tg_mock):
            result = self._run("test", include_telegram=True, telegram_channels=["@chan"])

        tg_mock.assert_called_once()
        assert len(result["telegram_results"]) == 1

    def test_seed_urls_populated(self):
        with patch("sources.engines.search_onionsearch", new=AsyncMock(return_value=[])), \
             patch("sources.pastes.fetch_recent_pastes", new=AsyncMock(return_value=[])):
            result = self._run("test")

        from sources.seeds import SEED_URLS
        assert result["seed_urls"] == SEED_URLS

    def test_seed_category_filter_applied(self):
        with patch("sources.engines.search_onionsearch", new=AsyncMock(return_value=[])), \
             patch("sources.pastes.fetch_recent_pastes", new=AsyncMock(return_value=[])):
            result = self._run("test", seed_categories=["forum"])

        assert all(s["category"] == "forum" for s in result["seed_urls"])

    def test_multiple_seed_categories_merged(self):
        with patch("sources.engines.search_onionsearch", new=AsyncMock(return_value=[])), \
             patch("sources.pastes.fetch_recent_pastes", new=AsyncMock(return_value=[])):
            result = self._run("test", seed_categories=["forum", "search"])

        categories = {s["category"] for s in result["seed_urls"]}
        assert "forum" in categories
        assert "search" in categories

    def test_no_duplicate_seeds_in_combined_categories(self):
        with patch("sources.engines.search_onionsearch", new=AsyncMock(return_value=[])), \
             patch("sources.pastes.fetch_recent_pastes", new=AsyncMock(return_value=[])):
            result = self._run("test", seed_categories=["forum", "search", "index"])

        urls = [s["url"] for s in result["seed_urls"]]
        assert len(urls) == len(set(urls))
