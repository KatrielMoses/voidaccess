"""22S-3: the GitHub source uses GITHUB_TOKEN when set, never calls code search
without one, and backs off on 403/429 with a ``rate_limited`` status instead
of "ok with 0 results". All HTTP is mocked (aioresponses)."""

from __future__ import annotations

import asyncio
import re
import time

import pytest
from aioresponses import aioresponses

import sources.github_scraper as gh
from sources import source_control as sc
from progress import trace as tr

SEARCH_CODE = re.compile(r"^https://api\.github\.com/search/code.*$")
SEARCH_REPOS = re.compile(r"^https://api\.github\.com/search/repositories.*$")
README = re.compile(r"^https://api\.github\.com/repos/.*/readme$")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    gh.reset_rate_limit_state()
    sc.reset_tracker()
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_SCRAPING_ENABLED", "true")
    monkeypatch.delenv("VOIDACCESS_DISABLED_SOURCES", raising=False)

    async def _no_sleep(*_a, **_k):
        return None

    monkeypatch.setattr(gh.asyncio, "sleep", _no_sleep)
    yield
    gh.reset_rate_limit_state()
    sc.reset_tracker()


def _repo_payload() -> dict:
    return {"items": [{"name": "toolkit", "full_name": "someone/toolkit",
                       "html_url": "https://github.com/someone/toolkit"}]}


def _readme_payload() -> dict:
    import base64

    body = "Research notes about a stealer family. " * 10
    return {"content": base64.b64encode(body.encode()).decode()}


def _calls(m, pattern) -> list:
    return [(k, v) for k, v in m.requests.items() if pattern.match(str(k[1]))]


def test_token_is_sent_and_code_search_runs(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-not-real")
    with aioresponses() as m:
        m.get(SEARCH_CODE, payload={"items": []})
        m.get(SEARCH_REPOS, payload={"items": []})
        asyncio.run(gh.scrape_github("lumma stealer"))
        assert _calls(m, SEARCH_CODE), "authenticated runs use code search"
    # The token rides on the session headers (aioresponses records only
    # per-call kwargs), and the authenticated search pacing applies.
    scraper = gh.GitHubScraper()
    assert scraper._headers["Authorization"] == "Bearer test-token-not-real"
    assert sc.resolve_status("github") == sc.STATUS_OK


def test_no_token_skips_code_search():
    with aioresponses() as m:
        m.get(SEARCH_REPOS, payload={"items": []})
        asyncio.run(gh.scrape_github("lumma stealer"))
        assert not _calls(m, SEARCH_CODE)
        assert len(_calls(m, SEARCH_REPOS)) == 1
    assert "Authorization" not in gh.GitHubScraper()._headers


def test_403_quota_spent_is_rate_limited_and_stops():
    reset = str(int(time.time()) + 30)
    with aioresponses() as m:
        m.get(SEARCH_REPOS, status=403, headers={"X-RateLimit-Remaining": "0",
                                                 "X-RateLimit-Reset": reset},
              payload={"message": "API rate limit exceeded"})
        out = asyncio.run(gh.scrape_github("redline stealer"))
        assert len(_calls(m, SEARCH_REPOS)) == 1
    assert out == []
    assert sc.resolve_status("github") == sc.STATUS_RATE_LIMITED
    entry = sc.source_entry("github", count=0)
    assert entry["status"] == "rate_limited"
    assert tr.map_source_status(entry["status"], allow_skipped=False) == "rate_limited"


def test_429_long_retry_after_is_not_waited_for():
    with aioresponses() as m:
        m.get(SEARCH_REPOS, status=429, headers={"Retry-After": "120"})
        out = asyncio.run(gh.scrape_github("redline stealer"))
        assert len(_calls(m, SEARCH_REPOS)) == 1
    assert out == []
    assert sc.resolve_status("github") == "rate_limited"


def test_429_short_retry_after_is_retried_once():
    with aioresponses() as m:
        m.get(SEARCH_REPOS, status=429, headers={"Retry-After": "1"})
        m.get(SEARCH_REPOS, payload=_repo_payload())
        m.get(README, payload=_readme_payload())
        out = asyncio.run(gh.scrape_github("stealer research"))
    assert len(out) == 1 and out[0]["source_type"] == "github"
    assert sc.resolve_status("github") == sc.STATUS_OK


def test_secondary_limit_403_without_headers_is_detected():
    with aioresponses() as m:
        m.get(SEARCH_REPOS, status=403,
              body='{"message": "You have exceeded a secondary rate limit."}')
        asyncio.run(gh.scrape_github("redline stealer"))
    assert sc.resolve_status("github") == "rate_limited"


def test_plain_403_is_not_a_rate_limit():
    with aioresponses() as m:
        m.get(SEARCH_REPOS, status=403, body='{"message": "Forbidden"}')
        asyncio.run(gh.scrape_github("redline stealer"))
    assert sc.resolve_status("github") != "rate_limited"


def test_rate_limit_mid_run_stops_later_calls():
    with aioresponses() as m:
        m.get(SEARCH_REPOS, payload={"items": [
            {"name": "a", "full_name": "x/a", "html_url": "https://github.com/x/a"},
            {"name": "b", "full_name": "x/b", "html_url": "https://github.com/x/b"},
        ]})
        m.get(README, status=429, headers={"Retry-After": "600"}, repeat=True)
        asyncio.run(gh.scrape_github("stealer research"))
        # The two README fetches run concurrently; after the limit no new call
        # is started (at most one in flight per item, never a retry).
        assert len(_calls(m, README)) <= 2
    assert sc.resolve_status("github") == "rate_limited"


def test_cooldown_skips_next_run_without_a_request():
    with aioresponses() as m:
        m.get(SEARCH_REPOS, status=429, headers={"Retry-After": "300"})
        asyncio.run(gh.scrape_github("redline stealer"))
    sc.reset_tracker()  # a new run in the same process
    with aioresponses() as m:
        out = asyncio.run(gh.scrape_github("redline stealer"))
        assert not m.requests
    assert out == []
    assert sc.resolve_status("github") == "rate_limited"


def test_cooldown_is_capped():
    with aioresponses() as m:
        m.get(SEARCH_REPOS, status=429, headers={"Retry-After": "999999"})
        asyncio.run(gh.scrape_github("redline stealer"))
    assert gh._cooldown_until <= time.time() + gh.COOLDOWN_MAX_S + 1


def test_trace_vocabulary_has_rate_limited():
    assert "rate_limited" in tr.SEARCH_STATUSES
    assert "rate_limited" in sc.SOURCE_STATUSES
    assert tr.map_source_status("rate_limited", allow_skipped=True) == "rate_limited"


def test_disabled_still_wins_over_rate_limited(monkeypatch):
    monkeypatch.setenv("VOIDACCESS_DISABLED_SOURCES", "github")
    sc.get_tracker().set_state("github", sc.STATUS_RATE_LIMITED)
    assert sc.resolve_status("github") == sc.STATUS_DISABLED
