"""
sources/github_scraper.py — GitHub clearnet intelligence source for VoidAccess.

Searches GitHub code and repositories for security-relevant content that
matches an investigation query.  Runs over CLEARNET — GitHub is public and
does not require Tor.

Typical high-signal content found on GitHub:
    - Leaked configs (API keys, credentials, internal endpoints)
    - Malware source code & proof-of-concept exploits
    - C2 / beacon configuration files
    - Threat actor tooling, dropper scripts, stealers
    - Security research write-ups

Authentication is OPTIONAL but strongly recommended:
    - Unauthenticated: 10 requests/minute on search, and a 60 requests/HOUR
      primary cap that /search/code cannot be used under at all (GitHub
      requires authentication for code search).
    - Authenticated:   30 requests/minute on search (10/minute on code
      search), 5,000/hour primary — set GITHUB_TOKEN to enable.

Public API:
    async def scrape_github(
        query: str,
        refined_query: str = "",
        max_results: int = 15,
    ) -> list[dict]

Returns page dicts compatible with the existing extraction pipeline:
    {
        "url": str,
        "text_content": str,
        "title": str,
        "source_type": "github",
        "source_name": "GitHub",
        "github_repo": str,
        "github_filename": str,
        "github_stars": int,
        "scraped_at": str,
        "word_count": int,
        "relevance": int,
    }
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

import aiohttp

import pacing
from sources.source_control import request_trace_config, source_gate
from utils.content_safety import (
    is_blocked_query,
    is_blocked_url,
    sanitize_content,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GITHUB_API_BASE = "https://api.github.com"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"

# Max file size to fetch (200KB)
MAX_FILE_SIZE = 200 * 1024

# Max results per search type
MAX_CODE_RESULTS = 10
MAX_REPO_RESULTS = 5

# Max total GitHub items per investigation
MAX_TOTAL_RESULTS = 15

# Rate limit delays (seconds).  Provider-dictated, so these are FLOORS routed
# through pacing.scale_delay_floor() — `aggressive` clamps at them, it must
# never shorten them.  Verified against GitHub's REST docs 2026-07-29:
#
#   /search/*      30 req/min authenticated, 10 req/min unauthenticated
#   /search/code   10 req/min AND requires authentication — the 30/min tier
#                  does not apply to it, so it keeps its own constant
#   core REST      5,000 req/hr authenticated (blob fetches live here, not
#                  under the search quota)
#
# NOTE: the *primary* unauthenticated limit is 60 req/hr, which no
# per-request delay can express — that is an hourly budget, tracked as
# pattern 1 in docs/BACKLOG.md. Set GITHUB_TOKEN to stay clear of it.
SEARCH_RATE_LIMIT_DELAY_UNAUTH = 6.5   # 10/min = 6.0 s + margin
SEARCH_RATE_LIMIT_DELAY_AUTH = 2.2     # 30/min = 2.0 s + margin
CODE_SEARCH_RATE_LIMIT_DELAY = 6.5     # 10/min in BOTH branches
BLOB_FETCH_RATE_LIMIT_DELAY = 1.0      # core REST; 5,000/hr needs 0.72 s

# Request timeout (`normal` pacing baseline)
REQUEST_TIMEOUT = 30

# Security-relevant file extensions to fetch
SECURITY_EXTENSIONS = {
    ".py", ".js", ".ts", ".go", ".rs",
    ".c", ".cpp", ".cs", ".java",
    ".sh", ".bash", ".ps1", ".bat",
    ".yaml", ".yml", ".json", ".toml",
    ".conf", ".config", ".ini", ".env",
    ".txt", ".md", ".log",
}

# File names that are almost always valuable
HIGH_VALUE_FILENAMES = {
    "config.py", "config.js", "config.json",
    "settings.py", "settings.json",
    "malware.py", "rat.py", "stealer.py",
    "c2.py", "c2.js", "server.py",
    "payload.py", "dropper.py",
    "keylogger.py", "ransomware.py",
    "exploit.py", "exploit.js",
    "credentials.txt", "passwords.txt",
    "victims.txt", "targets.txt",
    "README.md", "README.txt",
}

# Repositories to skip (noise: tutorials, awesome lists, etc.)
SKIP_REPO_PATTERNS = [
    r"awesome-.*",
    r".*-tutorial",
    r".*-course",
    r".*-book",
    r".*-cheatsheet",
]


# ---------------------------------------------------------------------------
# Scraper
# ---------------------------------------------------------------------------


class GitHubScraper:
    """
    Scrapes GitHub for security-relevant content using the GitHub Search API.
    Works with or without authentication.
    """

    def __init__(self):
        self._token = os.getenv("GITHUB_TOKEN", "").strip()
        self._session: Optional[aiohttp.ClientSession] = None
        # Provider-dictated quotas, so scale_delay_floor() — NOT scale_delay(),
        # which shrinks under `aggressive` and would push us past GitHub's
        # published per-minute limits.
        self._search_delay = pacing.scale_delay_floor(
            SEARCH_RATE_LIMIT_DELAY_AUTH if self._token
            else SEARCH_RATE_LIMIT_DELAY_UNAUTH
        )
        # /search/code is 10/min even authenticated — it does not share the
        # 30/min tier the other search endpoints get.
        self._code_search_delay = pacing.scale_delay_floor(
            CODE_SEARCH_RATE_LIMIT_DELAY
        )
        self._blob_fetch_delay = pacing.scale_delay_floor(
            BLOB_FETCH_RATE_LIMIT_DELAY
        )

    @property
    def _headers(self) -> dict:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "VoidAccess-OSINT/1.1",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            headers=self._headers,
            timeout=aiohttp.ClientTimeout(total=pacing.scale_timeout(REQUEST_TIMEOUT)),
            trace_configs=[request_trace_config("github")],
        )
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def search_and_fetch(
        self,
        query: str,
        refined_query: str = "",
        max_results: int = MAX_TOTAL_RESULTS,
    ) -> list[dict]:
        """
        Search GitHub and return page dicts compatible with the extraction
        pipeline.
        """
        blocked, _ = is_blocked_query(query)
        if blocked:
            logger.warning("GitHub scraping blocked — prohibited query")
            return []

        search_queries = self._build_search_queries(query, refined_query)

        auth_status = "authenticated" if self._token else "unauthenticated"
        logger.info(
            "GitHub scraping (%s): '%s'",
            auth_status,
            query[:50],
        )

        all_results: list[dict] = []
        seen_urls: set[str] = set()

        code_task = self._search_code(search_queries[0])
        repo_task = self._search_repos(search_queries[0])

        code_results, repo_results = await asyncio.gather(
            code_task,
            repo_task,
            return_exceptions=True,
        )

        if isinstance(code_results, list):
            for item in code_results:
                url = item.get("url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    all_results.append(item)

        if isinstance(repo_results, list):
            for item in repo_results:
                url = item.get("url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    all_results.append(item)

        all_results.sort(key=lambda x: x.get("relevance", 0), reverse=True)
        final = all_results[:max_results]

        logger.info("GitHub scraping: %d results found", len(final))
        return final

    def _build_search_queries(
        self,
        query: str,
        refined_query: str,
    ) -> list[str]:
        """
        Build GitHub search queries.  GitHub code search has specific syntax —
        keep queries short and reasonably safe.
        """
        queries: list[str] = []

        base = refined_query or query
        base = re.sub(r"[^\w\s\-.]", " ", base).strip()[:100]
        queries.append(base)

        # Add language-specific variants for known malware/tooling names.
        TOOL_LANGS = {
            "cobalt strike": "malleable",
            "metasploit": "language:ruby",
            "mimikatz": "language:c",
            "covenant": "language:csharp",
            "sliver": "language:go",
            "havoc": "language:c",
            "brute ratel": "config",
        }

        query_lower = query.lower()
        for tool, modifier in TOOL_LANGS.items():
            if tool in query_lower:
                queries.append(f"{tool} {modifier}")
                break

        return queries[:2]

    async def _search_code(self, search_query: str) -> list[dict]:
        """Search GitHub code and fetch file content."""
        if not self._session:
            return []

        results: list[dict] = []

        try:
            params = {
                "q": search_query,
                "per_page": MAX_CODE_RESULTS,
                "sort": "indexed",
                "order": "desc",
            }

            async with self._session.get(
                f"{GITHUB_API_BASE}/search/code",
                params=params,
            ) as resp:
                if resp.status == 403:
                    retry_after = int(
                        resp.headers.get("X-RateLimit-Reset", 60)
                    )
                    logger.warning(
                        "GitHub rate limit hit. Reset in %ss",
                        retry_after,
                    )
                    return []

                if resp.status == 422:
                    logger.debug(
                        "GitHub code search query invalid: %s",
                        search_query,
                    )
                    return []

                if resp.status != 200:
                    return []

                data = await resp.json()
                items = data.get("items", [])

            await asyncio.sleep(self._code_search_delay)

            fetch_tasks = []
            for item in items[:MAX_CODE_RESULTS]:
                repo_name = item.get("repository", {}).get("name", "")
                if self._is_noise_repo(repo_name):
                    continue

                filename = item.get("name", "")
                ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""

                if (
                    ext.lower() not in SECURITY_EXTENSIONS
                    and filename not in HIGH_VALUE_FILENAMES
                ):
                    continue

                fetch_tasks.append(self._fetch_code_file(item))

            if fetch_tasks:
                fetched = await asyncio.gather(
                    *fetch_tasks, return_exceptions=True
                )
                for f in fetched:
                    if isinstance(f, dict) and f.get("text_content"):
                        results.append(f)

        except Exception as e:
            logger.debug("GitHub code search error: %s", e)

        return results

    async def _fetch_code_file(self, item: dict) -> dict:
        """Fetch the raw content of a GitHub file."""
        if not self._session:
            return {}

        try:
            git_url = item.get("git_url", "")
            html_url = item.get("html_url", "")

            if not git_url:
                return {}

            blocked, _ = is_blocked_url(html_url)
            if blocked:
                return {}

            async with self._session.get(git_url) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()

            await asyncio.sleep(self._blob_fetch_delay)

            content_b64 = data.get("content", "").replace("\n", "")
            if not content_b64:
                return {}

            try:
                content = base64.b64decode(content_b64).decode(
                    "utf-8", errors="ignore"
                )
            except Exception:
                return {}

            if len(content) > MAX_FILE_SIZE:
                content = content[:MAX_FILE_SIZE]

            clean_content, was_flagged = sanitize_content(content)
            if was_flagged:
                return {}

            if not clean_content or len(clean_content.strip()) < 30:
                return {}

            repo = item.get("repository", {})
            repo_name = repo.get("full_name", "unknown")
            filename = item.get("name", "")

            title = f"GitHub: {repo_name} — {filename}"

            relevance = self._score_relevance(clean_content, filename, repo_name)

            return {
                "url": html_url,
                "text_content": clean_content,
                "title": title,
                "source_type": "github",
                "source_name": "GitHub",
                "github_repo": repo_name,
                "github_filename": filename,
                "github_stars": repo.get("stargazers_count", 0),
                "scraped_at": datetime.now(timezone.utc).isoformat(),
                "word_count": len(clean_content.split()),
                "relevance": relevance,
            }

        except Exception as e:
            logger.debug("GitHub file fetch error: %s", e)
            return {}

    async def _search_repos(self, search_query: str) -> list[dict]:
        """Search GitHub repositories and fetch README content."""
        if not self._session:
            return []

        results: list[dict] = []

        try:
            params = {
                "q": search_query,
                "per_page": MAX_REPO_RESULTS,
                "sort": "updated",
                "order": "desc",
            }

            async with self._session.get(
                f"{GITHUB_API_BASE}/search/repositories",
                params=params,
            ) as resp:
                if resp.status == 403:
                    logger.warning("GitHub rate limit on repo search")
                    return []

                if resp.status != 200:
                    return []

                data = await resp.json()
                items = data.get("items", [])

            await asyncio.sleep(self._search_delay)

            fetch_tasks = []
            for item in items[:MAX_REPO_RESULTS]:
                repo_name = item.get("name", "")
                if self._is_noise_repo(repo_name):
                    continue
                fetch_tasks.append(self._fetch_repo_readme(item))

            if fetch_tasks:
                fetched = await asyncio.gather(
                    *fetch_tasks, return_exceptions=True
                )
                for f in fetched:
                    if isinstance(f, dict) and f.get("text_content"):
                        results.append(f)

        except Exception as e:
            logger.debug("GitHub repo search error: %s", e)

        return results

    async def _fetch_repo_readme(self, repo: dict) -> dict:
        """Fetch README content for a repository."""
        if not self._session:
            return {}

        try:
            full_name = repo.get("full_name", "")
            if not full_name:
                return {}

            readme_url = f"{GITHUB_API_BASE}/repos/{full_name}/readme"

            async with self._session.get(readme_url) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()

            await asyncio.sleep(self._blob_fetch_delay)

            content_b64 = data.get("content", "").replace("\n", "")
            if not content_b64:
                return {}

            try:
                content = base64.b64decode(content_b64).decode(
                    "utf-8", errors="ignore"
                )
            except Exception:
                return {}

            if len(content) > MAX_FILE_SIZE:
                content = content[:MAX_FILE_SIZE]

            clean_content, was_flagged = sanitize_content(content)
            if (
                was_flagged
                or not clean_content
                or len(clean_content.strip()) < 50
            ):
                return {}

            html_url = repo.get(
                "html_url", f"https://github.com/{full_name}"
            )

            return {
                "url": html_url,
                "text_content": clean_content,
                "title": f"GitHub: {full_name} — README",
                "source_type": "github",
                "source_name": "GitHub",
                "github_repo": full_name,
                "github_filename": "README",
                "github_stars": repo.get("stargazers_count", 0),
                "github_description": repo.get("description", ""),
                "scraped_at": datetime.now(timezone.utc).isoformat(),
                "word_count": len(clean_content.split()),
                "relevance": self._score_relevance(
                    clean_content, "README", full_name
                ),
            }

        except Exception as e:
            logger.debug("GitHub README fetch error: %s", e)
            return {}

    def _is_noise_repo(self, repo_name: str) -> bool:
        """Returns True if this repo should be skipped (tutorial, awesome list, etc.)."""
        name_lower = (repo_name or "").lower()
        for pattern in SKIP_REPO_PATTERNS:
            if re.match(pattern, name_lower):
                return True
        return False

    def _score_relevance(
        self,
        content: str,
        filename: str,
        repo_name: str,
    ) -> int:
        """Score how relevant this file is."""
        score = 0
        content_lower = (content or "").lower()

        if filename in HIGH_VALUE_FILENAMES:
            score += 5

        IOC_PATTERNS = [
            r"\b[A-Fa-f0-9]{32}\b",                       # MD5
            r"\b[A-Fa-f0-9]{64}\b",                       # SHA256
            r"\bCVE-\d{4}-\d+\b",
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",    # IPv4
            r"[a-zA-Z2-7]{16,56}\.onion",
            r"-----BEGIN PGP",
            r"AKIA[0-9A-Z]{16}",                          # AWS access key
        ]
        for pattern in IOC_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                score += 3

        SEC_KEYWORDS = [
            "malware", "ransomware", "c2",
            "command and control", "botnet",
            "stealer", "rat", "trojan",
            "exploit", "payload", "shellcode",
            "cobalt strike", "beacon",
            "mimikatz", "credential",
            "lateral movement", "persistence",
        ]
        for kw in SEC_KEYWORDS:
            if kw in content_lower:
                score += 2

        return score


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _is_github_scraping_enabled() -> bool:
    """Read GITHUB_SCRAPING_ENABLED at call time so tests can monkey-patch it."""
    return os.getenv("GITHUB_SCRAPING_ENABLED", "true").lower() == "true"


async def scrape_github(
    query: str,
    refined_query: str = "",
    max_results: int = MAX_TOTAL_RESULTS,
) -> list[dict]:
    """
    Main entry point for GitHub scraping.
    Returns list of page dicts compatible with the extraction pipeline.
    """
    if not _is_github_scraping_enabled():
        logger.info("GitHub scraping disabled")
        return []
    if not source_gate("github"):
        return []

    async with GitHubScraper() as scraper:
        return await scraper.search_and_fetch(
            query=query,
            refined_query=refined_query,
            max_results=max_results,
        )
