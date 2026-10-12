"""
sources/gitlab_scraper.py — GitLab clearnet intelligence source for VoidAccess.

Searches GitLab code and repositories for security-relevant content that
matches an investigation query.  Runs over CLEARNET — GitLab is public and
does not require Tor.

Typical high-signal content found on GitLab:
    - Malware tooling and PoC exploits removed from GitHub but persisting here
    - C2 / beacon configuration files
    - Threat actor infrastructure configs
    - Leaked credentials and internal endpoint configs
    - Security research write-ups and proof-of-concept code

Authentication is OPTIONAL, and unlike most providers it does NOT raise the
search rate limit — GitLab.com caps /search at 10 requests/minute per IP
address whether or not a token is supplied.  A GITLAB_TOKEN still widens the
general API allowance (2,000/min per user vs 500/min per IP) and grants access
to private-visibility results, so it remains worth setting.

Public API:
    async def scrape_gitlab(
        query: str,
        refined_query: str = "",
        max_results: int = 15,
    ) -> list[dict]

Returns page dicts compatible with the existing extraction pipeline:
    {
        "url": str,
        "text_content": str,
        "title": str,
        "source_type": "gitlab",
        "source_name": "GitLab",
        "gitlab_repo": str,
        "gitlab_filename": str,
        "gitlab_stars": int,
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
from urllib.parse import quote

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

GITLAB_API_BASE = "https://gitlab.com/api/v4"

# Max file size to fetch (200KB)
MAX_FILE_SIZE = 200 * 1024

# Max results per search type
MAX_CODE_RESULTS = 10
MAX_REPO_RESULTS = 5

# Max total GitLab items per investigation
MAX_TOTAL_RESULTS = 15

# Rate limit delays (seconds).  Provider-dictated, so these are FLOORS routed
# through pacing.scale_delay_floor() — `aggressive` clamps at them, it must
# never shorten them.  Verified against GitLab.com's published limits
# 2026-07-29:
#
#   /search (advanced, project, group)   10 req/min PER IP
#   /projects/:id                        400 req/min
#   general authenticated API            2,000 req/min per user
#
# The search cap is applied per IP address and is NOT lifted by supplying a
# token, which breaks the "authenticated == faster" pattern NVD established.
# There is deliberately no AUTH/UNAUTH split here: an earlier version had
# 4.0 s / 1.0 s, i.e. 15/min and 60/min, and both exceeded the real 10/min.
SEARCH_RATE_LIMIT_DELAY = 6.5    # 10/min per IP = 6.0 s + margin; both branches
PROJECT_RATE_LIMIT_DELAY = 1.0   # /projects/:id; 400/min needs only 0.15 s

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


class GitLabScraper:
    """
    Scrapes GitLab for security-relevant content using the GitLab Search API v4.
    Works with or without authentication.
    """

    def __init__(self):
        self._token = os.getenv("GITLAB_TOKEN", "").strip()
        self._session: Optional[aiohttp.ClientSession] = None
        # Provider-dictated quotas, so scale_delay_floor() — NOT scale_delay(),
        # which shrinks under `aggressive` and would push us past GitLab's
        # published per-minute limits.  The search delay does not branch on
        # self._token: GitLab caps /search per IP regardless of authentication.
        self._search_delay = pacing.scale_delay_floor(SEARCH_RATE_LIMIT_DELAY)
        self._project_delay = pacing.scale_delay_floor(PROJECT_RATE_LIMIT_DELAY)

    @property
    def _headers(self) -> dict:
        headers = {
            "User-Agent": "VoidAccess-OSINT/1.1",
        }
        if self._token:
            headers["PRIVATE-TOKEN"] = self._token
        return headers

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            headers=self._headers,
            timeout=aiohttp.ClientTimeout(total=pacing.scale_timeout(REQUEST_TIMEOUT)),
            trace_configs=[request_trace_config("gitlab")],
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
        Search GitLab and return page dicts compatible with the extraction
        pipeline.
        """
        blocked, _ = is_blocked_query(query)
        if blocked:
            logger.warning("GitLab scraping blocked — prohibited query")
            return []

        search_queries = self._build_search_queries(query, refined_query)

        auth_status = "authenticated" if self._token else "unauthenticated"
        logger.info(
            "GitLab scraping (%s): '%s'",
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

        logger.info("GitLab: %d results found", len(final))
        return final

    def _build_search_queries(
        self,
        query: str,
        refined_query: str,
    ) -> list[str]:
        """
        Build GitLab search queries.  GitLab's search API accepts plain text;
        keep queries short and clean.
        """
        queries: list[str] = []

        base = refined_query or query
        base = re.sub(r"[^\w\s\-.]", " ", base).strip()[:100]
        queries.append(base)

        # Add tool-specific second query for known malware/tooling names.
        TOOL_VARIANTS = {
            "cobalt strike": "malleable",
            "metasploit": "meterpreter",
            "mimikatz": "sekurlsa",
            "covenant": "grunt",
            "sliver": "implant",
            "havoc": "demon",
            "brute ratel": "config",
        }

        query_lower = query.lower()
        for tool, modifier in TOOL_VARIANTS.items():
            if tool in query_lower:
                queries.append(f"{tool} {modifier}")
                break

        return queries[:2]

    async def _search_code(self, search_query: str) -> list[dict]:
        """Search GitLab code (blobs) and fetch file content."""
        if not self._session:
            return []

        results: list[dict] = []

        try:
            params = {
                "scope": "blobs",
                "search": search_query,
                "per_page": MAX_CODE_RESULTS,
            }

            async with self._session.get(
                f"{GITLAB_API_BASE}/search",
                params=params,
            ) as resp:
                if resp.status == 429:
                    reset_at = resp.headers.get("RateLimit-Reset", "")
                    logger.warning(
                        "GitLab rate limit hit. Resets at %s",
                        reset_at,
                    )
                    return []

                if resp.status == 401:
                    logger.debug(
                        "GitLab code search: authentication required for this query"
                    )
                    return []

                if resp.status != 200:
                    return []

                items = await resp.json()
                if not isinstance(items, list):
                    return []

            await asyncio.sleep(self._search_delay)

            fetch_tasks = []
            for item in items[:MAX_CODE_RESULTS]:
                repo_name = str(item.get("project_id", ""))
                filename = item.get("filename", "")
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
            logger.debug("GitLab code search error: %s", e)

        return results

    async def _fetch_code_file(self, item: dict) -> dict:
        """Fetch the raw content of a GitLab file via the repository files API."""
        if not self._session:
            return {}

        try:
            project_id = item.get("project_id")
            file_path = item.get("path", "")
            ref = item.get("ref", "main")
            filename = item.get("filename", "")

            if not project_id or not file_path:
                return {}

            # Build a synthetic html_url for is_blocked_url and result storage
            html_url = (
                f"https://gitlab.com/projects/{project_id}/-/blob/{ref}/{file_path}"
            )
            blocked, _ = is_blocked_url(html_url)
            if blocked:
                return {}

            # URL-encode the path (slashes must become %2F for the GitLab files API)
            encoded_path = quote(file_path, safe="")
            file_url = (
                f"{GITLAB_API_BASE}/projects/{project_id}"
                f"/repository/files/{encoded_path}?ref={ref}"
            )

            async with self._session.get(file_url) as resp:
                if resp.status != 200:
                    # Fall back to the snippet GitLab included in the search result
                    snippet = item.get("data", "")
                    if snippet and len(snippet.strip()) >= 30:
                        clean, flagged = sanitize_content(snippet)
                        if not flagged and clean and len(clean.strip()) >= 30:
                            score = self._score_relevance(clean, filename, str(project_id))
                            return {
                                "url": html_url,
                                "text_content": clean,
                                "title": f"GitLab: project/{project_id} — {filename}",
                                "source_type": "gitlab",
                                "source_name": "GitLab",
                                "gitlab_repo": str(project_id),
                                "gitlab_filename": filename,
                                "gitlab_stars": 0,
                                "scraped_at": datetime.now(timezone.utc).isoformat(),
                                "word_count": len(clean.split()),
                                "relevance": score,
                            }
                    return {}
                data = await resp.json()

            await asyncio.sleep(self._project_delay)

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

            # Build a better html_url if the search result had path_with_namespace
            # (the code search result doesn't include it directly, so we use project_id)
            title = f"GitLab: project/{project_id} — {filename}"
            relevance = self._score_relevance(clean_content, filename, str(project_id))

            return {
                "url": html_url,
                "text_content": clean_content,
                "title": title,
                "source_type": "gitlab",
                "source_name": "GitLab",
                "gitlab_repo": str(project_id),
                "gitlab_filename": filename,
                "gitlab_stars": 0,
                "scraped_at": datetime.now(timezone.utc).isoformat(),
                "word_count": len(clean_content.split()),
                "relevance": relevance,
            }

        except Exception as e:
            logger.debug("GitLab file fetch error: %s", e)
            return {}

    async def _search_repos(self, search_query: str) -> list[dict]:
        """Search GitLab projects and fetch README content."""
        if not self._session:
            return []

        results: list[dict] = []

        try:
            params = {
                "scope": "projects",
                "search": search_query,
                "per_page": MAX_REPO_RESULTS,
                "order_by": "updated_at",
            }

            async with self._session.get(
                f"{GITLAB_API_BASE}/search",
                params=params,
            ) as resp:
                if resp.status == 429:
                    logger.warning("GitLab rate limit on project search")
                    return []

                if resp.status != 200:
                    return []

                items = await resp.json()
                if not isinstance(items, list):
                    return []

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
            logger.debug("GitLab project search error: %s", e)

        return results

    async def _fetch_repo_readme(self, project: dict) -> dict:
        """Fetch README content for a GitLab project."""
        if not self._session:
            return {}

        try:
            project_id = project.get("id")
            if not project_id:
                return {}

            path_with_namespace = project.get("path_with_namespace", "")
            default_branch = project.get("default_branch") or "main"

            # Try README.md then readme.md
            readme_content = ""
            for readme_name in ("README.md", "readme.md", "README.txt"):
                encoded_name = quote(readme_name, safe="")
                readme_url = (
                    f"{GITLAB_API_BASE}/projects/{project_id}"
                    f"/repository/files/{encoded_name}?ref={default_branch}"
                )
                async with self._session.get(readme_url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        content_b64 = data.get("content", "").replace("\n", "")
                        if content_b64:
                            try:
                                readme_content = base64.b64decode(
                                    content_b64
                                ).decode("utf-8", errors="ignore")
                            except Exception:
                                pass
                        if readme_content:
                            break

            await asyncio.sleep(self._project_delay)

            if not readme_content:
                return {}

            if len(readme_content) > MAX_FILE_SIZE:
                readme_content = readme_content[:MAX_FILE_SIZE]

            clean_content, was_flagged = sanitize_content(readme_content)
            if (
                was_flagged
                or not clean_content
                or len(clean_content.strip()) < 50
            ):
                return {}

            web_url = project.get(
                "web_url",
                f"https://gitlab.com/{path_with_namespace}",
            )

            display_name = path_with_namespace or str(project_id)

            return {
                "url": web_url,
                "text_content": clean_content,
                "title": f"GitLab: {display_name} — README",
                "source_type": "gitlab",
                "source_name": "GitLab",
                "gitlab_repo": display_name,
                "gitlab_filename": "README",
                "gitlab_stars": project.get("star_count", 0),
                "gitlab_description": project.get("description", ""),
                "scraped_at": datetime.now(timezone.utc).isoformat(),
                "word_count": len(clean_content.split()),
                "relevance": self._score_relevance(
                    clean_content, "README", display_name
                ),
            }

        except Exception as e:
            logger.debug("GitLab README fetch error: %s", e)
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


def _is_gitlab_scraping_enabled() -> bool:
    """Read GITLAB_SCRAPING_ENABLED at call time so tests can monkey-patch it."""
    return os.getenv("GITLAB_SCRAPING_ENABLED", "true").lower() == "true"


async def scrape_gitlab(
    query: str,
    refined_query: str = "",
    max_results: int = MAX_TOTAL_RESULTS,
) -> list[dict]:
    """
    Main entry point for GitLab scraping.
    Returns list of page dicts compatible with the extraction pipeline.
    """
    if not _is_gitlab_scraping_enabled():
        logger.info("GitLab scraping disabled")
        return []
    if not source_gate("gitlab"):
        return []

    async with GitLabScraper() as scraper:
        return await scraper.search_and_fetch(
            query=query,
            refined_query=refined_query,
            max_results=max_results,
        )
