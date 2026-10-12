"""feeds — reusable bulk blocklist-feed matcher + provenance/license stamping.

Generalizes the P1.3 ``sources/exploitdb.py`` shape: download a bulk blocklist ONCE
(``CachedFeed`` + TTL), parse it into an in-memory index memoized by raw length, and
match investigation entities against it by membership — zero per-entity network. Used
for abuse.ch SSLBL, OpenPhish, and PhishTank here; reusable for P3 index-seeding and
P4 feed cross-validation.

Every feed-derived artifact is stamped with its source feed + license (``provenance``)
at ingest, so P4's trust gate never has to re-derive origin. Matched entities are
flagged via the ``corroborating_sources`` tag write-back (the reputation-module
pattern); a durable ``feed:<name>`` tag records provenance per entity.

All IOCs are routed through the P1.3 ``hygiene`` helper (defang for display, PII strip)
before they land in a page.
"""
from __future__ import annotations

import asyncio
import csv
import io
import logging
import os
import re
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import hygiene
from utils import cancel
from sources.cache import CachedFeed
from sources.enrichment_allowlist import is_enrichment_source_enabled
from sources.source_control import is_source_disabled

logger = logging.getLogger(__name__)

# Bound how many entities of a matchable type a single feed scans per investigation.
MAX_FEED_MATCH_ENTITIES = 200

_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")


# --------------------------------------------------------------------------- #
# License registry — the authoritative feed -> license map (provenance stamp)
# --------------------------------------------------------------------------- #
LICENSES: dict[str, dict[str, str]] = {
    "sslbl": {
        "license": "CC0-1.0",
        "attribution": "abuse.ch SSL Blacklist (SSLBL)",
        "url": "https://sslbl.abuse.ch/",
    },
    "openphish": {
        "license": "OpenPhish Community (non-commercial use)",
        "attribution": "OpenPhish",
        "url": "https://openphish.com/",
    },
    "phishtank": {
        "license": "PhishTank Terms of Use",
        "attribution": "PhishTank (Cisco Talos)",
        "url": "https://phishtank.org/",
    },
    "ransomlook": {
        "license": "CC BY 4.0",
        "attribution": "RansomLook — ransomlook.io",
        "url": "https://www.ransomlook.io/",
    },
    "feodo": {
        "license": "CC0-1.0",
        "attribution": "abuse.ch Feodo Tracker",
        "url": "https://feodotracker.abuse.ch/",
    },
    "ransomwhere": {
        "license": "Open dataset (ransomwhe.re)",
        "attribution": "ransomwhe.re",
        "url": "https://ransomwhe.re/",
    },
    "hibp_pwned_passwords": {
        "license": "HIBP Pwned Passwords (CC BY 4.0 / Acceptable Use)",
        "attribution": "Have I Been Pwned — Pwned Passwords",
        "url": "https://haveibeenpwned.com/Passwords",
    },
}


def provenance(feed: str) -> dict[str, str]:
    """Structured provenance+license stamp for a feed-derived artifact."""
    meta = LICENSES.get(feed, {})
    return {
        "feed": feed,
        "license": meta.get("license", "unknown"),
        "attribution": meta.get("attribution", feed),
        "url": meta.get("url", ""),
    }


# --------------------------------------------------------------------------- #
# Parsers (raw text -> membership set) + helpers
# --------------------------------------------------------------------------- #
def _url_host(url: str) -> str:
    try:
        u = url if "://" in url else "http://" + url
        return (urlparse(u).hostname or "").strip().lower()
    except Exception:
        return ""


def parse_sslbl_csv(text: str) -> set[str]:
    """abuse.ch SSLBL: ``Firstseen,SHA1,Listingreason`` — index the SHA-1 column."""
    out: set[str] = set()
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].lstrip().startswith("#"):
            continue
        if len(row) >= 2 and _SHA1_RE.match(row[1].strip()):
            out.add(row[1].strip().lower())
    return out


def parse_url_lines(text: str) -> set[str]:
    """OpenPhish feed.txt: one URL per line — index the host (domain or IP)."""
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = _url_host(line)
        if host:
            out.add(host)
    return out


def parse_phishtank_csv(text: str) -> set[str]:
    """PhishTank online-valid.csv: index the host of each phishing ``url``."""
    out: set[str] = set()
    for row in csv.DictReader(io.StringIO(text)):
        host = _url_host((row.get("url") or "").strip())
        if host:
            out.add(host)
    return out


def _normalize(value: str) -> str:
    return (value or "").strip().lower().rstrip(".")


def _normalize_wallet(value: str) -> str:
    """Strip only — NEVER lowercase. base58 crypto addresses are case-sensitive
    (mixed case is checksum-bearing); lowercasing corrupts them."""
    return (value or "").strip()


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (text or "unknown").strip().lower()).strip("_") or "unknown"


def parse_ransomwhere(text: str) -> dict[str, str]:
    """ransomwhe.re /export JSON -> {btc_address: family}. Address kept verbatim
    (case-sensitive base58); only the derived address→family label is retained."""
    import json

    out: dict[str, str] = {}
    try:
        data = json.loads(text)
    except Exception:
        return out
    for entry in (data.get("result") if isinstance(data, dict) else data) or []:
        if not isinstance(entry, dict):
            continue
        addr = (entry.get("address") or "").strip()
        if addr:
            out[addr] = (entry.get("family") or "unknown").strip() or "unknown"
    return out


# --------------------------------------------------------------------------- #
# The reusable matcher
# --------------------------------------------------------------------------- #
class BlocklistFeed:
    """A bulk blocklist: fetch-once, index-in-memory, membership-match entities.

    ``status()`` reports ``ok`` / ``skipped_no_key`` / ``unavailable`` (never
    ``ok`` with a silent zero when a key is missing or a fetch failed).
    """

    def __init__(
        self,
        name: str,
        cache_path: str,
        ttl_seconds: int,
        parser: Callable[[str], "set | dict"],
        match_entity_types: set[str],
        license_id: str,
        flag_tags: list[str],
        *,
        url: Optional[str] = None,
        url_factory: Optional[Callable[[], str]] = None,
        header_factory: Optional[Callable[[], Optional[dict]]] = None,
        requires_key: bool = False,
        key_env: Optional[str] = None,
        normalizer: Optional[Callable[[str], str]] = None,
        tag_builder: Optional[Callable[[Any], list[str]]] = None,
    ) -> None:
        self.name = name
        self.cache_path = cache_path
        self.ttl_seconds = ttl_seconds
        self.parser = parser
        self.match_entity_types = {t.upper() for t in match_entity_types}
        self.license_id = license_id
        self.flag_tags = list(flag_tags)
        self._url = url
        self._url_factory = url_factory
        self._header_factory = header_factory
        self.requires_key = requires_key
        self.key_env = key_env
        # Value normalizer used symmetrically on the index and the lookup. Defaults
        # to the case-folding `_normalize`; wallet feeds pass `_normalize_wallet`
        # (strip only) because base58 addresses are CASE-SENSITIVE.
        self._normalizer = normalizer or _normalize
        # For dict-index feeds, builds extra per-match tags from the matched entry
        # (e.g. the ransom family) — the static `flag_tags` are always applied too.
        self._tag_builder = tag_builder
        self._status = "ok"
        self._cached_index: Optional[tuple[int, "set | dict"]] = None

    def status(self) -> str:
        return self._status

    def _has_key(self) -> bool:
        if not self.key_env:
            return True
        return bool((os.environ.get(self.key_env) or "").strip())

    async def _fetch_text(self) -> Optional[str]:
        """Seam for tests. Builds a CachedFeed (memory cache is shared by URL) and
        fetches the raw text."""
        url = self._url_factory() if self._url_factory else self._url
        feed = CachedFeed(
            url, self.cache_path, self.ttl_seconds, parse="text",
            headers=self._header_factory,
        )
        return await feed.fetch()

    def _enabled(self) -> bool:
        """VOIDACCESS_ENRICHMENT_SOURCES gate: the feed's own id (``sslbl``,
        ``openphish``, ``phishtank``, ``ransomwhere``) or the umbrella id
        ``blocklists`` enables it. Unset allowlist => always enabled. The
        deny-list (``VOIDACCESS_DISABLED_SOURCES``) wins over both: the feed's own
        id or the ``blocklists`` umbrella there disables it."""
        if is_source_disabled(self.name):
            is_enrichment_source_enabled(self.name)  # records the refusal
            return False
        return (
            is_enrichment_source_enabled(self.name)
            or is_enrichment_source_enabled("blocklists")
        )

    async def index(self) -> set:
        """Return the (cached, memoized) membership set. Never raises."""
        if not self._enabled():
            # No fetch and the memoized index is not consulted, so a restricted
            # run never reuses (or leaks) an index built under another allowlist.
            self._status = "disabled"
            return set()
        if self.requires_key and not self._has_key():
            self._status = "skipped_no_key"
            return set()
        try:
            text = await self._fetch_text()
        except Exception as exc:
            logger.warning("feeds: %s fetch failed: %s", self.name, exc)
            text = None
        if not isinstance(text, str) or not text:
            if self._cached_index is None:
                self._status = "unavailable"
                return set()
            return self._cached_index[1]
        if self._cached_index is None or self._cached_index[0] != len(text):
            self._cached_index = (len(text), self.parser(text))
        self._status = "ok"
        return self._cached_index[1]

    def _tags(self) -> list[str]:
        return list(self.flag_tags) + [f"feed:{self.name}"]

    async def match(self, entities: list[dict]) -> list[tuple[dict, list[str]]]:
        """Return ``[(entity, tags), ...]`` for entities present in the blocklist.

        The index is fetched ONCE regardless of how many entities are matched —
        every lookup is an in-memory membership test (no per-entity network).
        """
        idx = await self.index()
        if not idx:
            return []
        is_dict = isinstance(idx, dict)
        out: list[tuple[dict, list[str]]] = []
        scanned = 0
        base_tags = self._tags()
        for e in entities or []:
            etype = (e.get("entity_type") or e.get("type") or "").upper()
            if etype not in self.match_entity_types:
                continue
            scanned += 1
            if scanned > MAX_FEED_MATCH_ENTITIES:
                break
            key = self._normalizer(e.get("value") or e.get("entity_value") or "")
            if key not in idx:
                continue
            tags = base_tags
            if is_dict and self._tag_builder is not None:
                tags = base_tags + self._tag_builder(idx[key])
            out.append((e, tags))
        return out


# --------------------------------------------------------------------------- #
# The three new feeds
# --------------------------------------------------------------------------- #
def _abusech_auth_header() -> Optional[dict]:
    key = (os.environ.get("ABUSECH_API_KEY") or "").strip()
    return {"Auth-Key": key} if key else None


def _phishtank_url() -> str:
    key = (os.environ.get("PHISHTANK_API_KEY") or "").strip()
    return f"http://data.phishtank.com/data/{key}/online-valid.csv"


SSLBL = BlocklistFeed(
    name="sslbl",
    url="https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
    cache_path="/tmp/voidaccess_sslbl.csv",
    ttl_seconds=86400,  # 24 h
    parser=parse_sslbl_csv,
    match_entity_types={"FILE_HASH_SHA1"},
    license_id="sslbl",
    flag_tags=["malicious_cert", "malicious_cert_sslbl"],
    # abuse.ch blocklist CSVs are public today (Feodo fetches keyless); the Auth-Key
    # is sent only if ABUSECH_API_KEY happens to be set (forward-compat). Not gated.
    header_factory=_abusech_auth_header,
)

OPENPHISH = BlocklistFeed(
    name="openphish",
    url="https://openphish.com/feed.txt",
    cache_path="/tmp/voidaccess_openphish.txt",
    ttl_seconds=43200,  # 12 h — OpenPhish rotates frequently
    parser=parse_url_lines,
    match_entity_types={"DOMAIN", "IP_ADDRESS"},
    license_id="openphish",
    flag_tags=["phishing", "phishing_openphish"],
)

PHISHTANK = BlocklistFeed(
    name="phishtank",
    url_factory=_phishtank_url,  # embeds the free app key
    cache_path="/tmp/voidaccess_phishtank.csv",
    ttl_seconds=86400,
    parser=parse_phishtank_csv,
    match_entity_types={"DOMAIN", "IP_ADDRESS"},
    license_id="phishtank",
    flag_tags=["phishing", "phishing_phishtank"],
    requires_key=True,  # bulk download needs a free PhishTank app key
    key_env="PHISHTANK_API_KEY",
)

RANSOMWHERE = BlocklistFeed(
    name="ransomwhere",
    # Live route is /export; the old /v1/export path 403s (API-Gateway
    # MissingAuthenticationToken = dead route). See INT-C3.
    url="https://api.ransomwhe.re/export",
    cache_path="/tmp/voidaccess_ransomwhere.json",
    ttl_seconds=86400,
    parser=parse_ransomwhere,  # -> {btc_address: family} (dict index)
    match_entity_types={"BITCOIN_ADDRESS"},
    license_id="ransomwhere",
    flag_tags=["ransom_wallet"],
    normalizer=_normalize_wallet,  # base58 is case-sensitive — do NOT lowercase
    tag_builder=lambda family: [f"ransom_wallet_{_slug(family)}"],
)

_FEEDS = [SSLBL, OPENPHISH, PHISHTANK, RANSOMWHERE]


# --------------------------------------------------------------------------- #
# Entity flag write-back (reputation-module pattern)
# --------------------------------------------------------------------------- #
def _write_entity_flags(updates: list[tuple[str, str, list[str]]]) -> None:
    """Append feed-match tags to matched entities' ``corroborating_sources``.

    ``updates`` is ``[(entity_type, value, tags)]``. Gated on DATABASE_URL; matches
    by exact (entity_type, value); never raises. Ranking reads the ``source_count``
    column, not these tags, so flagging does not inflate corroboration.
    """
    if not os.getenv("DATABASE_URL") or not updates:
        return
    try:
        import json

        from db.models import Entity
        from db.session import get_session

        with get_session() as session:
            for entity_type, value, tags in updates:
                db_entity = session.query(Entity).filter(
                    Entity.entity_type == entity_type,
                    Entity.value == value,
                ).first()
                if db_entity is None:
                    continue
                existing: list = json.loads(db_entity.corroborating_sources or "[]")
                for tag in tags:
                    if tag not in existing:
                        existing.append(tag)
                db_entity.corroborating_sources = json.dumps(existing)
            session.commit()
    except Exception as exc:
        logger.warning("feeds: entity flag write-back failed: %s", exc)


def _feed_page(feed: BlocklistFeed, matches: list[tuple[dict, list[str]]]) -> dict:
    """Build a provenance-stamped summary page for a feed's matches."""
    prov = provenance(feed.license_id)
    lines = [
        f"{prov['attribution']} — {len(matches)} matched indicator(s)",
        f"Source: {prov['attribution']} ({prov['url']}) — license: {prov['license']}",
    ]
    for ent, tags in matches:
        etype = (ent.get("entity_type") or ent.get("type") or "").upper()
        value = ent.get("value") or ent.get("entity_value") or ""
        lines.append(f"  {etype}: {hygiene.defang_ioc(etype, value)}  [{', '.join(tags)}]")
    content = hygiene.strip_pii("\n".join(lines))
    return {
        "link": prov["url"],
        "url": prov["url"],
        "content": content,
        "text": content,
        "status": 200,
        "source": feed.name,
        "via": f"{feed.name}_blocklist",
        "provenance": prov,  # structured feed+license stamp at ingest
    }


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
async def enrich_blocklists(entities: list[dict]) -> tuple[list[dict], dict[str, dict]]:
    """Match investigation entities against every blocklist feed.

    Returns ``(pages, stats)`` where ``pages`` are provenance-stamped summary pages
    (one per feed with matches) and ``stats`` is ``{feed: {status, count}}``. Flags
    matched entities in the DB. Graceful: a feed that is down / key-less contributes
    nothing and reports its status, never crashing the cluster.
    """
    pages: list[dict] = []
    stats: dict[str, dict] = {}
    updates: list[tuple[str, str, list[str]]] = []

    for feed in _FEEDS:
        if cancel.is_cancelled():
            break  # cancel checkpoint between feeds
        try:
            matches = await feed.match(entities or [])
        except Exception as exc:
            logger.warning("feeds: %s match failed: %s", feed.name, exc)
            matches = []
        stats[feed.name] = {"status": feed.status(), "count": len(matches)}
        if not matches:
            continue
        for ent, tags in matches:
            etype = (ent.get("entity_type") or ent.get("type") or "").upper()
            value = ent.get("value") or ent.get("entity_value") or ""
            updates.append((etype, value, tags))
        pages.append(_feed_page(feed, matches))

    if updates:
        await asyncio.to_thread(_write_entity_flags, updates)

    return pages, stats


async def derive_feed_hits(
    entities: list[dict],
) -> dict[tuple[str, str], frozenset[str]]:
    """Re-derive trusted-feed cross-hits for *entities* from the platform's OWN feeds.

    The P4.3 ingest boundary discards any submitter-supplied ``feed_hits`` and calls
    this to compute them server-side: it runs the same ``BlocklistFeed.match``
    machinery ``enrich_blocklists`` uses (no fork, no DB write-back) and returns
    ``{(entity_type, value): {feed_name, ...}}``. A forged feed hit therefore never
    survives — only a genuine match against a real feed does. Graceful: a feed that
    is down / key-less contributes nothing.
    """
    out: dict[tuple[str, str], set[str]] = {}
    for feed in _FEEDS:
        try:
            matches = await feed.match(entities or [])
        except Exception as exc:  # a single feed failing never breaks re-derivation
            logger.debug("feeds: derive_feed_hits %s failed: %s", feed.name, exc)
            matches = []
        for ent, _tags in matches:
            etype = (ent.get("entity_type") or ent.get("type") or "").upper()
            value = ent.get("value") or ent.get("entity_value") or ""
            out.setdefault((etype, value), set()).add(feed.name)
    return {k: frozenset(v) for k, v in out.items()}
