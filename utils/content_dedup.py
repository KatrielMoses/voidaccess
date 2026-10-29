"""Content-hash deduplication for investigation page records.

Two passes:

1. Exact: pages with the same content hash collapse into the first one.
2. Mirrors: pages on *different* onion hosts whose text is near-identical
   (64-bit SimHash over word 3-shingles, Hamming distance <= MIRROR_MAX_DISTANCE)
   collapse into the first one. Same-host pages are never merged by this pass,
   so a site's own templated pages stay separate.

"First" is input order, which every caller passes in rank order, so the
best-ranked page is the one kept. Each kept page carries ``source_urls`` (the
full set of merged URLs) and ``mirrors`` (the other onion hosts that served
the same page).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from typing import Optional
from urllib.parse import urlsplit

# Near-duplicate threshold and the minimum text size to judge it on. Short
# pages (error pages, captchas, "site down") are left to the exact pass.
MIRROR_MAX_DISTANCE = 3
MIRROR_MIN_TOKENS = 40
# Words hashed per page: enough to tell mirrors apart, bounded so long pages
# cost the same as medium ones.
_MAX_WORDS = 2_000
_SHINGLE = 3
_WORD_RE = re.compile(r"\w+", re.UNICODE)


def content_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def simhash64(text: str) -> Optional[int]:
    """64-bit SimHash of word 3-shingles, or None when the text is too short
    to judge."""
    import numpy as np

    words = _WORD_RE.findall((text or "").lower())[:_MAX_WORDS]
    if len(words) < MIRROR_MIN_TOKENS:
        return None
    digests = b"".join(
        hashlib.blake2b(
            " ".join(words[i:i + _SHINGLE]).encode("utf-8"), digest_size=8
        ).digest()
        for i in range(len(words) - _SHINGLE + 1)
    )
    bits = np.unpackbits(np.frombuffer(digests, dtype=np.uint8)).reshape(-1, 64)
    ones = bits.sum(axis=0, dtype=np.int64)
    majority = (ones * 2 > bits.shape[0]).astype(np.uint8)
    return int.from_bytes(np.packbits(majority).tobytes(), "big")


def _onion_host(url: str) -> str:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    return host if host.endswith(".onion") else ""


def _page_text(page: dict) -> str:
    return page.get("text") or page.get("content") or page.get("cleaned_text") or ""


def _merge_into(existing: dict, url: str, page: dict) -> None:
    existing["source_urls"] = list(dict.fromkeys([
        *existing.get("source_urls", []),
        url,
        *(page.get("source_urls") or []),
    ]))


def _onion_hosts(urls: Iterable[str]) -> set[str]:
    return {h for h in map(_onion_host, urls) if h}


def _set_mirrors(item: dict) -> None:
    own = _onion_host(item.get("url") or "")
    hosts: list[str] = []
    for u in item.get("source_urls") or []:
        h = _onion_host(u)
        if h and h != own and h not in hosts:
            hosts.append(h)
    item["mirrors"] = hosts


def deduplicate_page_records(pages: Iterable[dict]) -> list[dict]:
    """Collapse identical content, then onion mirrors, keeping every URL.

    The first page remains canonical for extraction and DB entity provenance;
    ``source_urls`` carries the complete merged URL set and ``mirrors`` the
    other onion hosts, for reporting.
    """
    by_hash: dict[str, dict] = {}
    for page in pages:
        text = _page_text(page)
        url = (page.get("url") or page.get("link") or "").strip()
        if not url:
            continue
        digest = page.get("raw_content_hash") or content_hash(text)
        existing = by_hash.get(digest)
        if existing is None:
            item = dict(page)
            item["url"] = url
            item["raw_content_hash"] = digest
            item["source_urls"] = list(dict.fromkeys([url, *(page.get("source_urls") or [])]))
            by_hash[digest] = item
        else:
            _merge_into(existing, url, page)

    kept: list[dict] = []
    # One entry per kept onion page: (simhash, onion hosts in its group, page).
    groups: list[tuple[int, set[str], dict]] = []
    for item in by_hash.values():
        host = _onion_host(item["url"])
        sig = simhash64(_page_text(item)) if host else None
        target = None
        if sig is not None:
            for other_sig, other_hosts, other in groups:
                if host in other_hosts:
                    continue  # same site: not a mirror
                if bin(sig ^ other_sig).count("1") <= MIRROR_MAX_DISTANCE:
                    target = (other_hosts, other)
                    break
        if target is not None:
            other_hosts, other = target
            _merge_into(other, item["url"], item)
            other_hosts.update(_onion_hosts(item["source_urls"]))
            continue
        kept.append(item)
        if sig is not None:
            groups.append((sig, _onion_hosts(item["source_urls"]), item))
    for item in kept:
        _set_mirrors(item)
    return kept
