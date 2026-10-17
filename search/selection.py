"""Which onion candidates to fetch: diversity, depth-aware top-N, backfill.

One rule for the heuristic and the LLM path (E5): candidates are taken in
rank order, real result links before .onion addresses that a search page only
mentioned in its text, with at most one link per host and at most two per
mirror family (hosts sharing their first seven characters, the usual shape of
vanity-address mirror sets). What is not picked stays, in order, as the
backfill pool, and the same rule applies when the pool is drawn from.
"""

from __future__ import annotations

import os
from typing import Iterable, Optional
from urllib.parse import urlparse

# Onion pages fetched per run: DEPTH_PRESETS[depth]["top_n"] in the CLI
# (15 / 25 / 40), overridable and bounded here.
ONION_TOP_N_ENV = "VOIDACCESS_ONION_TOP_N"
ONION_TOP_N_MIN, ONION_TOP_N_MAX = 5, 60
# Depth-1 links followed from fetched onion pages, per run (off for shallow).
DEPTH1_LINKS = {"shallow": 0, "normal": 10, "deep": 20}
MIRROR_PREFIX_LEN = 7
MAX_PER_HOST = 1
MAX_PER_FAMILY = 2


def onion_top_n(default: int) -> int:
    """*default* (the depth preset), or VOIDACCESS_ONION_TOP_N bounded to 5-60."""
    raw = (os.getenv(ONION_TOP_N_ENV) or "").strip()
    if raw:
        try:
            return min(ONION_TOP_N_MAX, max(ONION_TOP_N_MIN, int(raw)))
        except ValueError:
            pass
    return default


def link_of(item: dict) -> str:
    return str(item.get("link") or item.get("url") or "")


def host_of(link: str) -> str:
    try:
        return (urlparse(link).hostname or "").lower()
    except ValueError:
        return ""


def family_of(host: str) -> str:
    return host[:MIRROR_PREFIX_LEN]


def from_page_text(item: dict) -> bool:
    """An address a search page only mentioned, not one of its result links."""
    if item.get("from_text"):
        return True
    return (item.get("title") or "") == host_of(link_of(item))


class DiversityState:
    """Hosts and mirror families already taken (or already fetched)."""

    def __init__(self, links: Iterable[str] = ()) -> None:
        self.hosts: dict[str, int] = {}
        self.families: dict[str, int] = {}
        self.links: set[str] = set()
        for link in links:
            self.take(link)

    def allows(self, link: str) -> bool:
        host = host_of(link)
        if not host or link in self.links:
            return False
        return (
            self.hosts.get(host, 0) < MAX_PER_HOST
            and self.families.get(family_of(host), 0) < MAX_PER_FAMILY
        )

    def take(self, link: str) -> None:
        host = host_of(link)
        self.links.add(link)
        if host:
            self.hosts[host] = self.hosts.get(host, 0) + 1
            fam = family_of(host)
            self.families[fam] = self.families.get(fam, 0) + 1


def select_diverse(
    ranked: list[dict],
    n: int,
    state: Optional[DiversityState] = None,
) -> tuple[list[dict], list[dict]]:
    """``(picked, rest)``: up to *n* items from *ranked* under the rule above.

    *state* carries hosts/families already used (it is updated); *rest* keeps
    every unpicked item in rank order for a later backfill."""
    state = state if state is not None else DiversityState()
    picked: list[dict] = []
    picked_ids: set[int] = set()
    for tier in (False, True):  # result links first, then text-mentioned ones
        for item in ranked:
            if len(picked) >= n:
                break
            if from_page_text(item) != tier:
                continue
            link = link_of(item)
            if not state.allows(link):
                continue
            state.take(link)
            picked.append(item)
            picked_ids.add(id(item))
    rest = [item for item in ranked if id(item) not in picked_ids]
    return picked, rest


def depth1_candidates(
    outlinks_by_page: list[tuple[str, list[str]]],
    cap: int,
    state: DiversityState,
) -> list[str]:
    """Up to *cap* links to follow from fetched pages (given in rank order).

    Each page's own-site links come first (one per page, the next page down a
    site already found relevant), then links to other hosts; every pick obeys
    the diversity rule against everything already fetched or queued."""
    if cap <= 0:
        return []
    picked: list[str] = []
    passes = (
        lambda page, link: host_of(link) == host_of(page),
        lambda page, link: host_of(link) != host_of(page),
    )
    for same_host in passes:
        for page, links in outlinks_by_page:
            for link in links:
                if len(picked) >= cap:
                    return picked
                if not same_host(page, link):
                    continue
                if link in state.links or link in picked:
                    continue
                # Same-host links are other pages of a site already fetched;
                # the per-host limit applies to new hosts only.
                if host_of(link) != host_of(page) and not state.allows(link):
                    continue
                if host_of(link) != host_of(page):
                    state.take(link)
                else:
                    state.links.add(link)
                picked.append(link)
                break  # one link per page per pass
    return picked
