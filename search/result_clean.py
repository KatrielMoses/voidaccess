"""Search-result clean-up before ranking (23B-B3).

Three steps, all cheap and deterministic:

* **Engine-host drop** (:func:`is_search_engine_host`): a result whose host is
  itself a search engine (any catalog engine, whatever its status, the side
  sources, or another known onion search engine) is navigation to another
  engine, not a target page.
* **URL normalisation** (:func:`unwrap_redirect`, :func:`normalize_result_url`):
  an engine that wraps the target in a redirect parameter (``l=``, ``u=``,
  ``url=``, ``redirect=``..., ``q=`` on a redirect path) is unwrapped, and
  tracking noise (``utm_*``, ``ref``, ``fbclid``, session ids, the fragment) is
  stripped so the same page found twice has one URL.
* **Duplicate merge** (:func:`merge_duplicates`): exact duplicates after
  normalisation collapse into one candidate that records every engine that
  found it (``found_by`` / ``engine_count``); ranking can use the agreement.

Mirror merging (same content on another onion host) is not done here: it needs
the fetched page and happens after fetching.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Iterable, Optional
from urllib.parse import unquote, urlsplit, urlunsplit

# Onion search engines that VoidAccess does not query but whose result pages
# other engines link to (hosts taken from the competitor study's engine list,
# tools/competition results/ENGINES.md, 2026-10-29), plus clearnet engine hosts.
# A link to any of them is a search page, never a target.
KNOWN_SEARCH_HOSTS = frozenset({
    "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",  # DuckDuckGo
    "l4rsciqnpzdndt2llgjx3luvnxip7vbyj6k6nmdy4xs77tx6gkd24ead.onion",  # Dark Search Enginer
    "no6m4wzdexe3auiupv2zwif7rm6qwxcyhslkcnzisxgeiw6pvjsgafad.onion",  # Submarine
    "notevil2ebbr5xjww6nryjta7bycbriyi2vh7an3wcuovlznvobykmad.onion",  # notEvil
    "notevilmtxf25uw7tskqxj6njlpebyrmlrerfv5hc4tuq7c7hilbyiqd.onion",  # notEvil
    "phobosxilamwcg75xt22id7aywkzol6q6rfl2flipcqoc4e4ahima5id.onion",  # Phobos
    "tordexpmg4xy32rfp4ovnz7zq5ujoejwq2u26uxxtkscgo5u3losmeid.onion",  # Tordex
    "ahmia.fi",
    "tordex.cc",
    "onionengine.com",
})

# Query parameters an engine uses to wrap the real target URL.
_REDIRECT_KEYS = frozenset({
    "l", "u", "url", "redirect", "redirect_url", "redirect_uri", "redir",
    "link", "site", "address", "target", "to", "dest", "destination", "goto",
    "out",
})
# ``q`` carries the search text on a search page, so it is read as a target
# only on a redirect-looking path.
_REDIRECT_PATH_RE = re.compile(
    r"(?:^|/)(?:r|go|goto|out|redir|redirect|click|visit|away|jump|link|url)(?:\.php)?/?$",
    re.IGNORECASE,
)
_URL_START_RE = re.compile(r"^https?://", re.IGNORECASE)
_BARE_ONION_RE = re.compile(r"^[a-z2-7]{16,56}\.onion(?:[/?#]|$)", re.IGNORECASE)

# Tracking and session parameters dropped from result URLs.
_NOISE_KEYS = frozenset({
    "ref", "ref_src", "referrer", "fbclid", "gclid", "dclid", "gbraid", "wbraid",
    "msclkid", "yclid", "mc_cid", "mc_eid", "igshid", "_ga", "_gl", "spm",
    "phpsessid", "jsessionid", "sessionid", "session_id", "sessid",
    "aspsessionid", "cfid", "cftoken",
})
# ``sid`` is a session token on phpBB-style boards only when it looks like one.
_SID_TOKEN_RE = re.compile(r"^[0-9a-f]{16,64}$", re.IGNORECASE)
_PATH_SESSION_RE = re.compile(r";(?:jsessionid|phpsessid|sid)=[^/?#]*", re.IGNORECASE)


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


@lru_cache(maxsize=1)
def _catalog_hosts() -> frozenset[str]:
    """Hosts of every catalog engine (any status) and the side-source engines."""
    from search.engine_catalog import SEARCH_ENGINES  # noqa: PLC0415
    from sources.engines import _ONIONSEARCH_ENGINES  # noqa: PLC0415

    hosts = set()
    for engine in (*SEARCH_ENGINES, *_ONIONSEARCH_ENGINES):
        host = host_of(str(engine.get("url", "")).replace("{query}", "x"))
        if host:
            hosts.add(host)
    return frozenset(hosts)


def search_engine_hosts() -> frozenset[str]:
    return _catalog_hosts() | KNOWN_SEARCH_HOSTS


def is_search_engine_host(url_or_host: str) -> bool:
    """True when the URL (or bare host) belongs to a search engine."""
    host = host_of(url_or_host) if "/" in url_or_host else url_or_host.lower()
    if not host:
        return False
    if host.startswith("www."):
        host = host[4:]
    return host in search_engine_hosts()


def _param_pairs(query: str) -> list[tuple[str, str, str]]:
    """``(raw_piece, decoded_key, decoded_value)`` for each ``&``-separated piece."""
    pairs = []
    for piece in query.split("&"):
        if not piece:
            continue
        key, _, value = piece.partition("=")
        try:
            pairs.append((piece, unquote(key.replace("+", " ")), unquote(value.replace("+", " "))))
        except Exception:  # noqa: BLE001 - a malformed piece is kept as-is
            pairs.append((piece, key, value))
    return pairs


def unwrap_redirect(href: str) -> Optional[str]:
    """The target URL an engine wrapped in a redirect parameter, or None.

    The value is percent-decoded up to twice (some engines double-encode it).
    A bare ``<host>.onion/...`` value gets ``http://``."""
    try:
        parts = urlsplit(href)
    except ValueError:
        return None
    if not parts.query:
        return None
    redirect_path = bool(_REDIRECT_PATH_RE.search(parts.path or ""))
    for _piece, key, value in _param_pairs(parts.query):
        key = key.strip().lower()
        if key not in _REDIRECT_KEYS and not (key == "q" and redirect_path):
            continue
        candidate = value.strip()
        if "%" in candidate:
            candidate = unquote(candidate).strip()
        if _URL_START_RE.match(candidate):
            return candidate
        if _BARE_ONION_RE.match(candidate):
            return "http://" + candidate
    return None


def _is_noise_param(key: str, value: str) -> bool:
    key = key.strip().lower()
    if key.startswith("utm_") or key in _NOISE_KEYS:
        return True
    return key == "sid" and bool(_SID_TOKEN_RE.match(value.strip()))


def normalize_result_url(url: str) -> str:
    """*url* without tracking/session parameters and fragment, scheme and host
    lower-cased. Everything else (path case, parameter order and encoding) is
    kept, so a URL with no noise comes back unchanged apart from case."""
    if not url:
        return url
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url
    if not parts.scheme or not parts.netloc:
        return url
    path = _PATH_SESSION_RE.sub("", parts.path)
    kept = [piece for piece, key, value in _param_pairs(parts.query) if not _is_noise_param(key, value)]
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, "&".join(kept), ""))


def dedup_key(url: str) -> str:
    """The key exact duplicates share: normalised, lower-cased, no trailing
    slash, http and https folded (the fan-out's existing dedup rule on top of
    :func:`normalize_result_url`)."""
    norm = normalize_result_url(url or "")
    return norm.lower().rstrip("/").replace("https://", "http://")


def _engine_names(item: dict) -> list[str]:
    names = list(item.get("found_by") or [])
    engine = item.get("source_engine")
    if engine and engine not in names:
        names.append(engine)
    return names


def _better(candidate: dict, current: dict) -> bool:
    """A real result link beats an address a page only mentioned in its text;
    then the higher engine weight wins. Ties keep the earlier one."""
    cand_key = (not candidate.get("from_text"), float(candidate.get("source_weight", 0.5) or 0.5))
    curr_key = (not current.get("from_text"), float(current.get("source_weight", 0.5) or 0.5))
    return cand_key > curr_key


def merge_duplicates(links: Iterable[dict]) -> list[dict]:
    """Collapse exact duplicate URLs (after normalisation).

    The merged candidate takes the first occurrence's position and the best
    occurrence's fields, and records ``found_by`` (every engine that returned
    it, in order) and ``engine_count``. Links with an empty URL are dropped (as
    the fan-out's dedup always did)."""
    out: list[dict] = []
    index: dict[str, int] = {}
    for item in links:
        key = dedup_key(str(item.get("link", "")))
        if not key:
            continue
        pos = index.get(key)
        if pos is None:
            index[key] = len(out)
            names = _engine_names(item)
            if names:
                item["found_by"] = names
                item["engine_count"] = len(names)
            out.append(item)
            continue
        current = out[pos]
        names = _engine_names(current)
        for name in _engine_names(item):
            if name not in names:
                names.append(name)
        chosen = item if _better(item, current) else current
        if names:
            chosen["found_by"] = names
            chosen["engine_count"] = len(names)
        out[pos] = chosen
    return out
