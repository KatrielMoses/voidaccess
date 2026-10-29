"""
utils/onion_sweep.py — find v3 onion addresses written in page text.

Link extraction reads ``<a href>`` only, but leak sites and forums often print
mirror addresses as plain text, sometimes defanged so they do not render as a
link: ``[.]onion``, ``(dot)onion``, `` dot onion``, ``hxxp://``, spaces or
zero-width characters inside the address. This module undoes those forms and
returns only addresses that pass the full v3 format check (base32 length,
version byte and checksum), so joining stray words never yields a false
address.

Public API:
    is_valid_v3_host(host)             -> bool
    sweep_onion_addresses(text, ...)   -> list[SweptOnion]  (no safety gate)
    gated_text_onion_urls(text, ...)   -> list[str]         (safety-gated URLs)

Every caller that feeds a found address into a crawl frontier or into output
uses the gated form (or gates the result itself) so each address goes through
``utils.content_safety.url_is_blocked`` first.
"""

from __future__ import annotations

import base64
import hashlib
import html as _html
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional

# v3 onion: base32(pubkey[32] || checksum[2] || version[1]) = 56 chars.
V3_LEN = 56
_B32 = frozenset("abcdefghijklmnopqrstuvwxyz234567")
_VERSION = b"\x03"
_CHECKSUM_PREFIX = b".onion checksum"

# Characters removed outright: zero-width, joiners, soft hyphen, BOM.
_INVISIBLE_RE = re.compile("[­​-‏⁠-⁤﻿]")
# Defanged scheme.
_HXXP_RE = re.compile(r"\bh(?:xx|\*\*|XX)p(s?)(?=\s*(?:\[:\]|:))", re.IGNORECASE)
_BRACKET_COLON_RE = re.compile(r"\[:\]")
# Defanged dot before "onion": "[.]onion", "(.)onion", "{.}onion", "[dot]onion",
# " dot onion", ". onion", " .onion". Plain ".onion" is left alone.
_DOT_ONION_RE = re.compile(
    r"(?:\s*[\[\(\{<]\s*(?:\.|dot)\s*[\]\)\}>]\s*"
    r"|\s+dot\s+"
    r"|\s*\.\s+"
    r"|\s+\.\s*)"
    r"(?=onion\b)",
    re.IGNORECASE,
)
_ONION_MARK_RE = re.compile(r"\.onion\b")
# Path after the host: stop at whitespace, quotes and angle brackets.
_PATH_RE = re.compile(r"(?::\d{1,5})?(/[^\s\"'<>\]\)]*)?")
# How far back from ".onion" the scan may look (address + split spaces).
_MAX_BACK = V3_LEN + 64
_SCAN_SKIP = frozenset(" \t ")

DEFAULT_MAX_PER_PAGE = 20


@dataclass(frozen=True)
class SweptOnion:
    host: str            # "<56 chars>.onion", lower case
    url: str             # "http(s)://host[/path]"
    obfuscated: bool     # True when the text form needed un-defanging


def is_valid_v3_host(host: str) -> bool:
    """True when *host* (with or without ".onion") is a well-formed v3 onion
    address: 56 base32 chars decoding to a key, a matching checksum and
    version 3."""
    label = (host or "").strip().lower()
    if label.endswith(".onion"):
        label = label[: -len(".onion")]
    if len(label) != V3_LEN or not set(label) <= _B32:
        return False
    try:
        raw = base64.b32decode(label.upper())
    except Exception:
        return False
    pubkey, checksum, version = raw[:32], raw[32:34], raw[34:35]
    if version != _VERSION:
        return False
    digest = hashlib.sha3_256(_CHECKSUM_PREFIX + pubkey + version).digest()
    return digest[:2] == checksum


def _undefang(text: str) -> str:
    text = _html.unescape(text)
    text = _INVISIBLE_RE.sub("", text)
    text = _HXXP_RE.sub(lambda m: "http" + m.group(1), text)
    text = _BRACKET_COLON_RE.sub(":", text)
    text = _DOT_ONION_RE.sub(".", text)
    return text.lower()


def _label_before(text: str, end: int) -> Optional[tuple[str, int, bool]]:
    """Base32 label ending at *end* (exclusive), allowing spaces inside.

    Returns (label, start_index, had_spaces) or None. The 56 chars nearest to
    ".onion" are taken; a 57th base32 char glued directly to them means the
    run is longer than an address and is rejected.
    """
    chars: list[str] = []
    i = end - 1
    lo = max(0, end - _MAX_BACK)
    had_spaces = False
    start = end
    while i >= lo and len(chars) < V3_LEN:
        c = text[i]
        if c in _B32:
            chars.append(c)
            start = i
        elif c in _SCAN_SKIP and chars:
            had_spaces = True
        else:
            break
        i -= 1
    if len(chars) != V3_LEN:
        return None
    if start > 0 and text[start - 1] in _B32:
        return None  # glued to a longer base32 run
    return "".join(reversed(chars)), start, had_spaces


def sweep_onion_addresses(
    text: str,
    *,
    max_results: int = DEFAULT_MAX_PER_PAGE,
) -> List[SweptOnion]:
    """Valid v3 onion addresses in *text*, de-duplicated by host, in text
    order. No safety gate is applied here; see ``gated_text_onion_urls``."""
    if not text or max_results <= 0:
        return []
    raw_lower = text.lower()
    norm = _undefang(text)
    out: List[SweptOnion] = []
    seen: set[str] = set()
    for m in _ONION_MARK_RE.finditer(norm):
        found = _label_before(norm, m.start())
        if found is None:
            continue
        label, start, had_spaces = found
        if label in seen or not is_valid_v3_host(label):
            continue
        seen.add(label)
        host = f"{label}.onion"
        prefix = norm[max(0, start - 8):start]
        scheme = "https" if prefix.endswith("https://") else "http"
        path_m = _PATH_RE.match(norm, m.end())
        path = (path_m.group(1) or "") if path_m else ""
        path = path.rstrip(".,;:!?")
        obfuscated = had_spaces or host not in raw_lower
        out.append(SweptOnion(host=host, url=f"{scheme}://{host}{path}", obfuscated=obfuscated))
        if len(out) >= max_results:
            break
    return out


def gated_text_onion_urls(
    text: str,
    *,
    exclude_hosts: Iterable[str] = (),
    max_results: int = DEFAULT_MAX_PER_PAGE,
) -> List[str]:
    """Text-found onion URLs that pass the URL safety gate.

    Each address goes through ``url_is_blocked`` (host blocklists, URL terms
    and the content detector; fail-closed, drops counted) before it is
    returned. Hosts in *exclude_hosts* (e.g. already found as real links) are
    skipped before the gate so they are not counted twice.
    """
    from utils.content_safety import url_is_blocked

    excluded = {h.lower() for h in exclude_hosts}
    urls: List[str] = []
    if max_results <= 0:
        return urls
    for item in sweep_onion_addresses(text, max_results=max_results + len(excluded)):
        if item.host in excluded:
            continue
        if url_is_blocked(item.url):
            continue
        urls.append(item.url)
        if len(urls) >= max_results:
            break
    return urls
