"""Repair-then-reject filter for ORGANIZATION_NAME candidates.

NER labels link-directory titles ("Name - description"), markdown residue and
leak-site listing text as organisations (R1 measured about 6.5% of org values
as junk, the same in 2.0.3 and 2.1.0). This filter first repairs what is
recoverable (a markdown link tail, an unclosed parenthesis, emphasis marks,
leak-listing status words) and then rejects values that are not organisation
names. It runs in ``normalize_entities`` before the shape check, so a rejected
value never reaches the database or the NVD CPE lookup.

Built from and measured on 379 labelled R1 values (docs/regression notes).
"""

from __future__ import annotations

import re
from typing import Optional

# --- repair ------------------------------------------------------------------
_MD_TAIL = re.compile(r"\]\(.*$")            # "LinkedIn](https://..."  -> "LinkedIn"
_PAREN_TAIL = re.compile(r"\s*\([^)]*$")      # "OakBend Medical (USA"   -> "OakBend Medical"
# Leak-site listing status words around a victim name.
_LEAK_PREFIX = re.compile(r"^(?:(?:expired|published|pii|phi|new|updated)\s+)+", re.I)
_LEAK_SUFFIX = re.compile(r"\s+(?:confidential\s+)?(?:data(?:base)?\s+leak|data|leak(?:ed)?)$", re.I)

# --- reject ------------------------------------------------------------------
_SPACED_SEP = re.compile(r"\s[-–—|·•]+\s|[-–—|:]+$|^[-–—|:]+|:\s")
_MARKUP = re.compile(r"https?:|www\.|://|[\[\]{}<>#*@●←→]|-{3,}|[\U0001F000-\U0001FFFF]")
_SLASH = re.compile(r"[/\\]")
_FILE_OR_ONION = re.compile(r"\.(onion|7z|zip|rar|tar|gz|html?|php|py|txt|csv|sql|exe|dll)\b", re.I)
_DIRECTORY_WORDS = re.compile(
    r"\b(onion|onions|links?|director(?:y|ies)|urls?|hidden services?|v\.)(?=\W|$)", re.I
)
_B64 = re.compile(r"[A-Za-z0-9+/=]{16,}")
_KEY_MATERIAL = re.compile(r"\b(pgp|public key|seed phrase|mnemonic)\b", re.I)
# A title cut off mid-phrase ("Using AI to", "KrebsOnSecurity the").
_TRAILING_FUNCTION_WORD = re.compile(r"\s(?:to|the|of|for|and|a|an|in|on|with|by)$", re.I)
# Dark-market listing vocabulary, not organisation words.
_LISTING_WORDS = re.compile(
    r"\b(escrow|cashout|payouts|vendors?|register|powered|markets|ghb|gbl|thc)\b", re.I
)
_LATIN = re.compile(r"[A-Za-z]")
_CYRILLIC = re.compile(r"[\u0400-\u04FF]")
_WORD = re.compile(r"[^\W\d_]+", re.U)
_CONNECTORS = frozenset({"the", "of", "and", "for", "de", "du", "la", "le", "y", "und", "&"})
MAX_CONTENT_WORDS = 6


def repair(value: str) -> str:
    """The value with recoverable residue removed."""
    s = (value or "").strip()
    s = _MD_TAIL.sub("", s)
    s = _PAREN_TAIL.sub("", s)
    s = s.strip(" *_`")
    s = _LEAK_PREFIX.sub("", s)
    s = _LEAK_SUFFIX.sub("", s).strip(" ,")
    return s


def reject_reason(value: str) -> Optional[str]:
    """Why the *repaired* value is not an organisation name, or None."""
    s = repair(value)
    if len(s) < 2:
        return "empty"
    if _SPACED_SEP.search(s):
        return "title_separator"
    if _MARKUP.search(s):
        return "markup"
    if _SLASH.search(s):
        return "slash_list"
    if _FILE_OR_ONION.search(s):
        return "file_or_onion"
    if _DIRECTORY_WORDS.search(s):
        return "directory_word"
    m = _B64.search(s)
    if m and re.search(r"\d", m.group()) and re.search(r"[a-z]", m.group()) and re.search(r"[A-Z]", m.group()):
        return "base64"
    if _KEY_MATERIAL.search(s):
        return "key_material"
    if any(_LATIN.search(w) and _CYRILLIC.search(w) for w in re.findall(r"\w+", s)):
        return "mixed_script"  # homoglyph spam, not a name
    if _TRAILING_FUNCTION_WORD.search(s):
        return "truncated_phrase"
    if _LISTING_WORDS.search(s):
        return "listing_word"
    content = [w for w in _WORD.findall(s) if w.lower() not in _CONNECTORS]
    if len(content) > MAX_CONTENT_WORDS:
        return "too_long"
    return None


def clean_org_name(value: str) -> Optional[str]:
    """The repaired organisation name, or None when the value must be dropped."""
    if reject_reason(value) is not None:
        return None
    return repair(value)
