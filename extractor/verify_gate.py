"""
extractor/verify_gate.py — Deterministic verification gate for LLM-extracted IOCs.

belief-gate discipline applied to entity extraction.  The LLM *declares* which
format-constrained indicators it found (the "required" set); a deterministic
parser computes which of those are actually well-formed **and** present in the
source page text (the "present" set).  Anything the LLM claims that the parser
cannot confirm (``required - present``) is rejected before it enters the entity
store — the same set-difference guarantee described in belief-gate/gate-REPL.

Why this exists
---------------
``extractor/llm_extract.py`` merges the LLM's ``file_hashes_*``,
``cve_identifiers`` and ``mitre_techniques`` verbatim into the result dict.
Only wallets (``_classify_wallet``) and URLs (``.onion`` split) are
re-verified.  A truncated hash, a hallucinated ``CVE-2024-99999`` or an
invented ``T9999`` therefore flows straight into normalisation and can clear
the 0.80 confidence floor on method prior alone.  This module closes that leak.

Design
------
Only *format-constrained* types are gated, and only the values the LLM added
(regex/NER values are already deterministic and are never routed here):

    FILE_HASH_MD5, FILE_HASH_SHA1, FILE_HASH_SHA256, CVE_NUMBER, MITRE_TECHNIQUE

Two independent checks per value — **both** must pass:
  1. shape     — ``fullmatch`` against the strict format regex (catches
                 truncated / malformed values).
  2. grounding — the exact token appears in the source page text as a
                 well-formed match (catches hallucinations the LLM invented
                 that are syntactically valid but never appeared).

The regex patterns are imported from ``extractor.regex_patterns`` so there is a
single source of truth for what a valid hash / CVE / MITRE technique looks
like.  Zero runtime dependencies; every function is total and never raises.

Disable with ``VOIDACCESS_VERIFY_LLM_IOCS=false``.

Public interface
----------------
GateVerdict                              — dataclass: required / present / missing / ok
verify_type(entity_type, values, text)   — (kept_values, GateVerdict)
gate_llm_merged(merged, page_text)       — gate an llm_extract ``merged`` dict
is_enabled()                             — read the feature flag
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from extractor.regex_patterns import (
    _CVE_RE,
    _FILE_HASH_MD5_RE,
    _FILE_HASH_SHA1_RE,
    _FILE_HASH_SHA256_RE,
    _MITRE_TECHNIQUE_RE,
)

logger = logging.getLogger(__name__)

# Strict format patterns per gated entity type — single source of truth is
# extractor.regex_patterns (these are the same compiled objects the regex tier
# uses), so the gate and the regex extractor can never drift apart.
_FORMAT_RE = {
    "FILE_HASH_MD5": _FILE_HASH_MD5_RE,
    "FILE_HASH_SHA1": _FILE_HASH_SHA1_RE,
    "FILE_HASH_SHA256": _FILE_HASH_SHA256_RE,
    "CVE_NUMBER": _CVE_RE,
    "MITRE_TECHNIQUE": _MITRE_TECHNIQUE_RE,
}

# Hex indicators compare case-insensitively; CVE / MITRE canonicalise to upper
# (matching _extract_cve / _extract_mitre which upper-case their output).
_HEX_TYPES = frozenset({"FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"})
_UPPER_TYPES = frozenset({"CVE_NUMBER", "MITRE_TECHNIQUE"})

# llm_extract.py output keys → internal entity type, for the gated subset only.
# Keys absent here (crypto_wallets, urls, dates, threat_actor_handles,
# malware_names) are handled elsewhere and pass through this gate untouched.
_LLM_KEY_TO_GATED_TYPE = {
    "cve_identifiers": "CVE_NUMBER",
    "mitre_techniques": "MITRE_TECHNIQUE",
    "file_hashes_md5": "FILE_HASH_MD5",
    "file_hashes_sha1": "FILE_HASH_SHA1",
    "file_hashes_sha256": "FILE_HASH_SHA256",
}


@dataclass
class GateVerdict:
    """Outcome of verifying one entity type's LLM-claimed values.

    ``ok`` is True only when nothing was rejected — mirroring belief-gate's
    "never certify an answer it can't prove": if ``missing`` is non-empty the
    caller knows exactly which claims failed and why.
    """

    entity_type: str
    required: list[str] = field(default_factory=list)  # what the LLM claimed
    present: list[str] = field(default_factory=list)   # parser-verified, kept
    missing: list[str] = field(default_factory=list)   # required - present
    ok: bool = True


def is_enabled() -> bool:
    """True unless VOIDACCESS_VERIFY_LLM_IOCS is explicitly falsey."""
    return os.getenv("VOIDACCESS_VERIFY_LLM_IOCS", "true").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _canon(entity_type: str, value: str) -> str:
    """Canonical form for grounding comparison."""
    v = value.strip()
    if entity_type in _HEX_TYPES:
        return v.lower()
    if entity_type in _UPPER_TYPES:
        return v.upper()
    return v


def _present_tokens(entity_type: str, page_text: str) -> set[str]:
    """Canonical set of well-formed tokens of *entity_type* actually in *text*.

    Uses the format regex directly (no surrounding-context requirement) so a
    genuine hash the LLM found where the regex tier's context gate missed it is
    still credited as grounded — while a value the LLM invented (absent from the
    text) is not.
    """
    rex = _FORMAT_RE.get(entity_type)
    if rex is None or not page_text:
        return set()
    return {_canon(entity_type, m.group(0)) for m in rex.finditer(page_text)}


def verify_type(
    entity_type: str,
    values,
    page_text: str,
    *,
    grounded: bool = True,
) -> tuple[list[str], GateVerdict]:
    """Verify *values* claimed for *entity_type* against the deterministic parser.

    Returns ``(kept_values, verdict)``.  A value is kept only if it (1) matches
    the strict format regex and (2) — when *grounded* — appears in *page_text*.
    Non-gated types pass through unchanged with an all-ok verdict.  Never raises.
    """
    required = [str(v) for v in (values or [])]
    rex = _FORMAT_RE.get(entity_type)
    if rex is None:
        return required, GateVerdict(entity_type, required, list(required), [], True)

    try:
        present_in_text = _present_tokens(entity_type, page_text) if grounded else None
        kept: list[str] = []
        present: list[str] = []
        missing: list[str] = []
        seen: set[str] = set()

        for raw in required:
            val = (raw or "").strip()
            if not val:
                continue
            canon = _canon(entity_type, val)
            shape_ok = bool(rex.fullmatch(val))
            ground_ok = True if present_in_text is None else (canon in present_in_text)
            if shape_ok and ground_ok:
                if canon not in seen:
                    seen.add(canon)
                    kept.append(val)
                    present.append(val)
            else:
                missing.append(val)

        return kept, GateVerdict(entity_type, required, present, missing, not missing)
    except Exception as exc:  # noqa: BLE001 — gate must never break extraction
        logger.debug("verify_type failed for %s (non-fatal): %s", entity_type, exc)
        # Fail-open on an internal gate error: return the input unchanged rather
        # than silently dropping legitimate entities on a bug in the gate.
        return required, GateVerdict(entity_type, required, list(required), [], True)


def gate_llm_merged(
    merged: dict[str, list],
    page_text: str,
    *,
    grounded: bool = True,
) -> tuple[dict[str, list], list[GateVerdict]]:
    """Verify the format-constrained subset of an ``llm_extract`` merged dict.

    *merged* is keyed by LLM output key (e.g. ``file_hashes_sha256``).  Only the
    gated keys are touched; everything else is copied through untouched.  Returns
    ``(gated_merged, verdicts)`` where *verdicts* holds only the types that had
    at least one rejection (empty when nothing was rejected).
    """
    out = dict(merged)
    verdicts: list[GateVerdict] = []
    for llm_key, entity_type in _LLM_KEY_TO_GATED_TYPE.items():
        if llm_key not in out:
            continue
        kept, verdict = verify_type(
            entity_type, out[llm_key], page_text, grounded=grounded
        )
        out[llm_key] = kept
        if verdict.missing:
            verdicts.append(verdict)
    return out, verdicts
