"""
sanitizer/detectors.py — credential + PII detection/redaction primitives.

All reuse existing detectors — no new ML, no second regex zoo:

* **Credentials** — every secret detector in ``extractor.regex_patterns``
  (API keys, AWS/GitHub/Slack/Discord/Stripe/Google tokens, JWTs, PGP key
  blocks, the structured combo-list/stealer-log dumps) PLUS a small set of
  **prose heuristics** (``the password is X``, ``creds: X``, ``user/pass``)
  that the existing structured/entropy detectors deliberately miss. Every match
  is replaced by ``hygiene.CREDENTIAL_PRESENT`` — the raw secret is never
  emitted (presence-only, per requirement 5.L / 5.8).
* **PII** — emails/phones via the existing ``hygiene.strip_pii`` regexes, plus
  free-form-prose **personal names / locations** via the existing spaCy NER
  (``extractor.ner.get_nlp`` → PERSON/GPE/LOC labels). No new model.

Over-redact bias: a false-positive redaction is cosmetic; a missed secret/PII
string is a legal failure. Heuristics are tuned for recall, and PII redaction is
**fail-closed** — if the NER model is unavailable, name/location coverage cannot
be guaranteed, so :func:`redact_names_locations` reports that rather than
silently skipping.
"""

from __future__ import annotations

import re
from typing import Optional

from hygiene import CREDENTIAL_PRESENT, strip_pii

# spaCy's own performance cap (mirrors extractor.ner) — never feed the model an
# unbounded document.
_NER_WINDOW = 100_000

# NER labels that denote victim PII we must strip from free-form prose.
_PII_LABELS = frozenset({"PERSON", "GPE", "LOC"})

# --------------------------------------------------------------------------- #
# Prose credential heuristics (the gap the structured/entropy detectors miss)
# --------------------------------------------------------------------------- #
# Recall-biased: match a credential *keyword* followed by a value and redact the
# whole span. Deliberately loose — over-redaction here is acceptable.
_PROSE_CREDENTIAL_RES: tuple[re.Pattern, ...] = (
    # "the password is hunter2", "password = hunter2", "pwd: hunter2",
    # "passphrase is …", "pin is 1234", "otp: 000000"
    re.compile(
        r"(?:the\s+)?"
        r"(?:pass(?:word|phrase)?|passwd|pwd|pin|otp|secret|api[\s_-]?key|token)"
        r"\s*(?:is|was|=|:)\s*"
        r"[\"']?(\S{3,})[\"']?",
        re.IGNORECASE,
    ),
    # "creds: admin/pass", "credentials - admin:pass", "login: admin pass: x"
    re.compile(
        r"(?:creds?|credentials?|login)\s*[:=\-]\s*(\S{3,})",
        re.IGNORECASE,
    ),
    # inline "user/pass" or "username:password" slash/colon pair after a
    # user-ish keyword
    re.compile(
        r"(?:user(?:name)?|login|acct|account)\s*[:/]\s*\S{2,}\s*[:/]\s*\S{3,}",
        re.IGNORECASE,
    ),
)


def _structured_credential_patterns() -> tuple[re.Pattern, ...]:
    """Return every structured secret/credential regex from the extractor.

    Imported lazily: ``extractor.regex_patterns`` is heavy and the sanitizer may
    be imported on paths that never sanitize.
    """
    from extractor.regex_patterns import (
        API_KEY_PATTERN,
        AWS_ACCESS_KEY_PATTERN,
        AWS_SECRET_KEY_PATTERN,
        COMBO_LIST_PATTERN,
        DISCORD_TOKEN_PATTERN,
        GITHUB_TOKEN_PATTERN,
        GOOGLE_API_KEY_PATTERN,
        JWT_TOKEN_PATTERN,
        SLACK_TOKEN_PATTERN,
        STEALER_LOG_PATTERN,
        STRIPE_KEY_PATTERN,
    )

    patterns = [
        STEALER_LOG_PATTERN,
        COMBO_LIST_PATTERN,
        API_KEY_PATTERN,
        AWS_ACCESS_KEY_PATTERN,
        AWS_SECRET_KEY_PATTERN,
        GITHUB_TOKEN_PATTERN,
        SLACK_TOKEN_PATTERN,
        DISCORD_TOKEN_PATTERN,
        JWT_TOKEN_PATTERN,
        GOOGLE_API_KEY_PATTERN,
        STRIPE_KEY_PATTERN,
    ]
    # PGP private/public key blocks — armored secret material.
    try:
        from extractor.regex_patterns import _PGP_BLOCK_RE  # noqa: PLC0415

        patterns.append(_PGP_BLOCK_RE)
    except Exception:
        pass
    return tuple(patterns)


def _replace_spans(text: str, spans: list[tuple[int, int]], marker: str) -> str:
    """Replace non-overlapping (start, end) spans with *marker* (coalescing)."""
    if not spans:
        return text
    spans.sort()
    out: list[str] = []
    cursor = 0
    for start, end in spans:
        if start < cursor:
            if end > cursor:
                cursor = end
            continue
        out.append(text[cursor:start])
        out.append(marker)
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def redact_credentials(text: str) -> str:
    """Replace every detected credential/secret span with ``CREDENTIAL_PRESENT``.

    Composes the structured extractor detectors with the prose heuristics. The
    raw secret is never returned.
    """
    if not text:
        return text
    spans: list[tuple[int, int]] = []
    for pattern in _structured_credential_patterns() + _PROSE_CREDENTIAL_RES:
        for match in pattern.finditer(text):
            spans.append((match.start(), match.end()))
    return _replace_spans(text, spans, CREDENTIAL_PRESENT)


def looks_like_secret(value: str) -> bool:
    """True if *value* (a single token/entity value) matches any secret detector.

    Used by the entity gate to keep raw secrets out of the shared entity tier.
    """
    if not value:
        return False
    for pattern in _structured_credential_patterns():
        if pattern.search(value):
            return True
    return False


def redact_names_locations(text: str) -> Optional[str]:
    """Redact spaCy PERSON/GPE/LOC spans from free-form prose.

    Returns the redacted text, or ``None`` when the NER model is unavailable —
    a **fail-closed** signal so the caller does not store text whose personal
    names/locations could not be verified as removed. Reuses the single cached
    spaCy pipeline (``extractor.ner.get_nlp``); adds no new model.
    """
    if not text:
        return text

    from extractor.ner import get_nlp

    nlp = get_nlp()
    if nlp is None:
        return None  # fail-closed: cannot guarantee name/location redaction

    # NER the full document in windows (spaCy caps single calls); regex-based
    # PII (emails/phones) already covers the whole text elsewhere.
    result_parts: list[str] = []
    for start in range(0, len(text), _NER_WINDOW):
        chunk = text[start : start + _NER_WINDOW]
        try:
            doc = nlp(chunk)
        except Exception:
            # A model that loaded but fails on input is still an unverified
            # redaction — fail closed.
            return None
        spans = [
            (ent.start_char, ent.end_char)
            for ent in doc.ents
            if ent.label_ in _PII_LABELS
        ]
        result_parts.append(_replace_spans(chunk, spans, "[redacted-pii]"))
    return "".join(result_parts)


def redact_pii(text: str) -> Optional[str]:
    """Full PII redaction: emails/phones (regex) + names/locations (NER).

    Returns redacted text, or ``None`` (fail-closed) when NER is unavailable.
    """
    if not text:
        return text
    text = strip_pii(text)  # emails + phones (existing hygiene regexes)
    return redact_names_locations(text)
