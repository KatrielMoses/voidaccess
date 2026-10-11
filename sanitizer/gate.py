"""
sanitizer/gate.py — THE single shared-write sanitization choke point.

Every path that writes to the shared corpus routes through one of the two
functions here — there is no second sanitize path anywhere (grep-provable):

* ``sanitize_page(text)`` — for page-content bytes (the snapshot store). Full
  coverage: content-safety drop gate → comprehensive credential redaction
  (structured + prose) → PII redaction (emails/phones + spaCy PERSON/GPE).
  Returns sanitized text, or ``None`` to *not store* (empty, content-safety
  flagged, or — fail-closed — NER unavailable so name/location redaction cannot
  be guaranteed).

* ``sanitize_entity(entity_type, value)`` — for a single shared entity/IOC value
  (the global-entity tier). Rejects malformed/noise (shape validation), raw
  secrets (presence-only, never stored raw), and inherently-PII entity types.
  Returns the value safe to store canonically, or ``None`` to drop it.

Governing principle (requirement 5.L): over-redact, never leak. Every ambiguous
case biases to redaction/drop.

This is the blocking half of the Epic-3 trust gate (3.2 steps 1–3 + 3.5); the
trust-*scoring* half (quarantine, corroboration, reputation, anomaly) is P4.
"""

from __future__ import annotations

from typing import Optional

from sanitizer.detectors import looks_like_secret, redact_credentials, redact_pii
from sanitizer.validate import is_valid_shape

# Performance cap mirrored from the extraction pipeline.
_MAX_TEXT = 200_000

# Entity types that are inherently victim PII — never contributed to the shared
# corpus (over-redact: an actor's own name/location travels as a THREAT_ACTOR /
# ORGANIZATION entity, not these). Compared case-insensitively.
_PII_ENTITY_TYPES = frozenset(
    {
        "PERSON",
        "PERSON_NAME",
        "PERSON_OR_ROLE",
        "LOCATION",
        "GPE",
        "ADDRESS",
        "POSTAL_ADDRESS",
        "PHONE",
        "PHONE_NUMBER",
    }
)


def sanitize_page(text: str) -> Optional[str]:
    """Sanitize page text for shared storage, or ``None`` to skip storage.

    Order matters: credentials are redacted before PII so a whole
    ``email:password`` line is removed as a credential rather than leaving the
    password after the email is stripped.
    """
    if not text:
        return None

    text = text[:_MAX_TEXT]

    from utils.content_safety import sanitize_content

    cleaned, flagged = sanitize_content(text)
    if flagged:
        return None  # CSAM/gore — never stored, in any form

    cleaned = redact_credentials(cleaned)
    cleaned = redact_pii(cleaned)  # None if NER unavailable (fail-closed)
    if cleaned is None:
        return None
    return cleaned


def sanitize_entity(
    entity_type: str, value: str, context_text: str | None = None
) -> Optional[str]:
    """Return *value* if safe to store as a shared entity, else ``None``.

    Drops: empty values, inherently-PII entity types, raw secrets (kept
    presence-only elsewhere), and shape-invalid / noise artifacts.
    """
    if not value or not value.strip():
        return None

    if (entity_type or "").strip().upper() in _PII_ENTITY_TYPES:
        return None  # victim identity never enters the shared corpus

    if looks_like_secret(value):
        return None  # raw secret never stored; presence-only handled upstream

    if not is_valid_shape(entity_type, value, context_text=context_text):
        return None  # malformed / noise

    return value
