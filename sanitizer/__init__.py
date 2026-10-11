"""
sanitizer — the single, comprehensive shared-write sanitization choke point (P2.2).

The blocking half of the Epic-3 trust gate (3.2 steps 1–3 + 3.5): every path that
writes to the shared corpus (the page-snapshot object store, the global-entity
tier, and — in P4 — the write-to-shared pipeline) routes through
``sanitize_page`` or ``sanitize_entity`` here. There is no second sanitize path.

Coverage: PII strip (emails/phones + spaCy PERSON/GPE prose names/locations),
credential presence-only (structured combo/stealer/token detectors + prose
heuristics; raw secret never persisted), schema/structural validation
(entity_shape + gazetteer), and provenance stamping. All reuse existing
machinery — no new ML dependency. Governing principle: over-redact, never leak.

See ``sanitizer/README.md``.
"""

from sanitizer.detectors import (
    looks_like_secret,
    redact_credentials,
    redact_names_locations,
    redact_pii,
)
from sanitizer.gate import sanitize_entity, sanitize_page
from sanitizer.provenance import provenance_stamp, scraper_version
from sanitizer.validate import is_valid_shape

__all__ = [
    "sanitize_page",
    "sanitize_entity",
    "redact_credentials",
    "redact_pii",
    "redact_names_locations",
    "looks_like_secret",
    "is_valid_shape",
    "provenance_stamp",
    "scraper_version",
]
