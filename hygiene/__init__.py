"""hygiene — reusable IOC-hygiene helper (the Epic-3 sanitizer seed).

A pure, unit-testable normalization choke point that every new data source's output
passes through before storage/display. Built once as a function module rather than
inlined per source, because the Epic-3 trust-gate sanitizer will consume the same
primitives.

Three concerns:

  * **Defang** IOCs (URLs/domains/IPs/emails) — a DISPLAY transform. VoidAccess
    stores *canonical* values (so they stay queryable/joinable across sources) and
    defangs at the display/export boundary; this module is the single place that
    transform is reached from new code. Reuses ``utils/defang.py`` — do not
    reinvent. (A divergent all-octet IP defang exists in
    ``export/ioc_package.py:_defang_ip``; flagged for later consolidation, NOT
    changed here.)
  * **Credential presence-only** — never return a raw credential/password for
    storage. Reuses the extractor discipline: the storage backstop
    ``content_safety.is_blocked_entity_value`` (drops common-password-like values
    regardless of type) and ``export.redact_credential`` (partial redaction that
    never emits the raw secret). Sources emit a presence marker, never the secret.
  * **PII strip** — remove victim emails/phones from free text before storage.
    Personal-name and postal-address redaction needs NER and is DEFERRED to the
    fuller Epic-3 sanitizer; documented here, not silently skipped.

OUT OF SCOPE in this seed (lands in P4 with the trust gate): ToS/redistribution
"derived-indicators-only" enforcement — that only bites when republishing to the
shared tier, so it is deliberately not implemented here.
"""
from __future__ import annotations

import re
from typing import Optional

from utils.defang import defang_text as _defang_text
from utils.defang import defang_value as _defang_value

CREDENTIAL_PRESENT = "CREDENTIAL_PRESENT"

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# Deliberately conservative: 9+ digits with common separators, not adjacent to
# word chars, dots, or hyphens — so it won't eat CVE ids (CVE-2021-44228),
# hyphenated identifiers, hashes, or version strings.
_PHONE_RE = re.compile(r"(?<![\w.\-])(\+?\d[\d\s().\-]{7,}\d)(?![\w.\-])")


# --------------------------------------------------------------------------- #
# Defang — display-time (store canonical, defang here)
# --------------------------------------------------------------------------- #
def defang_ioc(entity_type: str, value: str) -> str:
    """Defang an IOC value for display, dispatched by entity type."""
    return _defang_value(entity_type, value)


def defang_text(text: str) -> str:
    """Defang all URLs/IPs in free text for display."""
    return _defang_text(text)


# --------------------------------------------------------------------------- #
# PII strip — storage-time
# --------------------------------------------------------------------------- #
def redact_email(email: str) -> str:
    """Privacy-safe email form: first 3 local chars + ``***@domain``.

    Consolidates the ``_safe_log_email`` helper that was copy-pasted across
    ``sources/email_reputation.py``, ``breach_lookup.py`` and ``infostealer.py``.
    """
    try:
        local, domain = email.split("@", 1)
        return f"{local[:3]}***@{domain}"
    except Exception:
        return "***@***"


def strip_pii(text: str) -> str:
    """Redact victim PII (emails, phone numbers) from free text before storage.

    Personal-name / postal-address redaction requires NER and is DEFERRED to the
    Epic-3 sanitizer; this seed covers the pattern-matchable PII classes only.
    """
    if not text:
        return text
    text = _EMAIL_RE.sub(lambda m: redact_email(m.group(0)), text)
    text = _PHONE_RE.sub("[redacted-phone]", text)
    return text


# --------------------------------------------------------------------------- #
# Credential presence-only — storage-time
# --------------------------------------------------------------------------- #
def is_blocked_value(entity_type: str, value: str) -> bool:
    """Storage backstop: True if *value* must be dropped (empty, common-password
    -like, or prohibited-content). Re-exports ``content_safety`` so there is one
    implementation of the rule."""
    from utils.content_safety import is_blocked_entity_value

    return is_blocked_entity_value(entity_type, value)


def redact_credential(value: str) -> str:
    """Partial redaction of a value KNOWN to be a credential — never emits the raw
    secret. Re-export of ``export.redact_credential`` (one implementation)."""
    from export.ioc_package import redact_credential as _rc

    return _rc(value)


def sanitize_for_storage(entity_type: str, value: str) -> Optional[str]:
    """The storage choke point. Returns the value safe to store (CANONICAL form —
    defanging is a display concern, see ``defang_ioc``), or ``None`` if it must be
    dropped (blocked / common-password-like). A ``None`` means the caller stores a
    presence marker (e.g. ``CREDENTIAL_PRESENT``), never the raw secret.
    """
    if not value:
        return None
    if is_blocked_value(entity_type, value):
        return None
    return value
