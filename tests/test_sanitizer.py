"""
tests/test_sanitizer.py — P2.2 comprehensive-sanitizer + consent acceptance.

Covers the legal classes per requirement (over-redact, never leak):
free-form-prose PII (names/locations/emails), prose + structured credentials
(presence-only, raw value absent), shape/noise rejection, provenance stamping,
the NER fail-closed posture, and the private-mode consent switch.
"""

from __future__ import annotations

import pytest

from sanitizer import (
    is_valid_shape,
    provenance_stamp,
    redact_credentials,
    redact_pii,
    sanitize_entity,
    sanitize_page,
    scraper_version,
)

# spaCy PERSON/GPE redaction is required for the prose-PII acceptance tests.
_SPACY = pytest.importorskip("spacy")
try:
    _SPACY.load("en_core_web_sm")
    _HAS_MODEL = True
except Exception:  # pragma: no cover - environment without the model
    _HAS_MODEL = False

requires_ner = pytest.mark.skipif(
    not _HAS_MODEL, reason="en_core_web_sm not installed"
)


# ---------------------------------------------------------------------------
# Credentials — structured + prose, presence-only
# ---------------------------------------------------------------------------

def test_structured_credentials_redacted():
    text = (
        "victim@example.com:SuperSecret123\n"
        "URL: https://site.example/login\n"
        "USER: jdoe\n"
        "PASS: Hunter2Pass\n"
    )
    out = redact_credentials(text)
    assert "SuperSecret123" not in out
    assert "Hunter2Pass" not in out
    assert "CREDENTIAL_PRESENT" in out


def test_prose_credentials_redacted():
    """The free-form cases P2.1 could not catch."""
    cases = [
        "the password is hunter2 for the panel",
        "password: correcthorse",
        "creds: admin/rootpass",
        "login: administrator pass: letmein123",
        "the api key is sk_live_abcdef1234567890abcdef",
    ]
    for text in cases:
        out = redact_credentials(text)
        # The secret value must be gone; a presence marker takes its place.
        for secret in ("hunter2", "correcthorse", "rootpass", "letmein123", "sk_live_"):
            assert secret not in out, f"{secret!r} leaked from {text!r}"
        assert "CREDENTIAL_PRESENT" in out, f"no marker for {text!r}"


def test_token_secrets_redacted():
    text = "leaked token AKIAIOSFODNN7EXAMPLE and ghp_1234567890abcdef1234567890abcdefABCD"
    out = redact_credentials(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "ghp_1234567890abcdef1234567890abcdefABCD" not in out


# ---------------------------------------------------------------------------
# PII — emails/phones + free-form-prose names/locations
# ---------------------------------------------------------------------------

@requires_ner
def test_prose_pii_names_and_locations_redacted():
    text = (
        "The stolen records belong to John Smith who lives in Manchester. "
        "Reach him at john.smith@personal.example or +1 (555) 987 6543."
    )
    out = redact_pii(text)
    assert out is not None
    assert "John Smith" not in out            # PERSON (spaCy)
    assert "Manchester" not in out            # GPE (spaCy)
    assert "john.smith@personal.example" not in out  # email (regex)
    assert "555" not in out                   # phone (regex)


def test_redact_pii_fail_closed_when_ner_unavailable(monkeypatch):
    """If the NER model is unavailable, redact_pii must fail-closed (None),
    not silently skip name/location redaction."""
    import sanitizer.detectors as detectors

    monkeypatch.setattr(detectors, "get_nlp", lambda: None, raising=False)
    # Patch the import target used inside redact_names_locations.
    import extractor.ner as ner

    monkeypatch.setattr(ner, "_get_nlp", lambda: None)
    assert detectors.redact_pii("Alice met Bob in Paris.") is None


def test_sanitize_page_fail_closed_drops_when_ner_down(monkeypatch):
    import extractor.ner as ner

    monkeypatch.setattr(ner, "_get_nlp", lambda: None)
    assert sanitize_page("Some ordinary page content with no secrets.") is None


# ---------------------------------------------------------------------------
# Shape / structural validation
# ---------------------------------------------------------------------------

def test_shape_validation_rejects_noise_accepts_real():
    # Bare common-language "handle" is noise for a shape-validated type.
    assert is_valid_shape("THREAT_ACTOR_HANDLE", "the") is False
    assert is_valid_shape("THREAT_ACTOR_HANDLE", "") is False
    # A precise IOC type passes through (validated by its own regex upstream).
    assert is_valid_shape("ip_address", "203.0.113.7") is True


# ---------------------------------------------------------------------------
# Entity gate
# ---------------------------------------------------------------------------

def test_sanitize_entity_drops_pii_types_and_secrets():
    assert sanitize_entity("PERSON_NAME", "John Smith") is None      # victim PII
    assert sanitize_entity("LOCATION", "Manchester") is None
    assert sanitize_entity("api_key", "AKIAIOSFODNN7EXAMPLE") is None  # raw secret
    # A legitimate IOC entity survives.
    assert sanitize_entity("ip_address", "203.0.113.7") == "203.0.113.7"
    assert sanitize_entity("email", "actor@evil.example") == "actor@evil.example"


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

def test_provenance_stamp_has_source_timestamp_version():
    stamp = provenance_stamp(source="abcd.onion")
    assert stamp["source"] == "abcd.onion"
    assert stamp["scraper_version"] == scraper_version()
    assert "captured_at" in stamp and "T" in stamp["captured_at"]  # ISO 8601


# ---------------------------------------------------------------------------
# Single choke point (structural)
# ---------------------------------------------------------------------------

def test_single_choke_point_grep():
    """sanitize_page / sanitize_entity are defined exactly once (in sanitizer)."""
    import os
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent
    _prune = {".claude", ".test_venv", ".git", "tests", "__pycache__", "node_modules"}
    by_name: dict[str, list[str]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _prune]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            py = pathlib.Path(dirpath) / fn
            try:
                text = py.read_text(encoding="utf-8")
            except Exception:
                continue
            for name in ("sanitize_page", "sanitize_entity"):
                if re.search(rf"^def {name}\b", text, re.MULTILINE):
                    by_name.setdefault(name, []).append(py.relative_to(root).as_posix())

    assert by_name.get("sanitize_page") == ["sanitizer/gate.py"], by_name
    assert by_name.get("sanitize_entity") == ["sanitizer/gate.py"], by_name
