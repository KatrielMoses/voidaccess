"""
tests/test_verify_gate.py — belief-gate verification of LLM-extracted IOCs.

The gate must be leak-proof: it may never keep a value that is malformed or
absent from the source text, and it must never drop a value that is both
well-formed and genuinely present.  These tests assert both directions plus
the fail-open / feature-flag behaviour.
"""

from __future__ import annotations

import pytest

from extractor.verify_gate import (
    GateVerdict,
    gate_llm_merged,
    is_enabled,
    verify_type,
)

# A realistic, fully-formed set of indicators.
GOOD_MD5 = "d41d8cd98f00b204e9800998ecf8427e"          # 32 hex
GOOD_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # 40 hex
GOOD_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # 64 hex
GOOD_CVE = "CVE-2024-3094"
GOOD_MITRE = "T1486"

PAGE_TEXT = (
    "Malware sample md5 "
    f"{GOOD_MD5} was dropped; the loader sha256 {GOOD_SHA256} beacons out. "
    f"Exploits {GOOD_CVE} and maps to ATT&CK {GOOD_MITRE}. "
    f"File hash sha1 {GOOD_SHA1} observed."
)


# --------------------------------------------------------------------------- #
# Shape rejection — malformed values never pass, regardless of grounding.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "entity_type,bad_value",
    [
        ("FILE_HASH_SHA256", "e3b0c44298fc1c149afbf4c8"),   # truncated
        ("FILE_HASH_MD5", "d41d8cd98f00b204e9800998ecf8427"),  # 31 chars
        ("FILE_HASH_SHA1", "zz39a3ee5e6b4b0d3255bfef95601890afd80709"),  # non-hex
        ("CVE_NUMBER", "CVE-24-3094"),                       # 2-digit year
        ("CVE_NUMBER", "CVE-2024-99"),                       # id too short
        ("MITRE_TECHNIQUE", "T999"),                         # only 3 digits
        ("MITRE_TECHNIQUE", "T1486.1"),                      # bad sub-technique
    ],
)
def test_malformed_values_are_rejected(entity_type, bad_value):
    # Put the bad value in the text too, to prove shape (not grounding) rejects it.
    kept, verdict = verify_type(entity_type, [bad_value], f"context {bad_value}")
    assert kept == []
    assert verdict.missing == [bad_value]
    assert verdict.ok is False


# --------------------------------------------------------------------------- #
# Grounding rejection — well-formed but hallucinated values never pass.
# --------------------------------------------------------------------------- #
def test_hallucinated_but_wellformed_hash_is_rejected():
    hallucinated = "a" * 64  # valid SHA256 shape, absent from PAGE_TEXT
    kept, verdict = verify_type("FILE_HASH_SHA256", [hallucinated], PAGE_TEXT)
    assert kept == []
    assert verdict.missing == [hallucinated]
    assert verdict.ok is False


def test_hallucinated_cve_is_rejected():
    kept, verdict = verify_type("CVE_NUMBER", ["CVE-2024-99999"], PAGE_TEXT)
    assert kept == []
    assert not verdict.ok


# --------------------------------------------------------------------------- #
# True positives — well-formed AND present values are kept.
# --------------------------------------------------------------------------- #
def test_genuine_values_are_kept():
    for entity_type, value in (
        ("FILE_HASH_MD5", GOOD_MD5),
        ("FILE_HASH_SHA1", GOOD_SHA1),
        ("FILE_HASH_SHA256", GOOD_SHA256),
        ("CVE_NUMBER", GOOD_CVE),
        ("MITRE_TECHNIQUE", GOOD_MITRE),
    ):
        kept, verdict = verify_type(entity_type, [value], PAGE_TEXT)
        assert kept == [value], f"{entity_type} dropped a genuine value"
        assert verdict.ok is True
        assert verdict.missing == []


def test_grounding_is_case_insensitive_for_hex():
    kept, verdict = verify_type("FILE_HASH_SHA256", [GOOD_SHA256.upper()], PAGE_TEXT)
    assert kept == [GOOD_SHA256.upper()]
    assert verdict.ok


def test_mixed_batch_keeps_only_verified():
    values = [GOOD_SHA256, "a" * 64, "e3b0c44298fc"]  # good, hallucinated, truncated
    kept, verdict = verify_type("FILE_HASH_SHA256", values, PAGE_TEXT)
    assert kept == [GOOD_SHA256]
    assert set(verdict.missing) == {"a" * 64, "e3b0c44298fc"}
    assert verdict.ok is False


# --------------------------------------------------------------------------- #
# gate_llm_merged — only gated keys touched; non-gated keys pass through.
# --------------------------------------------------------------------------- #
def test_gate_llm_merged_filters_only_gated_keys():
    merged = {
        "file_hashes_sha256": [GOOD_SHA256, "a" * 64],
        "cve_identifiers": [GOOD_CVE, "CVE-2024-99999"],
        "mitre_techniques": [GOOD_MITRE],
        # non-gated keys must be returned untouched
        "threat_actor_handles": ["@evilcorp"],
        "malware_names": ["LockBit"],
        "crypto_wallets": ["bc1qxy"],
    }
    out, verdicts = gate_llm_merged(merged, PAGE_TEXT)

    assert out["file_hashes_sha256"] == [GOOD_SHA256]
    assert out["cve_identifiers"] == [GOOD_CVE]
    assert out["mitre_techniques"] == [GOOD_MITRE]
    # untouched
    assert out["threat_actor_handles"] == ["@evilcorp"]
    assert out["malware_names"] == ["LockBit"]
    assert out["crypto_wallets"] == ["bc1qxy"]
    # verdicts recorded only for keys that had rejections
    rejected_types = {v.entity_type for v in verdicts}
    assert rejected_types == {"FILE_HASH_SHA256", "CVE_NUMBER"}


def test_ungated_type_passes_through_verify_type():
    kept, verdict = verify_type("MALWARE_FAMILY", ["LockBit", "Emotet"], PAGE_TEXT)
    assert kept == ["LockBit", "Emotet"]
    assert verdict.ok is True


# --------------------------------------------------------------------------- #
# Grounding can be disabled independently of shape.
# --------------------------------------------------------------------------- #
def test_grounding_disabled_keeps_wellformed_absent_value():
    hallucinated = "b" * 64
    kept, verdict = verify_type(
        "FILE_HASH_SHA256", [hallucinated], "no hashes here", grounded=False
    )
    assert kept == [hallucinated]  # shape passes, grounding not checked
    assert verdict.ok


# --------------------------------------------------------------------------- #
# Feature flag.
# --------------------------------------------------------------------------- #
def test_is_enabled_defaults_true(monkeypatch):
    monkeypatch.delenv("VOIDACCESS_VERIFY_LLM_IOCS", raising=False)
    assert is_enabled() is True


@pytest.mark.parametrize("val", ["false", "0", "no", "off", "FALSE", "Off"])
def test_is_enabled_falsey_values(monkeypatch, val):
    monkeypatch.setenv("VOIDACCESS_VERIFY_LLM_IOCS", val)
    assert is_enabled() is False


def test_empty_and_blank_values_are_dropped_quietly():
    kept, verdict = verify_type("CVE_NUMBER", ["", "   ", GOOD_CVE], PAGE_TEXT)
    assert kept == [GOOD_CVE]
    # blank strings are skipped, not counted as missing
    assert verdict.missing == []
    assert verdict.ok is True
