"""Offline tests for the reusable IOC-hygiene helper (the Epic-3 sanitizer seed).

Per attack class: IOC defanging, PII stripping, and credential presence-only.
"""
from __future__ import annotations

import hygiene


# --------------------------------------------------------------------------- #
# Defang (display)
# --------------------------------------------------------------------------- #
def test_defang_ioc_by_type():
    assert hygiene.defang_ioc("IP_ADDRESS", "1.2.3.4") == "1.2.3[.]4"
    assert hygiene.defang_ioc("DOMAIN", "http://evil.example.com/x") == "hxxp://evil[.]example[.]com/x"
    assert hygiene.defang_ioc("EMAIL_ADDRESS", "u@bad.com") == "u[@]bad[.]com"
    # Non-IOC types pass through unchanged.
    assert hygiene.defang_ioc("CVE", "CVE-2021-44228") == "CVE-2021-44228"


def test_defang_text_neutralizes_urls_and_ips():
    out = hygiene.defang_text("visit http://10.0.0.1/payload and 8.8.8.8")
    assert "hxxp://" in out
    assert "10.0.0[.]1" in out
    assert "8.8.8[.]8" in out
    assert "http://" not in out


# --------------------------------------------------------------------------- #
# PII strip (storage)
# --------------------------------------------------------------------------- #
def test_redact_email():
    assert hygiene.redact_email("johndoe@example.com") == "joh***@example.com"
    assert hygiene.redact_email("not-an-email") == "***@***"


def test_strip_pii_redacts_emails_and_phones():
    text = "contact victim@corp.com or call +1 (415) 555-1234 about the breach"
    out = hygiene.strip_pii(text)
    assert "victim@corp.com" not in out
    assert "vic***@corp.com" in out
    assert "555-1234" not in out
    assert "[redacted-phone]" in out


def test_strip_pii_leaves_cve_and_hashes_intact():
    # The phone regex must not eat CVE ids or hashes.
    text = "CVE-2021-44228 affects log4j; hash d41d8cd98f00b204e9800998ecf8427e"
    out = hygiene.strip_pii(text)
    assert "CVE-2021-44228" in out
    assert "d41d8cd98f00b204e9800998ecf8427e" in out


# --------------------------------------------------------------------------- #
# Credential presence-only (storage)
# --------------------------------------------------------------------------- #
def test_common_password_is_blocked_from_storage():
    # A weak/common password must never be stored, regardless of entity type.
    assert hygiene.sanitize_for_storage("API_KEY", "password123") is None
    assert hygiene.is_blocked_value("API_KEY", "password123") is True


def test_empty_value_dropped():
    assert hygiene.sanitize_for_storage("IP_ADDRESS", "") is None


def test_benign_ioc_stored_canonical_not_defanged():
    # Storage keeps the canonical form; defanging is a display concern.
    assert hygiene.sanitize_for_storage("IP_ADDRESS", "1.2.3.4") == "1.2.3.4"
    assert hygiene.sanitize_for_storage("CVE", "CVE-2021-44228") == "CVE-2021-44228"


def test_redact_credential_never_emits_raw_secret():
    secret = "AKIAIOSFODNN7EXAMPLE"
    red = hygiene.redact_credential(secret)
    assert "[REDACTED]" in red
    assert red != secret
    # A github token likewise never round-trips its body.
    gh = "ghp_" + "a" * 36
    assert hygiene.redact_credential(gh) == "ghp_[REDACTED]"
    assert "a" * 36 not in hygiene.redact_credential(gh)
