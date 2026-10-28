"""22R-1: query intent and the refined-query selector guard (synthetic queries)."""

from __future__ import annotations

import pytest

from voidaccess.query_intent import (
    classify_query,
    ensure_refined_query,
    find_selectors,
    normalize_domain,
    normalize_phone,
)


def _sel(query: str) -> list[tuple[str, str]]:
    return [(s.kind, s.value) for s in find_selectors(query)]


@pytest.mark.parametrize(
    "query,expected",
    [
        ("JDoe1987@Example.COM", [("email", "jdoe1987@example.com")]),
        ("+7 900 123-45-67", [("phone", "+79001234567")]),
        ("0044 20 7946 0000", [("phone", "+442079460000")]),
        ("https://www.Example-Corp.com/login", [("domain", "example-corp.com")]),
        ("www.acme.co.uk leak", [("domain", "acme.co.uk")]),
        ("8.8.4.4", [("ip", "8.8.4.4")]),
        ("2001:db8::1", [("ip", "2001:db8::1")]),
        ("cve 2024 3400", [("cve", "CVE-2024-3400")]),
        ("d41d8cd98f00b204e9800998ecf8427e", [("hash", "d41d8cd98f00b204e9800998ecf8427e")]),
        ("a" * 56 + ".onion", [("onion", "a" * 56 + ".onion")]),
        ("0x" + "Ab" * 20, [("wallet", "0x" + "ab" * 20)]),
        ("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", [("wallet", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")]),
        ("@SomeHandle selling access", [("handle", "@somehandle")]),
    ],
)
def test_each_selector_kind_is_found_and_normalised(query, expected):
    assert _sel(query) == expected
    assert classify_query(query).kind == "selector"


def test_phone_has_e164_and_digit_forms():
    sel = find_selectors("+79001234567")[0]
    assert sel.forms == ("+79001234567", "79001234567")
    assert normalize_phone("+7 (900) 123-45-67") == ("+79001234567", "79001234567")


def test_plain_numbers_and_versions_are_not_selectors():
    assert _sel("zqxvjwk plorbtank 7731 quenvax") == []
    assert _sel("LockBit 3.0") == []
    assert _sel("node.js stealer") == []
    assert _sel("released 2024-10-28") == []


def test_email_domain_is_not_a_second_selector():
    assert _sel("jdoe@example.com") == [("email", "jdoe@example.com")]


def test_normalize_domain_strips_scheme_www_path_port():
    assert normalize_domain("HTTPS://www.Example.com:8443/a?b") == "example.com"


@pytest.mark.parametrize(
    "query,kind,term",
    [
        ("LockBit ransomware", "named_threat", "lockbit"),
        ("RedLine stealer", "named_threat", "redline"),
        ("Lumma Stealer malware", "named_threat", "lumma"),
        ("Akira", "named_threat", "akira"),
        ("John Smith", "person_or_org", "john smith"),
        ("initial access broker", "topic", "initial access broker"),
        ("zqxvjwk plorbtank 7731 quenvax", "topic", "zqxvjwk plorbtank 7731 quenvax"),
    ],
)
def test_classify_kinds(query, kind, term):
    intent = classify_query(query)
    assert intent.kind == kind
    assert intent.terms[0] == term


def test_named_threat_carries_gazetteer_aliases():
    intent = classify_query("LockBit 3.0")
    assert intent.kind == "named_threat"
    assert "lockbit black" in intent.aliases


def test_selector_related_terms_are_parts_of_the_selector():
    assert classify_query("jdoe1987@example.com").related_terms == ["jdoe1987"]
    assert "acme" in classify_query("acme.com credentials leak").related_terms


# --- G2: the refine step can never lose the selector ----------------------


@pytest.mark.parametrize(
    "query,refined,expected,restored",
    [
        # e-mail reduced to its local part (seen in the baseline)
        ("jdoe1987@example.com", "jdoe1987 email", "jdoe1987@example.com", True),
        ("jdoe1987@example.com", "jdoe1987@example.com leak", "jdoe1987@example.com leak", False),
        # phone: '+' dropped is still the same number; a changed number is not
        ("+79001234567", "79001234567", "79001234567", False),
        ("+79001234567", "+7 900 123-45-67 leak", "+7 900 123-45-67 leak", False),
        ("+79001234567", "russian phone number", "+79001234567", True),
        # domain cut to its label (seen in the baseline)
        ("example-corp.com", "example-corp domain", "example-corp.com", True),
        ("example-corp.com", "example-corp.com darkweb", "example-corp.com darkweb", False),
        ("acme.com credentials leak", "acme credentials leak", "acme.com credentials leak", True),
        # person: name dropped or kept
        ("John Smith", "john smith darkweb", "john smith darkweb", False),
        ("John Smith", "smith leaked data", "John Smith", True),
        # named threat dropped
        ("LockBit ransomware", "ransomware leak site", "LockBit ransomware", True),
        ("LockBit ransomware", "LockBit 3.0 leak", "LockBit 3.0 leak", False),
        # topics are free to change
        ("initial access broker", "access broker", "access broker", False),
    ],
)
def test_ensure_refined_query(query, refined, expected, restored):
    out, was_restored = ensure_refined_query(refined, classify_query(query))
    assert out == expected
    assert was_restored is restored


def test_empty_refined_query_falls_back_to_original():
    assert ensure_refined_query("", classify_query("CVE-2024-3400"))[0] == "CVE-2024-3400"
