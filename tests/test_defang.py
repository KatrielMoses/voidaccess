"""INT-F4 regression — defang dispatch coverage + flag honesty.

Two guarantees are locked here:

  1. Every entity type that carries a resolvable/clickable network address is
     actually transformed by ``defang_value`` (no network IOC falls through to
     the identity branch and gets shown raw).
  2. ``defang_value_checked`` derives its ``changed`` flag from a real transform,
     so the API ``defanged`` flag can never claim a transform that did not happen.
"""
from __future__ import annotations

from utils.defang import (
    defang_url,
    defang_value,
    defang_value_checked,
)

# Representative live values per network-IOC type. Each MUST come back defanged.
_NETWORK_IOCS = {
    "URL": "http://evil.example.com/login",
    "PASTE_URL": "https://pastebin.com/raw/abcd",
    "ONION_URL": "http://abcdefghij.onion/market",
    "DOMAIN": "evil.example.com",
    "DOMAIN_NAME": "bad.example.net",
    "ENS_DOMAIN": "vitalik.eth",
    "IP_ADDRESS": "1.2.3.4",
    "IPV6_ADDRESS": "2001:db8::1",
    "EMAIL_ADDRESS": "user@bad.com",
}

# Types that are NOT network addresses — defanging is a no-op and the flag must
# stay False (a wallet/hash/handle is not "clickable").
_NON_NETWORK = {
    "BITCOIN_ADDRESS": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "FILE_HASH_SHA256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "TELEGRAM_HANDLE": "@darkvendor",
    "CVE_NUMBER": "CVE-2021-44228",
}


def test_url_and_paste_url_are_defanged():
    """RV-F4a: a clearnet URL and a paste URL both come back defanged."""
    url_out, url_changed = defang_value_checked("URL", "http://evil.example.com/login")
    assert url_out == "hxxp://evil[.]example[.]com/login"
    assert url_changed is True

    paste_out, paste_changed = defang_value_checked(
        "PASTE_URL", "https://pastebin.com/raw/abcd"
    )
    assert paste_out == "hxxps://pastebin[.]com/raw/abcd"
    assert paste_changed is True
    # No raw scheme or bare host survives.
    for out in (url_out, paste_out):
        assert "http://" not in out and "https://" not in out


def test_every_network_ioc_type_is_transformed():
    """Dispatch coverage: no network-IOC type is left un-defanged."""
    for etype, value in _NETWORK_IOCS.items():
        out, changed = defang_value_checked(etype, value)
        assert changed is True, f"{etype} was not defanged"
        assert out != value


def test_non_network_types_are_untouched_and_flag_false():
    for etype, value in _NON_NETWORK.items():
        out, changed = defang_value_checked(etype, value)
        assert out == value, f"{etype} should not be transformed"
        assert changed is False


def test_flag_equals_actual_transform_invariant():
    """RV-F4b: ``changed`` is exactly ``defanged_value != original`` for every
    type — the flag can never lie."""
    for etype, value in {**_NETWORK_IOCS, **_NON_NETWORK}.items():
        out, changed = defang_value_checked(etype, value)
        assert changed == (defang_value(etype, value) != value)
        assert changed == (out != value)


def test_empty_value_never_reports_defanged():
    for value in ("", None):
        out, changed = defang_value_checked("URL", value)  # type: ignore[arg-type]
        assert changed is False
        assert out == value


def test_ipv6_defang_breaks_colons():
    assert defang_value("IPV6_ADDRESS", "2001:db8::1") == "2001[:]db8[:][:]1"


def test_defang_url_primitive_unchanged():
    """Constraint: the defang primitives keep their existing behavior."""
    assert defang_url("http://a.b.com/x") == "hxxp://a[.]b[.]com/x"
    assert defang_url("https://a.b.com") == "hxxps://a[.]b[.]com"
