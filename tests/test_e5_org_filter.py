"""E5: the ORGANIZATION_NAME repair-then-reject filter.

Every value is synthetic (example.invalid hosts, made-up onion labels,
reserved CVE year 2099); nothing touches the network.
"""

from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
# E5-9: org-name filter
# --------------------------------------------------------------------------- #

KEEP = ["Deloitte", "Acme Corp", "Cryptomus", "KrebsOnSecurity", "Group-IB", "AT&T",
        "B&G Foods, Inc.", "WordPress.org", "the United States Federal Bureau of Investigation"]
REJECT = ["btc/bch", "tornet - darknet", "group name onion v. link", "ransomware group sites -",
          "OnionWay - Onion", "OnionLand Search - Search Hidden Services"]


@pytest.mark.parametrize("value", KEEP)
def test_real_organisations_are_kept(value):
    from extractor.org_filter import clean_org_name

    assert clean_org_name(value) == value


@pytest.mark.parametrize("value", REJECT)
def test_directory_titles_and_residue_are_rejected(value):
    from extractor.org_filter import clean_org_name

    assert clean_org_name(value) is None


def test_repairs_keep_the_name():
    from extractor.org_filter import clean_org_name

    assert clean_org_name("OakBend Medical (USA") == "OakBend Medical"
    assert clean_org_name("Example Corp](https://example.invalid/x") == "Example Corp"
    assert clean_org_name("Expired Example Airlines Data Leak") == "Example Airlines"


def test_normalize_entities_drops_junk_orgs_before_any_lookup():
    from extractor.normalizer import normalize_entities

    out = normalize_entities(
        {"ORGANIZATION_NAME": ["OnionWay - Onion", "btc/bch", "Example Holdings Ltd"]},
        page_url="https://example.invalid/page",
    )
    values = [e.value for e in out if e.entity_type == "ORGANIZATION_NAME"]
    assert "OnionWay - Onion" not in values and "btc/bch" not in values


def test_the_dead_org_validator_is_gone():
    import extractor.normalizer as n

    assert not hasattr(n, "_is_valid_org_name")
