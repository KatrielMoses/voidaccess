"""22R-2 / 22R-6: page kinds and page, entity and relationship tiers (synthetic)."""

from __future__ import annotations

import pytest

from voidaccess import relevance as rel
from voidaccess.query_intent import classify_query


def _matcher(query: str, refined: str = "") -> rel.QueryMatcher:
    return rel.QueryMatcher(classify_query(query), refined or query)


def _tier(query: str, text: str, refined: str = "", **page) -> tuple[str, str]:
    t, r, _ = rel.page_relevance({"text": text, "source": "tor_search", **page}, _matcher(query, refined))
    return t, r


PROSE = "This is an ordinary sentence of prose that runs well past eight words long. "


@pytest.mark.parametrize(
    "query,text,tier",
    [
        ("LockBit ransomware", "The LockBit 3.0 crew posted. " + PROSE, "direct"),
        ("LockBit ransomware", "Builder for lockbit3 leaked. " + PROSE, "direct"),
        ("LockBit ransomware", "A generic ransomware story. " + PROSE, "background"),
        ("RedLine stealer", "Logs from Redline and others. " + PROSE, "direct"),
        ("+79001234567", "call +7 (900) 123-45-67. " + PROSE, "direct"),
        ("+79001234567", "call 8 900 123 45 67. " + PROSE, "direct"),
        ("jdoe1987@gmail.com", "mail JDOE1987@GMAIL.COM now. " + PROSE, "direct"),
        ("jdoe1987@gmail.com", "user jdoe1987 posted. " + PROSE, "related"),
        ("example-corp.com", "host vpn.example-corp.com is up. " + PROSE, "direct"),
        ("example-corp.com", "example-corp.com.attacker.net phish. " + PROSE, "related"),
        ("CVE-2024-3400", "exploit for cve-2024-3400 in PAN-OS. " + PROSE, "direct"),
        ("initial access broker", "Two initial access brokers sell RDP. " + PROSE, "direct"),
        ("initial access broker", "An IAB sells VPN access. " + PROSE, "direct"),
        ("John Smith", "Record: Smith, John (DOB). " + PROSE, "direct"),
        ("zqxvjwk plorbtank 7731 quenvax", PROSE, "background"),
    ],
)
def test_page_tiers(query, text, tier):
    assert _tier(query, text)[0] == tier


def test_reason_codes():
    assert _tier("CVE-2024-3400", "CVE-2024-3400 " + PROSE)[1] == "selector_match"
    assert _tier("LockBit 3.0", "LockBit Black " + PROSE)[1] == "alias_match:lockbit black"
    assert _tier("LockBit ransomware", PROSE)[1] == "none"


def test_refined_term_makes_a_page_related():
    t, r = _tier("CVE-2024-3400", "GlobalProtect gateways were hit. " + PROSE, refined="CVE-2024-3400 GlobalProtect")
    assert (t, r) == ("related", "refined_term")


def test_generic_refined_words_do_not_make_pages_related():
    t, _ = _tier("zqxvjwk plorbtank", "darkweb market leak forum. " + PROSE, refined="zqxvjwk plorbtank darkweb market")
    assert t == "background"


def test_fallback_page_needs_content_match_not_refined_only_terms():
    m = _matcher("CVE-2024-3400", "CVE-2024-3400 GlobalProtect")
    page = {"text": "GlobalProtect gateways were hit. " + PROSE, "source": "tor_search", "via_fallback": True}
    assert rel.page_relevance(page, m)[0] == "background"
    page["via_fallback"] = False
    assert rel.page_relevance(page, m)[0] == "related"


def test_ambiguous_threat_query_needs_a_cue_for_direct():
    assert _tier("Play ransomware", "we play games all day. " + PROSE)[0] == "background"
    assert _tier("Play ransomware", "the Play ransomware group. " + PROSE)[0] == "direct"


# --- page kinds ----------------------------------------------------------------


def _onion(i: int) -> str:
    return ("abcdefghijklmnopqrstuvwxyz234567" * 2)[i % 20: i % 20 + 56].ljust(56, "a") + ".onion"


def test_page_kind_directory_and_link_list_only_rule():
    links = "\n".join(f"{_onion(i)} LockBit mirror" for i in range(20))
    page = {"text": links, "source": "tor_search", "title": "Best onion links"}
    assert rel.classify_page_kind(page) == "directory"
    tier, reason, _ = rel.page_relevance(page, _matcher("LockBit ransomware"))
    assert (tier, reason) == ("related", "link_list_only")
    page["text"] = links + "\nThe LockBit group has published a long statement about its new affiliate rules today."
    assert rel.page_relevance(page, _matcher("LockBit ransomware"))[0] == "direct"


@pytest.mark.parametrize(
    "page,kind",
    [
        ({"text": "x", "source": "paste_sites", "url": "https://pastebin.com/raw/a"}, "paste"),
        ({"text": "x", "source": "rss", "source_type": "rss_feed"}, "news_article"),
        ({"text": "x", "source": "rss", "source_type": "rss_feed", "recency_only": True}, "feed_item"),
        ({"text": "Search results for lockbit: 10 results", "title": "Ahmia search", "source": "tor_search"}, "search_portal"),
        ({"text": "Add to cart. Escrow. Vendor rating. In stock. Price 10 USD. Shipping", "source": "tor_search"}, "market_listing"),
        ({"text": "Reply Quote Posted by x Joined 2020 Posts: 10 thread", "source": "tor_search"}, "forum_thread"),
        ({"text": "Data leak published. Files 20GB. Deadline countdown. Victim: x. Download", "source": "tor_search"}, "leak_post"),
        ({"text": "short", "source": "tor_search"}, "other"),
    ],
)
def test_page_kinds(page, kind):
    assert rel.classify_page_kind(page) == kind


# --- entities and relationships -------------------------------------------------


def _pages(query: str, pages: list[dict]) -> tuple[list[dict], rel.QueryMatcher]:
    m = _matcher(query)
    rel.annotate_pages(pages, m)
    return pages, m


def test_entity_tiers_by_distance_and_page():
    near_far = "LockBit posted a note with 10.0.0.1 next to it. " + ("filler " * 120) + "and far away 10.9.9.9 here."
    pages, m = _pages("LockBit ransomware", [
        {"url": "u1", "text": near_far, "source": "tor_search"},
        {"url": "u2", "text": "unrelated page that mentions 192.168.7.7 only. " + PROSE, "source": "tor_search"},
    ])
    ents = [
        {"id": "1", "entity_type": "IP_ADDRESS", "value": "10.0.0.1", "source_url": "u1"},
        {"id": "2", "entity_type": "IP_ADDRESS", "value": "10.9.9.9", "source_url": "u1"},
        {"id": "3", "entity_type": "IP_ADDRESS", "value": "192.168.7.7", "source_url": "u2"},
        {"id": "4", "entity_type": "RANSOMWARE_GROUP", "value": "LockBit 3.0", "source_url": "u2"},
    ]
    rel.annotate_entities(ents, pages, m)
    got = {e["id"]: (e["relevance"], e["relevance_reason"]) for e in ents}
    assert got["1"] == ("direct", "near_direct_match")
    assert got["2"] == ("related", "direct_page")
    assert got["3"] == ("background", "none")
    assert got["4"] == ("direct", "query_entity")
    rels = [{"entity_a_id": "1", "entity_b_id": "3"}, {"entity_a_id": "1", "entity_b_id": "4"},
            {"entity_a_id": "2", "entity_b_id": "1"}]
    rel.annotate_relationships(rels, ents)
    assert [r["relevance"] for r in rels] == ["background", "direct", "related"]


def test_selector_entity_is_direct():
    pages, m = _pages("jdoe1987@gmail.com", [{"url": "u", "text": PROSE, "source": "tor_search"}])
    ents = [{"id": "1", "entity_type": "EMAIL", "value": "JDoe1987@gmail.com", "source_url": "u"}]
    rel.annotate_entities(ents, pages, m)
    assert ents[0]["relevance"] == "direct"


def test_agency_is_background_unless_next_to_a_direct_match():
    far = "LockBit leak. " + ("filler " * 30) + " The FBI said nothing."
    near = "The FBI seized LockBit servers."
    for text, tier in ((far, "background"), (near, "direct")):
        pages, m = _pages("LockBit ransomware", [{"url": "u", "text": text, "source": "tor_search"}])
        ents = [{"id": "1", "entity_type": "ORGANIZATION_NAME", "value": "FBI", "source_url": "u"}]
        rel.annotate_entities(ents, pages, m)
        assert ents[0]["relevance"] == tier


def test_recency_only_feed_item_is_background_feed_item():
    pages, _ = _pages("LockBit ransomware", [
        {"url": "u", "text": "General security news today. " + PROSE, "source": "rss",
         "source_type": "rss_feed", "recency_only": True},
    ])
    assert (pages[0]["relevance"], pages[0]["relevance_reason"], pages[0]["page_kind"]) == (
        "background", "recency_only", "feed_item")


def test_relevance_block_counts():
    intent = classify_query("LockBit ransomware")
    block = rel.build_relevance_block(
        intent,
        [{"relevance": "direct"}, {"relevance": "background"}],
        [{"relevance": "related"}],
        [],
        {"gazetteer_context": 2, "org_boilerplate": 1},
        3, True, False,
    )
    assert block == {
        "query_intent": "named_threat",
        "pages": {"direct": 1, "related": 0, "background": 1},
        "entities": {"direct": 0, "related": 1, "background": 0},
        "relationships": {"direct": 0, "related": 0, "background": 0},
        "removed": {"gazetteer_context": 2, "org_boilerplate": 1},
        "feed_items_capped": 3,
        "filter_fallback": True,
        "refined_query_restored": False,
    }


def test_no_direct_sentence_is_prepended_once():
    intent = classify_query("zqxvjwk plorbtank")
    once = rel.prepend_no_direct_sentence("Some text.", intent)
    assert once.startswith("No collected page mentions zqxvjwk plorbtank directly.")
    assert rel.prepend_no_direct_sentence(once, intent) == once
