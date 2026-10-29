"""
tests/test_23c_crawl_sweep.py — 23C: onion addresses in page text, mirror
merging after fetch, and the Ahmia banned-host MD5 list.

Synthetic fixtures only: every onion address here is generated from a made-up
seed (valid v3 format with a correct checksum) or is an obviously fake string.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

import utils.content_safety as cs
from utils.onion_sweep import (
    gated_text_onion_urls,
    is_valid_v3_host,
    sweep_onion_addresses,
)


def make_v3(seed: str) -> str:
    """A format-valid v3 onion label (no ".onion") derived from *seed*."""
    pubkey = hashlib.sha256(seed.encode()).digest()
    checksum = hashlib.sha3_256(b".onion checksum" + pubkey + b"\x03").digest()[:2]
    return base64.b32encode(pubkey + checksum + b"\x03").decode().lower()


A = make_v3("synthetic-a")
B = make_v3("synthetic-b")
C = make_v3("synthetic-c")


@pytest.fixture(autouse=True)
def _clean_blocklists(monkeypatch):
    monkeypatch.setattr(cs, "_blocked_host_hashes", frozenset())
    monkeypatch.setattr(cs, "_ahmia_banned", frozenset())
    monkeypatch.delenv(cs.AHMIA_BANNED_ENV, raising=False)


def _hosts(text: str) -> list[str]:
    return [s.host for s in sweep_onion_addresses(text)]


# ---------------------------------------------------------------------------
# C1 — v3 validation
# ---------------------------------------------------------------------------

def test_v3_validation_accepts_checksum_valid_address():
    assert is_valid_v3_host(A)
    assert is_valid_v3_host(A + ".onion")
    assert is_valid_v3_host(A.upper() + ".onion")


def test_v3_validation_rejects_bad_checksum_version_and_length():
    assert not is_valid_v3_host("a" * 56)
    # Flip one char: checksum no longer matches.
    flipped = ("b" if A[0] != "b" else "c") + A[1:]
    assert not is_valid_v3_host(flipped)
    # Wrong version byte with an otherwise matching checksum.
    pubkey = hashlib.sha256(b"v").digest()
    checksum = hashlib.sha3_256(b".onion checksum" + pubkey + b"\x02").digest()[:2]
    v2ver = base64.b32encode(pubkey + checksum + b"\x02").decode().lower()
    assert not is_valid_v3_host(v2ver)
    assert not is_valid_v3_host(A[:55])
    assert not is_valid_v3_host("abcdefghijklmnop")  # v2 length


# ---------------------------------------------------------------------------
# C1 — sweep, plain and obfuscated
# ---------------------------------------------------------------------------

def test_plain_address_with_scheme_and_path():
    found = sweep_onion_addresses(f"Mirror: http://{A}.onion/files/list.html, thanks")
    assert [(s.host, s.url, s.obfuscated) for s in found] == [
        (f"{A}.onion", f"http://{A}.onion/files/list.html", False)
    ]


def test_https_scheme_is_kept():
    assert sweep_onion_addresses(f"at https://{A}.onion/x")[0].url == f"https://{A}.onion/x"


@pytest.mark.parametrize("form", [
    "{a}[.]onion",
    "{a}(.)onion",
    "{a}{{.}}onion",
    "{a}[dot]onion",
    "{a} (dot) onion",
    "{a} dot onion",
    "{a} DOT onion",
    "{a} . onion",
    "{a}.onion",
])
def test_defanged_dot_forms(form):
    text = "new address: " + form.format(a=A) + " use it"
    assert _hosts(text) == [f"{A}.onion"]


def test_spaces_inside_address():
    spaced = " ".join(A[i:i + 8] for i in range(0, 56, 8))
    assert _hosts(f"go to {spaced} dot onion today") == [f"{A}.onion"]
    found = sweep_onion_addresses(f"go to {spaced}.onion")
    assert found[0].obfuscated is True


def test_zero_width_characters_inside_address():
    zw = "​".join(A[i:i + 4] for i in range(0, 56, 4))
    assert _hosts(f"link {zw}.onion") == [f"{A}.onion"]
    soft = "­".join(A[i:i + 7] for i in range(0, 56, 7))
    assert _hosts(f"link {soft}[.]onion") == [f"{A}.onion"]


def test_hxxp_and_bracket_colon():
    found = sweep_onion_addresses(f"hxxp://{A}[.]onion/login and hxxps[:]//{B}.onion")
    assert [s.url for s in found] == [f"http://{A}.onion/login", f"https://{B}.onion"]
    assert found[0].obfuscated is True  # host form was defanged


def test_html_entities_and_upper_case():
    assert _hosts(f"{A.upper()}&#46;onion") == [f"{A}.onion"]


def test_raw_html_and_javascript_text():
    html = f'<script>var m = "{A}.onion";</script><p>{B} [.] onion</p>'
    assert _hosts(html) == [f"{A}.onion", f"{B}.onion"]


def test_rejects_glued_runs_wrong_length_and_bad_checksum():
    assert _hosts(f"x{A}.onion") == []                 # 57-char base32 run
    assert _hosts(f"{A[1:]}.onion") == []              # 55 chars
    assert _hosts(f"{'a' * 56}.onion") == []           # fails checksum
    assert _hosts("end of the sentence. Onion routing is old.") == []
    assert _hosts("") == []


def test_dedup_and_cap():
    text = f"{A}.onion {A}[.]onion {B}.onion {C}.onion"
    assert _hosts(text) == [f"{A}.onion", f"{B}.onion", f"{C}.onion"]
    assert len(sweep_onion_addresses(text, max_results=2)) == 2
    assert sweep_onion_addresses(text, max_results=0) == []


# ---------------------------------------------------------------------------
# C1 — safety gate
# ---------------------------------------------------------------------------

def test_gated_drops_blocklisted_host(monkeypatch):
    monkeypatch.setattr(cs, "_blocked_host_hashes", frozenset({cs.host_hash(f"{B}.onion")}))
    cs.reset_safety_drop_counts()
    urls = gated_text_onion_urls(f"{A}.onion and {B}[.]onion")
    assert urls == [f"http://{A}.onion"]
    assert cs.safety_drop_counts()["url"] == 1


def test_gated_drops_url_with_prohibited_term(monkeypatch):
    term = cs.BLOCKED_URL_TERMS[0].replace(" ", "")
    urls = gated_text_onion_urls(f"{A}.onion/{term}/ and {B}.onion/ok")
    assert urls == [f"http://{B}.onion/ok"]


def test_gated_exclude_hosts_and_cap():
    text = f"{A}.onion {B}.onion {C}.onion"
    assert gated_text_onion_urls(text, exclude_hosts={f"{A}.onion"}, max_results=1) == [
        f"http://{B}.onion"
    ]
    assert gated_text_onion_urls(text, max_results=0) == []


def test_gate_failure_is_fail_closed(monkeypatch):
    def boom(_url):
        raise RuntimeError("x")

    monkeypatch.setattr(cs, "is_blocked_url", boom)
    assert gated_text_onion_urls(f"{A}.onion") == []


# ---------------------------------------------------------------------------
# C1 — extractor ONION_URL entities
# ---------------------------------------------------------------------------

def test_extractor_reports_defanged_onions_once():
    from extractor.regex_patterns import _extract_onion

    text = f"plain {A}.onion/x and defanged {B} [dot] onion and again {A}[.]onion"
    found = _extract_onion(text)
    assert f"{A}.onion/x" in found
    assert f"http://{B}.onion" in found
    assert sum(1 for v in found if A in v) == 1


def test_extractor_defanged_onion_passes_normalizer_and_gate(monkeypatch):
    from extractor.regex_patterns import _extract_onion
    from extractor.normalizer import _validate_onion_url

    found = _extract_onion(f"{B}(.)onion")
    assert found and all(_validate_onion_url(v) for v in found)
    monkeypatch.setattr(cs, "_blocked_host_hashes", frozenset({cs.host_hash(f"{B}.onion")}))
    assert _extract_onion(f"{B}(.)onion") == []


def test_extractor_unchanged_without_onion_text():
    from extractor.regex_patterns import _extract_onion

    assert _extract_onion("nothing to see here") == []


# ---------------------------------------------------------------------------
# C1 — scraper depth-1 outlinks: text addresses after real links, same cap
# ---------------------------------------------------------------------------

def test_scraper_outlinks_text_after_hrefs_and_gated(monkeypatch):
    from scraper import scrape

    page = f"http://{A}.onion/index"
    html = (
        f'<a href="http://{B}.onion/real">r</a>'
        f"<p>mirror: {C} [.] onion</p><p>also {B}.onion/other</p>"
    ).encode()
    links = scrape.extract_onion_outlinks(page, html)
    assert links == [f"http://{B}.onion/real", f"http://{C}.onion"]

    monkeypatch.setattr(cs, "_blocked_host_hashes", frozenset({cs.host_hash(f"{C}.onion")}))
    assert scrape.extract_onion_outlinks(page, html) == [f"http://{B}.onion/real"]


def test_scraper_outlinks_cap_respected(monkeypatch):
    from scraper import scrape

    monkeypatch.setattr(scrape, "MAX_OUTLINKS_PER_PAGE", 1)
    page = f"http://{A}.onion/"
    html = f'<a href="http://{B}.onion/real">r</a> {C}.onion'.encode()
    assert scrape.extract_onion_outlinks(page, html) == [f"http://{B}.onion/real"]


# ---------------------------------------------------------------------------
# C1 — spider frontier: lower priority, same relevance bar, gated
# ---------------------------------------------------------------------------

def _spider(min_relevance=0.3):
    from crawler.spider import Spider

    sp = Spider([], "query", max_depth=2, max_pages=5, min_relevance=min_relevance)
    sp._db_upsert_source = lambda *a, **k: None
    return sp


def test_spider_text_onions_queue_behind_real_links(monkeypatch):
    sp = _spider()
    monkeypatch.setattr(sp._frontier, "score", lambda url, snippet="": 0.9 if C in url else 0.4)
    sp._frontier.push(f"http://{B}.onion/real", 1, 0.4)
    sp._push_text_onions(f"see {C} [.] onion", [f"http://{B}.onion/real"], "t", 0)
    assert sp._text_urls_discovered == 1
    assert sp._new_urls_discovered == 1
    # The text-found address scores higher, yet pops after the real link.
    assert sp._frontier.pop() == (f"http://{B}.onion/real", 1)
    assert sp._frontier.pop() == (f"http://{C}.onion", 1)


def test_spider_text_onions_obey_min_relevance_and_dedup(monkeypatch):
    sp = _spider(min_relevance=0.5)
    monkeypatch.setattr(sp._frontier, "score", lambda url, snippet="": 0.1)
    sp._push_text_onions(f"{C}.onion", [], "t", 0)
    assert sp._frontier.empty()
    sp._push_text_onions(f"{C}.onion", [], "t", 0)  # already seen
    assert sp._text_urls_discovered == 1


def test_spider_text_onions_skip_blocked_and_linked_hosts(monkeypatch):
    sp = _spider(min_relevance=0.0)
    monkeypatch.setattr(sp._frontier, "score", lambda url, snippet="": 0.5)
    monkeypatch.setattr(cs, "_blocked_host_hashes", frozenset({cs.host_hash(f"{C}.onion")}))
    sp._push_text_onions(f"{B}.onion {C}.onion", [f"http://{B}.onion/x"], "t", 0)
    assert sp._frontier.empty()
    assert sp._text_urls_discovered == 0


# ---------------------------------------------------------------------------
# C2 — mirror merging after fetch
# ---------------------------------------------------------------------------

_BODY = " ".join(
    f"synthetic leak notice line {i} lorem ipsum dolor sit amet consectetur"
    for i in range(30)
)


def test_near_duplicate_pages_on_different_onion_hosts_merge():
    from utils.content_dedup import deduplicate_page_records

    pages = [
        {"url": f"http://{A}.onion/post", "text": "Title A - " + _BODY},
        {"url": "https://example.com/news", "text": "unrelated clearnet " * 30},
        {"url": f"http://{B}.onion/post", "text": "Title B - " + _BODY + " extra"},
        {"url": f"http://{C}.onion/p", "text": _BODY.replace("line 7 ", "line 70 ")},
    ]
    out = deduplicate_page_records(pages)
    assert [p["url"] for p in out] == [f"http://{A}.onion/post", "https://example.com/news"]
    kept = out[0]
    assert kept["text"].startswith("Title A")  # best-ranked (first) page kept
    assert kept["mirrors"] == [f"{B}.onion", f"{C}.onion"]
    assert kept["source_urls"] == [
        f"http://{A}.onion/post", f"http://{B}.onion/post", f"http://{C}.onion/p",
    ]
    assert out[1]["mirrors"] == []


def test_same_host_near_duplicates_are_not_merged():
    from utils.content_dedup import deduplicate_page_records

    pages = [
        {"url": f"http://{A}.onion/page1", "text": _BODY + " page one"},
        {"url": f"http://{A}.onion/page2", "text": _BODY + " page two"},
    ]
    out = deduplicate_page_records(pages)
    assert len(out) == 2
    assert all(p["mirrors"] == [] for p in out)


def test_different_or_short_pages_are_not_merged():
    from utils.content_dedup import deduplicate_page_records

    other = " ".join(f"completely different forum thread number {i} about tools" for i in range(30))
    pages = [
        {"url": f"http://{A}.onion/", "text": _BODY},
        {"url": f"http://{B}.onion/", "text": other},
        {"url": f"http://{C}.onion/", "text": "site down"},
        {"url": f"http://{make_v3('d')}.onion/", "text": "site down!"},
    ]
    assert len(deduplicate_page_records(pages)) == 4


def test_exact_duplicates_still_merge_and_record_mirrors():
    from utils.content_dedup import deduplicate_page_records

    pages = [
        {"url": f"http://{A}.onion/", "text": "same"},
        {"url": f"http://{B}.onion/", "text": "same"},
        {"url": f"http://{A}.onion/again", "text": "same"},
    ]
    out = deduplicate_page_records(pages)
    assert len(out) == 1
    assert out[0]["mirrors"] == [f"{B}.onion"]
    assert len(out[0]["source_urls"]) == 3


def test_simhash_close_for_mirrors_far_for_different_text():
    from utils.content_dedup import simhash64

    a = simhash64(_BODY)
    b = simhash64(_BODY + " extra words here")
    c = simhash64(" ".join(f"another unrelated topic entirely {i} words" for i in range(30)))
    assert bin(a ^ b).count("1") <= 3
    assert bin(a ^ c).count("1") > 10
    assert simhash64("too short") is None


# ---------------------------------------------------------------------------
# C3 — Ahmia banned-host MD5 list
# ---------------------------------------------------------------------------

def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def test_ahmia_md5_blocks_synthetic_host(monkeypatch):
    monkeypatch.setattr(cs, "_ahmia_banned", frozenset({_md5(f"{A}.onion")}))
    assert cs.is_blocked_url(f"http://{A}.onion/any/path")[0] is True
    assert cs.is_blocked_url(f"http://sub.{A}.onion/")[0] is True
    assert cs.is_blocked_url(f"http://{B}.onion/")[0] is False
    assert cs.url_is_blocked(f"http://{A}.onion/") is True
    assert gated_text_onion_urls(f"{A}[.]onion {B}.onion") == [f"http://{B}.onion"]


def test_ahmia_md5_ignores_clearnet_hosts(monkeypatch):
    monkeypatch.setattr(cs, "_ahmia_banned", frozenset({_md5("example.com")}))
    assert cs.is_blocked_url("https://example.com/")[0] is False


def test_ahmia_loader_reads_env_file(tmp_path, monkeypatch):
    path = tmp_path / "banned.txt"
    path.write_text(f"# header\n{_md5(f'{A}.onion').upper()}\nnot-a-hash\n\n{_md5('x')}\n")
    monkeypatch.setenv(cs.AHMIA_BANNED_ENV, str(path))
    cs.reset_ahmia_banned_cache()
    try:
        assert cs.ahmia_banned_md5s() == frozenset({_md5(f"{A}.onion"), _md5("x")})
        assert cs.is_blocked_url(f"http://{A}.onion/")[0] is True
    finally:
        cs.reset_ahmia_banned_cache()


def test_ahmia_loader_missing_file_is_empty(tmp_path, monkeypatch):
    monkeypatch.setenv(cs.AHMIA_BANNED_ENV, str(tmp_path / "absent"))
    cs.reset_ahmia_banned_cache()
    try:
        assert cs.ahmia_banned_md5s() == frozenset()
        assert cs.is_blocked_url(f"http://{A}.onion/")[0] is False
    finally:
        cs.reset_ahmia_banned_cache()

