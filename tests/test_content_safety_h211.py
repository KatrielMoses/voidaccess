"""Content-safety detector, normaliser and gates (2.1.1).

Fixtures are short synthetic strings built from the vocabulary constants by
transformation (hyphens, leetspeak, invisible characters...), so this file holds
no prohibited text of its own.
"""

from __future__ import annotations

import asyncio
import random
import string
import time

import pytest

import utils.content_safety as cs
from utils.content_safety import (
    CONTENT_BLOCKLIST,
    PROXIMITY_WINDOW,
    SAFETY_VOCAB,
    detect_prohibited,
    normalize_for_safety,
)

PHRASE = CONTENT_BLOCKLIST[1]  # a two-word phrase
MINOR = "toddler"  # a minor term no legacy pattern mentions
SEXUAL = "nude"
FILLER = ("market", "vendor", "escrow", "listing", "bitcoin", "review")
CLEAN = (
    "LockBit ransomware affiliate recruitment and leak site infrastructure "
    "discussion for defensive threat intelligence."
)
ONION = "http://" + "a" * 56 + ".onion"


@pytest.fixture(autouse=True)
def _isolated_state(monkeypatch):
    monkeypatch.setattr(cs, "_blocked_host_hashes", frozenset())
    cs.reset_safety_drop_counts()
    cs._recent_clean.clear()
    yield
    cs.reset_safety_drop_counts()
    cs._recent_clean.clear()


def _leet(text: str) -> str:
    return text.translate(str.maketrans("oieas", "01345"))


def _between_letters(text: str, sep: str) -> str:
    return " ".join(sep.join(word) for word in text.split())


# ---------------------------------------------------------------------------
# Normaliser
# ---------------------------------------------------------------------------


def test_normalize_returns_spaced_and_squashed_forms():
    assert normalize_for_safety("Ab-C_d.E  f!") == ("ab c d e f", "abcdef")


def test_normalize_handles_width_case_marks_invisibles_and_leet():
    assert normalize_for_safety("\uff21\uff22\uff23")[0] == "abc"  # NFKC
    assert normalize_for_safety("a\u200bb\u200dc\ufeffd")[0] == "abcd"  # zero-width
    assert normalize_for_safety("cafe\u0301")[0] == "cafe"  # combining mark
    assert normalize_for_safety("\u00c9COLE")[0] == "ecole"  # precomposed accent, casefold
    assert normalize_for_safety("h3ll0 w0rld $1t3 @")[0] == "hello world site a"


def test_normalize_empty():
    assert normalize_for_safety("") == ("", "")
    assert normalize_for_safety("!!! ---") == ("", "")


# ---------------------------------------------------------------------------
# Obfuscation shapes (rule a)
# ---------------------------------------------------------------------------


OBFUSCATIONS = {
    "plain": lambda p: p,
    "hyphen": lambda p: p.replace(" ", "-"),
    "underscore": lambda p: p.replace(" ", "_"),
    "dots_between_letters": lambda p: _between_letters(p, "."),
    "emoji_between_letters": lambda p: _between_letters(p, "\U0001F600"),
    "leetspeak": _leet,
    "mixed_case": lambda p: "".join(c.upper() if i % 2 else c for i, c in enumerate(p)),
    "zero_width": lambda p: "\u200b".join(p),
    "squashed": lambda p: p.replace(" ", ""),
    "hyphen_leet_mixed": lambda p: _leet(p).upper().replace(" ", "-"),
    "fullwidth": lambda p: "".join(chr(ord(c) + 0xFEE0) if c.isalpha() else c for c in p),
    "spaced_letters": lambda p: " ".join(p.replace(" ", "")),
}


@pytest.mark.parametrize("shape", sorted(OBFUSCATIONS))
def test_obfuscated_phrase_is_detected(shape):
    text = f"some listing {OBFUSCATIONS[shape](PHRASE)} videos here"
    assert detect_prohibited(text) == cs.RULE_PHRASE
    assert cs.sanitize_content(text) == ("", True)


@pytest.mark.parametrize("shape", ["hyphen", "dots_between_letters", "leetspeak", "zero_width"])
def test_obfuscated_phrase_in_url_is_blocked(shape):
    url = f"{ONION}/{OBFUSCATIONS[shape](PHRASE).replace(' ', '-')}/index"
    assert cs.is_blocked_url(url)[0] is True
    encoded = f"{ONION}/search?q=" + PHRASE.replace(" ", "%20")
    assert cs.is_blocked_url(encoded)[0] is True


def test_squashed_matching_ignores_accidental_joins_of_words():
    # Each line joins two ordinary words into a string that contains a
    # squashed vocabulary term; none of them starts a token.
    for text in (
        "items shipped overnight",
        "it stopped on monday",
        "canada is your home",
        "basic topics among others",
        "torpedo boats",
    ):
        assert detect_prohibited(text) is None, text


def test_url_terms_apply_to_text_as_word_starts():
    term = cs.BLOCKED_URL_TERMS[0]
    assert detect_prohibited(f"a {term} forum") == cs.RULE_URL_TERM
    assert detect_prohibited(f"a {'-'.join(term)} forum") == cs.RULE_URL_TERM


def test_gore_terms():
    for term in SAFETY_VOCAB["gore"]:
        assert detect_prohibited(f"watch {term.replace(' ', '_')} now") is not None, term
    assert detect_prohibited("hurt-c0re") == cs.RULE_GORE


def test_legacy_patterns_run_on_normalised_text():
    assert detect_prohibited("Kid--P.O.R.N clips") is not None
    assert detect_prohibited("teen-porn") == cs.RULE_PATTERN  # the teen rule is unchanged
    assert "teen" not in SAFETY_VOCAB["minor"]
    assert detect_prohibited(f"teen {' '.join(FILLER[:3])} {SEXUAL}") is None


# ---------------------------------------------------------------------------
# Proximity rule (d)
# ---------------------------------------------------------------------------


def _gap(n: int) -> str:
    return " ".join(FILLER[i % len(FILLER)] for i in range(n))


@pytest.mark.parametrize("first,second", [(MINOR, SEXUAL), (SEXUAL, MINOR)])
def test_proximity_both_orders(first, second):
    assert detect_prohibited(f"{first} {_gap(1)} {second}") == cs.RULE_PROXIMITY


@pytest.mark.parametrize("first,second", [(MINOR, SEXUAL), (SEXUAL, MINOR)])
def test_proximity_window_edge(first, second):
    # PROXIMITY_WINDOW tokens apart (adjacent = 1) is in; one more is out.
    inside = f"{first} {_gap(PROXIMITY_WINDOW - 1)} {second}"
    outside = f"{first} {_gap(PROXIMITY_WINDOW)} {second}"
    assert detect_prohibited(inside) == cs.RULE_PROXIMITY
    assert detect_prohibited(outside) is None


def test_proximity_multiword_minor_term_and_joined_token():
    two_word = next(t for t in SAFETY_VOCAB["minor"] if " " in t)
    assert detect_prohibited(f"{two_word} {SEXUAL}") == cs.RULE_PROXIMITY
    assert detect_prohibited(f"{MINOR}{SEXUAL}") == cs.RULE_PROXIMITY
    assert detect_prohibited(f"{SEXUAL}{MINOR}") == cs.RULE_PROXIMITY
    assert detect_prohibited(f"{' '.join(MINOR)} {SEXUAL}") == cs.RULE_PROXIMITY
    assert detect_prohibited(f"{_leet(MINOR)}-{_leet(SEXUAL)}") == cs.RULE_PROXIMITY


def test_proximity_ignores_longer_words():
    # Whole tokens only: "kidsexpress" is not kid + sex.
    assert detect_prohibited("kidsexpress delivery") is None
    assert detect_prohibited("kids express delivery") is None


# ---------------------------------------------------------------------------
# Known false positives: the CURRENT intended outcome (accepted for 2.1.1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,dropped",
    [
        # News about an arrest that names the offence is dropped. Accepted for
        # now: the phrase rule cannot tell reporting from advertising, and a
        # dropped news page costs less than a kept abuse page.
        (f"police arrested a man over {CONTENT_BLOCKLIST[2]} material", True),
        # Sex education aimed at children trips the proximity rule. Accepted.
        ("sex education for children", True),
        # A word that merely starts with a URL term is dropped (prefix match).
        ("a pedometer for runners", True),
        # Ordinary text is kept.
        (CLEAN, False),
        ("baby clothes and toddler shoes on sale", False),
        ("kids football league results", False),
    ],
)
def test_known_false_positive_outcomes(text, dropped):
    assert (detect_prohibited(text) is not None) is dropped


# ---------------------------------------------------------------------------
# Search results: a title-only flag drops the result
# ---------------------------------------------------------------------------


def test_title_only_flag_drops_search_result():
    flagged = {"link": f"{ONION}/listing", "title": PHRASE.replace(" ", "-").upper()}
    snippet = {"link": f"{ONION}/other", "title": "listing", "snippet": _leet(PHRASE)}
    clean = {"link": f"{ONION}/lockbit", "title": "LockBit leak site"}
    kept, dropped = cs.gate_search_results([flagged, snippet, clean])
    assert kept == [clean]
    assert dropped == [flagged, snippet]
    assert cs.safety_drop_counts()["title"] == 2


def test_engine_results_are_gated_before_dedup_and_traced(monkeypatch):
    import search.search as search_mod

    flagged = {"link": f"{ONION}/x", "title": PHRASE.replace(" ", "_")}
    clean = {"link": f"{ONION}/y", "title": "LockBit leak site"}

    async def fake_fetch(engine, query, session, semaphore):
        return search_mod.EngineResult(name=engine["name"], links=[dict(flagged), dict(clean)])

    async def no_stats():
        return []

    async def never_skip(_name):
        return False

    monkeypatch.setattr(search_mod, "_fetch_engine", fake_fetch)
    monkeypatch.setattr(search_mod, "get_all_engine_stats_async", no_stats)
    monkeypatch.setattr(search_mod, "should_skip_engine_async", never_skip)
    monkeypatch.setattr(search_mod, "record_engine_attempt_async", lambda *a: None)
    monkeypatch.setattr(search_mod.tor_isolation, "acquire_engine_session", lambda url: (object(), "k"))
    monkeypatch.setattr(search_mod.tor_isolation, "release_engine_session", lambda k: None)

    results = asyncio.run(
        search_mod._search_async(
            "lockbit", engines=[{"name": "E", "url": "http://e.onion/?q={query}"}], allow_diversify=False
        )
    )
    assert [r.links for r in results] == [[clean]]
    assert results[0].safety_dropped == [flagged]

    dropped: list[tuple[str, str]] = []
    monkeypatch.setattr(search_mod._trace, "url_dropped", lambda stage, url, reason: dropped.append((url, reason)))
    monkeypatch.setattr(search_mod._trace, "url_found", lambda *a, **k: None)
    monkeypatch.setattr(search_mod._trace, "search_result", lambda *a, **k: None)
    search_mod._trace_engine_result(results[0], 0)
    assert dropped == [(flagged["link"], "safety")]


# ---------------------------------------------------------------------------
# Host blocklist
# ---------------------------------------------------------------------------


def test_host_hash_hit_drops_url_and_its_entities(monkeypatch):
    host = "b" * 56 + ".onion"
    monkeypatch.setattr(cs, "_blocked_host_hashes", frozenset({cs.host_hash(host)}))

    for url in (f"http://{host}/", f"HTTPS://{host.upper()}:8080/a?b=c", f"{host}.", f"http://www.{host}/x"):
        assert cs.is_blocked_host(url), url
        assert cs.is_blocked_url(url)[0] is True
    assert cs.url_is_blocked(f"http://{host}/page") is True
    assert cs.is_blocked_entity_value("ONION_URL", f"http://{host}/page") is True
    assert cs.entity_value_is_blocked("URL", f"http://{host}") is True
    assert cs.entity_is_unsafe("ONION_URL", host) is True
    assert cs.safety_drop_counts() == {"page": 0, "title": 0, "url": 1, "entity": 2}

    assert cs.is_blocked_url(ONION + "/")[0] is False
    assert cs.is_blocked_entity_value("ONION_URL", ONION) is False


def test_url_entity_with_flagged_path_is_dropped():
    assert cs.is_blocked_entity_value("ONION_URL", f"{ONION}/{PHRASE.replace(' ', '-')}") is True
    assert cs.is_blocked_entity_value("URL", "https://example.com/lockbit") is False
    # Technical IOCs other than URLs keep the old behaviour.
    assert cs.is_blocked_entity_value("FILE_HASH_SHA256", "c" * 64) is False


def test_host_normalisation():
    assert cs.normalize_host("HTTP://User@Example.COM.:443/path") == "example.com"
    assert cs.normalize_host("example.com") == "example.com"
    assert cs.normalize_host("") == ""
    assert cs.host_hash("Example.com.") == cs.host_hash("http://example.com:80/x")


def test_shipped_blocklist_holds_only_hashes():
    import os
    import re

    monkey = cs._blocked_host_hashes
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(cs.__file__))), "data", cs.BLOCKED_HOSTS_FILENAME)
    with open(path, encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh if ln.strip()]
    entries = [ln for ln in lines if not ln.startswith("#")]
    assert entries, "the blocklist ships with entries"
    assert all(re.fullmatch(r"[0-9a-f]{64}", ln) for ln in entries)
    assert monkey == frozenset()  # the fixture's empty list is in force here

    cs._blocked_host_hashes = None
    try:
        assert cs.blocked_host_hashes() == frozenset(entries)
    finally:
        cs._blocked_host_hashes = frozenset()


def test_shipped_seeds_pass_the_url_gate():
    import json
    import os

    root = os.path.dirname(os.path.dirname(os.path.abspath(cs.__file__)))
    cs._blocked_host_hashes = None
    try:
        for rel in ("data/onion_seeds.json", "sources/data/onion_seeds.json"):
            with open(os.path.join(root, rel), encoding="utf-8") as fh:
                seeds = json.load(fh)
            for cat in seeds["categories"].values():
                for seed in cat["seeds"]:
                    assert not cs.is_blocked_url(seed.get("url", ""))[0], rel
    finally:
        cs._blocked_host_hashes = frozenset()


# ---------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------


def test_every_gate_fails_closed_when_the_detector_raises(monkeypatch):
    def boom(_text):
        raise RuntimeError("detector failure")

    monkeypatch.setattr(cs, "detect_prohibited", boom)
    assert cs.sanitize_content(CLEAN) == ("", True)
    assert cs.scan_page_text(ONION, CLEAN) == ("", True)
    assert cs.gate_pages({ONION: CLEAN}) == ({}, 1)
    assert cs.is_blocked_url(ONION)[0] is True
    assert cs.url_is_blocked(ONION) is True
    assert cs.is_blocked_query("lockbit")[0] is True
    assert cs.is_blocked_entity_value("ORGANIZATION_NAME", "Acme Corp") is True
    assert cs.is_blocked_entity_value("ONION_URL", ONION) is True
    assert cs.entity_is_unsafe("ORGANIZATION_NAME", "Acme Corp") is True
    assert cs.search_result_block_reason({"link": ONION, "title": "x"}) == "url"


def test_entity_is_unsafe_ignores_non_safety_reasons():
    assert cs.entity_is_unsafe("EMAIL_ADDRESS", "admin@example.com") is False  # password-like, not safety
    assert cs.entity_is_unsafe("ORGANIZATION_NAME", "") is False
    assert cs.entity_is_unsafe("ORGANIZATION_NAME", f"{MINOR} {SEXUAL} studio") is True


# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------


def test_drop_counters_count_each_kind_and_reset():
    blocked_text = f"x {PHRASE.replace(' ', '-')} y"
    cs.scan_page_text(ONION, blocked_text)
    cs.url_is_blocked(f"{ONION}/{PHRASE.replace(' ', '-')}")
    cs.entity_value_is_blocked("ORGANIZATION_NAME", blocked_text)
    cs.entity_value_is_blocked("EMAIL_ADDRESS", "admin@example.com")  # not counted: not a safety drop
    cs.gate_search_results([{"link": ONION, "title": blocked_text}])
    assert cs.safety_drop_counts() == {"page": 1, "title": 1, "url": 1, "entity": 1}
    cs.reset_safety_drop_counts()
    assert cs.safety_drop_counts() == {"page": 0, "title": 0, "url": 0, "entity": 0}


def test_cli_final_entity_gate_drops_entities_and_their_relationships():
    from voidaccess_cli.commands.investigate import _gate_final_entities

    entities = [
        {"id": "1", "entity_type": "ORGANIZATION_NAME", "value": "Acme Corp"},
        {"id": "2", "entity_type": "ONION_URL", "value": f"{ONION}/{PHRASE.replace(' ', '-')}"},
        {"id": "3", "entity_type": "MALWARE_FAMILY", "value": "x", "canonical_value": _leet(PHRASE)},
    ]
    rels = [
        {"id": "r1", "entity_a_id": "1", "entity_b_id": "2"},
        {"id": "r2", "entity_a_id": "1", "entity_b_id": "1"},
    ]
    kept, kept_rels = _gate_final_entities(entities, rels)
    assert [e["id"] for e in kept] == ["1"]
    assert [r["id"] for r in kept_rels] == ["r2"]


# ---------------------------------------------------------------------------
# Content-Type guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "head,is_text",
    [
        (b"<!doctype html><html><body>hello</body></html>", True),
        ("caf\u00e9 \u2014 r\u00e9sum\u00e9".encode(), True),
        ("caf\u00e9 r\u00e9sum\u00e9".encode("latin-1"), True),
        (b"", True),
        (b"\x89PNG\r\n\x1a\n" + b"\x00" * 8, False),
        (b"\xff\xd8\xff\xe0" + b"JFIF", False),
        (b"GIF89a" + b"\x01\x02", False),
        (b"\x00\x00\x00\x18ftypmp42", False),
        (b"RIFF\x10\x10\x10\x10WEBPVP8 ", False),
        (b"%PDF-1.7\n", False),
        (b"hello\x00world", False),
        (bytes(range(1, 32)) * 4, False),
    ],
)
def test_sniffs_as_text(head, is_text):
    from scraper.scrape import sniffs_as_text

    assert sniffs_as_text(head) is is_text


class _Content:
    def __init__(self, body: bytes):
        self.body = body

    async def iter_chunked(self, _n):
        yield self.body


class _Resp:
    def __init__(self, body: bytes, content_type: str | None):
        self.status = 200
        self.headers = {} if content_type is None else {"Content-Type": content_type}
        self.charset = None
        self.content = _Content(body)


class _Session:
    def __init__(self, resp):
        self.resp = resp

    def get(self, url, headers=None, **_kw):
        resp = self.resp

        class _CM:
            async def __aenter__(self_inner):
                return resp

            async def __aexit__(self_inner, *exc):
                return False

        return _CM()


@pytest.mark.parametrize(
    "body,content_type,fetched",
    [
        (b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, None, False),
        (b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "", False),
        (b"<html><body><p>" + CLEAN.encode() * 5 + b"</p></body></html>", None, True),
        (b"<html><body><p>" + CLEAN.encode() * 5 + b"</p></body></html>", "text/html", True),
        (b"\x89PNG\r\n\x1a\n", "image/png", False),
    ],
)
def test_empty_content_type_is_sniffed(monkeypatch, body, content_type, fetched):
    from scraper import scrape

    failures: list[object] = []
    monkeypatch.setattr(scrape.pacing, "retry_plan", lambda n, d: (0, ()))
    monkeypatch.setattr(scrape, "_trace_fetch_failure", lambda url, started, outcome: failures.append(outcome))
    monkeypatch.setattr(scrape, "PLAYWRIGHT_ENABLED", False)
    _url, _title, raw, _db_text, _posted = asyncio.run(
        scrape._fetch_one_impl(_Session(_Resp(body, content_type)), {"link": ONION + "/p", "title": "t"}, asyncio.Semaphore(1))
    )[:5]
    assert (raw is not None) is fetched
    if not fetched:
        assert failures == ["content_type"]


# ---------------------------------------------------------------------------
# A dropped page contributes no outlinks, relationships or seeds
# ---------------------------------------------------------------------------


async def test_dropped_page_contributes_no_outlinks_or_claims(db_engine, monkeypatch):
    from scraper import scrape

    other = "c" * 56 + ".onion"
    bad_url, good_url = f"{ONION}/bad", "http://" + "d" * 56 + ".onion/good"
    raw = f'<html><body><a href="http://{other}/next">next</a></body></html>'.encode()
    bad_text = ("context " * 30) + PHRASE.replace(" ", "-") + (" context" * 30)
    claims = [{"source": "a", "target": "b", "type": "USES"}]

    async def fake_gather(*_a, **_k):
        return [
            (bad_url, f"T - {bad_text}", raw, bad_text, None, claims),
            (good_url, f"T - {CLEAN}", raw, CLEAN, None, claims),
        ]

    async def no_seeds(**_kw):
        return 0

    monkeypatch.setattr(scrape, "_gather_all", fake_gather)
    monkeypatch.setattr(scrape, "validate_urls_for_scraping", lambda urls: (urls, []))
    monkeypatch.setattr(scrape, "_discover_seeds_from_one_page", no_seeds)

    result = await scrape.scrape_multiple(
        [{"link": bad_url, "title": "T"}, {"link": good_url, "title": "T"}],
        collect_outlinks=True,
        extract_typed_relationships=True,
    )
    assert list(result) == [good_url]
    assert set(result.outlinks_by_url) == {good_url}
    assert set(result.relationship_claims_by_url) == {good_url}
    assert cs.safety_drop_counts()["page"] == 1


def test_crawler_does_not_store_or_follow_a_dropped_page(monkeypatch):
    from unittest.mock import AsyncMock, patch

    from crawler.spider import Spider
    from tests.test_crawler import _mock_model, make_mock_response, make_session_mock

    child = "e" * 56 + ".onion"
    body = (
        f'<html><body><p>{"context " * 30}{PHRASE.replace(" ", "_")}{" context" * 30}</p>'
        f'<a href="http://{child}/x">x</a></body></html>'
    ).encode()
    spider = Spider([], "q", min_relevance=0.0)
    persisted: list[str] = []
    monkeypatch.setattr(spider, "_db_persist_page", lambda url, *a, **k: persisted.append(url))
    session = make_session_mock(make_mock_response(status=200, body=body))
    with patch("crawler.frontier._get_model", return_value=_mock_model()), \
         patch("crawler.spider.asyncio.sleep", new=AsyncMock()), \
         patch("crawler.spider.RETRY_DELAYS", (0.0, 0.0, 0.0)), \
         patch("config.DATABASE_URL", None):
        asyncio.run(spider._process_url(ONION + "/", depth=0, session=session))
    assert persisted == []
    assert spider._results == []
    assert spider._new_urls_discovered == 0


# ---------------------------------------------------------------------------
# Performance guard
# ---------------------------------------------------------------------------


def test_one_megabyte_of_random_text_under_200ms():
    rng = random.Random(211)
    # Without these letters no vocabulary term can be spelled, so every rule
    # runs to the end instead of returning on an early hit.
    letters = "".join(c for c in string.ascii_lowercase if c not in "cdlpx")
    words = []
    size = 0
    while size < 1_000_000:
        word = "".join(rng.choice(letters) for _ in range(rng.randint(2, 9)))
        words.append(word)
        size += len(word) + 1
    text = " ".join(words)[:1_000_000]
    detect_prohibited(text)  # warm-up (lazy regex compile, page cache)
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        result = detect_prohibited(text)
        best = min(best, time.perf_counter() - start)
    assert result is None
    assert best < 0.2, f"{best * 1000:.0f} ms"


def test_clean_verdict_cache_is_bounded_and_never_hides_a_hit():
    cs.sanitize_content(CLEAN)
    assert CLEAN in cs._recent_clean
    for i in range(cs._RECENT_CLEAN_MAX + 5):
        cs.sanitize_content(f"{CLEAN} {i}")
    assert len(cs._recent_clean) == cs._RECENT_CLEAN_MAX
    assert CLEAN not in cs._recent_clean  # oldest evicted
    flagged = f"{CLEAN} {PHRASE.replace(' ', '-')}"
    assert cs.sanitize_content(flagged) == ("", True)
    assert flagged not in cs._recent_clean


def test_every_minor_and_sexual_term_is_a_whole_token_class():
    terms = {t.replace(" ", "") for t in SAFETY_VOCAB["minor"]} | set(SAFETY_VOCAB["sexual"])
    assert terms <= set(cs._TOKEN_CLASS)
    for term in SAFETY_VOCAB["minor"]:
        norm = cs._Normalized(f"{term} {_gap(2)} {SEXUAL}")
        assert cs._proximity_hit(cs._proximity_tokens(norm)), term
        assert detect_prohibited(norm.spaced) is not None, term
