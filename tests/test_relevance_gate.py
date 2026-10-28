"""22R-4 / 22R-5: the extraction-time relevance gate (synthetic page text)."""

from __future__ import annotations

import pytest

from extractor import relevance_gate as gate
from extractor.normalizer import NormalizedEntity
from voidaccess import relevance
from voidaccess.query_intent import classify_query


@pytest.fixture(autouse=True)
def _reset():
    gate.reset_counts()
    relevance.set_current_intent(None)
    yield
    relevance.set_current_intent(None)


def _ent(etype: str, value: str) -> NormalizedEntity:
    return NormalizedEntity(entity_type=etype, value=value, confidence=0.9, source_url="", page_id=None)


# --- data files -------------------------------------------------------------


def test_ambiguous_list_covers_the_generic_values():
    names = gate.ambiguous_names()
    for word in ("php", "tor", "play", "android", "stop", "telegram", "root", "ctf", "entropy",
                 "royal", "quantum", "snake", "mars", "phantom", "predator", "aurora", "mystic"):
        assert word in names, word
    # Real names stay out (not dictionary words, or on the allow-override list).
    for word in ("lockbit", "redline", "lumma", "qilin", "akira", "clop"):
        assert word not in names, word


def test_dictionary_word_typed_as_malware_is_ambiguous_even_off_list():
    assert gate.is_ambiguous("less", "MALWARE_FAMILY")
    assert not gate.is_ambiguous("less", "ORGANIZATION_NAME")


# --- 22R-4 context rule ------------------------------------------------------


@pytest.mark.parametrize(
    "etype,value,text,kept",
    [
        ("RANSOMWARE_GROUP", "Play", "Kids like to play outside in the park every day.", False),
        ("RANSOMWARE_GROUP", "Play", "The Play ransomware gang listed three new victims.", True),
        ("RANSOMWARE_GROUP", "Royal", "Tea at the Royal hotel was served at four.", False),
        ("RANSOMWARE_GROUP", "Royal", "Royal operators moved to a new leak site last month.", True),
        ("MALWARE_FAMILY", "Snake", "A snake was seen near the river bank.", False),
        ("MALWARE_FAMILY", "Snake", "The Snake implant is a cyber espionage malware tool.", True),
        ("MALWARE_FAMILY", "Aurora", "The aurora was bright over the northern sky.", False),
        ("MALWARE_FAMILY", "Aurora", "Aurora stealer logs are sold here.", True),
        # Platform words are never threat names unless the query names them.
        ("MALWARE_FAMILY", "Tor", "Tor malware hides traffic; download the Tor browser.", False),
        ("RANSOMWARE_GROUP", "PHP", "PHP ransomware samples and PHP scripts.", False),
        ("RANSOMWARE_GROUP", "Android", "Android malware targets banking apps.", False),
        # Real names need no cue.
        ("RANSOMWARE_GROUP", "LockBit", "LockBit posted.", True),
        ("MALWARE_FAMILY", "RedLine", "Redline is popular.", True),
        ("RANSOMWARE_GROUP", "Qilin", "Qilin is active.", True),
        # Handles: the structural cue counts.
        ("THREAT_ACTOR_HANDLE", "phantom", "Thread posted by phantom yesterday.", True),
    ],
)
def test_context_rule(etype, value, text, kept):
    out = gate.gate_entities([_ent(etype, value)], text, "http://example.test/")
    assert (len(out) == 1) is kept
    assert gate.removal_counts()["gazetteer_context"] == (0 if kept else 1)


def test_cue_must_be_within_eight_tokens():
    far = "Play " + "word " * 12 + "ransomware"
    near = "Play " + "word " * 3 + "ransomware"
    assert gate.gate_entities([_ent("RANSOMWARE_GROUP", "Play")], far) == []
    assert len(gate.gate_entities([_ent("RANSOMWARE_GROUP", "Play")], near)) == 1


def test_query_naming_the_word_keeps_it():
    relevance.set_current_intent(classify_query("Play ransomware"))
    out = gate.gate_entities([_ent("RANSOMWARE_GROUP", "Play")], "we play games here")
    assert len(out) == 1


def test_misp_relation_name_is_a_cue():
    rel = gate.relations().get("conti") or []
    assert rel, "conti should have MISP relations in the snapshot"
    # "hive" is ambiguous; a relation name of it nearby is a cue when present.
    hive_rel = gate.relations_of("hive")
    if hive_rel:
        text = f"Hive and {hive_rel[0]} were mentioned together."
        assert len(gate.gate_entities([_ent("RANSOMWARE_GROUP", "Hive")], text)) == 1


# --- 22R-5 organisation boilerplate -----------------------------------------


@pytest.mark.parametrize(
    "value,url,title,reason",
    [
        ("KrebsOnSecurity", "https://krebsonsecurity.com/2026/10/x/", "", "own_site"),
        ("Unit 42", "https://unit42.example-vendor.com/post/", "", "own_site"),
        ("OnionLand", "http://" + "a" * 56 + ".onion/", "", "stoplist"),
        ("OAuth", "https://news.example/", "", "stoplist"),
        ("WordPress", "https://news.example/", "", "stoplist"),
        ("Example Daily", "http://" + "b" * 56 + ".onion/", "Example Daily - links", "own_site"),
        ("FBI", "https://news.example/", "", None),
        ("Acme Corp", "https://news.example/", "", None),
    ],
)
def test_org_boilerplate(value, url, title, reason):
    assert gate.org_boilerplate_reason(value, url, title) == reason


def test_org_removals_are_counted_and_agencies_kept():
    ents = [_ent("ORGANIZATION_NAME", "KrebsOnSecurity"), _ent("ORGANIZATION_NAME", "FBI"),
            _ent("ORGANIZATION_NAME", "Acme Corp")]
    out = gate.gate_entities(ents, "text", "https://krebsonsecurity.com/a")
    assert [e.value for e in out] == ["FBI", "Acme Corp"]
    assert gate.removal_counts() == {"gazetteer_context": 0, "org_boilerplate": 1}


def test_gate_runs_inside_page_extraction():
    import asyncio

    from extractor.pipeline import extract_entities_from_page

    text = "We play football. The Play ransomware group hit a target. " * 2
    res = asyncio.run(extract_entities_from_page(
        page_text="Children play football every weekend in the town park near the river.",
        page_url="http://example.test/a", persist=False,
    ))
    assert all(e.value.lower() != "play" for e in res.entities)
    res2 = asyncio.run(extract_entities_from_page(page_text=text, page_url="http://example.test/b", persist=False))
    assert any(e.value.lower() == "play" for e in res2.entities)
