#!/usr/bin/env python3
"""
scripts/build_relevance_data.py — Regenerate the relevance-tier reference data.

Writes two committed snapshots that the relevance tiers (22R) read offline:

data/ambiguous_threat_names.txt
    Threat names that are also ordinary English or technology words ("play",
    "royal", "tor", "php"). The extractor types one of these as a threat name
    only with a nearby threat cue or on a page that is directly about it
    (extractor/relevance_gate.py).

    How it is generated (deterministic, offline):
      1. Collect every name (canonical + synonyms) from data/threat_gazetteer.json
         and from the bundled malware / ransomware dictionaries in
         extractor/ner.py whose words are letters only.
      2. Keep the names whose every word is in the English dictionary
         data/common_words_en.txt (the ~370k-word list scripts/update_gazetteer.py
         downloads) or in the technology-word list TECH_WORDS
         (extractor/relevance_gate.py: protocols, languages, platforms and
         products the dictionary lacks). "Play", "Royal", "Dark Angels" and
         "PHP" qualify; "LockBit" and "Qilin" do not. Each is written as its
         canonical key (lower case, separators dropped), the form
         extractor/relevance_gate.py compares.
      3. Remove the manual allow-override list data/ambiguous_threat_names_allow.txt
         (distinct threat names that happen to be dictionary words, such as
         "clop" or "redline"; one per line, # comments allowed).

data/threat_relations.json
    For each gazetteer name (canonical key), the names MISP links to it
    ("uses", "variant-of", "successor-of", ...): a group's known malware, a
    malware's operators. Names that are ambiguous or shorter than 4
    characters are left out, so a relation never makes a page "related"
    through a common word. Needs the MISP galaxy cluster files: fetched from
    GitHub, or read from --misp-dir when given.

Run:
    python scripts/build_relevance_data.py               # both files
    python scripts/build_relevance_data.py --ambiguous-only
    python scripts/build_relevance_data.py --misp-dir /path/to/clusters
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "data")
sys.path.insert(0, ROOT)

GAZETTEER = os.path.join(DATA_DIR, "threat_gazetteer.json")
DICTIONARY = os.path.join(DATA_DIR, "common_words_en.txt")
ALLOW = os.path.join(DATA_DIR, "ambiguous_threat_names_allow.txt")
AMBIGUOUS_OUT = os.path.join(DATA_DIR, "ambiguous_threat_names.txt")
RELATIONS_OUT = os.path.join(DATA_DIR, "threat_relations.json")

MISP_BASE = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters"
MISP_FILES = (
    "ransomware.json", "threat-actor.json", "mitre-intrusion-set.json",
    "mitre-malware.json", "mitre-tool.json", "rat.json", "stealer.json", "malpedia.json",
)
RELATION_TYPES = frozenset({
    "uses", "used-by", "variant-of", "successor-of", "related-to", "deploys", "linked-to",
    "overlaps", "parent-of", "dropped-by", "part-of", "derived-from", "delivers",
    "associated-with",
})
MAX_RELATIONS = 30

# Technology, protocol and platform words the dictionary lacks
# (extractor/relevance_gate.py owns the list; the gate needs it at run time).
from extractor.relevance_gate import TECH_WORDS as _TECH_WORDS  # noqa: E402


def canonical_key(name: str) -> str:
    v = (name or "").lower()
    v = re.sub(r"[\s\-_.]", "", v)
    return re.sub(r"[^\w]", "", v)


def _read_lines(path: str) -> set[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            return {
                line.split("#", 1)[0].strip().lower()
                for line in fh
                if line.split("#", 1)[0].strip()
            }
    except FileNotFoundError:
        return set()


def _gazetteer_records() -> list[dict]:
    with open(GAZETTEER, encoding="utf-8") as fh:
        data = json.load(fh)
    out: list[dict] = []
    for category in ("threat_actors", "malware", "ransomware"):
        for record in data.get(category) or []:
            if isinstance(record, dict) and record.get("canonical"):
                out.append(record)
    return out


def all_names() -> list[str]:
    names: list[str] = []
    for record in _gazetteer_records():
        names.extend([record["canonical"], *(record.get("synonyms") or [])])
    from extractor import ner

    names.extend([*ner._MALWARE_DICT, *ner._RANSOMWARE_DICT])
    return names


def build_ambiguous() -> list[str]:
    dictionary = _read_lines(DICTIONARY)
    allow = _read_lines(ALLOW)
    ambiguous: set[str] = set()
    for name in all_names():
        k = canonical_key(name)
        if not re.fullmatch(r"[a-z]+", k) or len(k) < 2:
            continue
        words = [w.lower() for w in re.split(r"[\s\-_.]+", name.strip()) if w]
        if not words or not all(re.fullmatch(r"[a-z]+", w) for w in words):
            continue
        if all(w in dictionary or w in _TECH_WORDS for w in words):
            ambiguous.add(k)
    return sorted(ambiguous - {canonical_key(a) for a in allow})


def _load_cluster(name: str, misp_dir: str | None) -> dict:
    if misp_dir:
        with open(os.path.join(misp_dir, name), encoding="utf-8") as fh:
            return json.load(fh)
    import requests

    resp = requests.get(f"{MISP_BASE}/{name}", timeout=120)
    resp.raise_for_status()
    return resp.json()


def build_relations(misp_dir: str | None, ambiguous: set[str]) -> dict:
    names_by_uuid: dict[str, str] = {}
    edges: list[tuple[str, str]] = []
    similar: list[tuple[str, str]] = []
    for filename in MISP_FILES:
        try:
            cluster = _load_cluster(filename, misp_dir)
        except Exception as exc:  # noqa: BLE001
            print(f"  ! skipped {filename}: {exc}", file=sys.stderr)
            continue
        for entry in cluster.get("values", []):
            uuid = (entry.get("uuid") or "").strip()
            value = (entry.get("value") or "").strip()
            if not uuid or not value:
                continue
            names_by_uuid.setdefault(uuid, value)
            for rel in entry.get("related") or []:
                dest = (rel.get("dest-uuid") or "").strip()
                if not dest:
                    continue
                if rel.get("type") == "similar":
                    similar.append((uuid, dest))
                elif rel.get("type") in RELATION_TYPES:
                    edges.append((uuid, dest))

    # "similar" links the same threat across galaxies; merge those first.
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in similar:
        parent[find(a)] = find(b)

    linked: dict[str, set[str]] = {}
    for a, b in edges:
        ra, rb = find(a), find(b)
        if ra == rb:
            continue
        linked.setdefault(ra, set()).add(rb)
        linked.setdefault(rb, set()).add(ra)

    members: dict[str, set[str]] = {}
    for uuid in names_by_uuid:
        members.setdefault(find(uuid), set()).add(uuid)

    def usable(name: str) -> bool:
        n = name.strip().lower()
        if len(n) < 4 or n in ambiguous or canonical_key(n) in ambiguous:
            return False
        return not re.search(r"\s-\s[st]\d{4}$", n)

    gazetteer_keys = set()
    for record in _gazetteer_records():
        for name in [record["canonical"], *(record.get("synonyms") or [])]:
            gazetteer_keys.add(canonical_key(name))

    out: dict[str, list[str]] = {}
    for root, uuids in members.items():
        rel_names: set[str] = set()
        for other in linked.get(root, ()):  # 1 hop
            for uuid in members.get(other, ()):
                name = names_by_uuid.get(uuid, "")
                if usable(name):
                    rel_names.add(name.strip().lower())
        if not rel_names:
            continue
        own = {canonical_key(names_by_uuid[u]) for u in uuids}
        rel = sorted(n for n in rel_names if canonical_key(n) not in own)[:MAX_RELATIONS]
        if not rel:
            continue
        for key in own:
            if key in gazetteer_keys and len(key) >= 3:
                merged = sorted(set(out.get(key, [])) | set(rel))[:MAX_RELATIONS]
                out[key] = merged
    return dict(sorted(out.items()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--misp-dir", help="read MISP cluster files from this directory")
    parser.add_argument("--ambiguous-only", action="store_true")
    args = parser.parse_args()

    ambiguous = build_ambiguous()
    with open(AMBIGUOUS_OUT, "w", encoding="utf-8") as fh:
        fh.write(
            "# Generated by scripts/build_relevance_data.py; do not edit by hand.\n"
            "# Threat names that are also English or technology words. To keep a name\n"
            "# out of this list, add it to data/ambiguous_threat_names_allow.txt.\n"
        )
        fh.write("\n".join(ambiguous) + "\n")
    print(f"Wrote {AMBIGUOUS_OUT}: {len(ambiguous)} names")

    if not args.ambiguous_only:
        relations = build_relations(args.misp_dir, set(ambiguous))
        with open(RELATIONS_OUT, "w", encoding="utf-8") as fh:
            json.dump(relations, fh, ensure_ascii=False, indent=0, sort_keys=True)
            fh.write("\n")
        print(f"Wrote {RELATIONS_OUT}: {len(relations)} names with relations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
