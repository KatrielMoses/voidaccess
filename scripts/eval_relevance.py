#!/usr/bin/env python3
"""
scripts/eval_relevance.py — score relevance-tier runs (22R) per query.

Usage:
    python scripts/eval_relevance.py <runs_dir> [--baseline <runs_dir>] [--json]

<runs_dir> holds one directory per run variant (for example ``L-shallow``,
``L22-normal``), each with one directory per query key, each with the
engine output under ``out/*.json``. Optional per-run files are read when
present: ``done.json`` (``wall_s``) and ``usage.json`` (LLM ``input_tokens``,
``output_tokens``, ``calls``).

Per query it prints one table with a row per variant: entities per tier,
on-topic % of the Direct tier, the on-topic count over all tiers, the junk
count and the typed-generic count (the 18 GENERIC values), wall time, LLM
tokens, and checks for the summary (first sentence on 0-direct runs, the
content-safety detector) and for selector queries (exact selector in the
refined query and in the search log, ``events.jsonl``).

The on-topic / junk heuristic is the 2.1.0 QA judge: an entity is on-topic
when its context snippet, source URL or value mentions one of the query's
terms below; junk is a generic gazetteer word, a boilerplate organisation,
or a MAC / DATE / WIRE value. Only counts are printed, never page text.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from collections import OrderedDict

QUERIES = OrderedDict([
    ("lockbit", "LockBit ransomware"),
    ("redline", "RedLine stealer"),
    ("cve", "CVE-2024-3400"),
    ("brandleak", "acme.com credentials leak"),
    ("iab", "initial access broker"),
    ("gibberish", "zqxvjwk plorbtank 7731 quenvax"),
    ("person", "John Smith"),
    ("email", "jdoe1987@gmail.com"),
    ("phone", "+79001234567"),
    ("domain", "example-corp.com"),
    ("lumma", "Lumma Stealer malware"),
])
ON_TOPIC = {
    "lockbit": ["lockbit"],
    "redline": ["redline"],
    "cve": ["3400", "pan-os", "globalprotect", "palo alto"],
    "brandleak": ["acme"],
    "iab": ["initial access", "access broker", " iab", "rdp access", "vpn access", "network access"],
    "gibberish": ["zqxvjwk", "plorbtank", "quenvax"],
    "person": ["john smith"],
    "email": ["jdoe1987", "jdoe"],
    "phone": ["79001234567", "900 123", "9001234567"],
    "domain": ["example-corp"],
    "lumma": ["lumma"],
}
SELECTOR_QUERIES = {"email": "jdoe1987@gmail.com", "phone": "79001234567", "domain": "example-corp.com"}
JUNK_ORG = re.compile(
    r"^(the |a )|\b(oauth|wordpress|paypal|codeigniter|onionland|tordex|megalinks|linkedin|"
    r"powerpoint|krebsonsecurity|fbi|cisa)\b",
    re.I,
)
GENERIC = {
    "php", "tor", "play", "android", "stop", "telegram", "root", "ctf", "entropy", "less",
    "royal", "quantum", "snake", "mars", "phantom", "predator", "aurora", "mystic",
}
TIERS = ("direct", "related", "background")


def judge(key: str, ent: dict) -> tuple[bool, bool, bool]:
    """(on_topic, junk, typed_generic) for one entity, as the 2.1.0 judge scores it."""
    ctx = " ".join([
        ent.get("context_snippet") or "", ent.get("source_url") or "", ent.get("value") or "",
    ]).lower()
    value = (ent.get("canonical_value") or ent.get("value") or "").lower()
    generic = value in GENERIC
    junk = (
        generic
        or (ent.get("entity_type") == "ORGANIZATION_NAME" and bool(JUNK_ORG.search(ent.get("value") or "")))
        or ent.get("entity_type") in ("MAC_ADDRESS", "DATE", "WIRE_HANDLE")
    )
    on_topic = (not junk) and any(t in ctx for t in ON_TOPIC.get(key, []))
    return on_topic, junk, generic


def _load(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _first_sentence(text: str) -> str:
    text = (text or "").strip()
    m = re.match(r"(.+?[.!?])(\s|$)", text, re.S)
    return (m.group(1) if m else text[:200]).strip()


def _detector():
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from utils.content_safety import detect_prohibited

        return detect_prohibited
    except Exception:  # noqa: BLE001
        return None


def score_run(run_dir: str, key: str, detect=None) -> dict | None:
    outs = sorted(glob.glob(os.path.join(run_dir, "out", "*.json")))
    if not outs:
        return None
    report = _load(outs[-1]) or {}
    ents = report.get("entities") or []
    tiers = {t: 0 for t in TIERS}
    direct_on = on_total = junk = generic = 0
    for e in ents:
        tier = e.get("relevance") or "untiered"
        on, j, g = judge(key, e)
        if tier in tiers:
            tiers[tier] += 1
        if tier == "direct" and on:
            direct_on += 1
        on_total += on
        junk += j
        generic += g
    done = _load(os.path.join(run_dir, "done.json")) or {}
    usage = _load(os.path.join(run_dir, "usage.json")) or {}
    summary = report.get("summary") or ""
    rel = report.get("relevance") or {}
    row = {
        "entities": len(ents),
        "tiers": tiers if rel else None,
        "direct_on_topic_pct": round(100 * direct_on / tiers["direct"]) if tiers["direct"] else None,
        "on_topic": on_total,
        "junk": junk,
        "typed_generic": generic,
        "pages": rel.get("pages"),
        "removed": rel.get("removed"),
        "wall_s": done.get("wall_s"),
        "tokens_in": usage.get("input_tokens"),
        "tokens_out": usage.get("output_tokens"),
        "llm_calls": usage.get("calls"),
        "summary_kind": report.get("summary_kind"),
        "summary_flagged": bool(detect(summary)) if (detect and summary) else False,
        "first_sentence_no_direct": _first_sentence(summary).lower().startswith("no collected page mentions"),
        "content_safety": report.get("content_safety") or {},
        "refined_query": report.get("refined_query"),
    }
    if key in SELECTOR_QUERIES:
        sel = SELECTOR_QUERIES[key]
        refined = re.sub(r"[\s().\-+]", "", report.get("refined_query") or "") if key == "phone" else (report.get("refined_query") or "").lower()
        row["selector_in_refined"] = sel in refined
        logged = False
        try:
            with open(os.path.join(run_dir, "events.jsonl"), encoding="utf-8") as fh:
                for line in fh:
                    ev = json.loads(line)
                    texts = ev.get("refined_queries") or []
                    if ev.get("kind") == "query.refined":
                        texts = [(ev.get("data") or {}).get("text") or ""]
                    for t in texts:
                        t = re.sub(r"[\s().\-+]", "", t) if key == "phone" else t.lower()
                        logged = logged or sel in t
        except OSError:
            pass
        row["selector_in_search_log"] = logged
    return row


def _key_of(run_dir: str) -> str | None:
    name = os.path.basename(run_dir.rstrip("/"))
    return name if name in QUERIES else None


def collect(runs_dir: str, detect=None, keep: set[str] | None = None) -> dict[str, dict[str, dict]]:
    """{query_key: {variant: row}}"""
    out: dict[str, dict[str, dict]] = {k: OrderedDict() for k in QUERIES}
    for variant_dir in sorted(glob.glob(os.path.join(runs_dir, "*"))):
        if not os.path.isdir(variant_dir):
            continue
        if keep and os.path.basename(variant_dir) not in keep:
            continue
        for run_dir in sorted(glob.glob(os.path.join(variant_dir, "*"))):
            key = _key_of(run_dir)
            if key is None:
                continue
            row = score_run(run_dir, key, detect)
            if row is not None:
                out[key][os.path.basename(variant_dir)] = row
    return out


def _fmt(v, width: int) -> str:
    s = "-" if v is None else (("y" if v else "n") if isinstance(v, bool) else str(v))
    return s.rjust(width)


def print_tables(results: dict[str, dict[str, dict]]) -> None:
    header = (
        f"{'variant':<16}{'ents':>6}{'dir':>5}{'rel':>5}{'bg':>5}{'dirOn%':>7}{'onTop':>6}"
        f"{'junk':>5}{'gen':>4}{'pgD/R/B':>10}{'rmG/O':>7}{'wall':>6}{'tokIn':>7}{'tokOut':>7}"
        f"{'flag':>5}{'noDir1st':>9}{'selRef':>7}{'selLog':>7}"
    )
    for key, rows in results.items():
        if not rows:
            continue
        print(f"\n== {key}: {QUERIES[key]}")
        print(header)
        for variant, r in rows.items():
            t = r["tiers"] or {}
            pages = r["pages"] or {}
            removed = r["removed"] or {}
            pg = f"{pages.get('direct', '-')}/{pages.get('related', '-')}/{pages.get('background', '-')}" if pages else "-"
            rm = f"{removed.get('gazetteer_context', '-')}/{removed.get('org_boilerplate', '-')}" if removed else "-"
            wall = round(r["wall_s"]) if isinstance(r["wall_s"], (int, float)) else None
            print(
                f"{variant:<16}{_fmt(r['entities'], 6)}{_fmt(t.get('direct'), 5)}{_fmt(t.get('related'), 5)}"
                f"{_fmt(t.get('background'), 5)}{_fmt(r['direct_on_topic_pct'], 7)}{_fmt(r['on_topic'], 6)}"
                f"{_fmt(r['junk'], 5)}{_fmt(r['typed_generic'], 4)}{pg:>10}{rm:>7}{_fmt(wall, 6)}"
                f"{_fmt(r['tokens_in'], 7)}{_fmt(r['tokens_out'], 7)}{_fmt(r['summary_flagged'], 5)}"
                f"{_fmt(r['first_sentence_no_direct'], 9)}{_fmt(r.get('selector_in_refined'), 7)}"
                f"{_fmt(r.get('selector_in_search_log'), 7)}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Score relevance-tier runs per query.")
    parser.add_argument("runs_dir")
    parser.add_argument("--baseline", action="append", default=[],
                        help="another runs dir to show side by side (repeatable)")
    parser.add_argument("--variants", default="",
                        help="comma-separated variant names to keep (e.g. L-shallow,L-normal)")
    parser.add_argument("--json", action="store_true", help="print the rows as JSON")
    args = parser.parse_args()
    detect = _detector()
    keep = {v.strip() for v in args.variants.split(",") if v.strip()} or None
    results = collect(args.runs_dir, detect, keep)
    for base in args.baseline:
        for key, rows in collect(base, detect, keep).items():
            for variant, row in rows.items():
                results[key][f"base:{variant}"] = row
            results[key] = OrderedDict(sorted(results[key].items(), key=lambda kv: (
                kv[0].split("-")[-1], not kv[0].startswith("base:"), kv[0])))
    if args.json:
        json.dump(results, sys.stdout, indent=1, default=str)
        print()
    else:
        print_tables(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
