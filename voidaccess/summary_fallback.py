"""Deterministic, non-LLM fallback summary.

Used when the LLM summary times out or fails so a run that found pages never
ends with an empty summary. Built only from already-extracted entities and the
page list; the output is marked ``summary_kind: "fallback"`` by the caller.
"""

from __future__ import annotations

from typing import Any, Iterable

# Inclusion list, not an exclusion list: credential, key, email, phone and
# personal-name entities must never be echoed into a summary.
FALLBACK_ENTITY_TYPES = (
    "THREAT_ACTOR_HANDLE",
    "THREAT_ACTOR",
    "RANSOMWARE_GROUP",
    "MALWARE_FAMILY",
    "MALWARE",
    "CVE",
    "CVE_NUMBER",
    "MITRE_TECHNIQUE",
    "ORGANIZATION_NAME",
    "DOMAIN",
    "IP_ADDRESS",
)
FALLBACK_PER_TYPE = 5
FALLBACK_MAX_SOURCES = 5


def build_fallback_summary(
    query: str,
    entities: Iterable[dict[str, Any]],
    pages: Iterable[dict[str, Any]],
) -> str:
    entity_list = list(entities or [])
    page_list = list(pages or [])
    lines = [
        f"Automated summary for '{query}' "
        "(the AI summary was unavailable for this run, so this was built "
        "from extracted entities and sources only).",
        "",
        f"Pages analysed: {len(page_list)}. Entities extracted: {len(entity_list)}.",
    ]

    by_type: dict[str, list[dict[str, Any]]] = {}
    for ent in entity_list:
        etype = str(ent.get("entity_type") or "").upper()
        if etype in FALLBACK_ENTITY_TYPES and ent.get("value") and not ent.get("suppressed"):
            by_type.setdefault(etype, []).append(ent)

    for etype in FALLBACK_ENTITY_TYPES:
        items = by_type.get(etype)
        if not items:
            continue
        items = sorted(items, key=lambda e: -float(e.get("confidence") or 0.0))
        values = [str(e["value"]) for e in items[:FALLBACK_PER_TYPE]]
        label = etype.replace("_", " ").title()
        lines.append(f"- {label}: {', '.join(values)}")

    sources = []
    for page in page_list:
        url = page.get("url") or page.get("link")
        if url and url not in sources:
            sources.append(url)
        if len(sources) >= FALLBACK_MAX_SOURCES:
            break
    if sources:
        lines.append("")
        lines.append("Top sources:")
        lines.extend(f"- {u}" for u in sources)
    return "\n".join(lines)
