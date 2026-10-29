"""
extractor/relationship_extract.py — LLM-assisted *typed* relationship extraction.

This is a distinct pass from entity extraction.  Entity extraction answers
"what things are on this page"; this pass answers the different question
"how are those already-identified things related".  It reuses the page content
already read for entity extraction (no new scraping/chunking pipeline) plus the
list of entities already found on that page, and asks the LLM which specific,
typed relationship (if any) connects each pair.

Design constraints (see the task spec and CHANGELOG STIX saga):

* **Bounded vocabulary.**  The LLM may only emit one of a small, fixed set of
  relationship types (`_LLM_REL_VOCAB`).  Anything it cannot map cleanly is
  dropped — the pair then simply keeps its plain co-occurrence edge, which is
  generated independently by the graph builder.  We never invent new types.
* **Claim-specific confidence.**  Each returned relationship carries its own
  confidence for *that claim*, separate from the confidence of the two
  entities it connects.  A low-confidence relationship between two
  high-confidence entities stays low-confidence.
* **Additive, never replacing.**  This pass only ever *adds* typed edges where
  there is genuine evidence.  Co-occurrence edges are untouched.
* **Bounded cost.**  One LLM call per page, over a leading content window, and
  never more than `max_rel_pages` pages per investigation (mirrors the
  entity-extraction `MAX_LLM_PAGES_PER_INV` cap).  This is the specific guard
  against the historical near-cartesian relationship explosion.

Public interface
----------------
async extract_relationships_for_page(page_text, entities, llm, ...) -> list[dict]
async extract_relationships_from_results(results, page_text_by_url,
        page_id_by_url, llm, ...) -> list[dict]

Each returned dict has: entity_a_id, entity_b_id, relationship_type, confidence
(and, from the orchestrator, source_page_id).
"""

from __future__ import annotations

import asyncio
import json
import io
import logging
from contextlib import redirect_stdout
from typing import Any, Optional

from graph.model import EDGE_TYPES, RELATIONSHIP_TYPE_COMPATIBILITY

logger = logging.getLogger(__name__)

_DEFAULT_MAX_CHUNK_CHARS = 12000
# Cap how many entities we describe to the LLM for a single page.  This bounds
# the prompt size and — combined with the per-page relationship cap below —
# keeps the pass far away from the O(n^2) pair explosion.
_DEFAULT_MAX_ENTITIES_PER_PAGE = 40
# Defensive ceiling on how many typed relationships we accept from one page,
# regardless of what the LLM returns.
_DEFAULT_MAX_RELATIONSHIPS_PER_PAGE = 60

# Bounded relationship vocabulary.  Maps the lowercase token the LLM is asked
# to emit → the stored relationship_type (matches RelationshipType /
# EDGE_TYPES).  Passive forms map to the same stored type but flip the edge
# direction (handled below) so the stored edge always reads source -> target.
_LLM_REL_VOCAB: dict[str, str] = {
    relationship_type.lower(): relationship_type
    for relationship_type in RELATIONSHIP_TYPE_COMPATIBILITY
}
_LLM_REL_VOCAB["used"] = EDGE_TYPES.USES

# Tokens whose natural reading reverses source/target (passive voice).  E.g.
# "org targeted_by actor" means the *actor* TARGETS the *org*.
_PASSIVE_REL_VOCAB: dict[str, str] = {
    "targeted_by": "TARGETS",
    "controlled_by": "CONTROLS",
}

# Endpoint-type validation is deliberately kept in the relationship extractor
# so the prompt and the independent post-LLM gate share one source of truth.
# The sets are intentionally permissive for the project's current normalized
# entity vocabulary; unknown types are not accepted for typed edges.
_RELATIONSHIP_TYPE_COMPATIBILITY = RELATIONSHIP_TYPE_COMPATIBILITY


def _entity_type(entity: dict) -> str:
    return str(entity.get("type", "") or "").strip().upper()


def _is_compatible_relationship(rel_type: str, source: dict, target: dict) -> bool:
    """Validate endpoint types independently of the LLM's claimed verb."""
    allowed = _RELATIONSHIP_TYPE_COMPATIBILITY.get(rel_type)
    if allowed is None:
        return False
    source_types, target_types = allowed
    return _entity_type(source) in source_types and _entity_type(target) in target_types


def _compatibility_guide() -> str:
    lines = []
    for rel_type, (sources, targets) in _RELATIONSHIP_TYPE_COMPATIBILITY.items():
        lines.append(
            f"- {rel_type}: source {{{', '.join(sorted(sources))}}} -> "
            f"target {{{', '.join(sorted(targets))}}}"
        )
    return "\n".join(lines)


_COMPATIBILITY_GUIDE = _compatibility_guide()

_PROMPT_TEMPLATE = (
    "You are a threat intelligence analyst. Below is a numbered list of "
    "entities that were already extracted from a single dark-web page, "
    "followed by the page content.\n\n"
    "Your task: identify only the GENUINE, specific relationships between "
    "pairs of these entities that the content actually supports. Return ONLY a "
    "JSON object of the form:\n"
    '{{"relationships": [{{"source": <int>, "target": <int>, '
    '"type": "<type>", "confidence": <float 0.0-1.0>}}]}}\n\n'
    "Rules:\n"
    "- `source` and `target` are indices from the entity list below.\n"
    "- `type` MUST be exactly one of: {relationship_types}. "
    "If no listed type fits a pair, DO NOT include that pair.\n"
    "- Direction matters. Read source->target as: an actor `uses`/`controls` a "
    "tool or wallet; a malware family `drops` another payload; a malware "
    "family or actor `exploits` a CVE; an actor/campaign `targets` an "
    "organization; a host/malware `communicates_with` another host.\n"
    "- `confidence` reflects how strongly THIS page supports THIS specific "
    "relationship claim (not how confident you are the entities exist).\n"
    "- Do NOT link two entities merely because they appear on the same page. "
    "Plain co-occurrence is captured elsewhere — omit pairs that have no "
    "specific relationship.\n"
    "- Do not output any text outside the JSON object.\n\n"
    "Entity-type compatibility guide (source -> target):\n"
    "{compatibility_guide}\n"
    "Only emit a relationship when BOTH endpoint types match this guide.\n\n"
    "Entities:\n{entities}\n\n"
    "Content:\n{content}"
)

_PROMPT_TEMPLATE = _PROMPT_TEMPLATE.replace(
    "{relationship_types}",
    ", ".join(sorted(set(_LLM_REL_VOCAB) | set(_PASSIVE_REL_VOCAB))),
)


def _clamp_confidence(value: Any, default: float = 0.5) -> float:
    """Coerce an arbitrary value to a float in [0.0, 1.0]."""
    try:
        conf = float(value)
    except (TypeError, ValueError):
        return default
    if conf != conf:  # NaN
        return default
    return max(0.0, min(1.0, conf))


def _parse_relationship_json(raw: str) -> list[dict]:
    """Strip markdown fences and parse the LLM relationship JSON. [] on failure."""
    if not raw:
        return []
    try:
        cleaned = (
            raw.strip()
            .removeprefix("```json")
            .removeprefix("```")
            .strip()
            .removesuffix("```")
            .strip()
        )
        parsed = json.loads(cleaned)
    except (json.JSONDecodeError, AttributeError):
        logger.warning(
            "Relationship extraction: invalid JSON (len=%d)", len(raw or "")
        )
        return []
    if isinstance(parsed, dict):
        rels = parsed.get("relationships", [])
    elif isinstance(parsed, list):
        rels = parsed
    else:
        rels = []
    return rels if isinstance(rels, list) else []


class RelationshipLLMCallError(Exception):
    """Raised when the relationship-extraction LLM invocation itself fails.

    Distinct from a call that *succeeds* and legitimately returns no
    relationships — callers use this to log a visible warning so a broken LLM
    integration can never masquerade as "the LLM found no relationships".
    """


async def _invoke_llm(prompt: str, llm) -> str:
    """Call the LLM with streaming/callbacks disabled (mirrors llm_extract).

    Raises :class:`RelationshipLLMCallError` if the underlying invocation
    fails, so the caller can distinguish a *failed* call from a successful
    call that found nothing.
    """
    # ``bind(callbacks=[])`` puts ``callbacks`` into the model's invocation
    # kwargs, which LangChain forwards to ``agenerate_prompt`` as ``**kwargs``
    # — while ``ainvoke`` ALSO passes ``callbacks`` explicitly, raising
    # "agenerate_prompt() got multiple values for keyword argument 'callbacks'".
    # ``with_config`` overrides callbacks for this call WITHOUT adding model
    # kwargs, exactly as extractor/llm_extract._extract_chunk does.
    if hasattr(llm, "with_config"):
        silent_llm = llm.with_config({"callbacks": []})
    else:
        silent_llm = llm.bind(streaming=False, callbacks=[])
    try:
        # Guard stdout in case a legacy constructor callback still streams
        # partial JSON tokens even with an empty per-call callback list.
        with redirect_stdout(io.StringIO()):
            response = await silent_llm.ainvoke(prompt)
    except Exception as exc:  # noqa: BLE001 — surface as a typed failure
        raise RelationshipLLMCallError(str(exc)) from exc
    content = response.content if hasattr(response, "content") else str(response)
    return content.strip()


async def extract_relationships_for_page(
    page_text: str,
    entities: list[dict],
    llm,
    *,
    max_chunk_chars: int = _DEFAULT_MAX_CHUNK_CHARS,
    max_entities: int = _DEFAULT_MAX_ENTITIES_PER_PAGE,
    max_relationships: int = _DEFAULT_MAX_RELATIONSHIPS_PER_PAGE,
) -> list[dict]:
    """
    Ask the LLM which typed relationships connect the given entities.

    `entities` is a list of dicts, each with at least ``id``, ``type`` and
    ``value``.  Returns a list of dicts with ``entity_a_id``, ``entity_b_id``,
    ``relationship_type`` and ``confidence``.  Never raises; returns [] on any
    problem or when there is nothing to relate.
    """
    if llm is None or not page_text or len(entities) < 2:
        return []

    # Bound the entity list handed to the LLM.  We keep the highest-confidence
    # entities so the most trustworthy IOCs are always in scope.
    trimmed = sorted(
        entities,
        key=lambda e: float(e.get("confidence", 0.0) or 0.0),
        reverse=True,
    )[:max_entities]
    if len(trimmed) < 2:
        return []

    entity_lines = "\n".join(
        f"[{i}] {str(e.get('type', '')).upper()}: {e.get('value', '')}"
        for i, e in enumerate(trimmed)
    )
    content = page_text[:max_chunk_chars]
    from voidaccess.fence import format_prompt
    prompt = format_prompt(
        _PROMPT_TEMPLATE,
        entities=entity_lines,
        content=content,
        trusted={"compatibility_guide": _COMPATIBILITY_GUIDE},
    )

    try:
        raw = await _invoke_llm(prompt, llm)
    except RelationshipLLMCallError as exc:
        # The LLM call itself failed — this is NOT the same as the LLM running
        # successfully and finding no relationship.  Log loudly so a broken
        # integration is visible in normal operation instead of silently
        # degrading every page to zero typed relationships.
        logger.warning(
            "Relationship extraction: LLM call FAILED (%s) — this page yielded "
            "NO typed relationships due to an error, not because none exist",
            exc,
        )
        return []
    rels = _parse_relationship_json(raw)
    if not rels:
        return []

    n = len(trimmed)
    out: list[dict] = []
    # Dedup within a page on (a_id, b_id, type), keeping the max confidence.
    seen: dict[tuple, float] = {}
    for rel in rels:
        if not isinstance(rel, dict):
            continue
        try:
            src_idx = int(rel.get("source"))
            tgt_idx = int(rel.get("target"))
        except (TypeError, ValueError):
            continue
        if not (0 <= src_idx < n) or not (0 <= tgt_idx < n) or src_idx == tgt_idx:
            continue

        raw_type = str(rel.get("type", "")).strip().lower()
        if raw_type in _LLM_REL_VOCAB:
            rel_type = _LLM_REL_VOCAB[raw_type]
            a_ent, b_ent = trimmed[src_idx], trimmed[tgt_idx]
        elif raw_type in _PASSIVE_REL_VOCAB:
            # Passive voice — flip direction so the stored edge is source->target.
            rel_type = _PASSIVE_REL_VOCAB[raw_type]
            a_ent, b_ent = trimmed[tgt_idx], trimmed[src_idx]
        else:
            # Unknown / free-text label — do NOT invent a type.  The pair keeps
            # its plain co-occurrence edge, generated elsewhere.
            continue

        if not _is_compatible_relationship(rel_type, a_ent, b_ent):
            # Structural validation is independent of the model's claim.  Do
            # not downgrade invalid pairs to co-occurrence: the pair may be
            # spurious even though both entities appeared on the page.
            continue

        a_id = a_ent.get("id")
        b_id = b_ent.get("id")
        if not a_id or not b_id or a_id == b_id:
            continue

        confidence = _clamp_confidence(rel.get("confidence"))
        key = (str(a_id), str(b_id), rel_type)
        if key in seen:
            if confidence > seen[key]:
                seen[key] = confidence
            continue
        seen[key] = confidence

    for (a_id, b_id, rel_type), confidence in list(seen.items())[:max_relationships]:
        out.append(
            {
                "entity_a_id": a_id,
                "entity_b_id": b_id,
                "relationship_type": rel_type,
                "confidence": confidence,
            }
        )
    return out


def _page_entities_from_result(result) -> list[dict]:
    """Pair a page's DB entity ids with their NormalizedEntity metadata.

    `result.entity_ids` and `result.entities` are populated in lock-step by the
    pipeline for a given page (same filter/order), so index i lines up.
    """
    ids = getattr(result, "entity_ids", None) or []
    ents = getattr(result, "entities", None) or []
    out: list[dict] = []
    for eid, ent in zip(ids, ents):
        if eid is None:
            continue
        out.append(
            {
                "id": eid,
                "type": getattr(ent, "entity_type", "") or "",
                "value": getattr(ent, "value", "") or "",
                "confidence": float(getattr(ent, "confidence", 0.0) or 0.0),
            }
        )
    return out


async def extract_relationships_from_results(
    results: list,
    page_text_by_url: dict[str, str],
    page_id_by_url: Optional[dict[str, Any]],
    llm,
    *,
    max_rel_pages: int = 10,
    max_concurrent: int = 3,
) -> list[dict]:
    """
    Orchestrate the relationship pass across an investigation's pages.

    Only the top ``max_rel_pages`` pages (by extracted-entity count) get an LLM
    relationship call — this caps LLM spend per investigation exactly like the
    entity-extraction page cap.  Pages with fewer than two entities are skipped
    outright.  Returns a flat list of relationship-row dicts, each including a
    ``source_page_id`` (may be None).  Never raises.
    """
    if llm is None or not results or max_rel_pages <= 0:
        return []

    # Rank pages by how many entities they yielded — the most entity-dense
    # pages are where typed relationships are most likely to exist.
    candidates = []
    for result in results:
        page_entities = _page_entities_from_result(result)
        if len(page_entities) >= 2:
            candidates.append((result.page_url, page_entities))
    candidates.sort(key=lambda c: len(c[1]), reverse=True)
    candidates = candidates[:max_rel_pages]
    if not candidates:
        return []

    page_id_by_url = page_id_by_url or {}
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _run(url: str, page_entities: list[dict]) -> list[dict]:
        text = page_text_by_url.get(url, "")
        if not text:
            return []
        async with semaphore:
            try:
                rels = await extract_relationships_for_page(text, page_entities, llm)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Relationship extraction failed for %s: %s", url, exc)
                return []
        source_page_id = page_id_by_url.get(url)
        for r in rels:
            r["source_page_id"] = source_page_id
        return rels

    gathered = await asyncio.gather(
        *[_run(url, ents) for url, ents in candidates]
    )
    flat: list[dict] = [r for page_rels in gathered for r in page_rels]
    if flat:
        logger.info(
            "Relationship extraction: %d typed relationships across %d pages",
            len(flat),
            len(candidates),
        )
    return flat
