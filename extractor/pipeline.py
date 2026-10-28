"""
extractor/pipeline.py — Pipeline orchestrator for entity extraction.

Single entry point that the rest of the system calls.  Runs:
    1. Regex extraction  (extractor/regex_patterns.py)
    2. NER extraction    (extractor/ner.py)
    3. LLM extraction    (extractor/llm_extract.py)  — optional
    4. Normalisation     (extractor/normalizer.py)
    5. DB persistence    (extractor/normalizer.merge_with_db)

Public interface
----------------
async extract_entities_from_page(...)   → ExtractionResult
async extract_entities_from_pages(...)  → list[ExtractionResult]

ExtractionResult is a dataclass exported through extractor/__init__.py.
"""

from __future__ import annotations

import asyncio
import html
import logging
from dataclasses import dataclass, field
from typing import Any, Optional
import uuid

from extractor.regex_patterns import extract_all as _regex_extract_all
from extractor.ner import extract_named_entities as _ner_extract
from extractor.llm_extract import extract_with_llm as _llm_extract
from extractor import confidence as _conf
from extractor.software_suppression import (
    suppress_cpe_matched_organizations as _suppress_cpe_orgs,
)
from extractor.normalizer import (
    normalize_entities as _normalize,
    merge_with_db as _merge_db,
    NormalizedEntity,
    resolve_entity_type_conflicts as _resolve_conflicts,
    _REGEX_TYPES as _HIGH_CONFIDENCE_REGEX_TYPES,
    canonicalize_entity_value as _canonicalize_entity_value,
)

logger = logging.getLogger(__name__)


_RELATIONSHIP_TYPE_ALIASES: dict[str, frozenset[str]] = {
    "CVE": frozenset({"CVE", "CVE_NUMBER"}),
    "CVE_NUMBER": frozenset({"CVE", "CVE_NUMBER"}),
    "THREAT_ACTOR": frozenset({"THREAT_ACTOR", "THREAT_ACTOR_HANDLE"}),
    "THREAT_ACTOR_HANDLE": frozenset({"THREAT_ACTOR", "THREAT_ACTOR_HANDLE"}),
    "MALWARE": frozenset({"MALWARE", "MALWARE_FAMILY"}),
    "MALWARE_FAMILY": frozenset({"MALWARE", "MALWARE_FAMILY"}),
    "RANSOMWARE": frozenset({"RANSOMWARE", "RANSOMWARE_GROUP"}),
    "RANSOMWARE_GROUP": frozenset({"RANSOMWARE", "RANSOMWARE_GROUP"}),
}


def _relationship_entity_keys(entity_type: str, value: str) -> list[tuple[str, str]]:
    """Return exact and canonical keys used to match raw claims to entities."""
    normalized_type = str(entity_type or "").upper().strip()
    raw_value = str(value or "").strip()
    if not normalized_type or not raw_value:
        return []
    values = [raw_value.casefold()]
    try:
        canonical = _canonicalize_entity_value(normalized_type, raw_value)
    except Exception:
        canonical = raw_value
    if canonical and canonical.casefold() not in values:
        values.append(canonical.casefold())
    types = _RELATIONSHIP_TYPE_ALIASES.get(
        normalized_type, frozenset({normalized_type})
    )
    return [(candidate_type, candidate_value) for candidate_type in types for candidate_value in values]


def _resolve_dependency_relationship_endpoint(
    page_entities: dict[tuple[str, str], tuple[Any, Any]],
    all_entities: dict[tuple[str, str], tuple[Any, Any]],
    entity_type: str,
    value: str,
) -> Optional[tuple[Any, Any]]:
    """Resolve a raw claim endpoint to a validated entity and DB id.

    Page-local attribution is preferred for provenance, but normalized entity
    conflict resolution can legitimately retain the winning entity on a
    different page.  The global index is the fallback that preserves the claim
    without weakening the validated-entity gate.
    """
    keys = _relationship_entity_keys(entity_type, value)
    for index in (page_entities, all_entities):
        for key in keys:
            pair = index.get(key)
            if pair is not None:
                return pair
    return None

PER_TYPE_CAPS = {
    "ORGANIZATION_NAME": 50,
    "PERSON_NAME": 30,
    "LOCATION": 20,
    "THREAT_ACTOR_HANDLE": 80,
    # v1.7 MED-3: DATE entities from RSS changelogs and GitHub commit
    # timestamps dominated one run (85/182 entities).  A hard sub-cap keeps
    # genuinely relevant dates (ransomware leak announcement, CVE publication)
    # while suppressing changelog/commit noise.  20 dates per investigation is
    # far more than any analyst needs; the global entity_cap (400) handles
    # the ceiling for all types combined.
    "DATE": 20,
}

# ---------------------------------------------------------------------------
# LLM-extraction page selection
# ---------------------------------------------------------------------------
#
# `extract_entities_from_pages` is invoked on 15-22 pages per investigation
# and each page is chunked into ~3 LLM calls, yielding 45-66 LLM calls per
# investigation.  That's expensive.  We pre-score the pages and only run the
# LLM tier on the top `max_llm_pages` of them.
#
# Score components (higher = LLM adds more value):
#   - low regex entity count (< 3 entities)        +10.0  (LLM can fill gaps)
#   - text content length 500+ chars                up to +5.0
#   - source_type in {tor, onion} or .onion URL     +5.0  (dark-web specific)
#   - tie-breaker: text length / 1000              up to +1.0
#
# Pages with >= `_SKIP_LLM_THRESHOLD` high-confidence regex IOCs are
# already well-covered and get a strong negative score so they are never
# selected.  This implements step (a) of the optimisation brief.

_SKIP_LLM_THRESHOLD = 5  # high-confidence regex IOCs above which we skip LLM
_LLM_SKIP_PENALTY = -1000.0

# LLM tiers adds value for these entity types specifically:
# THREAT_ACTOR_HANDLE, MALWARE_FAMILY, DATE, ORGANIZATION_NAME (filtered),
# MITRE_TECHNIQUE, BTC/XMR/ETH wallets, file hashes.  The regex/NER tiers
# are weak for THREAT_ACTOR_HANDLE without @-prefix, MALWARE_FAMILY outside
# the dictionary, and DATE in informal contexts — so prioritising pages
# with low existing coverage maximises what LLM adds.


def _score_pages_for_llm(
    pages: list[dict],
    max_llm_pages: int,
) -> set[str]:
    """
    Return the set of page URLs that should get LLM extraction.

    Selection rules:
      1. Skip pages with >= 5 high-confidence regex IOCs (already covered).
      2. Prioritise pages with low regex coverage, long text, tor/onion source.
      3. Cap at `max_llm_pages` pages.

    Synchronous — runs once at the start of `extract_entities_from_pages`
    before the per-page async fan-out.  Regex is fast enough that doing
    it twice (once here for scoring, once inside each page's
    `extract_entities_from_page`) is cheaper than threading the result
    through the call graph.
    """
    if not pages or max_llm_pages <= 0:
        return set()

    scored: list[tuple[float, str]] = []
    for page in pages:
        url = (page.get("url") or "").strip()
        if not url:
            continue
        text = (
            page.get("text")
            or page.get("content")
            or page.get("cleaned_text")
            or ""
        )
        source_type = (page.get("source_type") or "").lower()
        is_tor_source = (
            source_type in ("tor", "onion")
            or ".onion" in url.lower()
        )

        # Cheap regex-only pass for the score
        try:
            regex_entities = _regex_extract_all(text)
        except Exception:
            regex_entities = {}

        high_conf_count = sum(
            len(v)
            for k, v in regex_entities.items()
            if k in _HIGH_CONFIDENCE_REGEX_TYPES
        )
        if high_conf_count >= _SKIP_LLM_THRESHOLD:
            logger.debug(
                "LLM-skip: %s has %d high-conf regex IOCs",
                url, high_conf_count,
            )
            continue

        total_count = sum(len(v) for v in regex_entities.values())
        text_len = len(text)

        score = 0.0
        if total_count < 3:
            score += 10.0
        if text_len > 500:
            score += min(text_len / 200.0, 5.0)
        if is_tor_source:
            score += 5.0
        # Tie-breaker: prefer longer pages (more LLM value per call)
        score += min(text_len / 1000.0, 1.0)

        scored.append((score, url))

    scored.sort(key=lambda pair: -pair[0])
    selected = {url for _, url in scored[:max_llm_pages]}
    logger.info(
        "LLM page selection: %d/%d pages selected (cap=%d)",
        len(selected), len(pages), max_llm_pages,
    )
    return selected

_ENTITY_TYPE_PRIORITY = {
    1: frozenset({"CVE", "CVE_NUMBER", "IP_ADDRESS", "IPV6_ADDRESS", "FILE_HASH", "FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256", "FILE_HASH_SHA512", "ONION_URL", "DOMAIN", "DOMAIN_NAME"}),
    2: frozenset({"MALWARE_FAMILY", "RANSOMWARE_GROUP", "THREAT_ACTOR", "THREAT_ACTOR_HANDLE"}),
    3: frozenset({"BITCOIN_ADDRESS", "MONERO_ADDRESS", "ETHEREUM_ADDRESS", "WALLET"}),
    4: frozenset({"EMAIL_ADDRESS", "PGP_KEY_BLOCK"}),
    5: frozenset({"ORGANIZATION_NAME", "PERSON_NAME"}),
}


def _type_priority(entity_type: str) -> int:
    for priority, types in _ENTITY_TYPE_PRIORITY.items():
        if entity_type in types:
            return priority
    return 99


def _clean_text_for_extraction(text: str) -> str:
    """Decode HTML entities before regex/NER/LLM extraction sees page text."""
    if not text:
        return ""
    return html.unescape(text)

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class ExtractionResult:
    page_url: str
    entity_count: int
    entities_by_type: dict[str, int] = field(default_factory=dict)
    entity_ids: list = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    entities: list = field(default_factory=list)

    def __iter__(self):
        return iter(self.entities)

    def __len__(self) -> int:
        return len(self.entities)

    def __getitem__(self, index):
        return self.entities[index]


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


async def extract_entities_from_page(
    page_text: str,
    page_url: str,
    page_id: Optional[int] = None,
    investigation_id: Optional[uuid.UUID] = None,
    llm=None,
    run_llm_extraction: bool = False,
    disable_cache: Optional[bool] = None,
    persist: bool = True,
    force_skip_llm: bool = False,
    page_title: str = "",
) -> ExtractionResult:
    """
    Run the full extraction pipeline for a single page.

    Each stage is wrapped in its own try/except so a failure in one stage
    never prevents later stages from running.  Non-fatal errors are collected
    in ExtractionResult.errors.

    Set persist=False to skip DB persistence (used when collecting entities
    for batch capping before write).

    `force_skip_llm=True` overrides `run_llm_extraction` for this single
    page — used by `extract_entities_from_pages` after the page-priority
    pre-score decided this page should not get LLM (already well-covered
    by regex, or below the top-N priority cut).
    """
    errors: list[str] = []
    page_text = _clean_text_for_extraction(page_text or "")

    # -----------------------------------------------------------------------
    # Stage 1 — Regex
    # -----------------------------------------------------------------------
    try:
        regex_entities = _regex_extract_all(page_text)
    except Exception as exc:
        logger.error("Regex extraction failed for %s: %s", page_url, exc)
        errors.append(f"regex: {exc}")
        regex_entities = {}

    # -----------------------------------------------------------------------
    # Stage 2 — NER
    # -----------------------------------------------------------------------
    try:
        ner_entities = _ner_extract(page_text)
    except Exception as exc:
        logger.error("NER extraction failed for %s: %s", page_url, exc)
        errors.append(f"ner: {exc}")
        ner_entities = {}

    # Merge regex + NER (regex results take precedence for shared types)
    combined: dict[str, list[str]] = dict(regex_entities)
    for entity_type, values in ner_entities.items():
        if entity_type in combined:
            combined[entity_type] = _dedup(combined[entity_type] + values)
        else:
            combined[entity_type] = list(values)

    # -----------------------------------------------------------------------
    # Stage 3 — LLM (optional)
    #
    # The `force_skip_llm` flag wins over `run_llm_extraction` so the page
    # selector can deterministically drop a page even when the caller
    # requested LLM globally (e.g. cap reached, or already well-covered).
    # -----------------------------------------------------------------------
    if run_llm_extraction and llm is not None and not force_skip_llm:
        try:
            import hashlib
            page_hash = hashlib.sha256(page_text.encode()).hexdigest() if page_text else None
            before_llm = {
                (entity_type, value)
                for entity_type, values in combined.items()
                for value in values
            }
            combined = await _llm_extract(
                page_text, llm, combined, page_hash=page_hash, disable_cache=disable_cache
            )
            llm_overrides = {
                (entity_type, value): "LLM"
                for entity_type, values in combined.items()
                for value in values
                if (entity_type, value) not in before_llm
            }
        except Exception as exc:
            logger.error("LLM extraction failed for %s: %s", page_url, exc)
            errors.append(f"llm: {exc}")
            llm_overrides = {}
    else:
        llm_overrides = {}

    # -----------------------------------------------------------------------
    # Stage 4 — Normalise
    # -----------------------------------------------------------------------
    try:
        normalized = _normalize(
            combined,
            page_url,
            page_id,
            page_text=page_text,
            extraction_method_overrides=llm_overrides,
        )
    except Exception as exc:
        logger.error("Normalization failed for %s: %s", page_url, exc)
        errors.append(f"normalize: {exc}")
        normalized = []

    # Relevance gate (22R-4/22R-5): drop a common word typed as a threat name
    # without a nearby threat cue, and an organisation that is the page's own
    # site or a protocol/CMS/directory brand. Each removal is counted.
    try:
        from extractor.relevance_gate import gate_entities as _gate_entities

        normalized = _gate_entities(normalized, page_text, page_url, page_title or "")
    except Exception as exc:  # pragma: no cover - the gate never raises
        logger.debug("Relevance gate skipped for %s: %s", page_url, exc)

    # Option A suppression happens before either direct or batch persistence.
    # Deterministic rules run in normalization; this bounded async pass adds
    # only partial NVD CPE coverage.
    if persist:
        try:
            normalized, suppressed_count = await _suppress_cpe_orgs(
                normalized,
                {page_url: page_text or ""},
            )
            if suppressed_count:
                logger.info(
                    "Suppressed %d software/product organization candidate(s)",
                    suppressed_count,
                )
        except Exception as exc:
            logger.debug(
                "CPE organization suppression unavailable for %s: %s",
                page_url,
                exc,
            )

    # -----------------------------------------------------------------------
    # Build result (no DB persist yet if persist=False)
    # -----------------------------------------------------------------------
    entities_by_type: dict[str, int] = {}
    for entity in normalized:
        entities_by_type[entity.entity_type] = (
            entities_by_type.get(entity.entity_type, 0) + 1
        )

    if not persist:
        return ExtractionResult(
            page_url=page_url,
            entity_count=len(normalized),
            entities_by_type=entities_by_type,
            entity_ids=[],
            errors=errors,
            entities=normalized,
        )

    # -----------------------------------------------------------------------
    # Stage 5 — DB persist
    # -----------------------------------------------------------------------
    try:
        entity_ids = _merge_db(normalized, investigation_id)
    except Exception as exc:
        logger.error("DB persist failed for %s: %s", page_url, exc)
        errors.append(f"db: {exc}")
        entity_ids = []

    return ExtractionResult(
        page_url=page_url,
        entity_count=len(normalized),
        entities_by_type=entities_by_type,
        entity_ids=entity_ids,
        errors=errors,
    )


async def extract_entities_from_pages(
    pages: list[dict],
    investigation_id: Optional[uuid.UUID] = None,
    llm=None,
    run_llm_extraction: bool = False,
    max_concurrent: int = 5,
    disable_cache: Optional[bool] = None,
    entity_cap: int = 400,
    max_llm_pages: int = 10,
    llm_progress_callback: Optional[Any] = None,
    build_graph_on_complete: bool = True,
) -> list[ExtractionResult]:
    """
    Run extraction concurrently across a list of pages.

    Each page dict must have at least a "url" key.  Content is read from
    "text", "content", or "cleaned_text" keys (first found wins).

    A semaphore limits concurrency to *max_concurrent* simultaneous pages.
    One page failing never blocks others — failures are captured in each
    page's ExtractionResult.errors.

    Before DB persistence, applies entity cap (default 400) ranked by:
    confidence (primary), entity type priority (secondary), occurrence count (tertiary).

    LLM extraction cap
    ------------------
    When `run_llm_extraction` is True and `llm` is provided, the LLM tier
    only runs on up to `max_llm_pages` pages per call.  Pages are scored by
    LLM value (low regex coverage, long text, tor/onion source) so the
    most informative pages get the LLM call budget.  Pages with
    already-strong regex coverage (≥ 5 high-confidence IOCs) are skipped.

    The optional `llm_progress_callback` is an async or sync callable
    invoked after each LLM-extracted page completes:
        callback(page_index_1based, total_llm_pages, page_url)
    Used by the API route to emit SSE progress events.
    """
    # Mirrored pages are one intelligence item.  Preserve all URLs on the
    # canonical record, but extract/persist entities once so corroboration and
    # investigation counts are not inflated by reposts.
    from utils.content_dedup import deduplicate_page_records
    pages = deduplicate_page_records(pages)
    semaphore = asyncio.Semaphore(max_concurrent)

    # -----------------------------------------------------------------------
    # Pre-score pages to decide which ones get LLM extraction.
    # Only runs when LLM is actually available — otherwise every page is
    # already in the regex/NER-only path.
    # -----------------------------------------------------------------------
    if run_llm_extraction and llm is not None and pages:
        llm_selected_urls = _score_pages_for_llm(pages, max_llm_pages)
    else:
        llm_selected_urls = set()

    llm_total = len(llm_selected_urls)
    llm_done_counter = {"n": 0}
    llm_done_lock = asyncio.Lock()

    async def _emit_progress(url: str) -> None:
        if llm_progress_callback is None or llm_total == 0:
            return
        async with llm_done_lock:
            llm_done_counter["n"] += 1
            current = llm_done_counter["n"]
        try:
            cb = llm_progress_callback(current, llm_total, url)
            if asyncio.iscoroutine(cb):
                await cb
        except Exception as exc:
            logger.debug("llm_progress_callback raised (non-fatal): %s", exc)

    async def _process(page: dict) -> ExtractionResult:
        async with semaphore:
            url = page.get("url", "")
            text = (
                page.get("text")
                or page.get("content")
                or page.get("cleaned_text")
                or ""
            )
            # Per-page LLM decision: only run LLM tier if the URL is in the
            # pre-scored selection set.  This caps LLM spend and prioritises
            # the pages where LLM adds the most value.
            page_runs_llm = (
                run_llm_extraction
                and llm is not None
                and url in llm_selected_urls
            )
            try:
                result = await extract_entities_from_page(
                    page_text=text,
                    page_url=url,
                    page_id=page.get("page_id"),
                    investigation_id=investigation_id,
                    llm=llm,
                    run_llm_extraction=run_llm_extraction,
                    disable_cache=disable_cache,
                    persist=False,
                    force_skip_llm=not page_runs_llm,
                    page_title=str(page.get("title") or ""),
                )
            except Exception as exc:
                logger.error("Page processing failed for %s: %s", url, exc)
                return ExtractionResult(
                    page_url=url,
                    entity_count=0,
                    entities_by_type={},
                    entity_ids=[],
                    errors=[str(exc)],
                )

            if page_runs_llm:
                await _emit_progress(url)
            return result

    results = list(await asyncio.gather(*[_process(p) for p in pages]))

    all_normalized: list[NormalizedEntity] = []
    for result in results:
        all_normalized.extend(result.entities)

    if not all_normalized:
        return results

    all_normalized = _resolve_conflicts(all_normalized)

    # Run CPE suppression once across the batch, after conflict resolution and
    # before the entity cap/database merge.  This keeps NVD calls bounded per
    # investigation rather than multiplying them by page count.
    page_text_by_url = {
        str(page.get("url", "") or ""): str(page.get("text", "") or "")
        for page in pages
    }
    try:
        all_normalized, suppressed_count = await _suppress_cpe_orgs(
            all_normalized,
            page_text_by_url,
        )
        if suppressed_count:
            surviving_ids = {id(entity) for entity in all_normalized}
            for result in results:
                result.entities = [
                    entity for entity in result.entities if id(entity) in surviving_ids
                ]
                result.entity_count = len(result.entities)
                result.entities_by_type = {}
                for entity in result.entities:
                    result.entities_by_type[entity.entity_type] = (
                        result.entities_by_type.get(entity.entity_type, 0) + 1
                    )
            logger.info(
                "Suppressed %d software/product organization candidate(s) in batch",
                suppressed_count,
            )
    except Exception as exc:
        logger.debug("Batch CPE organization suppression unavailable: %s", exc)

    if not all_normalized:
        return results

    # -----------------------------------------------------------------------
    # Content safety: drop prohibited entity values before capping/storing.
    # Only text-based types are checked; technical IOCs are never filtered.
    # The actual value is never logged — only type and count.
    # -----------------------------------------------------------------------
    from utils.content_safety import entity_value_is_blocked
    clean_entities: list[NormalizedEntity] = []
    blocked_entity_count = 0
    for _ent in all_normalized:
        if entity_value_is_blocked(_ent.entity_type, _ent.value):
            blocked_entity_count += 1
            logger.debug(
                "Entity value blocked — prohibited content: type=%s",
                _ent.entity_type,
            )
        else:
            clean_entities.append(_ent)
    if blocked_entity_count > 0:
        logger.info(
            "Blocked %d entities for prohibited content",
            blocked_entity_count,
        )
    all_normalized = clean_entities

    capped_entities, original_count = apply_entity_cap(
        all_normalized, cap=entity_cap, investigation_id=investigation_id
    )

    if capped_entities:
        try:
            entity_id_map = _merge_db(capped_entities, investigation_id)
            url_to_ids: dict[str, list] = {}
            # entity_id_map is aligned 1:1 with capped_entities; an entry is
            # None only when that single entity could not be persisted (a
            # collision or per-entity failure never sinks the rest of the
            # batch — see normalizer.merge_with_db).  Skip None so a partial
            # failure doesn't misalign the remaining entity IDs.
            for ent, eid in zip(capped_entities, entity_id_map):
                if eid is None:
                    continue
                if ent.source_url not in url_to_ids:
                    url_to_ids[ent.source_url] = []
                url_to_ids[ent.source_url].append(eid)

            for result in results:
                result.entity_ids = url_to_ids.get(result.page_url, [])
                result.entities = [e for e in capped_entities if e.source_url == result.page_url]
        except Exception as exc:
            logger.error("Batch entity persist failed: %s", exc)

    # -----------------------------------------------------------------------
    # Typed dependency relationships (no-LLM only).
    #
    # The scraper parsed the untruncated ``db_text`` and returned value/type
    # claims.  Resolve those claims against the exact normalized entities that
    # survived conflict resolution and the investigation cap, then persist
    # through the same compatibility-checked relationship writer used by the
    # LLM path.  This is intentionally before graph construction and is never
    # run when an LLM relationship pass is active.
    # -----------------------------------------------------------------------
    if (
        llm is None
        and not run_llm_extraction
        and investigation_id is not None
        and capped_entities
    ):
        try:
            import config as _config  # noqa: PLC0415

            if getattr(_config, "ENABLE_RELATIONSHIP_EXTRACTION", True):
                from db.queries import save_typed_relationships  # noqa: PLC0415
                from db.session import get_session  # noqa: PLC0415
                from extractor.relationship_extract import (  # noqa: PLC0415
                    _is_compatible_relationship,
                )

                by_page: dict[str, dict[tuple[str, str], tuple[Any, Any]]] = {}
                all_entity_keys: dict[tuple[str, str], tuple[Any, Any]] = {}
                for result in results:
                    page_entities: dict[tuple[str, str], tuple[Any, Any]] = {}
                    for ent, entity_id in zip(result.entities, result.entity_ids):
                        if entity_id is None:
                            continue
                        for key in _relationship_entity_keys(
                            str(getattr(ent, "entity_type", "") or ""),
                            str(getattr(ent, "value", "") or ""),
                        ):
                            page_entities[key] = (ent, entity_id)
                            all_entity_keys.setdefault(key, (ent, entity_id))
                    by_page[result.page_url] = page_entities

                # ``result.entities`` is intentionally page-local for the
                # normal graph/report path.  The conflict resolver, however,
                # can retain a validated winner whose source_url differs from
                # the page where a raw dependency claim was generated.  Index
                # every persisted validated entity globally so that attribution
                # differences do not silently delete otherwise valid claims.
                for ent, entity_id in zip(capped_entities, entity_id_map):
                    if entity_id is None:
                        continue
                    for key in _relationship_entity_keys(
                        str(getattr(ent, "entity_type", "") or ""),
                        str(getattr(ent, "value", "") or ""),
                    ):
                        all_entity_keys.setdefault(key, (ent, entity_id))

                dependency_rows: list[dict[str, Any]] = []
                for page in pages:
                    url = page.get("url", "")
                    page_entities = by_page.get(url, {})
                    for claim in page.get("dependency_relationships", []) or []:
                        source_key = (
                            str(claim.get("source_type", "")).upper(),
                            str(claim.get("source_value", "")).strip().casefold(),
                        )
                        target_key = (
                            str(claim.get("target_type", "")).upper(),
                            str(claim.get("target_value", "")).strip().casefold(),
                        )
                        source_pair = _resolve_dependency_relationship_endpoint(
                            page_entities,
                            all_entity_keys,
                            source_key[0],
                            source_key[1],
                        )
                        target_pair = _resolve_dependency_relationship_endpoint(
                            page_entities,
                            all_entity_keys,
                            target_key[0],
                            target_key[1],
                        )
                        if source_pair is None or target_pair is None:
                            continue
                        source_ent, source_id = source_pair
                        target_ent, target_id = target_pair
                        rel_type = str(claim.get("relationship_type", "")).upper()
                        source_data = {
                            "id": source_id,
                            "type": source_ent.entity_type,
                            "value": source_ent.value,
                        }
                        target_data = {
                            "id": target_id,
                            "type": target_ent.entity_type,
                            "value": target_ent.value,
                        }
                        if not _is_compatible_relationship(
                            rel_type, source_data, target_data
                        ):
                            continue
                        dependency_rows.append(
                            {
                                "entity_a_id": source_id,
                                "entity_b_id": target_id,
                                "relationship_type": rel_type,
                                "confidence": claim.get("confidence", 0.85),
                                "source_page_id": page.get("page_id"),
                            }
                        )
                if dependency_rows:
                    with get_session() as _rel_session:
                        inserted = save_typed_relationships(
                            _rel_session, investigation_id, dependency_rows
                        )
                    logger.info(
                        "Dependency typed relationships persisted for %s: %d new (of %d claims)",
                        investigation_id,
                        inserted,
                        len(dependency_rows),
                    )
        except Exception as exc:
            logger.warning(
                "Dependency relationship extraction failed for %s (non-fatal): %s",
                investigation_id,
                exc,
            )

    # -----------------------------------------------------------------------
    # Typed relationship extraction (distinct LLM pass).
    #
    # For pages that yielded entities, ask the LLM which specific typed
    # relationship (if any) connects them, and persist those as
    # EntityRelationship rows BEFORE the graph is built — the graph builder's
    # persisted-relationship pass then picks them up as typed edges alongside
    # the co-occurrence edges it generates itself.  This is additive: pages
    # with no confident typed relationship simply keep their co-occurrence
    # edges.  Bounded by MAX_REL_PAGES_PER_INV (one LLM call per selected
    # page) so it cannot scale unbounded with page count.
    # -----------------------------------------------------------------------
    if (
        run_llm_extraction
        and llm is not None
        and investigation_id is not None
        and capped_entities
    ):
        try:
            import config as _config  # noqa: PLC0415

            if getattr(_config, "ENABLE_RELATIONSHIP_EXTRACTION", True):
                from extractor.relationship_extract import (  # noqa: PLC0415
                    extract_relationships_from_results,
                )
                from db.queries import save_typed_relationships  # noqa: PLC0415
                from db.session import get_session  # noqa: PLC0415

                page_text_by_url: dict[str, str] = {}
                page_id_by_url: dict[str, Any] = {}
                for _p in pages:
                    _url = _p.get("url", "")
                    if not _url:
                        continue
                    page_text_by_url[_url] = (
                        _p.get("text")
                        or _p.get("content")
                        or _p.get("cleaned_text")
                        or ""
                    )
                    page_id_by_url[_url] = _p.get("page_id")

                # Some clearnet/side-source pages are materialized in the DB
                # during entity persistence, after the CLI's initial page-id
                # lookup.  Resolve those URLs again before relationship
                # extraction so provenance is never lost to that ordering.
                missing_urls = [url for url, page_id in page_id_by_url.items() if page_id is None]
                if missing_urls:
                    from db.models import Page  # noqa: PLC0415

                    with get_session() as _page_session:
                        persisted_pages = (
                            _page_session.query(Page)
                            .filter(Page.url.in_(missing_urls), (Page.investigation_id == investigation_id) | Page.investigation_id.is_(None))
                            .all()
                        )
                        for _page in persisted_pages:
                            page_id_by_url[_page.url] = _page.id

                max_rel_pages = int(
                    getattr(_config, "MAX_REL_PAGES_PER_INV", 10) or 10
                )
                typed_rels = await extract_relationships_from_results(
                    results,
                    page_text_by_url,
                    page_id_by_url,
                    llm,
                    max_rel_pages=max_rel_pages,
                )
                if typed_rels:
                    with get_session() as _rel_session:
                        inserted = save_typed_relationships(
                            _rel_session, investigation_id, typed_rels
                        )
                    logger.info(
                        "Typed relationships persisted for %s: %d new (of %d claims)",
                        investigation_id,
                        inserted,
                        len(typed_rels),
                    )
        except Exception as exc:
            logger.warning(
                "Typed relationship extraction failed for %s (non-fatal): %s",
                investigation_id,
                exc,
            )

    if build_graph_on_complete and investigation_id is not None and capped_entities:
        try:
            from graph.builder import (
                build_graph_from_db,
                infer_relationships,
                persist_graph_edges,
            )
            from db.models import Investigation
            from db.session import get_session

            graph = build_graph_from_db(investigation_id=investigation_id)
            nodes_count = graph.number_of_nodes()
            edges_count = graph.number_of_edges()
            logger.info(
                "Graph build completed for %s: nodes=%s edges=%s",
                investigation_id,
                nodes_count,
                edges_count,
            )

            graph = infer_relationships(graph)
            inferred_nodes = graph.number_of_nodes()
            inferred_edges = graph.number_of_edges()
            logger.info(
                "Graph inference completed for %s: nodes=%s edges=%s",
                investigation_id,
                inferred_nodes,
                inferred_edges,
            )

            with get_session() as session:
                persist_result = persist_graph_edges(graph, investigation_id, session)
                logger.info(
                    "Graph edge persistence for %s: %s",
                    investigation_id,
                    persist_result,
                )
                inv = session.get(Investigation, investigation_id)
                if inv is not None:
                    inv.graph_status = "complete"
                    session.commit()
        except Exception as exc:
            logger.warning(
                "Graph build pipeline failed for %s: %s",
                investigation_id,
                exc,
            )

    return results


# ---------------------------------------------------------------------------
# Entity cap logic
# ---------------------------------------------------------------------------

def _occurrence_count(entity: NormalizedEntity, all_entities: list[NormalizedEntity]) -> int:
    """Count how many times this entity value appears across all pages."""
    count = 0
    for other in all_entities:
        if other.entity_type == entity.entity_type and other.value == entity.value:
            count += 1
    return count


def _apply_per_type_caps(
    entities: list[NormalizedEntity],
    caps: dict = PER_TYPE_CAPS,
) -> list[NormalizedEntity]:
    """
    Apply per-type sub-caps before the global cap.

    This prevents high-volume low-specificity entity types (e.g., ORGANIZATION_NAME)
    from crowding out high-value IOCs (FILE_HASH, CVE, MITRE_TECHNIQUE).
    """
    type_counts: dict[str, int] = {}
    result: list[NormalizedEntity] = []

    for entity in entities:
        etype = entity.entity_type
        cap = caps.get(etype, float("inf"))
        count = type_counts.get(etype, 0)
        if count < cap:
            result.append(entity)
            type_counts[etype] = count + 1
        else:
            logger.debug(f"Per-type cap: {etype} capped at {cap}")

    return result


def apply_entity_cap(
    entities: list[NormalizedEntity],
    cap: int = 400,
    investigation_id: Optional[uuid.UUID] = None,
) -> tuple[list[NormalizedEntity], int]:
    """
    Apply quality-based entity filtering and hard cap.

    Steps:
    a) Remove any entity where confidence < 0.80
    b) Apply per-type sub-caps (see _apply_per_type_caps)
    c) Apply per-investigation hard cap of *cap* entities, ranked by:
       - confidence score (primary, descending)
       - entity type priority (secondary, ascending - lower number = higher priority)
       - occurrence count across pages (tertiary, descending)
    d) Log a warning when cap is applied

    Returns: (capped_entities, original_count)
    """
    original_count = len(entities)
    _CONFIDENCE_FLOOR = 0.80

    # Drop placeholder / reserved-range entities (source_quality == 0.0) up front.
    placeholder_count = sum(1 for e in entities if getattr(e, "source_quality", 1.0) == 0.0)
    candidates = [e for e in entities if getattr(e, "source_quality", 1.0) != 0.0]

    # Corroboration + source-quality lift is applied BEFORE the confidence floor,
    # so an entity observed across several independent sources can clear the
    # floor on the strength of that corroboration.  Confidence is already a
    # computed per-entity signal at this point (see extractor.confidence); here
    # we fold in the one signal that isn't knowable per-page — how many distinct
    # sources saw the same value.
    for ent in candidates:
        occ_pages = len({
            e.source_url
            for e in candidates
            if e.entity_type == ent.entity_type and e.value == ent.value
        })
        ent._occurrence = occ_pages
        source_quality = float(getattr(ent, "source_quality", 1.0) or 1.0)
        quality_boost = max(0.0, (source_quality - 0.5) * 0.06)
        _conf.apply_evidence(
            ent,
            _conf.corroboration_boost(occ_pages),
            quality_boost,
        )
        ent.confidence = min(ent.confidence, 0.99)

    # Step a: confidence floor (after corroboration).
    filtered = [e for e in candidates if e.confidence >= _CONFIDENCE_FLOOR]
    removed_confidence = len(candidates) - len(filtered)
    if removed_confidence:
        logger.warning(f"Entity confidence filter removed {removed_confidence} low-confidence entities")
    if placeholder_count:
        logger.info(f"Entity placeholder filter dropped {placeholder_count} reserved-range entities")

    # Step b: per-type sub-caps
    filtered = _apply_per_type_caps(filtered)

    # Step c: sort and cap — source_quality is kept separate and only used
    # as a ranking tie-breaker, not as part of confidence.
    if len(filtered) > cap:
        filtered.sort(key=lambda e: (
            -(e.confidence * (0.85 + 0.15 * float(getattr(e, "source_quality", 1.0) or 1.0))),
            -getattr(e, "source_quality", 1.0),  # higher quality = higher rank
            _type_priority(e.entity_type),
            -e._occurrence,
        ))
        filtered = filtered[:cap]
        logger.warning(
            f"Entity cap applied: {original_count} entities reduced to {len(filtered)} "
            f"for investigation {investigation_id}"
        )

    # Clean up temporary attribute
    for ent in filtered:
        if hasattr(ent, "_occurrence"):
            del ent._occurrence

    return filtered, original_count


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------


def _dedup(values) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result
