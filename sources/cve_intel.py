"""sources/cve_intel.py — unified vulnerability-intelligence fusion for CVEs.

Fuses the four free CVE feeds into one view + a persisted derived priority signal:
  * NVD 2.0    (CVSS score/severity/vector/CWEs)  — from sources/nvd.py
  * CISA KEV   (known-exploited, ransomware use)  — from sources/cisa.py
  * FIRST EPSS (exploitation probability)         — sources/epss.py  (net-new)
  * Exploit-DB (public-exploit exists + EDB-ID)   — sources/exploitdb.py (net-new)

**Not a second CVE path.** This CONSUMES the NVD + KEV results already produced by
``enrichment.py::_enrich_new_sources`` (so NVD/KEV run exactly once, behavior
unchanged) and only adds EPSS + Exploit-DB, then joins everything on the CVE id. It
does not re-fetch NVD/KEV.

The derived CVE-priority signal is stored as a label set on the CVE ``Entity`` via
``corroborating_sources`` (the reputation-module write-back pattern; ranking reads
the ``source_count`` column, not these tags, so they don't inflate corroboration).
It is a stored derived value (not recompute-on-read) that P1.6 ranking / P5 triage
consume. Every rendered field is run through the ``hygiene`` choke point.

Graceful degradation: any missing feed disables only its own contribution to the
signal; the fused view never crashes.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

import hygiene
from sources.enrichment_allowlist import (
    get_enrichment_allowlist,
    is_enrichment_source_enabled,
)
from sources.epss import enrich_epss
from sources.exploitdb import enrich_exploitdb

logger = logging.getLogger(__name__)

# The four feeds the fused view is built from. Under a
# VOIDACCESS_ENRICHMENT_SOURCES allowlist some may be off; the fused view then
# says so instead of presenting a partial signal as complete.
_FUSION_SOURCES = ("nvd", "cisa_kev", "epss", "exploitdb")


def _disabled_signals() -> list[str]:
    """Fusion sources switched off by the allowlist ([] when it is unset)."""
    if get_enrichment_allowlist() is None:
        return []
    return [s for s in _FUSION_SOURCES if not is_enrichment_source_enabled(s)]


_CVE_ENTITY_TYPES = {"CVE_NUMBER", "CVE"}


def _is_cve_entity(e: dict) -> bool:
    return (e.get("entity_type") or e.get("type") or "").upper() in _CVE_ENTITY_TYPES


def _cve_key(value: str) -> str:
    return (value or "").strip().upper()


def _by_cve(results: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in results or []:
        cve = _cve_key(r.get("entity_value") or r.get("cve") or "")
        if cve:
            out.setdefault(cve, r)
    return out


# --------------------------------------------------------------------------- #
# Derived priority signal (documented fusion rule)
# --------------------------------------------------------------------------- #
def _cvss_band(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _epss_band(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 0.5:
        return "high"
    if score >= 0.1:
        return "medium"
    return "low"


def _priority_band(kev: bool, ransomware: bool, exploit_public: bool,
                   cvss: Optional[float], epss: Optional[float]) -> str:
    """Composite ordinal the ranking/triage consumes. Documented rule:

    critical = actively exploited (KEV) AND severe/likely (ransomware use, a public
               exploit, CVSS ≥ 9, or EPSS ≥ 0.5);
    high     = actively exploited, OR EPSS ≥ 0.5, OR CVSS ≥ 9, OR a public exploit on
               a high-severity (CVSS ≥ 7) CVE;
    medium   = a public exploit exists, OR CVSS ≥ 7, OR EPSS ≥ 0.1;
    low      = otherwise.
    """
    c = cvss or 0.0
    e = epss or 0.0
    if kev and (ransomware or exploit_public or c >= 9.0 or e >= 0.5):
        return "critical"
    if kev or e >= 0.5 or c >= 9.0 or (exploit_public and c >= 7.0):
        return "high"
    if exploit_public or c >= 7.0 or e >= 0.1:
        return "medium"
    return "low"


def _derive(record: dict) -> tuple[str, list[str]]:
    """Return (priority_band, tags) — the derived label set stored on the entity."""
    kev = bool(record.get("kev"))
    ransomware = bool(record.get("kev_ransomware_use"))
    exploit_public = bool(record.get("exploit_public"))
    cvss = record.get("cvss_score")
    epss = record.get("epss_score")

    band = _priority_band(kev, ransomware, exploit_public, cvss, epss)
    tags: list[str] = [f"cve_priority:{band}"]
    if kev:
        tags.append("kev")
    if ransomware:
        tags.append("kev_ransomware")
    if exploit_public:
        tags.append("exploit_public")
    cb = _cvss_band(cvss)
    if cb:
        tags.append(f"cvss:{cb}")
    eb = _epss_band(epss)
    if eb:
        tags.append(f"epss:{eb}")
    if record.get("signals_disabled"):
        # Band is a lower bound: it was computed without every feed.
        tags.append("cve_priority_partial")
    return band, tags


def _fuse_one(cve: str, nvd: Optional[dict], kev: Optional[dict],
              epss: Optional[dict], edb: Optional[dict],
              signals_disabled: Optional[list[str]] = None) -> dict:
    nvd = nvd or {}
    kev = kev or {}
    epss = epss or {}
    edb = edb or {}
    record = {
        "cve": cve,
        "cvss_score": nvd.get("base_score"),
        "cvss_severity": nvd.get("base_severity") or "",
        "cvss_vector": nvd.get("vector") or "",
        "cwes": nvd.get("cwes") or [],
        "description": nvd.get("description") or "",
        "kev": bool(kev.get("is_actively_exploited")),
        "kev_date_added": kev.get("date_added") or "",
        "kev_due_date": kev.get("due_date") or "",
        "kev_ransomware_use": bool(kev.get("ransomware_use")),
        "epss_score": epss.get("epss_score"),
        "epss_percentile": epss.get("epss_percentile"),
        "exploit_public": bool(edb.get("exploit_public")),
        "edb_ids": edb.get("edb_ids") or [],
        "signals_disabled": list(signals_disabled or []),
    }
    band, tags = _derive(record)
    record["priority_band"] = band
    record["priority_tags"] = tags
    return record


# --------------------------------------------------------------------------- #
# Entity write-back (reputation-module pattern)
# --------------------------------------------------------------------------- #
def _write_cve_priority(cve_entities: list[dict], fused: dict[str, dict]) -> None:
    """Persist derived tags onto the CVE Entity rows via ``corroborating_sources``.

    Matches each entity by its EXACT stored (entity_type, value) so it works whether
    the CVE was stored as ``CVE_NUMBER`` or ``CVE``. Gated on DATABASE_URL like the
    other reputation write-backs; never raises.
    """
    if not os.getenv("DATABASE_URL") or not cve_entities:
        return
    try:
        from db.models import Entity
        from db.session import get_session

        with get_session() as session:
            for ent in cve_entities:
                value = ent.get("value") or ent.get("entity_value") or ""
                record = fused.get(_cve_key(value))
                if not record:
                    continue
                etype = ent.get("entity_type") or ent.get("type") or ""
                db_entity = session.query(Entity).filter(
                    Entity.entity_type == etype,
                    Entity.value == value,
                ).first()
                if db_entity is None:
                    continue
                existing: list = json.loads(db_entity.corroborating_sources or "[]")
                for tag in record["priority_tags"]:
                    if tag not in existing:
                        existing.append(tag)
                db_entity.corroborating_sources = json.dumps(existing)
            session.commit()
    except Exception as exc:
        logger.warning("cve_intel: entity write-back failed: %s", exc)


# --------------------------------------------------------------------------- #
# Unified page render (replaces the separate NVD + KEV-CVE pages)
# --------------------------------------------------------------------------- #
def _fused_to_pages(fused: dict[str, dict]) -> list[dict]:
    if not fused:
        return []
    header = "Unified CVE intelligence (NVD + CISA KEV + EPSS + Exploit-DB)"
    disabled = next(iter(fused.values())).get("signals_disabled") or []
    if disabled:
        header += f" — not queried (disabled by VOIDACCESS_ENRICHMENT_SOURCES): {', '.join(disabled)}"
    lines = [header + "\n"]
    for cve in sorted(fused):
        r = fused[cve]
        # Keep the CVE id + CWEs in the text so downstream re-extraction still
        # recovers the CVE/CWE entities exactly as the old NVD page did.
        lines.append(f"CVE: {cve}  [priority: {r['priority_band']}]")
        if r["cvss_score"] is not None:
            lines.append(f"  CVSS Base Score: {r['cvss_score']} {r['cvss_severity']}".rstrip())
        if r["cvss_vector"]:
            lines.append(f"  CVSS Vector: {r['cvss_vector']}")
        if r["cwes"]:
            lines.append(f"  Weaknesses: {', '.join(r['cwes'])}")
        if r["kev"]:
            extra = " (ransomware campaign use)" if r["kev_ransomware_use"] else ""
            lines.append(f"  CISA KEV: actively exploited, added {r['kev_date_added']}{extra}")
        if r["epss_score"] is not None:
            lines.append(
                f"  EPSS: {r['epss_score']:.5f} (percentile {r['epss_percentile']:.5f})"
            )
        if r["exploit_public"]:
            lines.append(f"  Exploit-DB: public exploit exists (EDB-ID {', '.join(r['edb_ids'])})")
        if r["description"]:
            # Hygiene choke point: strip victim PII from free text before storage.
            lines.append(f"  Description: {hygiene.strip_pii(r['description'])}")
        lines.append("")
    content = "\n".join(lines)
    return [{
        "link": "https://nvd.nist.gov/vuln",
        "url": "https://nvd.nist.gov/vuln",
        "content": content,
        "text": content,
        "status": 200,
        "source": "cve_intel",
        "via": "cve_intel_fusion",
    }]


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
async def fuse_cve_intelligence(
    query: str,
    entities: list[dict],
    nvd_results: list[dict],
    kev_results: list[dict],
) -> list[dict]:
    """Fuse NVD+KEV (already fetched) with EPSS+Exploit-DB, persist the derived
    priority signal on CVE entities, and return the unified CVE page(s).
    """
    cve_entities = [e for e in (entities or []) if _is_cve_entity(e)]
    nvd_by = _by_cve(nvd_results)
    kev_by = _by_cve(kev_results)

    cve_ids: list[str] = []
    seen: set[str] = set()
    for src in (list(nvd_by), list(kev_by), [e.get("value") or e.get("entity_value") or "" for e in cve_entities]):
        for v in src:
            c = _cve_key(v)
            if c and c not in seen:
                seen.add(c)
                cve_ids.append(c)

    if not cve_ids:
        return []

    disabled = _disabled_signals()
    if len(disabled) == len(_FUSION_SOURCES):
        # Every feed is off: there is nothing to fuse, and a bare "priority: low"
        # would claim knowledge we do not have. Emit nothing, write nothing.
        return []

    # EPSS + Exploit-DB — graceful: a failure yields {} and the signal omits it.
    # A feed switched off by the allowlist is skipped the same way (no call).
    epss_by: dict = {}
    edb_by: dict = {}
    if "epss" not in disabled:
        try:
            epss_by = await enrich_epss(cve_ids)
        except Exception as exc:
            logger.warning("cve_intel: EPSS unavailable: %s", exc)
            epss_by = {}
    if "exploitdb" not in disabled:
        try:
            edb_by = await enrich_exploitdb(cve_ids)
        except Exception as exc:
            logger.warning("cve_intel: Exploit-DB unavailable: %s", exc)
            edb_by = {}

    fused = {
        cve: _fuse_one(cve, nvd_by.get(cve), kev_by.get(cve), epss_by.get(cve), edb_by.get(cve),
                       disabled)
        for cve in cve_ids
    }

    _write_cve_priority(cve_entities, fused)
    return _fused_to_pages(fused)
