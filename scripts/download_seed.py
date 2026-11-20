"""
Download threat-intel seed data at Docker build time (or locally).

Uses ssl=False connector intentionally for sources with certificate issues.
Pass ABUSECH_API_KEY for MalwareBazaar / ThreatFox API bulk (see .env.example).
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import sys
from datetime import datetime
from typing import Any

import aiohttp

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_OUT = os.path.normpath(os.path.join(_SCRIPT_DIR, "..", "data", "seed_data.json.gz"))
SEED_OUTPUT = os.environ.get("SEED_OUTPUT", _DEFAULT_OUT)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"


def _abusech_headers() -> dict[str, str]:
    key = (os.environ.get("ABUSECH_API_KEY") or "").strip()
    return {"Auth-Key": key} if key else {}


def _base_headers() -> dict[str, str]:
    return {"User-Agent": USER_AGENT}


def _normalize_victim(v: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": "ransomware_live",
        "type": "ransomware_victim",
        "threat_actor": (
            v.get("group", "")
            or v.get("gang", "")
            or v.get("group_name", "")
            or v.get("name", "")
            or ""
        ).strip(),
        "victim_name": (
            v.get("post_title", "")
            or v.get("victim", "")
            or v.get("name", "")
            or v.get("company", "")
            or ""
        ).strip(),
        "victim_domain": (
            v.get("website", "")
            or v.get("domain", "")
            or v.get("url", "")
            or ""
        ).strip(),
        "country": (v.get("country", "") or "").strip(),
        "sector": (
            v.get("activity", "")
            or v.get("sector", "")
            or v.get("industry", "")
            or ""
        ).strip(),
        "published": (
            v.get("published", "")
            or v.get("date", "")
            or v.get("timestamp", "")
            or ""
        ),
        "description": str(v.get("description", ""))[:500],
    }


def _normalize_ransomware_victims_for_import(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Shape expected by import_seed.import_ransomware_victims."""
    out: list[dict[str, Any]] = []
    for v in raw:
        out.append(
            {
                "threat_actor": v.get("threat_actor", ""),
                "victim_name": v.get("victim_name", ""),
                "sector": v.get("sector", ""),
            }
        )
    return out


def _normalize_threatfox_ioc(ioc: dict[str, Any]) -> dict[str, Any]:
    conf = ioc.get("confidence_level")
    conf_f = float(conf) / 100.0 if conf is not None else float(ioc.get("confidence", 0.75))
    tags = ioc.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.replace("\n", ",").split(",") if t.strip()]
    elif not isinstance(tags, list):
        tags = []
    val = (ioc.get("ioc") or ioc.get("ioc_value") or "").strip()
    return {
        "source": "threatfox",
        "ioc_type": ioc.get("ioc_type", ""),
        "value": val,
        "malware": ioc.get("malware_printable", "") or ioc.get("malware", "") or "",
        "confidence": conf_f,
        "tags": tags,
    }


def _normalize_mb_sample(s: dict[str, Any]) -> dict[str, Any]:
    tags = s.get("tags") or []
    if not isinstance(tags, list):
        tags = []
    return {
        "source": "malwarebazaar",
        "type": "malware_sample",
        "sha256": s.get("sha256_hash", ""),
        "malware_family": (s.get("signature", "") or "").strip(),
        "file_type": s.get("file_type", ""),
        "tags": tags,
        "first_seen": s.get("first_seen", ""),
        "reporter": s.get("reporter", ""),
    }


def _merge_ransomware_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Dedupe by (threat_actor, victim_name) lowercase."""
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for r in rows:
        ta = (r.get("threat_actor") or "").strip().lower()
        vn = (r.get("victim_name") or "").strip().lower()
        key = (ta, vn)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


async def fetch_ransomware_live() -> list[dict[str, Any]]:
    """Fetch ransomware victims with multiple endpoint fallbacks."""
    endpoints: list[tuple[str, str]] = [
        ("GET", "https://api.ransomware.live/v2/victims"),
        ("GET", "https://api.ransomware.live/v1/victims"),
        ("GET", "https://api.ransomware.live/v2/recentvictims"),
        ("GET", "https://api.ransomware.live/recentvictims"),
        ("GET", "https://api.ransomware.live/v2/groups"),
    ]

    api_rows: list[dict[str, Any]] = []

    connector = aiohttp.TCPConnector(ssl=False)
    headers = {**_base_headers()}
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        for _method, url in endpoints:
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=30),
                    allow_redirects=True,
                ) as resp:
                    ctype = (resp.headers.get("Content-Type") or "").lower()
                    if resp.status != 200:
                        print(f"Ransomware.live: {url} returned {resp.status}")
                        continue
                    if "html" in ctype:
                        print(f"Ransomware.live: {url} returned HTML, skipping")
                        continue
                    try:
                        data = await resp.json(content_type=None)
                    except Exception as e:
                        print(f"Ransomware.live: {url} JSON error: {e}")
                        continue

                    victims: list[Any]
                    if isinstance(data, list):
                        victims = data
                    elif isinstance(data, dict):
                        victims = data.get("data", data.get("victims", []))
                        if isinstance(victims, dict):
                            victims = list(victims.values())
                        if not victims and data.get("group"):
                            victims = [data]
                    else:
                        continue

                    if not victims:
                        continue
                    norm = [_normalize_victim(v) for v in victims if isinstance(v, dict) and v]
                    if not norm:
                        continue
                    print(f"Ransomware.live: {url} -> {len(norm)} records")
                    api_rows = _normalize_ransomware_victims_for_import(norm)
                    break
            except Exception as e:
                print(f"Ransomware.live: {url} failed: {e}")
                continue

    if len(api_rows) >= 2000:
        return api_rows

    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector, headers=_base_headers()) as session:
            async with session.get(
                "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if isinstance(data, list):
                        norm = [_normalize_victim(v) for v in data if isinstance(v, dict)]
                        gh = _normalize_ransomware_victims_for_import(norm)
                        print(f"Ransomware.live (GitHub supplement): {len(gh)} records")
                        merged = _merge_ransomware_rows(api_rows + gh)
                        print(f"Ransomware.live merged: {len(merged)} records")
                        return merged
    except Exception as e:
        print(f"Ransomware.live GitHub supplement failed: {e}")

    return api_rows


async def fetch_threatfox_bulk() -> list[dict[str, Any]]:
    """Fetch maximum ThreatFox IOCs (API bulk, then per-family search)."""
    results: list[dict[str, Any]] = []
    connector = aiohttp.TCPConnector(ssl=False)
    merge_headers = {**_base_headers(), **_abusech_headers()}

    async with aiohttp.ClientSession(connector=connector, headers=merge_headers) as session:
        try:
            payload = {"query": "get_iocs", "days": 180}
            async with session.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=120),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if data.get("query_status") == "ok":
                        iocs = data.get("data", [])
                        for ioc in iocs:
                            if isinstance(ioc, dict):
                                results.append(_normalize_threatfox_ioc(ioc))
                        print(f"ThreatFox bulk (180d): {len(results)} IOCs")
                    else:
                        print(f"ThreatFox bulk: query_status={data.get('query_status')}")
                else:
                    print(f"ThreatFox bulk: HTTP {resp.status}")
        except Exception as e:
            print(f"ThreatFox bulk failed: {e}")

        if not results:
            TOP_FAMILIES = [
                "LockBit",
                "BlackCat",
                "Conti",
                "REvil",
                "Emotet",
                "Cobalt Strike",
                "Qakbot",
                "IcedID",
                "AgentTesla",
                "RedLine",
                "Raccoon",
                "Vidar",
                "FormBook",
                "AsyncRAT",
                "NjRAT",
                "Remcos",
                "DarkComet",
                "QuasarRAT",
                "XWorm",
                "DCRat",
            ]
            for family in TOP_FAMILIES:
                try:
                    payload = {"query": "search_ioc", "search_term": family}
                    async with session.post(
                        "https://threatfox-api.abuse.ch/api/v1/",
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as resp:
                        if resp.status != 200:
                            continue
                        data = await resp.json(content_type=None)
                        if data.get("query_status") == "ok":
                            for ioc in data.get("data", []):
                                if isinstance(ioc, dict):
                                    results.append(_normalize_threatfox_ioc(ioc))
                            print(f"ThreatFox search [{family}]: +{len(data.get('data', []))} IOCs")
                except Exception as e:
                    print(f"ThreatFox {family} failed: {e}")

    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for ioc in results:
        key = ioc.get("value", "")
        if key and key not in seen:
            seen.add(key)
            deduped.append(ioc)

    print(f"ThreatFox total (deduped): {len(deduped)} IOCs")
    return deduped


TOP_MB_TAGS = [
    "LockBit",
    "BlackCat",
    "Cobalt Strike",
    "Emotet",
    "Qakbot",
    "RedLine",
    "AgentTesla",
    "FormBook",
    "AsyncRAT",
    "NjRAT",
    "Remcos",
    "IcedID",
    "Vidar",
    "Raccoon",
    "XWorm",
    "ransomware",
    "stealer",
    "loader",
    "dropper",
    "backdoor",
]


async def fetch_malwarebazaar_expanded() -> list[dict[str, Any]]:
    """Fetch MalwareBazaar with expanded coverage across top families."""
    results: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()
    connector = aiohttp.TCPConnector(ssl=False)
    merge_headers = {**_base_headers(), **_abusech_headers()}

    async with aiohttp.ClientSession(connector=connector, headers=merge_headers) as session:
        try:
            form = {"query": "get_recent", "selector": "time", "limit": "1000"}
            async with session.post(
                "https://mb-api.abuse.ch/api/v1/",
                data=form,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if data.get("query_status") == "ok":
                        for s in data.get("data", []):
                            if not isinstance(s, dict):
                                continue
                            h = s.get("sha256_hash", "")
                            if h and h not in seen_hashes:
                                seen_hashes.add(h)
                                results.append(_normalize_mb_sample(s))
                        print(f"MalwareBazaar recent: {len(results)} samples")
                    else:
                        print(f"MalwareBazaar recent: query_status={data.get('query_status')}")
                else:
                    print(f"MalwareBazaar recent: HTTP {resp.status}")
        except Exception as e:
            print(f"MalwareBazaar recent failed: {e}")

        for tag in TOP_MB_TAGS:
            try:
                form = {"query": "get_taginfo", "tag": tag, "limit": "500"}
                async with session.post(
                    "https://mb-api.abuse.ch/api/v1/",
                    data=form,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json(content_type=None)
                    if data.get("query_status") != "ok":
                        continue
                    new = 0
                    for s in data.get("data", []):
                        if not isinstance(s, dict):
                            continue
                        h = s.get("sha256_hash", "")
                        if h and h not in seen_hashes:
                            seen_hashes.add(h)
                            results.append(_normalize_mb_sample(s))
                            new += 1
                    if new > 0:
                        print(f"MalwareBazaar [{tag}]: +{new} samples")
            except Exception as e:
                print(f"MalwareBazaar [{tag}] failed: {e}")

    print(f"MalwareBazaar total: {len(results)} samples")
    return results


async def fetch_otx_top_pulses(api_key: str) -> list[dict[str, Any]]:
    """Fetch subscribed OTX pulses (metadata for seed import)."""
    key = (api_key or "").strip()
    if not key:
        print("OTX: No API key set")
        return []

    connector = aiohttp.TCPConnector(ssl=True)
    headers = {**_base_headers(), "X-OTX-API-KEY": key}
    out: list[dict[str, Any]] = []

    try:
        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            for page in range(1, 8):
                url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
                params = {"limit": 100, "page": page}
                async with session.get(
                    url,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=45),
                ) as resp:
                    if resp.status != 200:
                        print(f"OTX page {page}: HTTP {resp.status}")
                        break
                    data = await resp.json(content_type=None)
                    results = data.get("results", [])
                    if not results:
                        break
                    for p in results:
                        if not isinstance(p, dict):
                            continue
                        out.append(
                            {
                                "source": "otx",
                                "pulse_name": (p.get("name") or "").strip(),
                                "description": ((p.get("description") or ""))[:1500],
                                "tags": p.get("tags") or [],
                                "malware_families": p.get("malware_families") or [],
                            }
                        )
                    print(f"OTX page {page}: {len(results)} pulses")
                    if len(results) < 100:
                        break
    except Exception as e:
        print(f"OTX failed: {e}")

    print(f"OTX total: {len(out)} pulse records")
    return out


# malware.json was removed upstream; mitre-malware is the large malware cluster list
MISP_GALAXY_URLS = [
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/ransomware.json",
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-malware.json",
]


async def fetch_misp_galaxy_actors() -> list[dict[str, Any]]:
    """
    Threat actor / malware entries from MISP galaxy (public GitHub).
    """
    results: list[dict[str, Any]] = []
    connector = aiohttp.TCPConnector(ssl=False)

    async with aiohttp.ClientSession(connector=connector, headers=_base_headers()) as session:
        for url in MISP_GALAXY_URLS:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                    if resp.status != 200:
                        print(f"MISP Galaxy {url}: HTTP {resp.status}")
                        continue
                    data = await resp.json(content_type=None)
                    galaxy_type = data.get("type", "unknown")
                    values = data.get("values", [])
                    if not isinstance(values, list):
                        continue

                    type_map = {
                        "ransomware": "MALWARE",
                        "threat-actor": "THREAT_ACTOR",
                        "malware": "MALWARE",
                        "mitre-malware": "MALWARE",
                    }
                    entity_type = type_map.get(str(galaxy_type).lower(), "THREAT_ACTOR")

                    for entry in values:
                        if not isinstance(entry, dict):
                            continue
                        name = (entry.get("value") or "").strip()
                        if not name or len(name) < 3:
                            continue
                        meta = entry.get("meta") or {}
                        aliases = meta.get("synonyms", []) if isinstance(meta, dict) else []
                        if not isinstance(aliases, list):
                            aliases = []
                        description = (entry.get("description") or "")[:500]
                        results.append(
                            {
                                "source": "misp_galaxy",
                                "type": "threat_intel",
                                "entity_type": entity_type,
                                "name": name,
                                "aliases": aliases,
                                "description": description,
                                "galaxy_type": galaxy_type,
                            }
                        )

                    print(f"MISP Galaxy [{galaxy_type}]: {len(values)} entries")
            except Exception as e:
                print(f"MISP Galaxy {url} failed: {e}")

    seen_misp: set[tuple[str, str]] = set()
    deduped_misp: list[dict[str, Any]] = []
    for r in results:
        name = (r.get("name") or "").strip().lower()
        et = str(r.get("entity_type", ""))
        key = (name, et)
        if not name or key in seen_misp:
            continue
        seen_misp.add(key)
        deduped_misp.append(r)

    print(f"MISP Galaxy total: {len(deduped_misp)} entries (deduped)")
    return deduped_misp


async def main() -> None:
    print("VoidAccess Seed Download")
    out_dir = os.path.dirname(SEED_OUTPUT)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    otx_key = (os.environ.get("OTX_API_KEY") or "").strip()

    ransomware, threatfox, malwarebazaar, otx, misp = await asyncio.gather(
        fetch_ransomware_live(),
        fetch_threatfox_bulk(),
        fetch_malwarebazaar_expanded(),
        fetch_otx_top_pulses(otx_key),
        fetch_misp_galaxy_actors(),
        return_exceptions=True,
    )

    def _list_result(x: Any, label: str) -> list[Any]:
        if isinstance(x, list):
            return x
        print(f"{label}: gather error: {x!r}")
        return []

    seed_data: dict[str, Any] = {
        "generated_at": datetime.utcnow().isoformat(),
        "ransomware_victims": _list_result(ransomware, "ransomware"),
        "threatfox_iocs": _list_result(threatfox, "threatfox"),
        "malwarebazaar_samples": _list_result(malwarebazaar, "malwarebazaar"),
        "otx_pulses": _list_result(otx, "otx"),
        "misp_galaxy": _list_result(misp, "misp"),
    }

    list_keys = (
        "ransomware_victims",
        "threatfox_iocs",
        "malwarebazaar_samples",
        "otx_pulses",
        "misp_galaxy",
    )
    total = sum(len(seed_data[k]) for k in list_keys)
    print(f"Total records: {total}")

    raw = json.dumps(seed_data, ensure_ascii=False).encode("utf-8")
    with gzip.open(SEED_OUTPUT, "wb", compresslevel=9) as f:
        f.write(raw)

    size_mb = os.path.getsize(SEED_OUTPUT) / (1024 * 1024)
    print(f"Compressed size: {size_mb:.2f} MB")
    print(f"Wrote {SEED_OUTPUT}")
    print("Done.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
