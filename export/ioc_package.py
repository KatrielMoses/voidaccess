"""
export/ioc_package.py — Builds a complete IOC package ZIP for an investigation.

A SOC analyst responding to an incident needs every artefact bundled in one
download.  This module produces a single ZIP containing:

  * README.md               — package overview + file index
  * metadata.json           — machine-readable package metadata (TLP, counts, etc.)
  * iocs/hashes.txt         — MD5 / SHA1 / SHA256 grouped by type
  * iocs/ip_addresses.txt   — IPv4 indicators (with defanged comments)
  * iocs/ipv6_addresses.txt — IPv6 indicators
  * iocs/domains.txt        — domain indicators
  * iocs/onion_urls.txt     — .onion URLs
  * iocs/email_addresses.txt — email indicators
  * iocs/urls.txt           — all extracted URLs
  * iocs/crypto_wallets.txt — crypto addresses in COIN:ADDRESS form
  * iocs/credentials.txt    — partially-redacted credentials
  * iocs/cve_identifiers.txt — CVE IDs
  * iocs/mitre_techniques.txt — MITRE ATT&CK technique IDs
  * threat_intel/stix.json  — STIX 2.1 bundle (delegates to export.stix)
  * threat_intel/misp.json  — MISP event JSON (delegates to export.misp)
  * detections/sigma.yml    — all Sigma rules (delegates to export.sigma)
  * detections/yara.yar     — YARA rules (delegates to export.yara_export)
  * detections/snort.rules  — Snort rules (delegates to export.snort_export)
  * detections/suricata.rules — Suricata rules (delegates to export.snort_export)
  * reports/summary.md      — investigation LLM summary
  * reports/entities.csv    — full entity CSV

Public interface
----------------
generate_ioc_package(investigation_id, entities, investigation, session, ...) -> bytes
redact_credential(value) -> str  (exposed for testing)

The function is `async` so it slots into FastAPI handlers without an extra
executor hop, but it does no actual blocking I/O — ZIP construction happens
in-memory via zipfile.ZipFile + io.BytesIO.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import zipfile
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Iterable, Optional

from extractor.identity import entity_canonical_id

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PACKAGE_FORMAT = "voidaccess-ioc-v1"
PACKAGE_VERSION = "2.2.0"  # keep in step with voidaccess_cli.__version__ (tests check it)
SNORT_SID_BASE = 9000001  # 9xxxxxx reserved for VoidAccess-generated rules

# Map extractor upper-case entity types to the per-file bucket they belong to.
_HASH_TYPES = {"FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"}
_IPV4_TYPES = {"IP_ADDRESS"}  # filtered later for IPv6
_DOMAIN_TYPES = {"DOMAIN"}
_ONION_TYPES = {"ONION_URL"}
_EMAIL_TYPES = {"EMAIL_ADDRESS", "EMAIL"}
_URL_TYPES = {"URL", "ONION_URL"}  # ONION_URL appears in both
_CVE_TYPES = {"CVE_NUMBER", "CVE"}
_MITRE_TYPES = {"MITRE_TECHNIQUE"}
_MALWARE_TYPES = {"MALWARE_FAMILY", "RANSOMWARE_GROUP", "MALWARE"}

# Crypto wallet types
_BTC_TYPES = {"BITCOIN_ADDRESS", "BTC_ADDRESS"}
_ETH_TYPES = {"ETHEREUM_ADDRESS", "ETH_ADDRESS"}
_XMR_TYPES = {"MONERO_ADDRESS", "XMR_ADDRESS"}
_WALLET_TYPES = {"CRYPTO_WALLET"} | _BTC_TYPES | _ETH_TYPES | _XMR_TYPES

# Credential-like types
_CREDENTIAL_TYPES = {
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "STRIPE_KEY",
    "JWT_TOKEN",
    "SLACK_TOKEN",
    "GENERIC_API_KEY",
    "API_KEY",
    "PRIVATE_KEY",
}

# Entity type normalisations between DB enum (lower_snake) and extractor (UPPER_SNAKE)
_TYPE_NORMALISATION: dict[str, str] = {
    "ip_address": "IP_ADDRESS",
    "domain": "DOMAIN",
    "email": "EMAIL_ADDRESS",
    "onion_url": "ONION_URL",
    "cve": "CVE_NUMBER",
    "file_hash_md5": "FILE_HASH_MD5",
    "file_hash_sha1": "FILE_HASH_SHA1",
    "file_hash_sha256": "FILE_HASH_SHA256",
    "mitre_technique": "MITRE_TECHNIQUE",
    "malware": "MALWARE_FAMILY",
    "ransomware_group": "RANSOMWARE_GROUP",
    "handle": "THREAT_ACTOR_HANDLE",
    "crypto_wallet": "CRYPTO_WALLET",
    "phone": "PHONE",
    "pgp_key": "PGP_KEY",
    "other": "OTHER",
}

_TLP_DESCRIPTIONS: dict[str, str] = {
    "white": "TLP:WHITE — Subject to standard copyright rules. May be distributed freely.",
    "green": "TLP:GREEN — Limited to the community. Recipients may share within their community.",
    "amber": "TLP:AMBER — Limited disclosure. Recipients may share only on a need-to-know basis.",
    "red": "TLP:RED — Restricted. Recipients may not share further.",
}


# ---------------------------------------------------------------------------
# Entity attribute accessors — work for dicts, NormalizedEntity, and DB Entity
# ---------------------------------------------------------------------------


def _entity_type(e: Any) -> str:
    """Return the upper-cased entity type for an entity (dict | object)."""
    if isinstance(e, dict):
        raw = e.get("entity_type") or e.get("type") or ""
    else:
        raw = getattr(e, "entity_type", "") or ""
    raw = str(raw).strip()
    if not raw:
        return ""
    # Already upper case?  Return as-is.
    if raw == raw.upper():
        return raw
    # Lower case → map via normalisation table.
    return _TYPE_NORMALISATION.get(raw.lower(), raw.upper())


def _entity_value(e: Any) -> str:
    """Return the entity's canonical value via the shared identity module.

    Migrated (audit finding 1.3 / 3.9 item 2) from the old
    ``entity.canonical_value or entity.value`` pattern to call
    ``extractor.identity.entity_canonical_id`` directly.  Phase 1 already fixed
    ``NormalizedEntity.canonical_value`` so that old pattern no longer returned
    the raw value for pipeline-stage entities — but this makes the choice
    explicit at the call site (one shared function, not an assumption about
    what a property returns), so DB-backed and pipeline-stage versions of the
    same entity can never produce inconsistent casing here again.
    """
    etype = _entity_type(e)
    if isinstance(e, dict):
        raw = e.get("value") or e.get("canonical_value") or e.get("canonical") or ""
    else:
        raw = getattr(e, "value", None) or getattr(e, "canonical_value", None) or ""
    if not raw:
        return ""
    try:
        return entity_canonical_id(SimpleNamespace(entity_type=etype, value=raw))
    except Exception:
        return raw


def _entity_confidence(e: Any) -> float:
    try:
        if isinstance(e, dict):
            return float(e.get("confidence") or 0.0)
        return float(getattr(e, "confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _entity_source_url(e: Any) -> str:
    if isinstance(e, dict):
        return e.get("source_url") or ""
    return getattr(e, "source_url", "") or ""


# ---------------------------------------------------------------------------
# Credential redaction
# ---------------------------------------------------------------------------


def redact_credential(value: str) -> str:
    """
    Partially redact a credential for safe sharing.

    Patterns handled (case-sensitive on the prefix, partial on the body):
        * AWS access key (AKIA + 16 chars)
        * GitHub tokens  (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_)
        * GitLab tokens  (glpat-)
        * Stripe keys    (sk_live_, sk_test_, pk_live_, pk_test_, rk_live_)
        * Slack tokens   (xoxb-, xoxp-, xoxa-, xoxr-, xoxs-)
        * JWT            (header.payload.signature)
        * Generic API key (first 4 chars + [REDACTED])
    """
    if value is None:
        return ""
    v = str(value).strip()
    if not v:
        return ""

    # AWS access key
    if re.match(r"^AKIA[0-9A-Z]{12,}$", v):
        return v[:8] + "[REDACTED]"

    # GitHub tokens
    m = re.match(r"^(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)(.+)$", v)
    if m:
        return m.group(1) + "[REDACTED]"

    # GitLab personal access tokens
    m = re.match(r"^(glpat-)([A-Za-z0-9_\-]{20,})$", v)
    if m:
        return m.group(1) + "[REDACTED]"

    # Stripe keys
    m = re.match(r"^(sk_live_|sk_test_|pk_live_|pk_test_|rk_live_)(.+)$", v)
    if m:
        return m.group(1) + "[REDACTED]"

    # Slack tokens
    m = re.match(r"^(xox[bpars]-[0-9]+-[0-9]+-)([A-Za-z0-9]+)$", v)
    if m:
        return m.group(1) + "[REDACTED]"

    # JWT: header.payload.signature
    if v.count(".") == 2:
        parts = v.split(".")
        if all(parts):
            return f"{parts[0][:8]}.[REDACTED].[REDACTED]"

    # Generic: keep first 4 chars
    if len(v) >= 12:
        return v[:4] + "[REDACTED]"

    # Short value → fully redact
    return "[REDACTED]"


# ---------------------------------------------------------------------------
# IP utilities
# ---------------------------------------------------------------------------


def _is_ipv6(value: str) -> bool:
    return ":" in value and "." not in value.split("/")[0].split("%")[0]


def _defang_ip(ip: str) -> str:
    """Convert 1.2.3.4 → 1[.]2[.]3[.]4 for comment lines."""
    if _is_ipv6(ip):
        return ip.replace(":", "[:]")
    return ip.replace(".", "[.]")


# ---------------------------------------------------------------------------
# Snort / YARA rule generation — delegated to the dedicated export modules.
# ---------------------------------------------------------------------------
#
# Phase 4.2/4.3 shipped basic stub generators inline in this module.  Those
# have been promoted to full standalone modules (``export.yara_export`` and
# ``export.snort_export``) and the helpers below are thin pass-throughs that
# keep the IOC package ZIP construction code unchanged.  Any improvement to
# the detection rule output should be made in the dedicated modules.


def _build_snort_rules(
    entities: Iterable[Any],
    investigation: dict,
    tlp: str = "TLP:WHITE",
) -> str:
    """Build Snort rules (delegates to ``export.snort_export``)."""
    try:
        from export.snort_export import generate_snort_rules

        return generate_snort_rules(
            list(entities or []),
            investigation or {},
            format="snort",
            tlp=tlp,
        )
    except Exception as exc:
        logger.warning("_build_snort_rules (Snort) failed: %s", exc)
        return _stub_snort_rules(entities)


def _build_suricata_rules(
    entities: Iterable[Any],
    investigation: dict,
    tlp: str = "TLP:WHITE",
) -> str:
    """Build Suricata rules (delegates to ``export.snort_export``)."""
    try:
        from export.snort_export import generate_snort_rules

        return generate_snort_rules(
            list(entities or []),
            investigation or {},
            format="suricata",
            tlp=tlp,
        )
    except Exception as exc:
        logger.warning("_build_suricata_rules failed: %s", exc)
        return _stub_snort_rules(entities)


def _build_yara_rules(
    entities: Iterable[Any],
    investigation: dict,
    tlp: str = "TLP:WHITE",
) -> str:
    """Build YARA rules (delegates to ``export.yara_export``)."""
    try:
        from export.yara_export import generate_yara_rules

        return generate_yara_rules(
            list(entities or []),
            investigation or {},
            tlp=tlp,
        )
    except Exception as exc:
        logger.warning("_build_yara_rules failed: %s", exc)
        return _stub_yara_rules(entities)


def _stub_snort_rules(entities: Iterable[Any]) -> str:
    """Last-resort fallback used when ``export.snort_export`` is unavailable."""
    lines: list[str] = [
        "# VoidAccess Snort rules — fallback stub",
        "# SID range: 9000001+ reserved for VoidAccess-generated rules",
        "",
    ]
    sid = SNORT_SID_BASE
    seen_ips: set[str] = set()
    seen_domains: set[str] = set()
    for entity in entities:
        etype = _entity_type(entity)
        value = _entity_value(entity).strip()
        if not value:
            continue
        if etype in _IPV4_TYPES and value not in seen_ips:
            seen_ips.add(value)
            ip_proto = "ip6" if _is_ipv6(value) else "ip"
            lines.append(
                f"alert {ip_proto} {value} any -> $HOME_NET any (\n"
                f"    msg:\"VoidAccess IOC - Malicious IP {value}\";\n"
                f"    sid:{sid};\n"
                f"    rev:1;\n"
                f"    classtype:trojan-activity;\n"
                f")"
            )
            sid += 1
        elif etype in _DOMAIN_TYPES and value not in seen_domains:
            seen_domains.add(value)
            lines.append(
                f"alert dns any any -> any 53 (\n"
                f"    msg:\"VoidAccess IOC - Malicious Domain {value}\";\n"
                f"    dns.query; content:\"{value}\";\n"
                f"    sid:{sid};\n"
                f"    rev:1;\n"
                f")"
            )
            sid += 1
    return "\n".join(lines).rstrip() + "\n"


def _stub_yara_rules(entities: Iterable[Any]) -> str:
    """Last-resort fallback used when ``export.yara_export`` is unavailable."""
    rules: list[str] = [
        "// VoidAccess YARA rules — fallback stub",
        "",
    ]
    for entity in entities:
        etype = _entity_type(entity)
        value = _entity_value(entity).strip()
        if etype == "FILE_HASH_SHA256" and re.match(r"^[A-Fa-f0-9]{64}$", value):
            short_hash = value[:8].lower()
            rules.append(
                f"rule VoidAccess_Hash_SHA256_{short_hash} {{\n"
                f"    condition:\n"
                f"        hash.sha256(0, filesize) == \"{value.lower()}\"\n"
                f"}}"
            )
    return "\n".join(rules).rstrip() + "\n"


# ---------------------------------------------------------------------------
# IOC bucket writers — one per file in iocs/
# ---------------------------------------------------------------------------


def _write_hashes(entities: Iterable[Any]) -> str:
    md5: list[str] = []
    sha1: list[str] = []
    sha256: list[str] = []
    for e in entities:
        etype = _entity_type(e)
        v = _entity_value(e).strip()
        if not v:
            continue
        if etype == "FILE_HASH_MD5" and re.match(r"^[A-Fa-f0-9]{32}$", v):
            md5.append(v.lower())
        elif etype == "FILE_HASH_SHA1" and re.match(r"^[A-Fa-f0-9]{40}$", v):
            sha1.append(v.lower())
        elif etype == "FILE_HASH_SHA256" and re.match(r"^[A-Fa-f0-9]{64}$", v):
            sha256.append(v.lower())
    sections: list[str] = ["# File hashes extracted by VoidAccess", ""]
    for label, items in (("MD5", md5), ("SHA1", sha1), ("SHA256", sha256)):
        sections.append(f"# {label}")
        sections.extend(items)
        sections.append("")
    return "\n".join(sections).rstrip() + "\n"


def _write_ipv4(entities: Iterable[Any]) -> str:
    ips: list[str] = []
    for e in entities:
        if _entity_type(e) != "IP_ADDRESS":
            continue
        v = _entity_value(e).strip()
        if not v or _is_ipv6(v):
            continue
        ips.append(v)
    if not ips:
        return ""
    lines = ["# IPv4 indicators (real values, ready for tool import)", ""]
    for ip in ips:
        lines.append(ip)
        lines.append(f"# {_defang_ip(ip)} (defanged)")
    return "\n".join(lines).rstrip() + "\n"


def _write_ipv6(entities: Iterable[Any]) -> str:
    ips: list[str] = []
    for e in entities:
        if _entity_type(e) != "IP_ADDRESS":
            continue
        v = _entity_value(e).strip()
        if v and _is_ipv6(v):
            ips.append(v)
    return "\n".join(ips).rstrip() + ("\n" if ips else "")


def _write_domains(entities: Iterable[Any]) -> str:
    items: list[str] = []
    for e in entities:
        if _entity_type(e) in _DOMAIN_TYPES:
            v = _entity_value(e).strip()
            if v:
                items.append(v)
    return "\n".join(items).rstrip() + ("\n" if items else "")


def _write_onion_urls(entities: Iterable[Any]) -> str:
    items: list[str] = []
    for e in entities:
        if _entity_type(e) in _ONION_TYPES:
            v = _entity_value(e).strip()
            if v and (".onion" in v.lower() or v.lower().endswith(".onion")):
                items.append(v)
    return "\n".join(items).rstrip() + ("\n" if items else "")


def _write_emails(entities: Iterable[Any]) -> str:
    items: list[str] = []
    for e in entities:
        if _entity_type(e) in _EMAIL_TYPES:
            v = _entity_value(e).strip()
            if v:
                items.append(v)
    content = "\n".join(items).rstrip()
    # v1.7 MED-4: if entities matched but all had empty values, write a
    # header comment so the file is never 0 bytes (0-byte files inside a
    # ZIP are technically valid but confusing to downstream tooling).
    if items and not content:
        return "# Email addresses extracted by VoidAccess\n"
    if content:
        return content + "\n"
    return ""


def _write_urls(entities: Iterable[Any]) -> str:
    items: list[str] = []
    for e in entities:
        etype = _entity_type(e)
        if etype in _URL_TYPES:
            v = _entity_value(e).strip()
            if v:
                items.append(v)
    return "\n".join(items).rstrip() + ("\n" if items else "")


def _write_crypto_wallets(entities: Iterable[Any]) -> str:
    """Format: COIN_TYPE:ADDRESS (one per line)."""
    items: list[str] = []
    for e in entities:
        etype = _entity_type(e)
        v = _entity_value(e).strip()
        if not v:
            continue
        if etype in _BTC_TYPES:
            items.append(f"BTC:{v}")
        elif etype in _ETH_TYPES:
            items.append(f"ETH:{v}")
        elif etype in _XMR_TYPES:
            items.append(f"XMR:{v}")
        elif etype == "CRYPTO_WALLET":
            # Heuristic: leading char often signals the network
            upper = v.upper()
            if upper.startswith(("1", "3", "bc1")):
                items.append(f"BTC:{v}")
            elif upper.startswith("0X"):
                items.append(f"ETH:{v}")
            elif len(v) >= 90:
                items.append(f"XMR:{v}")
            else:
                items.append(f"WALLET:{v}")
    return "\n".join(items).rstrip() + ("\n" if items else "")


def _write_credentials(
    entities: Iterable[Any],
    redact: bool = True,
) -> str:
    lines: list[str] = [
        "# Credentials — partially redacted for safe sharing.",
        "# Format: TYPE:REDACTED_VALUE",
        "",
    ]
    if not redact:
        lines.append("# WARNING: --redact-credentials=false was set.")
        lines.append("")
    for e in entities:
        etype = _entity_type(e)
        if etype not in _CREDENTIAL_TYPES:
            continue
        v = _entity_value(e).strip()
        if not v:
            continue
        if redact:
            lines.append(f"{etype}:{redact_credential(v)}")
        else:
            lines.append(f"{etype}:{v}")
    return "\n".join(lines).rstrip() + "\n"


def _write_cves(entities: Iterable[Any]) -> str:
    items: list[str] = []
    for e in entities:
        if _entity_type(e) in _CVE_TYPES:
            v = _entity_value(e).strip()
            if v:
                items.append(v)
    return "\n".join(items).rstrip() + ("\n" if items else "")


def _write_mitre(entities: Iterable[Any]) -> str:
    items: list[str] = []
    for e in entities:
        if _entity_type(e) in _MITRE_TYPES:
            v = _entity_value(e).strip()
            if v:
                # Accept "T1234" or "T1234.001" or "T1234 - name"
                tech_id = v.split(" - ")[0].strip()
                items.append(tech_id)
    return "\n".join(items).rstrip() + ("\n" if items else "")


# ---------------------------------------------------------------------------
# Entity CSV + investigation summary
# ---------------------------------------------------------------------------


def _build_entity_csv(entities: Iterable[Any]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "entity_type",
            "value",
            "canonical_value",
            "confidence",
            "source_url",
            "context_snippet",
        ]
    )
    for e in entities:
        etype = _entity_type(e)
        value = _entity_value(e)
        canonical = value  # _entity_value prefers canonical_value already
        if isinstance(e, dict):
            source_url = e.get("source_url") or ""
            context = (e.get("context_snippet") or "").replace("\n", " ")[:500]
        else:
            source_url = getattr(e, "source_url", "") or ""
            context = (getattr(e, "context_snippet", "") or "").replace("\n", " ")[:500]
        writer.writerow(
            [
                etype,
                value,
                canonical,
                f"{_entity_confidence(e):.2f}",
                source_url,
                context,
            ]
        )
    return buf.getvalue()


def _build_summary_md(investigation: dict) -> str:
    parts: list[str] = [
        "# Investigation Summary",
        "",
    ]
    query = investigation.get("query") or "(unknown query)"
    parts.append(f"**Query:** {query}")
    parts.append("")
    created = investigation.get("created_at")
    if created:
        parts.append(f"**Created:** {created}")
        parts.append("")
    summary = investigation.get("summary") or "_(No summary available.)_"
    parts.append("## Summary")
    parts.append("")
    parts.append(summary)
    parts.append("")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Counts
# ---------------------------------------------------------------------------


def _count_by_type(entities: Iterable[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for e in entities:
        etype = _entity_type(e)
        if not etype:
            continue
        counts[etype] = counts.get(etype, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Filename helpers
# ---------------------------------------------------------------------------


_SAFE_FNAME = re.compile(r"[^A-Za-z0-9_-]+")


def _safe_filename_segment(text: str, fallback: str = "package") -> str:
    s = _SAFE_FNAME.sub("-", text or "").strip("-_")
    if not s:
        s = fallback
    return s[:60]  # keep filenames sane


# ---------------------------------------------------------------------------
# STIX / MISP / Sigma access (delegated; tolerant if stix2 missing)
# ---------------------------------------------------------------------------


def _safe_stix_json(entities: list[Any], investigation_id: Any) -> str:
    try:
        from export.stix import investigation_to_stix_bundle, bundle_to_json
        # investigation_to_stix_bundle loads entities from the DB via its own
        # session.  When running with dict entities (e.g. CLI export), we
        # can't pass them through that path — fall back to the empty bundle.
        bundle = investigation_to_stix_bundle(investigation_id)
        try:
            from export.stix import get_last_relationship_warning
            warning = get_last_relationship_warning()
            if warning:
                logger.warning(
                    "STIX relationships were not included in IOC package: %s",
                    warning,
                )
        except Exception:
            pass
        return bundle_to_json(bundle)
    except Exception as exc:
        logger.warning("STIX generation for IOC package failed: %s", exc)
        return json.dumps({"type": "bundle", "id": "bundle--placeholder", "objects": []}, indent=2)


def _safe_misp_json(entities: list[Any], investigation_id: Any) -> str:
    try:
        from export.misp import investigation_to_misp_event, misp_event_to_json
        event = investigation_to_misp_event(investigation_id)
        return misp_event_to_json(event)
    except Exception as exc:
        logger.warning("MISP generation for IOC package failed: %s", exc)
        return json.dumps({"Event": {"info": "Unavailable", "Attribute": []}}, indent=2)


def _safe_sigma_yml(entities: list[Any]) -> str:
    try:
        from export.sigma import render_sigma_rules
        return render_sigma_rules(entities or [])
    except Exception as exc:
        logger.warning("Sigma generation for IOC package failed: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# README + metadata builders
# ---------------------------------------------------------------------------


def _build_readme(
    investigation: dict,
    counts: dict[str, int],
    sources_used: dict,
    tlp: str,
    redact_credentials: bool,
    include_raw: bool,
    generated_at: str,
) -> str:
    query = investigation.get("query") or "(unknown query)"
    lines: list[str] = [
        "# VoidAccess IOC Package",
        "",
        f"**TLP:** {_TLP_DESCRIPTIONS.get(tlp.lower(), tlp.upper())}",
        "",
        f"**Investigation query:** {query}",
        f"**Generated at:** {generated_at}",
        f"**Investigation ID:** {investigation.get('id', 'n/a')}",
        f"**Package format:** {PACKAGE_FORMAT}",
        f"**VoidAccess version:** {PACKAGE_VERSION}",
        "",
        "## Entity Counts",
        "",
    ]
    if counts:
        for etype, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"- **{etype}**: {n}")
    else:
        lines.append("_(no entities)_")
    lines.append("")

    lines.append("## Sources Used")
    lines.append("")
    if sources_used:
        for name, status in sorted(sources_used.items()):
            lines.append(f"- **{name}**: `{status}`")
    else:
        lines.append("_(no source metadata)_")
    lines.append("")

    lines.extend(
        [
            "## File Index",
            "",
            "### Indicators (`iocs/`)",
            "- `hashes.txt` — File hashes (MD5 / SHA1 / SHA256, grouped)",
            "- `ip_addresses.txt` — IPv4 indicators + defanged comments",
            "- `ipv6_addresses.txt` — IPv6 indicators",
            "- `domains.txt` — Domain indicators",
            "- `onion_urls.txt` — `.onion` URLs",
            "- `email_addresses.txt` — Email addresses",
            "- `urls.txt` — All extracted URLs",
            "- `crypto_wallets.txt` — Crypto wallet addresses (`COIN:ADDRESS`)",
            f"- `credentials.txt` — Credentials, partially redacted ({'YES' if redact_credentials else 'NO'})",
            "- `cve_identifiers.txt` — CVE IDs",
            "- `mitre_techniques.txt` — MITRE ATT&CK technique IDs",
            "",
            "### Threat intel (`threat_intel/`)",
            "- `stix.json` — STIX 2.1 bundle (importable into MISP, OpenCTI, etc.)",
            "- `misp.json` — MISP event JSON (importable into MISP platform)",
            "",
            "### Detections (`detections/`)",
            "- `sigma.yml` — Sigma rules (SIEM-agnostic)",
            "- `yara.yar` — YARA rules (hash, malware string, network IOC, credential-leak pattern rules)",
            "- `snort.rules` — Snort detection rules (IP reputation, DNS, HTTP, CVE)",
            "- `suricata.rules` — Suricata rules (Snort-compatible with `metadata:` block, TLS SNI, `filemd5:`)",
            "",
            "### Reports (`reports/`)",
            "- `summary.md` — Investigation LLM summary",
            "- `entities.csv` — Full entity CSV (type, value, confidence, source)",
            "",
            "### Metadata",
            "- `metadata.json` — Machine-readable package metadata",
            "",
        ]
    )

    if include_raw:
        lines.append("### Raw content")
        lines.append("")
        lines.append(
            "Raw scraped page content is included under `pages/`.  These files "
            "may contain unredacted sensitive data — handle with care."
        )
        lines.append("")

    lines.extend(
        [
            "## Notes",
            "",
            "- All hashes / IPs / domains are listed in their real form so they",
            "  can be ingested directly by SIEM / EDR / TIP tooling.  Defanged",
            "  versions are included as comments where useful.",
            "- `credentials.txt` is partially redacted by default.  The original",
            "  credentials are NOT included in this package.",
            "- This package is generated by VoidAccess.  Validate any rules",
            "  against your environment before enabling in production.",
            "",
        ]
    )
    return "\n".join(lines)


def _build_metadata(
    investigation: dict,
    counts: dict[str, int],
    sources_used: dict,
    tlp: str,
    redact_credentials: bool,
    include_raw: bool,
    generated_at: str,
    package_size: int = 0,
) -> str:
    # Pull the runtime version when possible, fall back to the package constant.
    runtime_version = PACKAGE_VERSION
    try:
        import voidaccess_cli  # type: ignore
        runtime_version = getattr(voidaccess_cli, "__version__", PACKAGE_VERSION)
    except Exception:
        pass

    payload = {
        "voidaccess_version": runtime_version,
        "package_format": PACKAGE_FORMAT,
        "generated_at": generated_at,
        "investigation_id": investigation.get("id"),
        "run_id": investigation.get("run_id"),
        "query": investigation.get("query"),
        "entity_counts": counts,
        "sources_used": sources_used or {},
        "tlp": f"TLP:{tlp.upper()}",
        "redact_credentials": redact_credentials,
        "include_raw": include_raw,
    }
    if package_size:
        payload["package_size_bytes"] = package_size
    return json.dumps(payload, indent=2, default=str)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def generate_ioc_package(
    investigation_id: Any,
    entities: list[Any],
    investigation: dict,
    session: Any = None,
    *,
    tlp: str = "white",
    redact_credentials: bool = True,
    include_raw: bool = False,
    raw_pages: Optional[list[dict]] = None,
) -> bytes:
    """
    Build a ZIP containing every artefact a SOC analyst needs to import an
    investigation into their stack.

    Parameters
    ----------
    investigation_id : str | UUID
        Used for filenames and embedded in metadata.  Also passed to STIX /
        MISP generators when they need to load the investigation record.
    entities : list
        Entities as dicts, NormalizedEntity instances, or DB Entity instances.
        Must expose ``entity_type`` and ``canonical_value`` / ``value``.
    investigation : dict
        Investigation metadata (query, summary, created_at, sources_used…).
    session : optional
        DB session for downstream STIX / MISP / Sigma generators.  Currently
        unused inside this function — the generators open their own sessions.
    tlp : str
        Traffic Light Protocol marker.  One of: white, green, amber, red.
    redact_credentials : bool
        If True (default), credential values are partially redacted.
    include_raw : bool
        If True, attach raw scraped page content under ``pages/`` in the ZIP.
    raw_pages : list[dict] | None
        Optional list of ``{"url": ..., "text": ...}`` for raw inclusion.
    """
    entities = list(entities or [])
    counts = _count_by_type(entities)
    sources_used = investigation.get("sources_used") or {}
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    tlp_norm = (tlp or "white").lower()
    if tlp_norm not in _TLP_DESCRIPTIONS:
        logger.warning("Unknown TLP %r — defaulting to TLP:WHITE", tlp)
        tlp_norm = "white"

    # ---- build each artefact -------------------------------------------------
    readme = _build_readme(
        investigation=investigation,
        counts=counts,
        sources_used=sources_used,
        tlp=tlp_norm,
        redact_credentials=redact_credentials,
        include_raw=include_raw,
        generated_at=generated_at,
    )
    stix_json = _safe_stix_json(entities, investigation_id)
    misp_json = _safe_misp_json(entities, investigation_id)
    sigma_yml = _safe_sigma_yml(entities)
    tlp_marker = f"TLP:{tlp_norm.upper()}"
    investigation_meta = {
        "id": investigation.get("id"),
        "query": investigation.get("query") or "",
        "summary": investigation.get("summary") or "",
        "created_at": investigation.get("created_at"),
        "run_id": investigation.get("run_id"),
    }
    snort_rules = _build_snort_rules(entities, investigation_meta, tlp=tlp_marker)
    suricata_rules = _build_suricata_rules(entities, investigation_meta, tlp=tlp_marker)
    yara_rules = _build_yara_rules(entities, investigation_meta, tlp=tlp_marker)
    entity_csv = _build_entity_csv(entities)
    summary_md = _build_summary_md(investigation)

    metadata_json = _build_metadata(
        investigation=investigation,
        counts=counts,
        sources_used=sources_used,
        tlp=tlp_norm,
        redact_credentials=redact_credentials,
        include_raw=include_raw,
        generated_at=generated_at,
    )

    # ---- assemble ZIP --------------------------------------------------------
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        _writestr(zf, "README.md", readme)
        _writestr(zf, "metadata.json", metadata_json)

        _writestr(zf, "iocs/hashes.txt", _write_hashes(entities))
        _writestr(zf, "iocs/ip_addresses.txt", _write_ipv4(entities))
        _writestr(zf, "iocs/ipv6_addresses.txt", _write_ipv6(entities))
        _writestr(zf, "iocs/domains.txt", _write_domains(entities))
        _writestr(zf, "iocs/onion_urls.txt", _write_onion_urls(entities))
        _writestr(zf, "iocs/email_addresses.txt", _write_emails(entities))
        _writestr(zf, "iocs/urls.txt", _write_urls(entities))
        _writestr(zf, "iocs/crypto_wallets.txt", _write_crypto_wallets(entities))
        _writestr(
            zf, "iocs/credentials.txt", _write_credentials(entities, redact=redact_credentials)
        )
        _writestr(zf, "iocs/cve_identifiers.txt", _write_cves(entities))
        _writestr(zf, "iocs/mitre_techniques.txt", _write_mitre(entities))

        _writestr(zf, "threat_intel/stix.json", stix_json)
        _writestr(zf, "threat_intel/misp.json", misp_json)

        _writestr(zf, "detections/sigma.yml", sigma_yml)
        _writestr(zf, "detections/yara.yar", yara_rules)
        _writestr(zf, "detections/snort.rules", snort_rules)
        _writestr(zf, "detections/suricata.rules", suricata_rules)

        _writestr(zf, "reports/summary.md", summary_md)
        _writestr(zf, "reports/entities.csv", entity_csv)

        if include_raw and raw_pages:
            for i, page in enumerate(raw_pages):
                url = (page.get("url") if isinstance(page, dict) else "") or f"page-{i}"
                text = (page.get("text") if isinstance(page, dict) else "") or ""
                safe = _safe_filename_segment(url, fallback=f"page-{i}")
                _writestr(zf, f"pages/{safe}.txt", text)

    data = buf.getvalue()

    # Rewrite metadata.json with the final package size if it changed.
    # (We rebuild it after the ZIP so the file inside the archive reports
    # its own size — useful for downstream tools that introspect the package.)
    try:
        metadata_with_size = _build_metadata(
            investigation=investigation,
            counts=counts,
            sources_used=sources_used,
            tlp=tlp_norm,
            redact_credentials=redact_credentials,
            include_raw=include_raw,
            generated_at=generated_at,
            package_size=len(data),
        )
        buf2 = io.BytesIO()
        with zipfile.ZipFile(buf2, mode="w", compression=zipfile.ZIP_DEFLATED) as zf2:
            for name in zipfile.ZipFile(io.BytesIO(data)).namelist():
                if name == "metadata.json":
                    zf2.writestr(name, metadata_with_size)
                else:
                    zf2.writestr(
                        name,
                        zipfile.ZipFile(io.BytesIO(data)).read(name),
                    )
        return buf2.getvalue()
    except Exception as exc:
        logger.warning("Final metadata rewrite failed, returning initial package: %s", exc)
        return data


def _writestr(zf: zipfile.ZipFile, name: str, content: str) -> None:
    """Write a UTF-8 string entry to the ZIP, swallowing individual errors."""
    try:
        if not isinstance(content, str):
            content = str(content)
        zf.writestr(name, content.encode("utf-8"))
    except Exception as exc:
        logger.warning("Failed to write %s to ZIP: %s", name, exc)


# ---------------------------------------------------------------------------
# Convenience: package filename for an investigation
# ---------------------------------------------------------------------------


def build_package_filename(
    investigation: dict,
    investigation_id: Any,
    *,
    date: Optional[datetime] = None,
) -> str:
    """Return a sanitised download filename for the IOC package."""
    query = (investigation or {}).get("query") or ""
    segment = _safe_filename_segment(query, fallback="investigation")
    d = date or datetime.now(timezone.utc)
    return f"voidaccess-{segment}-{d.strftime('%Y%m%d')}.zip"
