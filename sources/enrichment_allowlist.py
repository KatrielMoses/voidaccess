"""Opt-in allowlist for enrichment sources (``VOIDACCESS_ENRICHMENT_SOURCES``).

When the env var is UNSET or blank, nothing changes: every enrichment source
behaves exactly as before (its own key/feature checks still apply).

When set to a comma-separated list of source ids, ONLY those sources may make
network calls during enrichment. A disabled source contributes the same
empty/neutral result the code already returns when a key is missing or a call
fails. The gate lives inside the ``sources`` modules, so every path that runs
enrichment (CLI ``investigate``, CLI ``enrich``, the API) is covered.

Only enrichment sources are registered here. Search-stage sources (onion
engines, paste sites, GitHub/GitLab scrapers, RSS, Telegram, proxy) are not.

An unknown id raises :class:`EnrichmentAllowlistError`; a typo must never
silently enable or disable a source.
"""

from __future__ import annotations

import logging
import os

from sources.source_control import (
    STATUS_DISABLED,
    STATUS_SKIPPED_BY_ALLOWLIST,
    is_source_disabled,
    note_gate_refusal,
)

logger = logging.getLogger(__name__)

ENV_VAR = "VOIDACCESS_ENRICHMENT_SOURCES"

ENRICHMENT_SOURCE_IDS: dict[str, str] = {
    "otx": "AlienVault OTX pulses (sources/enrichment.py)",
    "malwarebazaar": "abuse.ch MalwareBazaar (sources/enrichment.py, sources/hash_reputation.py)",
    "threatfox": "abuse.ch ThreatFox (sources/enrichment.py, sources/hash_reputation.py)",
    "urlhaus": "abuse.ch URLhaus (sources/enrichment.py)",
    "ransomware_live": "ransomware.live API v2 (sources/enrichment.py)",
    "ransomlook": "RansomLook (sources/enrichment.py)",
    "cisa_kev": "CISA KEV catalogue and advisories (sources/cisa.py, sources/historical_intel.py)",
    "nvd": "NIST NVD 2.0 CVE/CPE data (sources/nvd.py)",
    "epss": "FIRST EPSS scores (sources/epss.py, used by sources/cve_intel.py)",
    "exploitdb": "Exploit-DB CVE-to-EDB mapping (sources/exploitdb.py, used by sources/cve_intel.py)",
    "shodan_internetdb": "Shodan InternetDB (sources/shodan.py)",
    "virustotal": "VirusTotal entity enrichment and hash lookup (sources/virustotal.py, sources/hash_reputation.py)",
    "mitre_attack": "MITRE ATT&CK STIX actor-to-technique mapping (sources/historical_intel.py, overlay in sources/enrichment.py)",
    "fbi_doj_press": "justice.gov press-release RSS actor matches (sources/historical_intel.py)",
    "blocklists": "umbrella: enables all four bulk blocklists below (feeds/__init__.py)",
    "sslbl": "abuse.ch SSLBL blocklist (feeds/__init__.py)",
    "openphish": "OpenPhish community feed (feeds/__init__.py)",
    "phishtank": "PhishTank bulk feed (feeds/__init__.py)",
    "ransomwhere": "Ransomwhere BTC ransom-wallet list (feeds/__init__.py)",
    "feodo_tracker": "abuse.ch Feodo Tracker C2 IP list (sources/ip_reputation.py)",
    "c2_tracker": "C2IntelFeeds / C2-Tracker GitHub lists (sources/ip_reputation.py)",
    "abuseipdb": "AbuseIPDB IP checks (sources/ip_reputation.py)",
    "greynoise": "GreyNoise Community IP checks (sources/ip_reputation.py)",
    "crtsh": "crt.sh certificate transparency (sources/domain_reputation.py)",
    "wayback": "Wayback Machine first-seen lookup (sources/domain_reputation.py)",
    "urlscan": "urlscan.io search/submit (sources/domain_reputation.py)",
    "hybrid_analysis": "Hybrid Analysis hash lookup (sources/hash_reputation.py)",
    "hibp": "Have I Been Pwned v3 breached-account lookup (sources/email_reputation.py)",
    "emailrep": "EmailRep.io (sources/email_reputation.py)",
    "disposable_email": "disposable-email-domains list download (sources/email_reputation.py)",
    "xposedornot": "XposedOrNot breach lookup (sources/breach_lookup.py)",
    "leakcheck": "LeakCheck public API (sources/breach_lookup.py)",
    "hudsonrock": "Hudson Rock Cavalier infostealer OSINT (sources/infostealer.py)",
    "rdap": "RDAP via rdap.org / rdap.arin.net (sources/dns_enrichment.py)",
    "circl": "CIRCL passive DNS and passive SSL (sources/dns_enrichment.py)",
    "securitytrails": "SecurityTrails DNS history (config key only; no call site in sources/dns_enrichment.py today)",
    "blockcypher": "BlockCypher Bitcoin lookups (sources/blockchain.py)",
    "etherscan": "Etherscan Ethereum lookups (sources/blockchain.py)",
    "hibp_pwned_passwords": "HIBP Pwned Passwords k-anonymity range API (credential_presence/__init__.py)",
}

# Recommended value for the hosted/cloud product: the E0 licence table's
# "fine on our keys" sources that are enrichment sources. NOT applied by default.
CLOUD_ENRICHMENT_SOURCES = "rdap,crtsh,wayback,cisa_kev,nvd,mitre_attack"


class EnrichmentAllowlistError(ValueError):
    """VOIDACCESS_ENRICHMENT_SOURCES names one or more unknown source ids."""


_logged_disabled: set[str] = set()


def get_enrichment_allowlist() -> frozenset[str] | None:
    """Return the allowlist, or None when the env var is unset/blank.

    Read at call time (no caching) so tests and long-running processes see
    changes. Raises EnrichmentAllowlistError for unknown ids.
    """
    raw = os.environ.get(ENV_VAR)
    if raw is None or not raw.strip():
        return None
    ids = [p.strip().lower() for p in raw.split(",")]
    ids = [p for p in ids if p]
    if not ids:
        return None
    unknown = sorted({p for p in ids if p not in ENRICHMENT_SOURCE_IDS})
    if unknown:
        raise EnrichmentAllowlistError(
            f"{ENV_VAR} contains unknown source id(s): {', '.join(unknown)}. "
            f"Valid ids: {', '.join(sorted(ENRICHMENT_SOURCE_IDS))}"
        )
    return frozenset(ids)


def validate_enrichment_allowlist() -> frozenset[str] | None:
    """Validate the env var early (CLI startup); returns the allowlist or None."""
    return get_enrichment_allowlist()


def is_enrichment_source_enabled(source_id: str) -> bool:
    """True when the source may run: not on the deny-list
    (``VOIDACCESS_DISABLED_SOURCES``) and the allowlist is unset or contains it.

    Raises KeyError-style EnrichmentAllowlistError if *source_id* itself is not
    registered, so call sites cannot use unregistered ids.
    """
    if source_id not in ENRICHMENT_SOURCE_IDS:
        raise EnrichmentAllowlistError(
            f"unregistered enrichment source id {source_id!r}; "
            f"register it in sources/enrichment_allowlist.py"
        )
    if is_source_disabled(source_id):
        note_gate_refusal(source_id, STATUS_DISABLED)
        return False
    allow = get_enrichment_allowlist()
    if allow is None or source_id in allow:
        return True
    note_gate_refusal(source_id, STATUS_SKIPPED_BY_ALLOWLIST)
    if source_id not in _logged_disabled:
        _logged_disabled.add(source_id)
        logger.debug("enrichment source %s disabled by %s", source_id, ENV_VAR)
    return False


def reset_enrichment_allowlist_state() -> None:
    """Clear the once-only log memo (tests)."""
    _logged_disabled.clear()
