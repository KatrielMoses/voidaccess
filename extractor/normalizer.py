"""
extractor/normalizer.py — Entity deduplication and canonical record merging.

The same wallet address may appear in 50 pages; it gets one NormalizedEntity
per call to normalize_entities() (deduped by canonical value within that call).
merge_with_db() upserts records to the DB and returns the assigned IDs.

Confidence is monotonic after extraction: new evidence may raise an entity's
stored confidence, but never lowers it.  The canonical merge rule is
``extractor.confidence.get_entity_confidence``.

Public interface
----------------
normalize_entities(raw_entities, page_url, page_id) → list[NormalizedEntity]
merge_with_db(entities, investigation_id)            → list  (DB IDs / empty)
resolve_entity_type_conflicts(entities)             → list  (deduped by canonical value)
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional
import uuid
from urllib.parse import urlparse

from extractor import entity_shape as _shape
from extractor import confidence as _conf
from extractor import gazetteer as _gazetteer
from extractor import org_filter as _org_filter
from extractor import software_suppression as _software

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical type priority for conflict resolution
# Lower number = higher specificity, wins in conflicts
# ---------------------------------------------------------------------------

TYPE_PRIORITY = {
    "CVE": 1,
    "MITRE_TECHNIQUE": 1,
    "MITRE_TACTIC": 1,
    "FILE_HASH_SHA256": 1,
    "FILE_HASH_SHA1": 1,
    "FILE_HASH_MD5": 1,
    "IP_ADDRESS": 1,
    "IPV6_ADDRESS": 1,
    "MAC_ADDRESS": 1,
    "IPFS_CID": 1,
    "EXPLOIT_DB_ID": 1,
    "YARA_RULE": 2,
    "NUCLEI_TEMPLATE": 2,
    "ONION_URL": 1,
    # Credential / token IOCs — high specificity, high value, priority 1.
    "AWS_ACCESS_KEY": 1,
    "AWS_SECRET_KEY": 1,
    "GITHUB_TOKEN": 1,
    "SLACK_TOKEN": 1,
    "DISCORD_TOKEN": 1,
    "JWT_TOKEN": 1,
    "GOOGLE_API_KEY": 1,
    "STRIPE_KEY": 1,
    "STEALER_LOG_ENTRY": 1,
    # Messaging / identity handle IOCs — high specificity shapes.  XMPP_JID
    # at priority 1 means an "xmpp: user@host" address wins over a plain
    # EMAIL_ADDRESS (priority 4) when the same value would qualify as both.
    "TELEGRAM_HANDLE": 1,
    "DISCORD_HANDLE": 1,
    "XMPP_JID": 1,
    "TOX_ID": 1,
    "SESSION_ID": 1,
    "MATRIX_HANDLE": 1,
    "BITCOIN_ADDRESS": 2,
    "MONERO_ADDRESS": 2,
    "ETH_ADDRESS": 2,
    "ETHEREUM_ADDRESS": 2,
    "LITECOIN_ADDRESS": 2,
    "ZCASH_ADDRESS": 2,
    "DOGECOIN_ADDRESS": 2,
    "XRP_ADDRESS": 2,
    "SOLANA_ADDRESS": 2,
    "TRON_ADDRESS": 2,
    "BITCOIN_CASH_ADDRESS": 2,
    "DASH_ADDRESS": 2,
    "ENS_DOMAIN": 2,
    "API_KEY": 2,  # generic — slightly broader pattern, lower priority than vendor-specific
    # Context-dependent messaging handles — slightly lower priority than the
    # shape-specific ones above because they require a context keyword.
    "WIRE_HANDLE": 2,
    "ICQ_NUMBER": 2,
    "WICKR_ID": 2,
    "COMBO_LIST_ENTRY": 1,
    "CRYPTO_SEED_PHRASE": 1,
    "RANSOMWARE_GROUP": 3,
    "THREAT_ACTOR": 3,
    "MALWARE_FAMILY": 3,
    "EMAIL_ADDRESS": 4,
    "PGP_KEY_BLOCK": 4,
    "DOMAIN": 5,
    "ORGANIZATION_NAME": 6,
    "PERSON_NAME": 6,
    "LOCATION": 7,
}
DEFAULT_PRIORITY = 99

# Tiebreak order when types have equal priority
TIEBREAK_ORDER = [
    "RANSOMWARE_GROUP",
    "THREAT_ACTOR",
    "MALWARE_FAMILY",
    "FILE_HASH_SHA256",
    "FILE_HASH_SHA1",
    "FILE_HASH_MD5",
    "CVE",
    "MITRE_TECHNIQUE",
    "IP_ADDRESS",
    "ONION_URL",
    # Credentials — vendor-specific wins over generic in a tie.
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "GITHUB_TOKEN",
    "SLACK_TOKEN",
    "DISCORD_TOKEN",
    "JWT_TOKEN",
    "GOOGLE_API_KEY",
    "STRIPE_KEY",
    "STEALER_LOG_ENTRY",
    "API_KEY",
    # Messaging / identity handles — placed next to credentials in the
    # tiebreak ladder so shape-specific messaging IOCs outrank EMAIL.
    "TELEGRAM_HANDLE",
    "DISCORD_HANDLE",
    "XMPP_JID",
    "TOX_ID",
    "SESSION_ID",
    "MATRIX_HANDLE",
    "WIRE_HANDLE",
    "ICQ_NUMBER",
    "WICKR_ID",
    # Network / forensic identifiers (Phase 2 — final subphase).  All
    # placed near the high-specificity IOCs at the top of the tiebreak
    # ladder so they win against generic types when the same value
    # would qualify as more than one entity.
    "IPV6_ADDRESS",
    "MAC_ADDRESS",
    "IPFS_CID",
    "EXPLOIT_DB_ID",
    "YARA_RULE",
    "NUCLEI_TEMPLATE",
    "MITRE_TACTIC",
    "COMBO_LIST_ENTRY",
    "CRYPTO_SEED_PHRASE",
    "EMAIL_ADDRESS",
    "PGP_KEY_BLOCK",
    "BITCOIN_ADDRESS",
    "ETHEREUM_ADDRESS",
    "MONERO_ADDRESS",
    "LITECOIN_ADDRESS",
    "ZCASH_ADDRESS",
    "DOGECOIN_ADDRESS",
    "XRP_ADDRESS",
    "SOLANA_ADDRESS",
    "TRON_ADDRESS",
    "BITCOIN_CASH_ADDRESS",
    "DASH_ADDRESS",
    "ENS_DOMAIN",
    "DOMAIN",
    "ORGANIZATION_NAME",
    "PERSON_NAME",
    "LOCATION",
]


def _get_priority(entity_type: str) -> int:
    return TYPE_PRIORITY.get(entity_type, DEFAULT_PRIORITY)


def _get_tiebreak_rank(entity_type: str) -> int:
    try:
        return TIEBREAK_ORDER.index(entity_type)
    except ValueError:
        return len(TIEBREAK_ORDER)


def resolve_entity_type_conflicts(entities: list) -> list:
    """
    Resolve entity type conflicts by keeping only the most specific type
    for each unique canonical value.

    When the same value appears with multiple types:
    - Lower TYPE_PRIORITY wins (higher specificity)
    - Equal priority resolved by TIEBREAK_ORDER
    """
    value_to_entities: dict[str, list] = {}
    for entity in entities:
        key = entity.value.lower()
        if key not in value_to_entities:
            value_to_entities[key] = []
        value_to_entities[key].append(entity)

    resolved = []
    for value_lower, group in value_to_entities.items():
        if len(group) == 1:
            resolved.append(group[0])
            continue

        type_to_entity = {}
        for entity in group:
            et = entity.entity_type
            if et not in type_to_entity:
                type_to_entity[et] = entity
            else:
                existing = type_to_entity[et]
                if entity.confidence > existing.confidence:
                    type_to_entity[et] = entity

        conflicting_types = list(type_to_entity.keys())
        if len(conflicting_types) == 1:
            resolved.append(type_to_entity[conflicting_types[0]])
            continue

        def _sort_key(t):
            return (_get_priority(t), _get_tiebreak_rank(t))

        conflicting_types.sort(key=_sort_key)
        winner_type = conflicting_types[0]
        winner = type_to_entity[winner_type]

        logger.debug(
            f"Type conflict: '{winner.value}' resolved from {conflicting_types} to {winner_type}"
        )
        resolved.append(winner)

    return resolved


def _validate_hash_length(entity_type: str, value: str) -> bool:
    """Validate that a hash entity has the correct length for its type."""
    if entity_type == "FILE_HASH_MD5":
        return len(value) == 32 and re.fullmatch(r"[0-9a-fA-F]{32}", value) is not None
    elif entity_type == "FILE_HASH_SHA1":
        return len(value) == 40 and re.fullmatch(r"[0-9a-fA-F]{40}", value) is not None
    elif entity_type == "FILE_HASH_SHA256":
        return len(value) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None
    return True


def _validate_onion_url(value: str) -> bool:
    """Return True only if value is a valid .onion address."""
    value = value.lower().strip()
    if not value.endswith(".onion") and ".onion/" not in value:
        return False
    _ONION_PATTERN = re.compile(r'^(https?://)?[a-z2-7]{16,56}\.onion(/.*)?$')
    return bool(_ONION_PATTERN.match(value))


def _validate_crypto_wallet(entity_type: str, value: str) -> bool:
    """
    Defensive shape check for the new cryptocurrency wallet types.

    The regex extractors already enforce these shapes, but this is a
    second-line check in the normalizer so a malformed value can never
    slip into the DB even if a future refactor weakens the regex.
    """
    if not value:
        return False

    if entity_type == "BITCOIN_ADDRESS":
        return _validate_bitcoin_address(value)
    if entity_type == "ETHEREUM_ADDRESS":
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
            return False
        # Lowercase/uppercase addresses are valid; mixed case must satisfy EIP-55.
        if value[2:] not in (value[2:].lower(), value[2:].upper()):
            return _eth_checksum(value) == value
        return True
    if entity_type == "MONERO_ADDRESS":
        return _validate_monero_address(value)

    if entity_type == "LITECOIN_ADDRESS":
        # L or M prefix, base58, 27-34 chars total
        return bool(re.fullmatch(r"[LM][a-km-zA-HJ-NP-Z1-9]{26,33}", value))

    if entity_type == "ZCASH_ADDRESS":
        # Transparent (t1/t3 + 33 base58) or shielded (zs1 + 74-78 [a-z0-9])
        return bool(
            re.fullmatch(r"t[13][a-km-zA-HJ-NP-Z1-9]{33}", value)
            or re.fullmatch(r"zs1[a-z0-9]{74,78}", value)
        )

    if entity_type == "DOGECOIN_ADDRESS":
        # D prefix, standard base58 (1-9 + A-Z excl I/O + a-z excl l), 26-34 chars total
        return bool(re.fullmatch(r"D[1-9A-HJ-NP-Za-km-z]{24,33}", value))

    if entity_type == "XRP_ADDRESS":
        # r prefix, 25-35 alphanumeric
        return bool(re.fullmatch(r"r[0-9a-zA-Z]{24,34}", value))

    if entity_type == "SOLANA_ADDRESS":
        # base58, 32-44 chars, no prefix
        return bool(re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", value))

    if entity_type == "TRON_ADDRESS":
        # T prefix, base58 (no 0/O/I/l), 34 chars total
        return bool(re.fullmatch(r"T[A-HJ-NP-Za-km-z1-9]{33}", value))

    if entity_type == "BITCOIN_CASH_ADDRESS":
        # cashaddr: bitcoincash:q... or bitcoincash:p... with 41-111 chars payload
        if not value.startswith("bitcoincash:"):
            return False
        payload = value[len("bitcoincash:"):]
        if len(payload) < 42 or len(payload) > 112:
            return False
        if payload[0] not in ("q", "p"):
            return False
        return bool(re.fullmatch(r"[a-z0-9]+", payload))

    if entity_type == "DASH_ADDRESS":
        # X prefix, base58 (excludes 0/O), 34 chars total
        return bool(re.fullmatch(r"X[1-9A-HJ-NP-Za-km-z]{33}", value))

    if entity_type == "ENS_DOMAIN":
        # <label>.eth, label 3-63 chars, alphanumeric + hyphen (no edge hyphens)
        if not value.lower().endswith(".eth"):
            return False
        label = value[:-4]
        if len(label) < 3 or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        return bool(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9]", label))

    # Unknown crypto entity type — let it through (validator should be added).
    return True


_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_decode(value: str) -> bytes:
    number = 0
    for char in value:
        number = number * 58 + _BASE58_ALPHABET.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + raw


def _validate_bitcoin_address(value: str) -> bool:
    if value.lower().startswith("bc1"):
        return _validate_bech32(value.lower())
    try:
        decoded = _base58_decode(value)
        return len(decoded) in (25, 26) and hashlib.sha256(hashlib.sha256(decoded[:-4]).digest()).digest()[:4] == decoded[-4:]
    except (ValueError, IndexError):
        return False


def _bech32_polymod(values: list[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit, gen in enumerate(generator):
            if (top >> bit) & 1:
                checksum ^= gen
    return checksum


def _validate_bech32(value: str) -> bool:
    if value.lower() != value and value.upper() != value:
        return False
    value = value.lower()
    if not value.startswith("bc1") or len(value) > 90:
        return False
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    pos = value.rfind("1")
    if pos < 1 or pos + 7 > len(value) or any(c not in alphabet for c in value[pos + 1:]):
        return False
    data = [alphabet.index(c) for c in value[pos + 1:]]
    hrp = [ord(c) >> 5 for c in value[:pos]] + [0] + [ord(c) & 31 for c in value[:pos]]
    if _bech32_polymod(hrp + data) not in (1, 0x2BC830A3):
        return False
    return 2 <= data[0] <= 40 and 4 <= len(data[1:-6]) <= 65


def _validate_monero_address(value: str) -> bool:
    if not re.fullmatch(r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}", value):
        return False
    try:
        decoded = b""
        for start in range(0, len(value), 11):
            block = value[start:start + 11]
            decoded += _base58_decode(block)
        if len(decoded) < 5:
            return False
        try:
            from Crypto.Hash import keccak
            digest = keccak.new(digest_bits=256, data=decoded[:-4]).digest()
        except ImportError:
            from eth_hash.auto import keccak
            digest = keccak(decoded[:-4])
        return digest[:4] == decoded[-4:]
    except (ValueError, IndexError, ImportError):
        return False


def _validate_network_forensic(entity_type: str, value: str) -> bool:
    """
    Defensive shape check for the network / forensic identifier types
    added per Phase 2 (final subphase).

    The regex extractors already enforce these shapes via regex +
    validators, but this is a second line of defence so a malformed
    value can never reach the DB even if a future refactor weakens the
    regex.

    Returns True if the value passes the shape check, False otherwise.
    """
    if not value:
        return False

    if entity_type == "IPV6_ADDRESS":
        # Defer to the regex_patterns helper (handles all standard
        # forms plus the private/loopback filter).
        try:
            from extractor.regex_patterns import _is_valid_ipv6
            return _is_valid_ipv6(value)
        except Exception:
            return False

    if entity_type == "MAC_ADDRESS":
        # Canonical form is AA:BB:CC:DD:EE:FF (17 chars, 5 colons).
        return bool(re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}", value))

    if entity_type == "IPFS_CID":
        # CIDv0 (Qm + 44 base58) or CIDv1 (bafy + 55-60 base32)
        return bool(
            re.fullmatch(r"Qm[1-9A-HJ-NP-Za-km-z]{44}", value)
            or re.fullmatch(r"bafy[a-z2-7]{55,60}", value)
        )

    if entity_type == "YARA_RULE":
        return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{2,127}", value))

    if entity_type == "MITRE_TACTIC":
        if not re.fullmatch(r"TA\d{4}", value):
            return False
        n = int(value[2:])
        return 1 <= n <= 43

    if entity_type == "EXPLOIT_DB_ID":
        return bool(re.fullmatch(r"[0-9]{4,6}", value))

    if entity_type == "NUCLEI_TEMPLATE":
        return bool(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+){2,6}", value))

    if entity_type == "COMBO_LIST_ENTRY":
        # The canonical value is the email side of an email:password
        # line.  It must look like an email and must NOT contain the
        # password-substring indicators (a downstream blocklist check
        # catches that — this is the shape check).
        return "@" in value and "." in value

    if entity_type == "CRYPTO_SEED_PHRASE":
        # The canonical value is one of two fixed marker strings.  If
        # a future refactor accidentally leaks an actual seed phrase
        # through the normalizer, we reject anything that is not one
        # of the two known marker strings.
        return value in (
            "SEED_PHRASE_DETECTED_12_WORDS",
            "SEED_PHRASE_DETECTED_24_WORDS",
        )

    return True


# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Confidence scores by extraction source (inferred from entity_type)
# ---------------------------------------------------------------------------

_TIER_1_CONFIDENCE = 1.0
_TIER_2_CONFIDENCE = 0.90
_TIER_3_CONFIDENCE = 0.82
_MAX_OCCURRENCE_BOOST = 0.05

_REGEX_TYPES: frozenset[str] = frozenset({
    "BITCOIN_ADDRESS",
    "ETHEREUM_ADDRESS",
    "MONERO_ADDRESS",
    "LITECOIN_ADDRESS",
    "ZCASH_ADDRESS",
    "DOGECOIN_ADDRESS",
    "XRP_ADDRESS",
    "SOLANA_ADDRESS",
    "TRON_ADDRESS",
    "BITCOIN_CASH_ADDRESS",
    "DASH_ADDRESS",
    "ENS_DOMAIN",
    "ONION_URL",
    "EMAIL_ADDRESS",
    "PGP_KEY_BLOCK",
    "CVE_NUMBER",
    "FILE_HASH_MD5",
    "FILE_HASH_SHA1",
    "FILE_HASH_SHA256",
    "IP_ADDRESS",
    "PHONE_NUMBER",
    "PASTE_URL",
    "MITRE_TECHNIQUE",
    # Credential / token types — all bypass blocklist and use regex confidence.
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "GITHUB_TOKEN",
    "SLACK_TOKEN",
    "DISCORD_TOKEN",
    "JWT_TOKEN",
    "GOOGLE_API_KEY",
    "STRIPE_KEY",
    "STEALER_LOG_ENTRY",
    "API_KEY",
    # Messaging / identity handle types — also bypass blocklist (their
    # shapes are precise enough to require a context-keyword check in the
    # regex extractor; the blocklist would otherwise false-positive on
    # common messaging usernames).
    "TELEGRAM_HANDLE",
    "DISCORD_HANDLE",
    "XMPP_JID",
    "TOX_ID",
    "SESSION_ID",
    "MATRIX_HANDLE",
    "WIRE_HANDLE",
    "ICQ_NUMBER",
    "WICKR_ID",
    # Network / forensic identifier types (Phase 2 — final subphase).
    # Bypass the blocklist (their shapes are precise / context-checked)
    # and use the per-type confidence map below.
    "IPV6_ADDRESS",
    "MAC_ADDRESS",
    "IPFS_CID",
    "YARA_RULE",
    "MITRE_TACTIC",
    "EXPLOIT_DB_ID",
    "NUCLEI_TEMPLATE",
    "COMBO_LIST_ENTRY",
    "CRYPTO_SEED_PHRASE",
})

_TIER_1_TYPES: frozenset[str] = frozenset({
    "BITCOIN_ADDRESS",
    "FILE_HASH_MD5",
    "FILE_HASH_SHA1",
    "FILE_HASH_SHA256",
    "CVE",
    "CVE_NUMBER",
    "MITRE_TECHNIQUE",
    "ONION_URL",
    "EMAIL_ADDRESS",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "GITHUB_TOKEN",
    "SLACK_TOKEN",
    "DISCORD_TOKEN",
    "JWT_TOKEN",
    "GOOGLE_API_KEY",
    "STRIPE_KEY",
    "STEALER_LOG_ENTRY",
    "TOX_ID",
    "SESSION_ID",
    "MATRIX_HANDLE",
    "IPV6_ADDRESS",
    "MAC_ADDRESS",
    "IPFS_CID",
    "MITRE_TACTIC",
    "EXPLOIT_DB_ID",
})

_TIER_2_TYPES: frozenset[str] = frozenset({
    "ETHEREUM_ADDRESS",
    "ETH_ADDRESS",
    "MONERO_ADDRESS",
    "LITECOIN_ADDRESS",
    "ZCASH_ADDRESS",
    "DOGECOIN_ADDRESS",
    "XRP_ADDRESS",
    "SOLANA_ADDRESS",
    "TRON_ADDRESS",
    "BITCOIN_CASH_ADDRESS",
    "DASH_ADDRESS",
    "ENS_DOMAIN",
    "IP_ADDRESS",
    "PHONE_NUMBER",
    "TELEGRAM_HANDLE",
    "DISCORD_HANDLE",
    "XMPP_JID",
    "WIRE_HANDLE",
    "ICQ_NUMBER",
    "WICKR_ID",
    "YARA_RULE",
    "NUCLEI_TEMPLATE",
    "COMBO_LIST_ENTRY",
    "CRYPTO_SEED_PHRASE",
    "API_KEY",
})

_TIER_3_TYPES: frozenset[str] = frozenset({
    "THREAT_ACTOR_HANDLE",
    "ORGANIZATION_NAME",
    "PERSON_NAME",
    "LOCATION",
    "DATE",
})

_NER_TYPES: frozenset[str] = frozenset({
    "THREAT_ACTOR_HANDLE",
    "MALWARE_FAMILY",
    "RANSOMWARE_GROUP",
    "ORGANIZATION_NAME",
})


_ELEVATED_CONFIDENCE: dict[str, float] = {
    "DATE": 0.82,
    "DOMAIN": 0.82,
    "LOCATION": 0.82,
    "PERSON_NAME": 0.82,
}


def _confidence_for(entity_type: str, extraction_method: str = "") -> float:
    if extraction_method.upper() == "LLM":
        return 0.80
    if entity_type in _TIER_1_TYPES:
        return _TIER_1_CONFIDENCE
    if entity_type in _TIER_2_TYPES:
        return _TIER_2_CONFIDENCE
    if entity_type in _TIER_3_TYPES:
        return _TIER_3_CONFIDENCE
    if entity_type in _REGEX_TYPES:
        return _TIER_1_CONFIDENCE
    if entity_type in _NER_TYPES:
        return _TIER_3_CONFIDENCE
    return _ELEVATED_CONFIDENCE.get(entity_type, 0.75)


# Backward-compatible export for the existing Phase 1 test suite.  The new
# tiered model still exposes the regex-type confidence mapping, but its values
# now reflect the calibrated tiers.
_REGEX_TYPE_CONFIDENCE: dict[str, float] = {
    entity_type: _confidence_for(entity_type)
    for entity_type in _REGEX_TYPES
}


def _extraction_method_for(entity_type: str, override: str = "") -> str:
    if override:
        return override
    if entity_type in _REGEX_TYPES:
        return "regex"
    if entity_type in _NER_TYPES:
        return "NER"
    return "LLM"


# Regex IOC types whose canonical form is a genuine cryptographic checksum, not
# just a shape match, when the checksum library is available.
_CHECKSUM_TYPES: frozenset[str] = frozenset({"ETHEREUM_ADDRESS", "ETH_ADDRESS"})


def _validation_tier(entity_type: str, value: str, shape_verdict, raw_value: Optional[str] = None) -> str:
    """Classify how strongly *value* was validated, for confidence computation.

    Name types carry the shape/gazetteer tier from entity_shape; regex IOC types
    are at least format-verified (the pattern enforces a precise structure) and
    checksum-verified when the address as written genuinely passes EIP-55
    (Ethereum).  The checksum test runs against the *raw* extracted string —
    the canonical form is re-checksummed, so testing it would always pass.
    """
    if shape_verdict is not None:
        return shape_verdict.tier
    if entity_type in _REGEX_TYPES:
        if entity_type in _CHECKSUM_TYPES and eth_is_checksum_valid(
            raw_value if raw_value is not None else value
        ):
            return "checksum_verified"
        return "format_verified"
    # Remaining NER/LLM types (PERSON_NAME, LOCATION, DATE) that cleared the
    # light structural check — a modest positive tier, not "unvalidated".
    return "heuristic_ok"


def _context_snippet(page_text: str, needle: str, max_len: int = 2000) -> str:
    """Return a window of *page_text* around *needle* for analyst / stylometry context."""
    try:
        if not page_text or not needle:
            return ""
        idx = page_text.find(needle)
        if idx < 0:
            idx = page_text.lower().find(needle.lower())
        if idx < 0:
            return ""
        half = max_len // 2
        start = max(0, idx - half)
        end = min(len(page_text), start + max_len)
        return page_text[start:end].strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Blocklist (NER / LLM only — regex types bypass; see normalize_entities)
# ---------------------------------------------------------------------------

ENTITY_BLOCKLIST: frozenset[str] = frozenset({
    "bitcoin", "btc", "ethereum", "eth", "monero", "xmr", "litecoin", "ltc",
    "dogecoin", "doge", "dash", "zcash", "zec", "ripple", "xrp", "usdt",
    "tether", "usdc", "bnb", "solana", "sol",
    "darknet", "dark web", "darkweb", "deep web", "tor", "onion",
    "marketplace", "market", "shop", "store", "vendor",
    "interface", "server", "client", "host", "system", "network",
    "database", "application", "service", "api", "endpoint",
    "stop", "start", "end", "new", "old", "free", "paid", "pro", "basic",
    "admin", "user", "root", "guest", "test", "demo",
    "h4ck3r", "h4cker", "hax0r", "haxor", "1337", "leet", "elite",
    "noob", "n00b", "script", "scriptkiddie", "skid",
    "vproxy", "proxychains", "nmap", "metasploit", "burpsuite",
    "cobalt", "covenant", "empire", "mimikatz", "lazagne", "pypykatz",
    "identities", "identity", "workflows", "workflow", "process",
    "processes", "services", "service", "systems", "system",
    "network", "networks", "access", "accounts", "account",
    "platform", "platforms", "solution", "solutions",
    "interface", "interfaces", "backend", "frontend",
    "resources", "resource", "project", "projects",
    "community", "communities", "member", "members",
    "moderator", "administrator", "operator", "staff", "support",
    "customer", "vendor", "buyer", "seller", "trader",
    "dropper", "loader", "stager", "payload", "beacon",
    # Audit-confirmed NER false positives (1.6.2, 1.7.0, 1.7.1).
    "asks", "keyword", "sends", "input", "content", "delivery", "into",
    "submits", "advertising", "attempts", "pass", "consent", "devices",
    "stdin", "stdout", "detect", "uri_regex:1", "intel", "passive",
    "commands",
})

KNOWN_TOOLS: frozenset[str] = frozenset({
    "nmap", "metasploit", "cobaltstr", "cobaltstrike", "empire",
    "covenant", "brute", "hydra", "sqlmap", "nikto", "burp",
    "wireshark", "tcpdump", "netcat", "nc", "vproxy", "proxifier",
    "tor", "torbrowser", "onionbrowser", "i2p", "freenet",
    "kali", "parrot", "blackarch", "backtrack",
})

COMMON_THREAT_TERMS: frozenset[str] = frozenset({
    "apt41", "apt28", "apt29", "fin7", "fin8", "lockbitsupp",
    "scatteredspider", "lazarus", "sandworm", "blackcat", "alphv",
})

LEET_GENERIC = re.compile(r"^h[4a][ck]+[3e]?r?$")
HANDLE_SHAPE_RE = re.compile(
    r"^(?:[A-Z]{2,}\d{1,3}|[A-Za-z]+[A-Z][A-Za-z0-9]*|[A-Za-z0-9]+[_\-.][A-Za-z0-9_.-]+|[A-Za-z]+\d+[A-Za-z0-9]*)$"
)


ENTITY_MIN_LENGTH: dict[str, int] = {
    "THREAT_ACTOR_HANDLE": 4,
    "MALWARE_FAMILY": 3,
    "RANSOMWARE_GROUP": 4,
    "ORGANIZATION_NAME": 4,
    "BITCOIN_ADDRESS": 10,
    "ETHEREUM_ADDRESS": 10,
    "MONERO_ADDRESS": 10,
    "LITECOIN_ADDRESS": 10,
    "ZCASH_ADDRESS": 10,
    "DOGECOIN_ADDRESS": 10,
    "XRP_ADDRESS": 10,
    "SOLANA_ADDRESS": 10,
    "TRON_ADDRESS": 10,
    "BITCOIN_CASH_ADDRESS": 16,  # includes the "bitcoincash:" prefix
    "DASH_ADDRESS": 10,
    "ENS_DOMAIN": 5,  # "<a>.eth" minimum
    "ONION_URL": 16,
    "EMAIL_ADDRESS": 6,
    "CVE_NUMBER": 9,
    "IP_ADDRESS": 7,
    "PGP_KEY_BLOCK": 8,
    "PASTE_URL": 10,
    # Credential / token min lengths — the regexes already enforce
    # the structural shape, these floors only matter as a defence in
    # depth against a future refactor that loosens the regex.
    "AWS_ACCESS_KEY": 20,    # AKIA + 16
    "AWS_SECRET_KEY": 40,    # base64 40
    "GITHUB_TOKEN": 10,      # prefix + payload
    "SLACK_TOKEN": 20,       # xox[bpas]- + payload
    "DISCORD_TOKEN": 50,     # 24+1+6+1+27 = 59, but at least 50
    "JWT_TOKEN": 20,         # eyJ... + 2 segments
    "GOOGLE_API_KEY": 39,    # AIza + 35
    "STRIPE_KEY": 30,        # sk_live_ + 24
    "STEALER_LOG_ENTRY": 8,  # the URL string itself
    "API_KEY": 16,
    # Messaging / identity handle min lengths — these are defence-in-depth
    # floors; the regexes already enforce the shape (e.g. Telegram username
    # is 5-32 chars, Tox ID is exactly 76 hex chars).
    "TELEGRAM_HANDLE": 5,    # "lockb" (5 chars) is the shortest valid Telegram username
    "DISCORD_HANDLE": 3,     # "ab#0" technically too short for discriminator; minimum realistic: "ab#0000" (6)
    "XMPP_JID": 6,           # a@b.cd
    "TOX_ID": 76,            # exactly 76 hex chars
    "SESSION_ID": 66,        # 66 hex chars (05 + 64)
    "MATRIX_HANDLE": 5,      # @a:b.cd
    "WIRE_HANDLE": 2,        # "ab"
    "ICQ_NUMBER": 5,         # 5-digit UIN
    "WICKR_ID": 1,           # single char (rare but valid)
    # Network / forensic identifier min lengths (Phase 2 — final subphase).
    # These are defence-in-depth floors; the regexes already enforce the
    # structural shape, but the floors stop a future refactor from
    # silently allowing a too-short value through.
    "IPV6_ADDRESS": 2,         # "::" is the shortest valid form
    "MAC_ADDRESS": 17,         # "AA:BB:CC:DD:EE:FF" (17 chars including colons)
    "IPFS_CID": 46,            # Qm + 44 base58 (46 chars)
    "YARA_RULE": 3,            # 3-char minimum identifier per regex
    "MITRE_TACTIC": 6,         # "TA0001" — 6 chars
    "EXPLOIT_DB_ID": 4,        # 4-digit minimum
    "NUCLEI_TEMPLATE": 5,      # "a-b-c" minimum (3 segments)
    "COMBO_LIST_ENTRY": 5,     # "a@b.c" minimum
    "CRYPTO_SEED_PHRASE": 24,  # "SEED_PHRASE_DETECTED_12_WORDS"
}


def normalize_wallet_value(value: str) -> str:
    """Normalize wallet addresses for deduplication (Ethereum compared lowercase)."""
    value = value.strip()
    if value.startswith("0x"):
        return value.lower()
    return value


def is_blocked_entity(entity_type: str, entity_value: str) -> bool:
    """
    Returns True if an entity should be filtered as noise (NER/LLM only).
    Regex-extracted entities must not use this — their patterns are precise.
    """
    value_lower = entity_value.lower().strip()

    if value_lower in ENTITY_BLOCKLIST:
        return True

    if entity_type == "THREAT_ACTOR_HANDLE":
        if value_lower in KNOWN_TOOLS:
            return True
        if LEET_GENERIC.match(value_lower):
            return True
        if value_lower in COMMON_THREAT_TERMS:
            return False
        if re.fullmatch(r"[a-z]+", value_lower) and not HANDLE_SHAPE_RE.match(entity_value.strip()):
            return True

    if entity_type == "ORGANIZATION_NAME" and value_lower in ENTITY_BLOCKLIST:
        return True

    min_len = ENTITY_MIN_LENGTH.get(entity_type, 3)
    if len(value_lower) < min_len:
        return True

    norm_num = value_lower.replace(".", "").replace(",", "")
    if norm_num.isnumeric():
        return True

    return False


# ---------------------------------------------------------------------------
# Reserved-range / placeholder blocklists  (v1.7 — Q-1/Q-2 fixes)
# ---------------------------------------------------------------------------
#
# RFC 5737 documentation IP ranges — reserved for use in examples/docs,
# never real routable addresses.
#   192.0.2.0/24  (TEST-NET-1)
#   198.51.100.0/24 (TEST-NET-2)
#   203.0.113.0/24 (TEST-NET-3)
_RFC5737_NETWORKS: list[tuple[str, str]] = [
    ("192.0.2.0", "255.255.255.0"),    # 192.0.2.0/24
    ("198.51.100.0", "255.255.255.0"),  # 198.51.100.0/24
    ("203.0.113.0", "255.255.255.0"),   # 203.0.113.0/24
]

# Real, routable IPs that are never a meaningful indicator of compromise:
# the unspecified/null address, the broadcast address, and the well-known
# public DNS resolvers that appear constantly in technical content for
# reasons unrelated to being an IOC.  Filtered like the RFC 5737 ranges so a
# user pulling ip_addresses.txt into a blocklist can't end up blocking a
# legitimate public resolver or a null route.
_NON_ACTIONABLE_IPS: frozenset[str] = frozenset({
    "0.0.0.0",              # unspecified / null route — never a real host
    "255.255.255.255",      # limited broadcast
    "8.8.8.8", "8.8.4.4",           # Google Public DNS
    "1.1.1.1", "1.0.0.1",           # Cloudflare Public DNS
    "9.9.9.9", "149.112.112.112",   # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "4.2.2.1", "4.2.2.2",           # Level3 legacy resolvers
})


def _is_non_actionable_ip(value: str) -> bool:
    """Return True for real IPs that are never meaningful IOCs (null route, public DNS)."""
    return value.strip() in _NON_ACTIONABLE_IPS

# RFC 2606 reserved domain names.
_RFC2606_DOMAINS: frozenset[str] = frozenset({
    "example.com",
    "example.net",
    "example.org",
    "example.edu",
    "test",
})

# Well-known placeholder email patterns that appear in examples/docs.
_PLACEHOLDER_EMAIL_RE = re.compile(
    r"(?i)^(test|user|admin|example|foo|bar|noreply|no.reply)"
    r"@(example\.com|example\.net|example\.org|domain\.com|localhost)$"
)


def _is_rfc5737_ip(value: str) -> bool:
    """Return True if value is an IPv4 address in an RFC 5737 documentation range."""
    try:
        ip = __import__("ipaddress").ip_address(value.strip())
        if not isinstance(ip, __import__("ipaddress").IPv4Address):
            return False
        for net_str, mask_str in _RFC5737_NETWORKS:
            network = __import__("ipaddress").IPv4Network(f"{net_str}/{mask_str}", strict=False)
            if ip in network:
                return True
        return False
    except Exception:
        return False


def _is_rfc2606_domain(value: str) -> bool:
    """Return True if value is an RFC 2606 reserved domain."""
    v = value.strip().lower()
    # Exact match
    if v in _RFC2606_DOMAINS:
        return True
    # Suffix match: "foo.example.com" etc.
    parts = v.split(".")
    for i in range(1, len(parts)):
        suffix = ".".join(parts[i:])
        if suffix in _RFC2606_DOMAINS:
            return True
    return False


def _is_placeholder_email(value: str) -> bool:
    """Return True if value looks like a documentation/example email address."""
    return bool(_PLACEHOLDER_EMAIL_RE.match(value.strip()))


# ---------------------------------------------------------------------------
# Source quality assignment  (v1.7 — Q-2: GitHub source tier)
# ---------------------------------------------------------------------------
#
# Known low-trust URL patterns that are documentation/example content, not
# actual threat intelligence.  Entities extracted from these are given
# source_quality=0.6 and are further de-prioritised in the entity cap.

_LOW_TRUST_URL_PATH_RE = re.compile(
    r"(?i)"
    # README, CHANGELOG, LICENSE, CONTRIBUTING, SECURITY, INSTALL, docs/
    # anything at the repo root that looks like documentation
    r"(^|/)(README|CHANGELOG|LICENSE|CONTRIBUTING|SECURITY|"
    r"INSTALL|USER_GUIDE|DOCUMENTATION"
    r"(\.md|\.txt|\.rst|\.html)?"
    r"|(^|/)(docs?|examples?|specs?|schemas?)"
    r"|(\.github[/\\])"          # GitHub Actions / stored workflow files
    r"|((^|/)examples?/)"         # example/ directory
    r"|(/issues/[0-9]+)"          # GitHub issue comment — moderate signal
    r"|(/pull/[0-9]+)"            # PR comment — moderate signal
    r"|(\.git)"                   # git metadata URLs
    r")"
)


def _source_quality_from_url(url: str) -> float:
    """
    Return a source-quality multiplier (0.0-1.0) for a given source URL.

    Higher values = more trustworthy source.  Used to de-prioritise
    documentation and example content vs. actual threat intel sources.
    """
    if not url:
        return 1.0
    url_lower = url.lower()

    # GitHub
    if "github.com" in url_lower:
        if _LOW_TRUST_URL_PATH_RE.search(url):
            return 0.6
        # GitHub issue / PR comments — moderate value
        if "/issues/" in url_lower or "/pull/" in url_lower:
            return 0.7
        # Default GitHub pages (raw blob from a repo)
        return 0.6

    # GitLab
    if "gitlab.com" in url_lower:
        if _LOW_TRUST_URL_PATH_RE.search(url):
            return 0.6
        if "/issues/" in url_lower or "/merge_requests/" in url_lower:
            return 0.7
        return 0.6

    # Default: primary threat source
    return 1.0


# ---------------------------------------------------------------------------
# NormalizedEntity dataclass
# ---------------------------------------------------------------------------


@dataclass
class NormalizedEntity:
    entity_type: str
    value: str
    confidence: float
    source_url: str
    page_id: Optional[uuid.UUID]
    context_snippet: str = field(default="")
    extraction_method: str = field(default="")
    # v1.7 — source_quality reflects the trustworthiness of the source.
    # Higher = more credible.  Used to downgrade README / documentation sources.
    # 1.0 = primary threat source (dark web, paste sites, RSS, forum posts)
    # 0.6 = secondary source (GitHub README, GitLab repo files)
    # 0.0 = placeholder / reserved range (RFC 5737 IPs, RFC 2606 domains)
    source_quality: float = field(default=1.0)
    # Validation tier that fed the computed confidence — one of
    # "checksum_verified", "format_verified", "gazetteer", "shape_strong",
    # "shape_ok", "shape_weak", "unvalidated".  Kept for introspection/ranking;
    # not persisted to the DB.
    validation_tier: str = field(default="")
    # The cleaned/extracted text that produced this entity.  Entity-path page
    # persistence can use this to materialize the same page content that was
    # already available to extraction instead of creating a URL-only row.
    cleaned_text: str = field(default="")

    @property
    def canonical_value(self) -> str:
        # Return the genuine canonical (deduplication-safe) form of the value,
        # matching what the DB `Entity.canonical_value` column means.  This used
        # to return the raw `self.value`, which silently disagreed with the DB
        # column of the same name — a daily trap and the direct cause of the
        # IOC-package casing bug.  Canonicalising here makes the two
        # representations agree.  (Prefer `extractor.identity.entity_canonical_id`
        # in new code so the choice is explicit at the call site.)
        return canonicalize_entity_value(self.entity_type, self.value)

    @property
    def is_placeholder(self) -> bool:
        """True when the entity is a known reserved-range value, not real intel."""
        return self.source_quality == 0.0

    def get(self, key: str, default=None):
        return getattr(self, key, default)

    def __getitem__(self, key: str):
        return getattr(self, key)


# ---------------------------------------------------------------------------
# Normalization rules per entity type
# ---------------------------------------------------------------------------


def _normalize_value(entity_type: str, value: str) -> str:
    """
    Return the canonical form of *value* for a given *entity_type*.
    Never raises — on any error returns the value stripped of leading/trailing
    whitespace.
    """
    try:
        if entity_type == "BITCOIN_ADDRESS":
            if value.lower().startswith("bc1"):
                return value.lower()
            return value

        if entity_type == "ETHEREUM_ADDRESS":
            return _eth_checksum(value)

        if entity_type == "EMAIL_ADDRESS":
            return value.lower()

        if entity_type == "CVE_NUMBER":
            return value.upper()

        if entity_type == "MITRE_TECHNIQUE":
            return value.upper()

        if entity_type in ("FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"):
            return value.lower()

        if entity_type == "ONION_URL":
            try:
                from crawler.utils import normalize_url
                return normalize_url(value)
            except Exception:
                parsed_lower = value.lower()
                return parsed_lower

        stripped = value.strip()
        return re.sub(r"\s+", " ", stripped)

    except Exception:
        return value.strip()


# ---------------------------------------------------------------------------
# Ethereum EIP-55 checksum support (import once at module load)
# ---------------------------------------------------------------------------
# We use eth-utils (a lightweight checksum-only library) rather than full web3
# so an extracted Ethereum address can be genuinely checksum-validated instead
# of only shape-matched.  web3 is accepted as a fallback if it happens to be the
# thing installed; without either, ETH addresses degrade to format-verified.

_eth_to_checksum = None
_eth_is_checksum = None
try:
    from eth_utils import to_checksum_address as _eth_to_checksum
    from eth_utils import is_checksum_address as _eth_is_checksum
    ETH_CHECKSUM_AVAILABLE = True
except Exception:
    try:
        from web3 import Web3 as _Web3

        _eth_to_checksum = _Web3.to_checksum_address
        _eth_is_checksum = _Web3.is_checksum_address
        ETH_CHECKSUM_AVAILABLE = True
    except Exception:
        ETH_CHECKSUM_AVAILABLE = False

# Backwards-compatible alias (older code / tests referenced WEB3_AVAILABLE).
WEB3_AVAILABLE = ETH_CHECKSUM_AVAILABLE


def _eth_checksum(addr: str) -> str:
    """
    Apply EIP-55 mixed-case checksum encoding to an Ethereum address.
    Falls back to lowercase if no checksum library is available or it fails.
    """
    if not addr:
        return ""

    addr = addr.strip()
    if not addr.startswith("0x") or len(addr) != 42:
        return addr.lower()

    if not ETH_CHECKSUM_AVAILABLE:
        return addr.lower()

    try:
        return _eth_to_checksum(addr)
    except Exception:
        return addr.lower()


def eth_is_checksum_valid(addr: str) -> bool:
    """Return True only if *addr* is written in valid EIP-55 checksummed form.

    An all-lowercase (or all-uppercase) address is syntactically valid but not
    checksum-protected, so it is NOT checksum-verified — this is the genuine
    "checksum-valid vs. shape-only" distinction the confidence model rewards.
    Returns False when no checksum library is available.
    """
    if not ETH_CHECKSUM_AVAILABLE or not addr:
        return False
    addr = addr.strip()
    if not addr.startswith("0x") or len(addr) != 42:
        return False
    try:
        return bool(_eth_is_checksum(addr))
    except Exception:
        return False


def canonicalize_entity_value(entity_type: str, value: str) -> str:
    """
    Produce a canonical form of an entity value for deduplication.
    The canonical form is used as the dedup key — NOT stored as the display value.
    The original casing/formatting is preserved for display.
    """
    if not value:
        return (value or "").lower().strip()

    v = value.strip()

    if entity_type in ("THREAT_ACTOR", "MALWARE", "FORUM", "THREAT_ACTOR_HANDLE", "MALWARE_FAMILY", "RANSOMWARE_GROUP"):
        v = unicodedata.normalize("NFKD", v)
        v = v.encode("ascii", "ignore").decode("ascii")
        v = v.lower()
        v = re.sub(r"[\s\-_\.]", "", v)
        v = re.sub(r"[^\w]", "", v)
        return v

    elif entity_type in (
        "WALLET",
        "BITCOIN_ADDRESS",
        "ETHEREUM_ADDRESS",
        "MONERO_ADDRESS",
        "LITECOIN_ADDRESS",
        "ZCASH_ADDRESS",
        "DOGECOIN_ADDRESS",
        "XRP_ADDRESS",
        "SOLANA_ADDRESS",
        "TRON_ADDRESS",
        "BITCOIN_CASH_ADDRESS",
        "DASH_ADDRESS",
    ):
        if v.startswith("0x"):
            return v.lower()
        if v.startswith("4") and len(v) in (95, 106):
            return v.lower()
        if v.startswith("bitcoincash:"):
            # Lowercase the BCH prefix; cashaddr payload is already lowercase.
            return v.lower()
        if v.startswith("zs1"):
            return v.lower()
        # Solana / XRP / LTC / DOGE / TRX / DASH / ZEC: case-preserving
        # canonical forms (base58 alphabet is mixed case but addresses are
        # conventionally written in their original case to preserve the
        # implicit checksum).  We only normalize outer whitespace.
        return v.strip()

    elif entity_type == "ENS_DOMAIN":
        return v.lower().strip()

    elif entity_type in (
        # Credential / token canonicalisation — strip whitespace,
        # preserve original case (secrets are case-sensitive).  AWS
        # access keys are upper-case by format but we don't enforce
        # that here (the regex enforces it upstream).
        "AWS_ACCESS_KEY",
        "AWS_SECRET_KEY",
        "GITHUB_TOKEN",
        "SLACK_TOKEN",
        "DISCORD_TOKEN",
        "JWT_TOKEN",
        "GOOGLE_API_KEY",
        "STRIPE_KEY",
        "STEALER_LOG_ENTRY",
        "API_KEY",
    ):
        return v.strip()

    elif entity_type in (
        # Network / forensic identifier canonicalisation.  Most of these
        # are case-insensitive (IPv6 hex, MAC upper-cased, IPFS base58
        # / base32 which use a specific charset, MITRE tactic IDs are
        # uppercase, EDB-IDs numeric, YARA rule names case-preserved).
        # IPFS CIDs are kept as-is (base58/base32 charsets don't
        # benefit from case folding; the regex enforces the charset).
        # COMBO_LIST_ENTRY is the email side of a credential combo
        # block — same canonicalisation as EMAIL_ADDRESS.
        # CRYPTO_SEED_PHRASE is a marker string already; preserved.
        "IPV6_ADDRESS",
        "MAC_ADDRESS",
        "IPFS_CID",
        "YARA_RULE",
        "MITRE_TACTIC",
        "EXPLOIT_DB_ID",
        "NUCLEI_TEMPLATE",
        "COMBO_LIST_ENTRY",
        "CRYPTO_SEED_PHRASE",
    ):
        if entity_type == "MITRE_TACTIC":
            return v.upper().strip()
        if entity_type == "MAC_ADDRESS":
            # Canonicalise to uppercase colon form via the regex
            # helper (the extractor already does this on extraction
            # but the normaliser re-applies as defence in depth).
            from extractor.regex_patterns import _normalize_mac_address
            return _normalize_mac_address(v)
        if entity_type == "IPV6_ADDRESS":
            # Lowercase the hex (RFC 5952 recommends lowercase for
            # display) but preserve the zone-id suffix.
            base, sep, zone = v.partition("%")
            return base.lower() + (sep + zone if zone else "")
        if entity_type == "NUCLEI_TEMPLATE":
            return v.lower().strip()
        if entity_type == "COMBO_LIST_ENTRY":
            return v.lower().strip()
        return v.strip()

    elif entity_type in (
        # Messaging / identity handle canonicalisation.  Most platforms
        # treat handles as case-insensitive (Telegram, Discord, Wire,
        # Wickr, Matrix, XMPP) so we lowercase.  TOX_ID is always uppercase
        # hex by convention.  SESSION_ID is always lowercase.  ICQ number
        # is numeric and stays as-is.
        "TELEGRAM_HANDLE",
        "DISCORD_HANDLE",
        "XMPP_JID",
        "MATRIX_HANDLE",
        "WIRE_HANDLE",
        "WICKR_ID",
        "TOX_ID",
        "SESSION_ID",
        "ICQ_NUMBER",
    ):
        if entity_type == "TOX_ID":
            return v.upper().strip()
        if entity_type == "ICQ_NUMBER":
            return v.strip()
        return v.lower().strip()

    elif entity_type in ("CVE", "CVE_NUMBER"):
        v = v.upper().strip()
        v = re.sub(r"\s+", "-", v)
        return v

    elif entity_type in ("FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"):
        return v.lower()

    elif entity_type == "MITRE_TECHNIQUE":
        return v.upper().strip()

    elif entity_type in ("EMAIL", "EMAIL_ADDRESS"):
        return v.lower().strip()

    elif entity_type == "ONION_URL":
        v = v.lower().rstrip("/")
        v = re.sub(r"^https://", "http://", v)
        return v

    elif entity_type in ("PGP_KEY", "PGP_KEY_BLOCK"):
        normalized = re.sub(r"\s+", "", v).upper()
        return "pgp:" + hashlib.sha256(normalized.encode()).hexdigest()

    else:
        v = v.lower().strip()

    return v[:1024]


def are_same_entity(type_a: str, value_a: str, type_b: str, value_b: str) -> bool:
    """Returns True if two entities should be considered the same."""
    if type_a != type_b:
        return False
    return canonicalize_entity_value(type_a, value_a) == canonicalize_entity_value(type_b, value_b)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def normalize_entities(
    raw_entities: dict[str, list[str]],
    page_url: str,
    page_id: Optional[uuid.UUID] = None,
    page_text: Optional[str] = None,
    extraction_method_overrides: Optional[dict[tuple[str, str], str]] = None,
) -> list[NormalizedEntity]:
    """
    Convert raw extraction results into deduplicated NormalizedEntity records.
    """
    seen_values: set[str] = set()
    result: list[NormalizedEntity] = []

    noise_count = 0

    for raw_entity_type, values in raw_entities.items():
        for raw_value in values:
            if not raw_value or not raw_value.strip():
                continue

            entity_type = raw_entity_type

            # NER may label a known actor/malware span as ORGANIZATION_NAME
            # when generic qualifiers are included in the span.  Let the
            # gazetteer classification win after its suffix/prefix retry,
            # while leaving unrelated organization candidates unchanged.
            if entity_type == "ORGANIZATION_NAME":
                known_category = _gazetteer.category_of(raw_value)
                entity_type = {
                    "threat_actor": "THREAT_ACTOR_HANDLE",
                    "malware": "MALWARE_FAMILY",
                    "ransomware": "RANSOMWARE_GROUP",
                }.get(known_category, entity_type)

            if entity_type in ("FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"):
                if not _validate_hash_length(entity_type, raw_value):
                    logger.debug(
                        f"Hash length validation failed for {entity_type}={raw_value}"
                    )
                    continue

            if entity_type == "ONION_URL":
                if not _validate_onion_url(raw_value):
                    logger.debug("ONION_URL discarded (not a valid onion address): %r", raw_value)
                    continue

            # Defensive shape check for the new crypto wallet types.  The
            # extractor already enforces these shapes via regex + validators;
            # this is a second line of defence so a malformed value can
            # never reach the DB even if a future refactor weakens the regex.
            _CRYPTO_WALLET_TYPES = (
                "BITCOIN_ADDRESS",
                "ETHEREUM_ADDRESS",
                "MONERO_ADDRESS",
                "LITECOIN_ADDRESS",
                "ZCASH_ADDRESS",
                "DOGECOIN_ADDRESS",
                "XRP_ADDRESS",
                "SOLANA_ADDRESS",
                "TRON_ADDRESS",
                "BITCOIN_CASH_ADDRESS",
                "DASH_ADDRESS",
                "ENS_DOMAIN",
            )
            if entity_type in _CRYPTO_WALLET_TYPES:
                if not _validate_crypto_wallet(entity_type, raw_value):
                    logger.debug(
                        "Crypto wallet validation failed for %s=%r",
                        entity_type,
                        raw_value,
                    )
                    continue

            # Defensive shape check for the network / forensic
            # identifier types added in Phase 2 (final subphase).  The
            # extractors already enforce these shapes; this is a
            # second line of defence so a malformed value can never
            # reach the DB even if a future refactor weakens the regex.
            _NETWORK_FORENSIC_TYPES = (
                "IPV6_ADDRESS",
                "MAC_ADDRESS",
                "IPFS_CID",
                "YARA_RULE",
                "MITRE_TACTIC",
                "EXPLOIT_DB_ID",
                "NUCLEI_TEMPLATE",
                "COMBO_LIST_ENTRY",
                "CRYPTO_SEED_PHRASE",
            )
            if entity_type in _NETWORK_FORENSIC_TYPES:
                if not _validate_network_forensic(entity_type, raw_value):
                    logger.debug(
                        "Network/forensic validation failed for %s=%r",
                        entity_type,
                        raw_value,
                    )
                    continue

            canonical = _normalize_value(entity_type, raw_value)
            if not canonical:
                continue

            if entity_type == "ORGANIZATION_NAME":
                # Repair-then-reject (extractor/org_filter.py): link-directory
                # titles, markup and listing residue are not organisations and
                # must not reach the DB or the NVD CPE lookup.
                cleaned = _org_filter.clean_org_name(canonical)
                if cleaned is None:
                    noise_count += 1
                    logger.debug("Org filter rejected an ORGANIZATION_NAME candidate")
                    continue
                canonical = cleaned

            if (
                entity_type == "ORGANIZATION_NAME"
                and _software.should_suppress_organization(canonical, page_text)
            ):
                noise_count += 1
                logger.debug("Suppressed software/product organization candidate")
                continue

            # -------------------------------------------------------------
            # Acceptance gate.
            #
            # Shape-validated name types (THREAT_ACTOR_HANDLE, ORGANIZATION_NAME,
            # MALWARE_FAMILY, RANSOMWARE_GROUP) are accepted ONLY if they
            # plausibly have the entity's shape or match the known-good
            # gazetteer — the accept-if-plausible test that replaces the old
            # reject-if-on-denylist approach.  A never-before-seen generic word
            # is rejected structurally the first time it appears, without anyone
            # having to have added it to a list.
            #
            # The remaining NER/LLM types (PERSON_NAME, LOCATION, DATE) keep a
            # light structural check only (length / numeric-only); regex IOC
            # types bypass both — their patterns are already precise.
            # -------------------------------------------------------------
            shape_verdict = None
            if _conf.is_shape_validated_type(entity_type):
                shape_verdict = _shape.evaluate(
                    entity_type, canonical, context_text=page_text
                )
                if not shape_verdict.accept:
                    noise_count += 1
                    logger.debug(
                        "Shape-rejected %s=%r (tier=%s score=%.2f)",
                        entity_type, canonical, shape_verdict.tier, shape_verdict.score,
                    )
                    continue
            elif entity_type not in _REGEX_TYPES:
                if is_blocked_entity(entity_type, canonical):
                    noise_count += 1
                    logger.debug("Filtered blocked entity: %s=%s", entity_type, canonical)
                    continue

            dedup_key = f"{entity_type}::{canonical}"
            if dedup_key in seen_values:
                continue
            seen_values.add(dedup_key)

            extraction_method = (extraction_method_overrides or {}).get(
                (entity_type, raw_value), ""
            )
            method = _extraction_method_for(entity_type, extraction_method)
            confidence = _confidence_for(entity_type, extraction_method)

            # v1.7 Q-1 — reserved-range / placeholder filtering.
            # Assign source_quality=0.0 so these are excluded from the entity
            # store (pipeline.py's apply_entity_cap drops confidence < 0.80,
            # and source_quality=0.0 propagates a near-zero effective score).
            source_quality = _source_quality_from_url(page_url)

            if entity_type == "IP_ADDRESS" and _is_rfc5737_ip(canonical):
                source_quality = 0.0
                logger.debug(
                    "RFC 5737 IP rejected (reserved documentation range): %s", canonical
                )
                continue

            if entity_type == "IP_ADDRESS" and _is_non_actionable_ip(canonical):
                source_quality = 0.0
                logger.debug(
                    "Non-actionable IP rejected (null route / broadcast / public DNS resolver): %s",
                    canonical,
                )
                continue

            if entity_type == "DOMAIN" and _is_rfc2606_domain(canonical):
                source_quality = 0.0
                logger.debug(
                    "RFC 2606 domain rejected (reserved documentation domain): %s", canonical
                )
                continue

            if entity_type == "EMAIL_ADDRESS" and _is_placeholder_email(canonical):
                source_quality = 0.0
                logger.debug(
                    "Placeholder email rejected (documentation/example address): %s", canonical
                )
                continue

            snip = _context_snippet(page_text, canonical) if page_text else ""

            # Computed, continuous confidence from real signals — validation
            # strength, shape plausibility, context support, and method prior —
            # instead of a fixed lookup by type.  Corroboration across sources is
            # folded in later at the batch cap stage (pipeline.apply_entity_cap).
            validation = _validation_tier(entity_type, canonical, shape_verdict, raw_value=raw_value)
            context_window = snip or (page_text or "")[:2000]
            context_ok = _conf.context_supports(entity_type, context_window)
            confidence = _conf.compute_confidence(
                entity_type,
                method,
                validation=validation,
                shape_score=(shape_verdict.score if shape_verdict is not None else None),
                context_support=context_ok,
            )

            result.append(
                NormalizedEntity(
                    entity_type=entity_type,
                    value=canonical,
                    confidence=confidence,
                    source_url=page_url,
                    page_id=page_id,
                    context_snippet=snip,
                    extraction_method=_extraction_method_for(entity_type, extraction_method),
                    source_quality=source_quality,
                    validation_tier=validation,
                    cleaned_text=page_text or "",
                )
            )

    if noise_count:
        logger.warning(
            "Shape/structural validation filtered %d candidate entities "
            "(rejected as not entity-shaped)", noise_count
        )

    return result


def _source_label_from_url(url: str) -> str:
    """Return a stable corroboration label for the page's source host."""
    try:
        host = (urlparse(url or "").hostname or "").lower().strip(".")
        if host.startswith("www."):
            host = host[4:]
        return host
    except (TypeError, ValueError):
        return ""


def merge_with_db(
    entities: list[NormalizedEntity],
    investigation_id: Optional[uuid.UUID] = None,
) -> list:
    """
    Upsert each entity to the DB entities table using canonical deduplication.

    Returns a list of DB-assigned entity IDs (as strings) aligned 1:1 with the
    input ``entities`` list — an entry is ``None`` only if that one entity could
    not be persisted.  Callers rely on this positional alignment (see
    ``extractor/pipeline.py``), so the length always matches the input.

    Issue 3 — a collision on a single entity must never discard the rest of the
    batch.  Each entity is persisted inside its own SAVEPOINT: if a concurrent
    writer inserts the same canonical value between our existence check and our
    INSERT, the unique constraint fires, we roll back *only that entity's*
    savepoint, then resolve it cleanly by re-running the upsert (which now finds
    the committed row and links it to this investigation).  Every other entity
    in the batch is committed normally.
    """
    if not os.getenv("DATABASE_URL"):
        logger.warning(
            "DATABASE_URL not set — skipping DB persist (%d entities)", len(entities)
        )
        return [None] * len(entities)

    if not entities:
        return []

    ids: list = []
    new_count = 0
    dedup_count = 0
    collision_count = 0
    failed_count = 0

    try:
        from db.session import get_session
        from db.queries import (
            upsert_entity_canonical,
            create_page,
            get_page_by_url,
            update_entity_source_count,
        )
        from sqlalchemy.exc import IntegrityError

        def _persist_one(session, entity, page) -> tuple[object, bool]:
            db_entity, created = upsert_entity_canonical(
                session=session,
                investigation_id=investigation_id,
                entity_type=entity.entity_type,
                entity_value=entity.value,
                confidence=entity.confidence,
                source_page_id=page.id if page is not None else None,
                context_snippet=entity.context_snippet,
                extraction_method=entity.extraction_method or None,
            )
            source_label = _source_label_from_url(entity.source_url)
            if source_label:
                update_entity_source_count(session, db_entity.id, source_label)
            return db_entity, created

        with get_session() as session:
            from db.models import Investigation
            origin = session.get(Investigation, investigation_id) if investigation_id else None
            page_scope = investigation_id if origin and origin.user_id is not None else None
            page_cache: dict[str, object] = {}

            def _page_text(entity: NormalizedEntity) -> str:
                return str(getattr(entity, "cleaned_text", "") or "")

            def _materialize_page_text(page: object, entity: NormalizedEntity) -> None:
                """Fill a URL-only page row with the best text seen this run."""
                if page is None:
                    return
                text = _page_text(entity)
                if not text:
                    return
                existing = str(getattr(page, "cleaned_text", "") or "")
                if len(text) > len(existing):
                    page.cleaned_text = text

            for entity in entities:
                url = entity.source_url

                # Resolve the source Page in its own savepoint so a later
                # entity-level rollback can never invalidate a cached page.
                page = page_cache.get(url)
                if page is None:
                    try:
                        with session.begin_nested():
                            page = get_page_by_url(session, url, investigation_id=page_scope)
                            if page is None:
                                page = create_page(
                                    session,
                                    url=url,
                                    investigation_id=page_scope,
                                    cleaned_text=_page_text(entity) or None,
                                )
                            else:
                                _materialize_page_text(page, entity)
                        page_cache[url] = page
                    except IntegrityError:
                        # Concurrent page insert — re-read the now-committed row.
                        try:
                            with session.begin_nested():
                                page = get_page_by_url(session, url, investigation_id=page_scope)
                            if page is not None:
                                page_cache[url] = page
                        except Exception as _pexc:
                            logger.debug("page re-read failed for %s: %s", url, _pexc)
                            page = None
                    except Exception as _pexc:
                        logger.debug("page resolve failed for %s: %s", url, _pexc)
                        page = None

                if page is not None and page_cache.get(url) is not None:
                    # A page may have been cached from an entity without text
                    # and receive a populated entity later in the batch.
                    try:
                        with session.begin_nested():
                            _materialize_page_text(page, entity)
                    except Exception as _pexc:
                        logger.debug("page text update failed for %s: %s", url, _pexc)

                try:
                    with session.begin_nested():  # SAVEPOINT per entity
                        db_entity, created = _persist_one(session, entity, page)
                    if created:
                        new_count += 1
                    else:
                        dedup_count += 1
                    ids.append(str(db_entity.id))
                    continue
                except IntegrityError as exc:
                    # A concurrent writer inserted the same canonical entity
                    # between our existence check and our INSERT.  The savepoint
                    # rolled back just this entity's work — resolve it by
                    # retrying the upsert, which now finds the committed row and
                    # links it to this investigation.
                    logger.debug(
                        "Entity collision for %s=%s — resolving via re-link: %s",
                        entity.entity_type, entity.value, exc,
                    )
                except Exception as exc:
                    logger.warning(
                        "merge_with_db: entity %s=%s failed (skipped, batch continues): %s",
                        entity.entity_type, entity.value, exc,
                    )
                    ids.append(None)
                    failed_count += 1
                    continue

                # Collision-resolution retry, isolated in its own savepoint.
                try:
                    with session.begin_nested():
                        db_entity, created = _persist_one(session, entity, page)
                    collision_count += 1
                    if created:
                        new_count += 1
                    else:
                        dedup_count += 1
                    ids.append(str(db_entity.id))
                except Exception as re_exc:
                    logger.warning(
                        "merge_with_db: entity %s=%s failed to resolve after "
                        "collision (skipped, batch continues): %s",
                        entity.entity_type, entity.value, re_exc,
                    )
                    ids.append(None)
                    failed_count += 1

            session.commit()
            if investigation_id:
                logger.warning(
                    f"[{investigation_id}] Entity dedup: {new_count} new, "
                    f"{dedup_count} merged with existing, "
                    f"{collision_count} concurrent collisions resolved, "
                    f"{failed_count} failed"
                )

    except Exception as exc:
        logger.warning("merge_with_db failed: %s", exc)
        # Preserve positional alignment for the caller even on total failure.
        return ids + [None] * (len(entities) - len(ids))

    return ids
