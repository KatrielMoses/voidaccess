"""
extractor/regex_patterns.py — Pre-compiled regex patterns for entity extraction.

All patterns are compiled at module load time.  No pattern is ever compiled
inside a function call.

Public interface
----------------
extract_all(text)           → dict[str, list[str]]
extract_type(text, entity_type) → list[str]   raises ValueError on unknown type

Entity type constants are exported so callers can use them symbolically
(e.g. regex_patterns.BITCOIN_ADDRESS) rather than raw strings.

Pattern constants
-----------------
In addition to the legacy entity-type constants, the raw compiled regex
objects are exposed as ``<NAME>_PATTERN`` so callers and tests can verify
the patterns directly without going through the extractor wrappers:

    BITCOIN_PATTERN, ETHEREUM_PATTERN, MONERO_PATTERN,
    LITECOIN_PATTERN, ZCASH_PATTERN, DOGECOIN_PATTERN, XRP_PATTERN,
    SOLANA_PATTERN, TRON_PATTERN, BITCOIN_CASH_PATTERN, DASH_PATTERN,
    ENS_PATTERN
    AWS_ACCESS_KEY_PATTERN, AWS_SECRET_KEY_PATTERN, GITHUB_TOKEN_PATTERN,
    SLACK_TOKEN_PATTERN, DISCORD_TOKEN_PATTERN, JWT_TOKEN_PATTERN,
    GOOGLE_API_KEY_PATTERN, STRIPE_KEY_PATTERN, API_KEY_PATTERN,
    STEALER_LOG_PATTERN
    TELEGRAM_HANDLE_PATTERN, DISCORD_HANDLE_PATTERN, XMPP_JID_PATTERN,
    TOX_ID_PATTERN, SESSION_ID_PATTERN, MATRIX_HANDLE_PATTERN,
    WIRE_HANDLE_PATTERN, ICQ_NUMBER_PATTERN, WICKR_ID_PATTERN
    IPV6_PATTERN, MAC_ADDRESS_PATTERN, IPFS_CID_PATTERN,
    YARA_RULE_PATTERN, MITRE_TACTIC_PATTERN, EXPLOIT_DB_PATTERN,
    COMBO_LIST_PATTERN, NUCLEI_TEMPLATE_PATTERN, CRYPTO_SEED_PHRASE_PATTERN

Note: ``SOLANA_PATTERN`` and ``XRP_PATTERN`` are *broad* patterns; the
extractors that use them also apply a crypto-context window filter
(see CRYPTO_CONTEXT_TERMS / _has_crypto_context) so naked matches without
surrounding crypto vocabulary are dropped.

Note: ``DISCORD_AT_PATTERN`` is a broad pattern that matches any
``@username``; the extractor that uses it applies a messaging-context
window filter (see MESSAGING_CONTEXT_TERMS / _has_messaging_context) so
naked matches without surrounding messaging vocabulary are dropped.

Note: ``IPV6_PATTERN`` is *broad* and matches anything that *looks* like
an IPv6 address; the extractor validates candidates with
``ipaddress.ip_address`` and rejects private/loopback/ULA ranges
(``::1``, ``fe80::/10``, ``fc00::/7``) so a stray colon-delimited hex
string in narrative text never slips through.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Entity type constants
# ---------------------------------------------------------------------------

BITCOIN_ADDRESS = "BITCOIN_ADDRESS"
ETHEREUM_ADDRESS = "ETHEREUM_ADDRESS"
MONERO_ADDRESS = "MONERO_ADDRESS"
LITECOIN_ADDRESS = "LITECOIN_ADDRESS"
ZCASH_ADDRESS = "ZCASH_ADDRESS"
DOGECOIN_ADDRESS = "DOGECOIN_ADDRESS"
XRP_ADDRESS = "XRP_ADDRESS"
SOLANA_ADDRESS = "SOLANA_ADDRESS"
TRON_ADDRESS = "TRON_ADDRESS"
BITCOIN_CASH_ADDRESS = "BITCOIN_CASH_ADDRESS"
DASH_ADDRESS = "DASH_ADDRESS"
ENS_DOMAIN = "ENS_DOMAIN"
ONION_URL = "ONION_URL"
EMAIL_ADDRESS = "EMAIL_ADDRESS"
PGP_KEY_BLOCK = "PGP_KEY_BLOCK"
CVE_NUMBER = "CVE_NUMBER"
IP_ADDRESS = "IP_ADDRESS"
PHONE_NUMBER = "PHONE_NUMBER"
PASTE_URL = "PASTE_URL"
FILE_HASH_MD5 = "FILE_HASH_MD5"
FILE_HASH_SHA1 = "FILE_HASH_SHA1"
FILE_HASH_SHA256 = "FILE_HASH_SHA256"
MITRE_TECHNIQUE = "MITRE_TECHNIQUE"

# Credential / token entity types (added per Phase 2 — credential extraction).
AWS_ACCESS_KEY = "AWS_ACCESS_KEY"
AWS_SECRET_KEY = "AWS_SECRET_KEY"
GITHUB_TOKEN = "GITHUB_TOKEN"
SLACK_TOKEN = "SLACK_TOKEN"
DISCORD_TOKEN = "DISCORD_TOKEN"
JWT_TOKEN = "JWT_TOKEN"
API_KEY = "API_KEY"
GOOGLE_API_KEY = "GOOGLE_API_KEY"
STRIPE_KEY = "STRIPE_KEY"
STEALER_LOG_ENTRY = "STEALER_LOG_ENTRY"

# Messaging / identity handle entity types (added per Phase 2 — messaging
# platform extraction).  These appear constantly on dark-web forums where
# threat actors advertise contact methods and recruit affiliates.
TELEGRAM_HANDLE = "TELEGRAM_HANDLE"
DISCORD_HANDLE = "DISCORD_HANDLE"
XMPP_JID = "XMPP_JID"
TOX_ID = "TOX_ID"
SESSION_ID = "SESSION_ID"
MATRIX_HANDLE = "MATRIX_HANDLE"
WIRE_HANDLE = "WIRE_HANDLE"
ICQ_NUMBER = "ICQ_NUMBER"
WICKR_ID = "WICKR_ID"

# Network / forensic identifier entity types (added per Phase 2 — final
# subphase).  IPv6, MAC, IPFS CIDs, MITRE TACTIC IDs, YARA rules, Exploit-DB
# IDs, Nuclei templates, BIP39 seed phrases, and credential combo-list
# blocks are all extremely high-value IOCs that appear routinely on
# exploit-sharing forums, malware analysis blogs, and paste sites.
IPV6_ADDRESS = "IPV6_ADDRESS"
MAC_ADDRESS = "MAC_ADDRESS"
IPFS_CID = "IPFS_CID"
COMBO_LIST_ENTRY = "COMBO_LIST_ENTRY"
YARA_RULE = "YARA_RULE"
MITRE_TACTIC = "MITRE_TACTIC"
EXPLOIT_DB_ID = "EXPLOIT_DB_ID"
NUCLEI_TEMPLATE = "NUCLEI_TEMPLATE"
CRYPTO_SEED_PHRASE = "CRYPTO_SEED_PHRASE"

ENTITY_TYPES: frozenset[str] = frozenset({
    BITCOIN_ADDRESS,
    ETHEREUM_ADDRESS,
    MONERO_ADDRESS,
    LITECOIN_ADDRESS,
    ZCASH_ADDRESS,
    DOGECOIN_ADDRESS,
    XRP_ADDRESS,
    SOLANA_ADDRESS,
    TRON_ADDRESS,
    BITCOIN_CASH_ADDRESS,
    DASH_ADDRESS,
    ENS_DOMAIN,
    ONION_URL,
    EMAIL_ADDRESS,
    PGP_KEY_BLOCK,
    CVE_NUMBER,
    IP_ADDRESS,
    PHONE_NUMBER,
    PASTE_URL,
    FILE_HASH_MD5,
    FILE_HASH_SHA1,
    FILE_HASH_SHA256,
    MITRE_TECHNIQUE,
    # Credential types
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    GITHUB_TOKEN,
    SLACK_TOKEN,
    DISCORD_TOKEN,
    JWT_TOKEN,
    API_KEY,
    GOOGLE_API_KEY,
    STRIPE_KEY,
    STEALER_LOG_ENTRY,
    # Messaging / identity handle types
    TELEGRAM_HANDLE,
    DISCORD_HANDLE,
    XMPP_JID,
    TOX_ID,
    SESSION_ID,
    MATRIX_HANDLE,
    WIRE_HANDLE,
    ICQ_NUMBER,
    WICKR_ID,
    # Network / forensic identifier types (Phase 2 final subphase)
    IPV6_ADDRESS,
    MAC_ADDRESS,
    IPFS_CID,
    COMBO_LIST_ENTRY,
    YARA_RULE,
    MITRE_TACTIC,
    EXPLOIT_DB_ID,
    NUCLEI_TEMPLATE,
    CRYPTO_SEED_PHRASE,
})

# ---------------------------------------------------------------------------
# Pre-compiled regex patterns
# ---------------------------------------------------------------------------

# Bitcoin — three formats, all word-bounded:
#   Bech32 (native segwit):  bc1 + bech32 charset, 25-62 chars
#   P2PKH legacy:            starts with 1, base58 charset, 25-34 chars
#   P2SH:                    starts with 3, base58 charset, 25-34 chars
_BITCOIN_RE = re.compile(
    r"\b(?:"
    r"bc1[a-zA-HJ-NP-Z0-9]{25,62}"
    r"|1[a-km-zA-HJ-NP-Z1-9]{25,34}"
    r"|3[a-km-zA-HJ-NP-Z1-9]{25,34}"
    r")\b"
)

# Ethereum — 0x + exactly 40 hex chars, word-bounded to exclude longer hex blobs
_ETHEREUM_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# Monero — starts with 4, second char in [0-9AB], 93 base58 chars, total 95
_MONERO_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

# Litecoin — Legacy P2PKH addresses start with L (most common) or M (p2sh-style).
# Total length 27-34 chars; uses the same base58 charset as BTC.
# BTC legacy uses 1/3 — so LTC's L/M prefix is unambiguous vs BTC.
_LITECOIN_RE = re.compile(r"\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b")

# Zcash — transparent addresses (t1/t3 prefix, 35 chars total) and
# shielded Sapling addresses (zs1 prefix, 76-82 chars total).
_ZCASH_RE = re.compile(
    r"\b(?:"
    r"t[13][a-km-zA-HJ-NP-Z1-9]{33}"
    r"|zs1[a-z0-9]{74,78}"
    r")\b"
)

# Dogecoin — D prefix, base58 charset (1-9, A-Z excluding I/O, a-z excluding l),
# 26-34 chars total.  The leading D makes it unambiguous vs BTC's 1/3 and
# LTC's L/M.  Digit class is [1-9] (standard base58) to match the BTC legacy
# and LTC patterns in this file.
_DOGECOIN_RE = re.compile(r"\bD[1-9A-HJ-NP-Za-km-z]{24,33}\b")

# Ripple / XRP — r prefix + 25-35 alphanumeric chars (classic addresses).
# Base58-encoded with r prefix; length range is 25-35 for classic addresses.
# The r-prefix is broad, so XRP_PATTERN matches many random words — the
# XRP extractor applies a crypto-context window filter.
_XRP_RE = re.compile(r"\br[0-9a-zA-Z]{24,34}\b")

# Solana — base58, 32-44 chars, no prefix.
# The Solana extractor applies a crypto-context window filter because this
# pattern is *very* broad and will otherwise match many false positives.
_SOLANA_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")

# Tron — T prefix + 33 base58 chars (no 0/O/I/l).  Total 34 chars.
_TRON_RE = re.compile(r"\bT[A-HJ-NP-Za-km-z1-9]{33}\b")

# Bitcoin Cash — cashaddr format: bitcoincash:q... or bitcoincash:p...
# Legacy format (1/3 prefix) is intentionally NOT extracted to avoid confusion
# with BTC.  The cashaddr prefix makes it unambiguous.
_BITCOIN_CASH_RE = re.compile(r"\bbitcoincash:[qp][a-z0-9]{41,111}\b")

# Dash — X prefix + 33 base58 chars (no 0/O/I/l).  Total 34 chars.
_DASH_RE = re.compile(r"\bX[1-9A-HJ-NP-Za-km-z]{33}\b")

# ENS domain — *.eth pattern (Ethereum Name Service).
# Label structure: [a-zA-Z0-9] (start) + [a-zA-Z0-9\-]{1,61} (middle) +
# [a-zA-Z0-9] (end), totalling 3-63 chars per label.  Negative lookbehind
# for [a-zA-Z0-9\-] prevents matches like "-foo.eth" (leading hyphen)
# where the regex would otherwise pick up the substring starting at "f".
# Negative lookahead after ".eth" prevents matches like "foo.eth.bar".
_ENS_RE = re.compile(
    r"(?<![a-zA-Z0-9\-])"
    r"[a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9]"
    r"\.eth"
    r"(?![a-zA-Z0-9\-])"
)

# Onion URLs — full URL (http/https + path) tried before bare hostname so the
# longer form is preferred by re.finditer when both would match the same text.
_ONION_RE = re.compile(
    r"https?://[a-z2-7]{16,56}\.onion(?:/[^\s\"'<>]*)?"
    r"|[a-z2-7]{16,56}\.onion(?:/[^\s\"'<>]*)?",
    re.IGNORECASE,
)

# Email — simplified RFC 5322.  Leading/trailing-dot and consecutive-dot
# validation is done in _is_valid_email() rather than in the regex itself
# to keep the pattern readable.
_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9][a-zA-Z0-9._%+\-]*@[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}\b"
)

# PGP — full armored block (multiline, lazy inner match)
_PGP_BLOCK_RE = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)

# PGP — colon-separated fingerprint: 20 groups of exactly 2 hex chars
# e.g. AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01
# Also space-separated (with or without spaces): ABCD 1234 ABCD 1234...
_PGP_FINGERPRINT_RE = re.compile(
    r"\b[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){19}\b|"
    r"\b[0-9A-F]{4}(?:\s?[0-9A-F]{4}){9}\b",
    re.IGNORECASE,
)

# PGP — explicit fingerprint keyword context (within 50 chars of hex string)
_PGP_CONTEXT_RE = re.compile(
    r"fingerprint[\s:]{0,50}[0-9A-Fa-f]{40}"
)

# MD5 — exactly 32 hex chars, word-bounded
_FILE_HASH_MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")

# SHA1 — exactly 40 hex chars, word-bounded (used to exclude from PGP)
_FILE_HASH_SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")

# SHA256 — exactly 64 hex chars, word-bounded
_FILE_HASH_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")

_HASH_CONTEXT_RE = re.compile(
    r"\b(?:hash|md5|sha(?:1|224|256|384|512)?|checksum|digest|file|malware|sample)\b",
    re.IGNORECASE,
)


def _has_hash_context(text: str, start: int, end: int, window: int = 80) -> bool:
    """Require nearby hash/file terminology for bare hexadecimal strings."""
    return bool(_HASH_CONTEXT_RE.search(text[max(0, start - window):min(len(text), end + window)]))

# CVE — case insensitive; 4-digit year + 4-8 digit ID.  MITRE now
# assigns 8-digit suffixes for very high-volume years (e.g. CVE-2024-12345678)
# so the upper bound was bumped from 7 → 8 in the Phase 2 final subphase.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)

# MITRE ATT&CK technique — T + 4 digits, optional . + 3 sub-technique digits
# e.g. T1486, T1071.001, T1059.003 (case-insensitive)
_MITRE_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# IPv4 — strict octet ranges (0-255), word-bounded.
# RFC1918/loopback filtering happens in _is_public_ip() — not in regex.
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Phone — E.164 (+[1-9] then 6-14 digits) captures most international formats.
_PHONE_RE = re.compile(r"\+[1-9]\d{6,14}\b")

# Paste site URLs — known domains only, full URL required
_PASTE_DOMAINS = (
    r"(?:pastebin\.com|rentry\.co|ghostbin\.com|paste\.ee"
    r"|hastebin\.com|privatebin\.net|bin\.bini\.monster)"
)
_PASTE_RE = re.compile(
    rf"https?://(?:www\.)?{_PASTE_DOMAINS}/[^\s\"'<>]*",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Credential / token patterns (Phase 2)
# ---------------------------------------------------------------------------
#
# These are seen constantly on paste sites, GitHub leak scanners, and dark-web
# credential dumps.  Each pattern is anchored to a vendor-specific prefix or a
# JWT-header marker (eyJ) so false positives are rare.

# AWS access key — AKIA + 16 uppercase alphanumeric = 20 chars total.
# The fixed AKIA prefix is very specific; the suffix is base32-ish but
# uppercase so we use [0-9A-Z].
_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# AWS secret key — context-dependent: 40-char base64 string that follows an
# "aws_secret_access_key" or "SecretAccessKey" label.  We capture the value
# (group 1) so the URL label can be discarded.  Value charset: A-Z, a-z,
# 0-9, +, /  — exactly 40 chars.
_AWS_SECRET_KEY_RE = re.compile(
    r"(?:aws_secret_access_key|SecretAccessKey)"
    r"\s*[=:]\s*"
    r"([A-Za-z0-9/+]{40})\b",
    re.IGNORECASE,
)

# GitHub PAT — four families:
#   ghp_  classic personal access token   (36 chars)
#   gho_  OAuth user token                (36 chars)
#   ghs_  GitHub Actions server token     (36 chars)
#   ghu_  GitHub Apps user-to-server      (36 chars)
#   ghr_  GitHub Apps refresh             (36 chars)
#   github_pat_  fine-grained PAT         (82 chars incl. underscores)
_GITHUB_TOKEN_RE = re.compile(
    r"\b(?:gh[posaur]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"
)

# Slack tokens — xoxb (bot), xoxp (user), xoxa (app-level deprecated),
# xoxs (legacy workspace), xoxr (refresh).  All four are xox[bpas] followed
# by digits and dashes.  Length 10-100 is wide enough to cover all variants
# but tight enough to reject random punctuation.
_SLACK_TOKEN_RE = re.compile(r"\bxox[bpas]-[0-9A-Za-z\-]{10,100}\b")

# Discord tokens — three dot-separated base64url groups:
#   24 chars . 6 chars . 27 chars
# Note: this can collide with random base64 strings in the wild, so we
# require word boundaries on both ends and the strict length counts.
_DISCORD_TOKEN_RE = re.compile(
    r"\b[A-Za-z0-9]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}\b"
)

# JWT — base64url.base64url.base64url, anchored on the eyJ prefix (which is
# the base64url encoding of ``{"`` — the start of every JWT header object).
# The header is followed by 1+ base64url chars, then two more dot-separated
# base64url segments.
_JWT_TOKEN_RE = re.compile(
    r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"
)

# Google API key — AIza prefix + 35 chars from [0-9A-Za-z\-_].  Total 39.
_GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")

# Stripe key — pk_live_/pk_test_/sk_live_/sk_test_/rk_live_/rk_test_
# followed by 24-99 base62 chars.  We use [0-9a-zA-Z] for the body.
_STRIPE_KEY_RE = re.compile(r"\b[psr]k_(?:live|test)_[0-9a-zA-Z]{24,99}\b")

# Generic API key — label + high-entropy value.  We anchor on a fairly
# strict list of secret-bearing labels and let the entropy filter reject
# noise.  Each match returns the *value* (group 1) so the label can be
# discarded.
_API_KEY_LABELS = (
    r"api[_\-]?key"
    r"|apikey"
    r"|access[_\-]?key"
    r"|secret[_\-]?key"
    r"|auth[_\-]?token"
    r"|client[_\-]?secret"
    r"|bearer"
    r"|password"
    r"|passwd"
    r"|pwd"
    r"|credential"
)
_API_KEY_RE = re.compile(
    rf"\b(?:{_API_KEY_LABELS})\s*[=:]?\s*[\"']?"
    r"([A-Za-z0-9+/=_\-]{16,64})[\"']?",
    re.IGNORECASE,
)

# Stealer-log entry — the URL/LOGIN/PASSWORD three-line format used by
# RedLine, Raccoon, Vidar, StealC, and most modern info-stealer dumpers.
# We capture URL (group 1), login (group 2), password (group 3) as one
# match; the extractor emits URL→PASTE_URL and login→EMAIL_ADDRESS (when
# shaped like an email) or THREAT_ACTOR_HANDLE otherwise, and *never*
# emits the password value (content safety).
_STEALER_LOG_RE = re.compile(
    r"(?:URL|HOST)\s*[:=]\s*(\S+)\s*[\r\n]+"
    r"(?:LOGIN|USER|USERNAME|EMAIL)\s*[:=]\s*(\S+)\s*[\r\n]+"
    r"(?:PASSWORD|PASS|PWD)\s*[:=]\s*(\S+)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Messaging / identity handle patterns (Phase 2)
# ---------------------------------------------------------------------------
#
# These appear constantly in dark-web forums where threat actors advertise
# contact methods and recruit affiliates.  Three patterns are very specific
# by shape (TOX_ID, SESSION_ID, MATRIX_HANDLE) and emit unconditionally.
# The rest require a context keyword (telegram / discord / xmpp / wire / etc.)
# so a bare username like @john isn't misclassified.

# Telegram handle — three patterns merged into one alternation:
#   a) (?:telegram|tg)\s*[:\-]?\s*@username
#   b) t\.me/username
#   c) (?:contact|reach|dm|message|signal)\s*[:\-]?\s*@username
# Group 1 always captures the username (without @ prefix).
_TELEGRAM_RE = re.compile(
    r"(?:(?:telegram|tg)\s*[:\-]?\s*@"
    r"|t\.me/"
    r"|(?:contact|reach|dm|message|signal)\s*[:\-]?\s*@)"
    r"([A-Za-z][A-Za-z0-9_]{4,31})\b",
    re.IGNORECASE,
)

# Discord legacy — username#1234 (the old discriminator format).
# Username: alphanumeric + . + _, 2-32 chars.  Discriminator: exactly 4 digits.
_DISCORD_LEGACY_RE = re.compile(r"\b([A-Za-z0-9_.]{2,32})#([0-9]{4})\b")

# Discord invite — discord.gg/CODE (2-20 alphanumeric chars).
_DISCORD_INVITE_RE = re.compile(
    r"\bdiscord\.gg/([A-Za-z0-9]{2,20})\b",
    re.IGNORECASE,
)

# Discord user profile link — discord.com/users/<snowflake-id>.
# Snowflakes are 17-19 digit IDs (Discord epoch start).
_DISCORD_USER_RE = re.compile(
    r"\bdiscord\.com/users/([0-9]{17,19})\b",
    re.IGNORECASE,
)

# Discord new-format @username — only extracted when "discord" appears within
# ±100 chars (the @username shape alone is too broad).  The extractor applies
# the context window check after the regex match.
_DISCORD_AT_RE = re.compile(r"@([A-Za-z][A-Za-z0-9_.]{2,32})\b")

# XMPP / Jabber JID — looks like an email but only when an XMPP context
# keyword precedes it.  Group 1 captures the JID.
_XMPP_JID_RE = re.compile(
    r"(?:xmpp|jabber|jid|pidgin|gajim|xabber|conversations|delta\s+chat)"
    r"\s*[:\-]?\s*"
    r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b",
    re.IGNORECASE,
)

# Tox ID — exactly 76 hex chars (64-char public key + 8-char nospam +
# 4-char checksum).  Length is greater than SHA256 (64 chars) so the two
# patterns do not collide.
_TOX_ID_RE = re.compile(r"\b[A-Fa-f0-9]{76}\b")

# Session messenger ID — 66 hex chars, always starts with "05".
_SESSION_ID_RE = re.compile(r"\b05[A-Fa-f0-9]{64}\b")

# Matrix handle — @user:server.tld.  Captures both halves so the canonical
# form can preserve the original casing of the homeserver.
_MATRIX_HANDLE_RE = re.compile(
    r"@([A-Za-z0-9._\-/=]+):([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b"
)

# Wire handle — context-dependent.  Captures the username (the @ prefix
# is optional).
_WIRE_HANDLE_RE = re.compile(
    r"(?:wire|wire\.com)\s*[:\-]?\s*@?([A-Za-z0-9_.\-]{2,30})\b",
    re.IGNORECASE,
)

# ICQ number — context-dependent, 5-9 digit numeric ID.
_ICQ_NUMBER_RE = re.compile(
    r"\b(?:icq)(?:\s+(?:number|id))?\s*[:\-]?\s*([0-9]{5,9})\b",
    re.IGNORECASE,
)

# Wickr ID — context-dependent, 1-20 char alphanumeric username.
# Note: "wickrme" and "wickr me" both collapse to "wickr" + optional "me".
_WICKR_ID_RE = re.compile(
    r"\b(?:wickr)(?:\s+me|me)?\s*[:\-]?\s*([A-Za-z0-9_]{1,20})\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Network / forensic identifier patterns (Phase 2 — final subphase)
# ---------------------------------------------------------------------------
#
# These cover the IOCs that show up in malware analysis write-ups, exploit
# listings, paste sites, and dark-web paste aggregators:
#   * IPv6 addresses (with private/loopback filtering)
#   * MAC addresses (colon / hyphen / Cisco three-octet forms)
#   * IPFS CIDs (CIDv0 / CIDv1 with optional /ipfs/ prefix)
#   * YARA rule names (with YARA-specific context check)
#   * MITRE ATT&CK TACTIC IDs (TA0001–TA0043) — distinct from TECHNIQUE
#   * Exploit-DB EDB-IDs (both the EDB-ID: 12345 form and the URL form)
#   * Nuclei template IDs (vendor-product-cve-type.yaml) with context check
#   * Credential combo-list blocks (3+ lines of email:password)
#   * BIP39 seed phrases (12 or 24 consecutive BIP39 words — detection
#     only; the actual seed is NEVER stored)
#
# The validators in this module are *defence in depth* — the regexes
# already enforce the structural shape, but a malformed value must never
# reach the DB even if a future refactor weakens the pattern.

# IPv6 — broad match covering all standard forms.  We use a single
# alternation with the *longest* (most-specific) forms first, and rely
# on Python's leftmost-first alternation rule to pick the greedy
# match.  Each candidate is then validated with ``ipaddress.ip_address``
# so the filter is the canonical "valid IPv6 + not in the
# private/loopback/ULA ranges" check the brief requires.
#
# Forms covered:
#   - full 8-group:        2001:0db8:85a3:0000:0000:8a2e:0370:7334
#   - zero-compressed:     2001:db8::1
#   - trailing ::         2001:db8::
#   - leading ::          ::1
#   - bare ::             ::
#   - IPv4-mapped:        ::ffff:192.0.2.1
#   - zone-id suffix:     fe80::1%eth0
_IPV6_RE = re.compile(
    r"(?<![\w:.])"  # negative lookbehind — colon, dot, or word char
    r"(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"  # 1. full 8-group form
    r"|"
    # 2. Middle :: with at least one group on each side (greedy).
    #    The `(?:[0-9a-fA-F]{1,4}:)*` patterns are greedy so the
    #    longest possible match wins over the trailing-:: form.
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:"  # 3. trailing :: (1-7 groups + ::)
    r"|"
    r"::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"  # 4. leading ::
    r"|"
    r"::"  # 5. bare ::
    r")"
    r"(?:%[0-9a-zA-Z_.+\-]+)?"  # optional zone-id
    r"(?![\w:.])"  # negative lookahead
    r"|"
    # 6. IPv4-mapped: ::ffff:192.0.2.1 or ::192.0.2.1
    r"(?<![\w:])::(?:ffff:)?"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?:%[0-9a-zA-Z_.+\-]+)?"
    r"(?![\w:.])"
)

# MAC address — three formats:
#   - colon:    AA:BB:CC:DD:EE:FF
#   - hyphen:   AA-BB-CC-DD-EE-FF
#   - Cisco:    AABB.CCDD.EEFF
_MAC_COLON_HYPHEN_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"
)
_MAC_CISCO_RE = re.compile(
    r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b"
)

# IPFS CID — three patterns covering both CIDv0 / CIDv1 with optional
# /ipfs/ path prefix:
#   - CIDv0:  Qm + 44 base58 chars (Qm has been the default since 2015)
#   - CIDv1:  bafy + 55-60 base32 chars (current default for new content)
#   - /ipfs/  prefix form for either version (URL paths, gateway URLs)
_IPFS_CID_V0_RE = re.compile(r"\bQm[1-9A-HJ-NP-Za-km-z]{44}\b")
_IPFS_CID_V1_RE = re.compile(r"\bbafy[a-z2-7]{55,60}\b")
_IPFS_PATH_V0_RE = re.compile(r"/ipfs/(Qm[1-9A-HJ-NP-Za-km-z]{44})\b")
_IPFS_PATH_V1_RE = re.compile(r"/ipfs/(bafy[a-z2-7]{55,60})\b")

# YARA rule declaration — captures the rule name (group 1).  The full
# declaration form is ``rule <Name> [: tag1 tag2 ...] { ... }``.  We
# require:
#   1. The keyword ``rule`` to be at the start of a line (after optional
#      indentation) — this prevents prose like "YARA rule detected:"
#      from being picked up as a YARA rule declaration.
#   2. A literal ``{`` to follow the optional tag block — so we don't
#      pick up the word "rule" in prose that doesn't include a body.
#   3. A YARA-specific context keyword (``strings:``, ``condition:``,
#      ``meta:``, ``import "``) to appear in the surrounding ±500 chars
#      — final filter against narrative text that happens to mention
#      "rule" in a YARA context but isn't actually a rule dump.
_YARA_RULE_RE = re.compile(
    r"(?:^|\n)[ \t]*rule[ \t]+"
    r"([A-Za-z_][A-Za-z0-9_]{2,127})"
    r"(?:[ \t]*:[ \t]*[A-Za-z_][A-Za-z0-9_]*(?:[ \t]+[A-Za-z_][A-Za-z0-9_]*)*)?"
    r"[ \t]*\{",
    re.MULTILINE,
)

# MITRE ATT&CK TACTIC — TA + 4 digits, range TA0001 through TA0043.
# Note: this is a different namespace from MITRE_TECHNIQUE (T + 4 digits).
# Case-insensitive to accept lowercase ``ta0001``; the validator
# canonicalises to uppercase and rejects anything outside the published
# range.
_MITRE_TACTIC_RE = re.compile(r"\bTA\d{4}\b", re.IGNORECASE)

# Exploit-DB EDB-ID — two forms:
#   - "EDB-ID: 12345" or "EDB-ID:12345" (with optional space)
#   - "exploit-db.com/exploits/12345" (URL form)
# Group 1 captures the numeric ID in both cases.
_EXPLOIT_DB_RE = re.compile(
    r"\bEDB-ID\s*[:=]\s*([0-9]{4,6})\b"
    r"|"
    r"\bexploit-db\.com/exploits/([0-9]{4,6})\b",
    re.IGNORECASE,
)

# Nuclei template ID — ``vendor-product-cve-type.yaml``.  The pattern
# requires 3-7 dash-separated lowercase alphanumeric segments terminated
# by ``.yaml`` (a Nuclei-specific extension).  The extractor requires the
# literal "nuclei" to appear within ±200 chars before emitting.
_NUCLEI_TEMPLATE_RE = re.compile(
    r"\b([a-z0-9]+(?:-[a-z0-9]+){2,6})\.yaml\b"
)

# Credential combo-list entry — one line of the email:password format
# used in paste-site credential dumps.  The ``MULTILINE`` flag is required
# so ``^`` and ``$`` anchor to line boundaries.  Group 1 captures the
# email (the side we want to surface); the password (group 2) is NEVER
# stored (content safety).
#
# Only the email:password form is accepted (no bare user:password) to
# keep the false-positive rate low — a threshold of 3+ matching lines
# on a page is what the extractor uses to decide the document is a
# combo-list dump, and false positives on prose are common if the
# pattern is too broad.
_COMBO_LINE_RE = re.compile(
    r"^[ \t]*"
    r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"
    r"\s*:\s*"
    r"([^\s]{6,})"
    r"[ \t]*$",
    re.MULTILINE,
)

# BIP39 seed phrase — detect sequences of consecutive BIP39 words.
# The full BIP39 wordlist is 2048 English words; we load a curated subset
# of ~150 words that are either highly distinctive (rare outside seed
# phrases) or sufficient to count a contiguous run of 12 / 24.  The
# actual phrase value is NEVER stored; the canonical emit is one of
#   SEED_PHRASE_DETECTED_12_WORDS
#   SEED_PHRASE_DETECTED_24_WORDS
# so the detection signal is preserved without leaking the secret.
_BIP39_WORDLIST: frozenset[str] = frozenset({
    "abandon", "ability", "able", "about", "above", "absent",
    "absorb", "abstract", "absurd", "abuse", "access", "accident",
    "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "aerobic", "affair", "afford",
    "afraid", "again", "age", "agent", "agree", "ahead",
    "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow",
    "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused",
    "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer",
    "antenna", "antique", "anxiety", "any", "apart", "apology",
    "appear", "apple", "approve", "april", "arch", "arctic",
    "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow",
    "art", "artefact", "artist", "artwork", "ask", "aspect",
    "assault", "asset", "assist", "assume", "asthma", "athlete",
    "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn",
    "average", "avocado", "avoid", "awake", "aware", "away",
    "awesome", "awful", "awkward", "axis", "baby", "bachelor",
    "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain",
    "barrel", "base", "basic", "basket", "battle", "beach",
    "bean", "beauty", "because", "become", "beef", "before",
    "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between",
    "beyond", "bicycle", "bid", "bike", "bind", "biology",
    "bird", "birth", "bitter", "black", "blade", "blame",
    "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board",
    "boat", "body", "boil", "bomb", "bone", "bonus",
    "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick",
    "bridge", "brief", "bright", "bring", "brisk", "broccoli",
    "broken", "bronze", "broom", "brother", "brown", "brush",
    "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger",
    "burst", "bus", "business", "busy", "butter", "buyer",
    "buzz", "cabbage", "cabin", "cable", "cactus", "cage",
    "cake", "call", "calm", "camera", "camp", "canal",
    "cancel", "candy", "cannon", "canoe", "canvas", "canyon",
    "capable", "capital", "captain", "car", "carbon", "card",
    "cargo", "carpet", "carry", "cart", "case", "cash",
    "casino", "castle", "casual", "cat", "catalog", "catch",
    "category", "cattle", "caught", "cause", "caution", "cave",
    "ceiling", "celery", "cement", "census", "century", "cereal",
    "certain", "chair", "chalk", "champion", "change", "chaos",
    "chapter", "charge", "chase", "chat", "cheap", "check",
    "cheese", "chef", "cherry", "chest", "chicken", "chief",
    "child", "chimney", "choice", "choose", "chronic", "chuckle",
    "chunk", "churn", "cigar", "cinnamon", "circle", "citizen",
    "city", "civil", "claim", "clap", "clarify", "claw",
    "clay", "clean", "clerk", "clever", "click", "client",
    "cliff", "climb", "clinic", "clip", "clock", "clog",
    "close", "cloth", "cloud", "clown", "club", "clump",
    "cluster", "clutch", "coach", "coast", "coconut", "code",
    "coffee", "coil", "coin", "collect", "color", "column",
    "combine", "come", "comfort", "comic", "common", "company",
    "concert", "conduct", "confirm", "congress", "connect", "consider",
    "control", "convince", "cook", "cool", "copper", "copy",
    "coral", "core", "corn", "correct", "cost", "cotton",
    "couch", "country", "couple", "course", "cousin", "cover",
    "coyote", "crack", "cradle", "craft", "cram", "crane",
    "crash", "crater", "crawl", "crazy", "cream", "credit",
    "creek", "crew", "cricket", "crime", "crisp", "critic",
    "crop", "cross", "crouch", "crowd", "crucial", "cruel",
    "cruise", "crumble", "crunch", "crush", "cry", "crystal",
    "cube", "culture", "cup", "cupboard", "curious", "current",
    "curtain", "curve", "cushion", "custom", "cute", "cycle",
})

# Minimum length of a contiguous BIP39 run that counts as a seed phrase.
# 12 words is the BIP39 default; 15 / 18 / 21 / 24 are valid longer
# variants.  The canonical emit collapses to 12-word / 24-word markers.
_BIP39_SEED_PHRASE_LENGTHS: tuple[int, ...] = (12, 15, 18, 21, 24)

# ---------------------------------------------------------------------------
# Pattern constants (public aliases for tests and verification scripts)
# ---------------------------------------------------------------------------
#
# The verify scripts import these by name, so they must be the compiled regex
# objects (not just strings).  Tests that want the raw pattern string should
# access ``<NAME>_PATTERN.pattern``.

BITCOIN_PATTERN = _BITCOIN_RE
ETHEREUM_PATTERN = _ETHEREUM_RE
MONERO_PATTERN = _MONERO_RE
LITECOIN_PATTERN = _LITECOIN_RE
ZCASH_PATTERN = _ZCASH_RE
DOGECOIN_PATTERN = _DOGECOIN_RE
XRP_PATTERN = _XRP_RE
SOLANA_PATTERN = _SOLANA_RE
TRON_PATTERN = _TRON_RE
BITCOIN_CASH_PATTERN = _BITCOIN_CASH_RE
DASH_PATTERN = _DASH_RE
ENS_PATTERN = _ENS_RE

# Credential pattern aliases (used by tests and the verify scripts).
AWS_ACCESS_KEY_PATTERN = _AWS_ACCESS_KEY_RE
AWS_SECRET_KEY_PATTERN = _AWS_SECRET_KEY_RE
GITHUB_TOKEN_PATTERN = _GITHUB_TOKEN_RE
SLACK_TOKEN_PATTERN = _SLACK_TOKEN_RE
DISCORD_TOKEN_PATTERN = _DISCORD_TOKEN_RE
JWT_TOKEN_PATTERN = _JWT_TOKEN_RE
GOOGLE_API_KEY_PATTERN = _GOOGLE_API_KEY_RE
STRIPE_KEY_PATTERN = _STRIPE_KEY_RE
API_KEY_PATTERN = _API_KEY_RE
STEALER_LOG_PATTERN = _STEALER_LOG_RE

# Messaging / identity handle pattern aliases.
TELEGRAM_HANDLE_PATTERN = _TELEGRAM_RE
DISCORD_HANDLE_PATTERN = _DISCORD_LEGACY_RE  # legacy username#0000 form
DISCORD_INVITE_PATTERN = _DISCORD_INVITE_RE
DISCORD_USER_PATTERN = _DISCORD_USER_RE
DISCORD_AT_PATTERN = _DISCORD_AT_RE
XMPP_JID_PATTERN = _XMPP_JID_RE
TOX_ID_PATTERN = _TOX_ID_RE
SESSION_ID_PATTERN = _SESSION_ID_RE
MATRIX_HANDLE_PATTERN = _MATRIX_HANDLE_RE
WIRE_HANDLE_PATTERN = _WIRE_HANDLE_RE
ICQ_NUMBER_PATTERN = _ICQ_NUMBER_RE
WICKR_ID_PATTERN = _WICKR_ID_RE

# Network / forensic identifier pattern aliases (Phase 2 — final subphase).
# All new patterns are exposed so the verify scripts and tests can import
# them by name without going through the extractor wrappers.
IPV6_PATTERN = _IPV6_RE
MAC_ADDRESS_PATTERN = _MAC_COLON_HYPHEN_RE  # the two-form union (colon/hyphen)
MAC_ADDRESS_CISCO_PATTERN = _MAC_CISCO_RE    # the Cisco three-octet form
IPFS_CID_PATTERN = _IPFS_CID_V0_RE           # default — v0 (Qm-prefix) form
IPFS_CID_V1_PATTERN = _IPFS_CID_V1_RE        # CIDv1 (bafy) form
IPFS_PATH_V0_PATTERN = _IPFS_PATH_V0_RE
IPFS_PATH_V1_PATTERN = _IPFS_PATH_V1_RE
YARA_RULE_PATTERN = _YARA_RULE_RE
MITRE_TACTIC_PATTERN = _MITRE_TACTIC_RE
EXPLOIT_DB_PATTERN = _EXPLOIT_DB_RE
NUCLEI_TEMPLATE_PATTERN = _NUCLEI_TEMPLATE_RE
COMBO_LIST_PATTERN = _COMBO_LINE_RE

# ---------------------------------------------------------------------------
# Crypto context detection (for broad patterns: XRP, SOL)
# ---------------------------------------------------------------------------
#
# XRP and Solana addresses have very broad regex shapes (single lowercase r +
# base58 for XRP, pure base58 32-44 chars for SOL).  To avoid false positives
# in non-crypto text, we only emit them when the surrounding ±window text
# contains at least one crypto vocabulary term.

CRYPTO_CONTEXT_TERMS: frozenset[str] = frozenset({
    "wallet", "address", "send", "receive",
    "payment", "transfer", "crypto", "coin",
    "blockchain", "transaction", "deposit",
    "withdraw", "btc", "eth", "sol", "xrp",
    "solana", "ripple", "monero", "bitcoin",
    "litecoin", "dogecoin", "tron", "dash", "zcash",
    "usdt", "usdc", "stablecoin", "defi",
    "exchange", "swap", "escrow",
})

_CRYPTO_CONTEXT_WINDOW = 200


def _has_crypto_context(
    text: str,
    match_start: int,
    match_end: int,
    window: int = _CRYPTO_CONTEXT_WINDOW,
) -> bool:
    """
    Return True if any crypto-context term appears within ±*window* chars
    around the match in *text*.

    Used by the XRP and Solana extractors to suppress false positives.
    """
    if not text:
        return False
    lo = max(0, match_start - window)
    hi = min(len(text), match_end + window)
    context = text[lo:hi].lower()
    return any(term in context for term in CRYPTO_CONTEXT_TERMS)


# ---------------------------------------------------------------------------
# Messaging context detection (for context-dependent handles)
# ---------------------------------------------------------------------------
#
# Some messaging handles (Discord new-format, Wire, Wickr) match text that
# could be a generic username — so we require a messaging-platform keyword
# within ±100 chars of the match before emitting the entity.
#
# TOX_ID, SESSION_ID, and MATRIX_HANDLE have shape-specific regexes and do
# not need a context window check.

MESSAGING_CONTEXT_TERMS: frozenset[str] = frozenset({
    "telegram", "signal", "discord", "wickr",
    "wire", "jabber", "xmpp", "tox", "session",
    "matrix", "element", "briar", "threema",
    "contact", "reach me", "dm me", "message me",
    "encrypted", "secure chat", "opsec",
    "pgp", "e2e", "end-to-end",
})

_MESSAGING_CONTEXT_WINDOW = 100


def _has_messaging_context(
    text: str,
    match_start: int,
    match_end: int,
    window: int = _MESSAGING_CONTEXT_WINDOW,
) -> bool:
    """
    Return True if any messaging-context term appears within ±*window* chars
    around the match in *text*.

    Used by the Discord new-format @username extractor to suppress false
    positives.  Discord's old ``username#0000`` form, invite codes, and
    user-profile snowflakes have shape-specific regexes that do not need
    this check.
    """
    if not text:
        return False
    lo = max(0, match_start - window)
    hi = min(len(text), match_end + window)
    context = text[lo:hi].lower()
    return any(term in context for term in MESSAGING_CONTEXT_TERMS)


def _has_text_within_window(
    text: str,
    match_start: int,
    match_end: int,
    needle: str,
    window: int,
) -> bool:
    """
    Return True if *needle* (case-insensitive) appears within ±*window* chars
    of the [match_start, match_end) span in *text*.

    Used by the Discord new-format extractor, which requires the literal word
    "discord" to be within ±100 chars of the @username match.
    """
    if not text or not needle:
        return False
    lo = max(0, match_start - window)
    hi = min(len(text), match_end + window)
    return needle.lower() in text[lo:hi].lower()


# ---------------------------------------------------------------------------
# YARA context detection (for YARA rule name extraction)
# ---------------------------------------------------------------------------
#
# The word "rule" appears in plenty of non-YARA prose.  The YARA rule
# extractor requires at least one YARA-specific keyword to appear in the
# surrounding text before it emits.  These keywords are unique enough to
# YARA that a hit is strong evidence the document is a YARA rule dump.
#
#   strings:     — the YARA strings section
#   condition:   — the YARA condition expression
#   meta:        — the YARA metadata block
#   import "     — the YARA import directive
#   $           — YARA string identifier (any string ref starts with $)
#
# The first four are anchored to their trailing colon / quote to reduce
# false positives; the dollar sign is too common in non-YARA text so we
# don't include it.

YARA_CONTEXT_TERMS: frozenset[str] = frozenset({
    "strings:", "condition:", "meta:", 'import "',
    "yara", "yara rule",
})

_YARA_CONTEXT_WINDOW = 500


def _has_yara_context(
    text: str,
    match_start: int,
    match_end: int,
    window: int = _YARA_CONTEXT_WINDOW,
) -> bool:
    """
    Return True if any YARA-context term appears within ±*window* chars
    of the [match_start, match_end) span in *text*.

    Used by the YARA rule extractor to suppress prose false positives.
    """
    if not text:
        return False
    lo = max(0, match_start - window)
    hi = min(len(text), match_end + window)
    context = text[lo:hi].lower()
    return any(term in context for term in YARA_CONTEXT_TERMS)


# Patterns whose matches the Solana extractor must skip because they are
# already classified as another coin.  This prevents a 34-char BTC legacy
# address from also being emitted as a SOL match, and prevents an XRP
# r-prefix address from being double-emitted as both XRP and SOL.
#
# SOL is excluded from this list — Solana addresses are 32-44 base58 chars
# with no prefix, and an XRP r-prefix address is also a valid SOL base58
# string.  We resolve the ambiguity in SOL's favor by letting the SOL
# extractor also skip XRP-classified ranges.
_ALREADY_CLASSIFIED_FOR_SOL: tuple[re.Pattern, ...] = (
    _BITCOIN_RE,
    _ETHEREUM_RE,
    _MONERO_RE,
    _LITECOIN_RE,
    _ZCASH_RE,
    _DOGECOIN_RE,
    _XRP_RE,
    _TRON_RE,
    _BITCOIN_CASH_RE,
    _DASH_RE,
)

# Patterns whose matches the XRP extractor must skip because they are
# already classified as another coin.  XRP is excluded from this list
# (the XRP extractor must not skip its own matches).
_ALREADY_CLASSIFIED_FOR_XRP: tuple[re.Pattern, ...] = (
    _BITCOIN_RE,
    _ETHEREUM_RE,
    _MONERO_RE,
    _LITECOIN_RE,
    _ZCASH_RE,
    _DOGECOIN_RE,
    _TRON_RE,
    _BITCOIN_CASH_RE,
    _DASH_RE,
)


def _is_already_classified(
    text: str, start: int, end: int, patterns: tuple[re.Pattern, ...]
) -> bool:
    """Return True if [start, end) of text overlaps any pattern in *patterns*."""
    for pat in patterns:
        for m in pat.finditer(text):
            m_start, m_end = m.span()
            # Overlap: [a, b) and [c, d) overlap when a < d and c < b
            if m_start < end and start < m_end:
                return True
    return False


# ---------------------------------------------------------------------------
# Private IP ranges to exclude (RFC1918 + loopback)
# ---------------------------------------------------------------------------

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_public_ip(addr: str) -> bool:
    """Return True if *addr* is a syntactically valid, non-private IPv4 address."""
    try:
        ip = ipaddress.ip_address(addr)
        return not any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _is_valid_email(email: str) -> bool:
    """Return False for emails with consecutive dots or leading/trailing dots."""
    local, _, domain = email.partition("@")
    if ".." in local or ".." in domain:
        return False
    if local.startswith(".") or local.endswith("."):
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    return True


def _is_valid_litecoin(addr: str) -> bool:
    """
    Litecoin sanity check — must start with L or M and have base58 length.
    Full base58check checksum is not enforced here (same posture as BTC legacy
    pattern, which also does not verify checksum); the regex itself enforces
    the length and charset.
    """
    return bool(re.fullmatch(r"[LM][a-km-zA-HJ-NP-Z1-9]{26,33}", addr))


def _is_valid_xrp(addr: str) -> bool:
    """
    XRP classic address sanity check — starts with 'r', 25-35 alphanumeric
    chars.  We deliberately accept any alphanumeric because the X-address
    format uses different prefixes but starts with 'r' as well; the regex
    already enforces the length and prefix.
    """
    return bool(re.fullmatch(r"r[0-9a-zA-Z]{24,34}", addr))


def _is_valid_tron(addr: str) -> bool:
    """Tron address — T prefix + 33 base58 chars (no 0/O/I/l)."""
    return bool(re.fullmatch(r"T[A-HJ-NP-Za-km-z1-9]{33}", addr))


def _is_valid_dash(addr: str) -> bool:
    """Dash address — X prefix + 33 base58 chars (no 0/O/I/l)."""
    return bool(re.fullmatch(r"X[1-9A-HJ-NP-Za-km-z]{33}", addr))


def _is_valid_zcash(addr: str) -> bool:
    """Zcash — either transparent (t1/t3 + 33 base58) or shielded (zs1 + 74-78 lower/num)."""
    return bool(
        re.fullmatch(r"t[13][a-km-zA-HJ-NP-Z1-9]{33}", addr)
        or re.fullmatch(r"zs1[a-z0-9]{74,78}", addr)
    )


def _is_valid_dogecoin(addr: str) -> bool:
    """Dogecoin — D prefix + 24-33 base58 chars (standard base58 charset,
    1-9 + A-Z excluding I/O + a-z excluding l)."""
    return bool(re.fullmatch(r"D[1-9A-HJ-NP-Za-km-z]{24,33}", addr))


def _is_valid_bitcoin_cash(addr: str) -> bool:
    """
    Bitcoin Cash cashaddr — ``bitcoincash:q...`` or ``bitcoincash:p...`` with
    lowercase alphanumeric payload of 41-111 chars.  Length is enforced by
    the regex; this function re-asserts prefix + version byte + length.
    """
    if not addr.startswith("bitcoincash:"):
        return False
    payload = addr[len("bitcoincash:"):]
    if len(payload) < 42 or len(payload) > 112:
        return False
    if payload[0] not in ("q", "p"):
        return False
    return bool(re.fullmatch(r"[a-z0-9]+", payload))


# ---------------------------------------------------------------------------
# Credential validators + entropy helper
# ---------------------------------------------------------------------------

def _has_high_entropy(s: str, threshold: float = 3.5) -> bool:
    """
    Shannon-entropy filter for the generic API_KEY extractor.

    Returns True if the Shannon entropy (in bits per character) of *s* is
    at least *threshold*.  Used to reject obvious non-secrets such as
    ``password123`` (low entropy) and ``aaaaaaaaaaaaaaaa`` (very low
    entropy) while accepting real secrets like ``aB3dE5fG7hI9jK1lM3nO``
    (high entropy).

    Defaults to threshold=3.5 — empirically enough to reject common
    dictionary words, repeated characters, and short alpha strings.
    Strings shorter than 8 chars are rejected outright (not enough data
    to estimate entropy meaningfully).
    """
    if not s or len(s) < 8:
        return False
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    entropy = -sum(
        (f / n) * math.log2(f / n)
        for f in freq.values()
    )
    return entropy >= threshold


def _is_valid_aws_access_key(value: str) -> bool:
    """Defensive shape check: AKIA + 16 uppercase alphanumeric."""
    return bool(re.fullmatch(r"AKIA[0-9A-Z]{16}", value))


def _is_valid_aws_secret_key(value: str) -> bool:
    """Defensive shape check: exactly 40 chars from [A-Za-z0-9/+]."""
    return bool(re.fullmatch(r"[A-Za-z0-9/+]{40}", value))


def _is_valid_github_token(value: str) -> bool:
    """Defensive shape check: gh[posaur]_ + 36 base62 chars, OR
    github_pat_ + 82 chars from [A-Za-z0-9_]."""
    if re.fullmatch(r"gh[posaur]_[A-Za-z0-9]{36}", value):
        return True
    return bool(re.fullmatch(r"github_pat_[A-Za-z0-9_]{82}", value))


def _is_valid_slack_token(value: str) -> bool:
    """Defensive shape check: xox[bpas]- + 10-100 chars from [0-9A-Za-z-]."""
    return bool(re.fullmatch(r"xox[bpas]-[0-9A-Za-z\-]{10,100}", value))


def _is_valid_discord_token(value: str) -> bool:
    """Defensive shape check: 24 . 6 . 27 chars from [A-Za-z0-9_-]."""
    return bool(
        re.fullmatch(r"[A-Za-z0-9]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}", value)
    )


def _is_valid_jwt_token(value: str) -> bool:
    """Defensive shape check: three dot-separated base64url segments;
    first segment must start with ``eyJ`` (the base64url of ``{"``)."""
    parts = value.split(".")
    if len(parts) != 3:
        return False
    if not parts[0].startswith("eyJ"):
        return False
    for p in parts:
        if not p or not re.fullmatch(r"[A-Za-z0-9_\-]+", p):
            return False
    return True


def _is_valid_google_api_key(value: str) -> bool:
    """Defensive shape check: AIza + 35 chars from [0-9A-Za-z_-]."""
    return bool(re.fullmatch(r"AIza[0-9A-Za-z\-_]{35}", value))


def _is_valid_stripe_key(value: str) -> bool:
    """Defensive shape check: [psr]k_(live|test)_ + 24-99 base62 chars."""
    return bool(re.fullmatch(r"[psr]k_(?:live|test)_[0-9a-zA-Z]{24,99}", value))


def _is_stealer_log_url(value: str) -> bool:
    """
    The URL slot of a stealer-log entry is the credential origin (login
    page).  We accept anything that looks like an http(s) URL with a host;
    we don't require ``.onion`` because stealer logs frequently contain
    clearnet credentials (banks, social media, etc.).
    """
    if not value:
        return False
    return bool(re.match(r"^https?://[^\s/$.?#].[^\s]*$", value, re.IGNORECASE))


# ---------------------------------------------------------------------------
# Network / forensic identifier validators
# ---------------------------------------------------------------------------


def _is_valid_ipv6(value: str) -> bool:
    """
    Return True if *value* is a syntactically valid IPv6 address AND is
    not in a private / loopback / link-local range.  The ``ipaddress``
    module handles all form variations (full, zero-compressed, IPv4-mapped,
    zone-id suffix).

    The filter list matches the brief verbatim — we exclude:
      - ::1/128          (loopback)
      - fe80::/10        (link-local)
      - fc00::/7         (unique local — RFC4193)

    We deliberately do NOT exclude 2001:db8::/32 (documentation range)
    even though ipaddress.is_global would mark it as non-global — the
    brief's test cases use documentation addresses, and the goal of
    the filter is to suppress meaningless addresses, not enforce
    strict global routability.
    """
    if not value:
        return False
    try:
        # Strip the optional zone-id suffix (``%eth0``) — ipaddress
        # understands it on Python 3.9+ but we pass it through anyway
        # to keep the canonical form consistent.
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    # Reject only the explicit private / loopback ranges called out
    # in the design brief.  We do not use is_global() because it
    # excludes documentation (2001:db8::/32) and other ranges we want
    # to keep.
    private_nets = (
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("::/128"),
        ipaddress.ip_network("fe80::/10"),
        ipaddress.ip_network("fc00::/7"),
    )
    return not any(ip in net for net in private_nets)


def _is_valid_mac_address(value: str) -> bool:
    """
    Return True if *value* is a 12-hex-char string shaped as a MAC address
    in any of the three supported forms (colon, hyphen, Cisco three-octet).

    All-zeros (00:00:00:00:00:00) and broadcast (FF:FF:FF:FF:FF:FF) are
    rejected — neither is a useful identifier.
    """
    if not value:
        return False
    raw = value.upper().replace(":", "").replace("-", "").replace(".", "")
    if len(raw) != 12:
        return False
    if not re.fullmatch(r"[0-9A-F]{12}", raw):
        return False
    if raw == "000000000000" or raw == "FFFFFFFFFFFF":
        return False
    return True


def _normalize_mac_address(value: str) -> str:
    """
    Return the canonical colon-separated uppercase form of a MAC address
    (AA:BB:CC:DD:EE:FF).  Accepts the colon, hyphen, and Cisco three-octet
    input forms.
    """
    if not value:
        return ""
    raw = re.sub(r"[:\-.]", "", value).upper()
    if len(raw) != 12:
        return value  # pass through; validator will reject
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def _is_valid_ipfs_cid(value: str) -> bool:
    """
    Return True if *value* is a valid IPFS CIDv0 (Qm + 44 base58) or
    CIDv1 (bafy + 55-60 base32) identifier.  Both are the content
    addresses used in ``/ipfs/`` gateway paths and inline references.
    """
    if not value:
        return False
    if re.fullmatch(r"Qm[1-9A-HJ-NP-Za-km-z]{44}", value):
        return True
    if re.fullmatch(r"bafy[a-z2-7]{55,60}", value):
        return True
    return False


def _is_valid_yara_rule_name(value: str) -> bool:
    """
    Return True if *value* is shaped like a YARA rule name — 3-128
    chars from ``[A-Za-z_][A-Za-z0-9_]*`` (the YARA grammar allows only
    identifier characters, and YARA rule names are conventionally
    TitleCase or snake_case).
    """
    if not value:
        return False
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{2,127}", value))


def _is_valid_mitre_tactic(value: str) -> bool:
    """
    Return True if *value* is a published MITRE ATT&CK TACTIC ID.

    MITRE tactic IDs are TA0001 through TA0043 (as of 2024-Q4 — the
    enterprise matrix is the reference; mobile / ICS matrices reuse
    a subset of the same range).  We accept any TA-prefixed 4-digit
    identifier in that range.
    """
    if not value:
        return False
    m = re.fullmatch(r"TA(\d{4})", value.upper())
    if not m:
        return False
    n = int(m.group(1))
    return 1 <= n <= 43


def _is_valid_exploit_db_id(value: str) -> bool:
    """
    Return True if *value* is shaped like an Exploit-DB EDB-ID
    (4-6 digit numeric identifier).  The actual upper bound is ~52000
    (Exploit-DB has 51k+ entries as of 2024) but the regex stays at 6
    digits so a future EDB-999999 is still accepted.
    """
    if not value:
        return False
    return bool(re.fullmatch(r"[0-9]{4,6}", value))


def _is_valid_nuclei_template_id(value: str) -> bool:
    """
    Return True if *value* is shaped like a Nuclei template ID —
    3-7 dash-separated lowercase alphanumeric segments
    (e.g. ``cve-2024-1234``, ``apache-log4j-rce``).

    The format is intentionally permissive: Nuclei's official template
    directory uses vendor-product-{cve,exposure,tech}-type naming,
    but community templates diverge.  The context-window check (literal
    ``nuclei`` within ±200 chars) is what actually decides whether to
    emit — this validator only enforces the structural shape.
    """
    if not value:
        return False
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+){2,6}", value):
        return False
    return True


# ---------------------------------------------------------------------------
# Messaging / identity handle validators (defence in depth)
# ---------------------------------------------------------------------------


def _is_valid_telegram_handle(value: str) -> bool:
    """Telegram username — 5-32 chars from [A-Za-z0-9_], starts with a letter."""
    if not value:
        return False
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}", value))


def _is_valid_discord_legacy(value: str) -> bool:
    """Discord ``username#0000`` legacy form."""
    if not value or "#" not in value:
        return False
    parts = value.split("#")
    if len(parts) != 2:
        return False
    user, disc = parts
    return (
        bool(re.fullmatch(r"[A-Za-z0-9_.]{2,32}", user))
        and bool(re.fullmatch(r"[0-9]{4}", disc))
    )


def _is_valid_xmpp_jid(value: str) -> bool:
    """XMPP JID — basic RFC-5321 email-shape sanity check."""
    if not value or "@" not in value:
        return False
    local, _, domain = value.partition("@")
    if not local or not domain:
        return False
    if ".." in local or ".." in domain:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9._%+\-]+", local)) and bool(
        re.match(r"^[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", domain)
    )


def _is_valid_tox_id(value: str) -> bool:
    """Tox ID — exactly 76 hex chars (case insensitive)."""
    if not value or len(value) != 76:
        return False
    return bool(re.fullmatch(r"[A-Fa-f0-9]{76}", value))


def _is_valid_session_id(value: str) -> bool:
    """Session messenger ID — exactly 66 hex chars, starts with "05"."""
    if not value or len(value) != 66:
        return False
    if not value.startswith("05"):
        return False
    return bool(re.fullmatch(r"05[A-Fa-f0-9]{64}", value))


def _is_valid_matrix_handle(value: str) -> bool:
    """Matrix handle — @user:server.tld with non-empty user and hostname."""
    if not value or not value.startswith("@"):
        return False
    if ":" not in value[1:]:
        return False
    user, _, server = value[1:].partition(":")
    if not user or not server:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9._\-/=]+", user)) and bool(
        re.fullmatch(r"[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", server)
    )


def _is_valid_icq_number(value: str) -> bool:
    """ICQ number — 5-9 digits."""
    if not value:
        return False
    return bool(re.fullmatch(r"[0-9]{5,9}", value))


def _is_valid_ens_domain(domain: str) -> bool:
    """
    ENS domain — ``<label>.eth``.  Label must be 3-63 chars (regex enforces
    min 3 via the {1,61} middle class; we re-assert here), RFC-1035-ish
    (alphanumeric + hyphen, no leading/trailing hyphen).
    """
    if not domain.lower().endswith(".eth"):
        return False
    label = domain[:-4]  # strip ".eth"
    if len(label) < 3 or len(label) > 63:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    return bool(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9]", label))


def _findall(pattern: re.Pattern, text: str) -> list[str]:
    """Return all non-overlapping matches as full-match strings."""
    return [m.group(0) for m in pattern.finditer(text)]


def _dedup(values) -> list[str]:
    """Deduplicate while preserving first-occurrence order."""
    seen: set[str] = set()
    result: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result


# ---------------------------------------------------------------------------
# Per-type extractor lambdas (used by extract_type)
# ---------------------------------------------------------------------------

def _extract_bitcoin(text: str) -> list[str]:
    return _dedup(_findall(_BITCOIN_RE, text))


def _extract_ethereum(text: str) -> list[str]:
    return _dedup(_findall(_ETHEREUM_RE, text))


def _extract_monero(text: str) -> list[str]:
    return _dedup(_findall(_MONERO_RE, text))


def _extract_litecoin(text: str) -> list[str]:
    return _dedup(
        m for m in _findall(_LITECOIN_RE, text) if _is_valid_litecoin(m)
    )


def _extract_zcash(text: str) -> list[str]:
    return _dedup(
        m for m in _findall(_ZCASH_RE, text) if _is_valid_zcash(m)
    )


def _extract_dogecoin(text: str) -> list[str]:
    return _dedup(
        m for m in _findall(_DOGECOIN_RE, text) if _is_valid_dogecoin(m)
    )


def _extract_xrp(text: str) -> list[str]:
    """
    XRP — broad regex + crypto-context filter.

    Only emit a match when:
      1. The candidate passes the basic r-prefix + length sanity check, AND
      2. The surrounding text contains at least one crypto vocabulary term
         within ±200 chars, AND
      3. The candidate is not already classified as another narrower coin
         (BTC, LTC, ZEC, DOGE, TRX, BCH, DASH, ETH, XMR).
    """
    out: list[str] = []
    for m in _XRP_RE.finditer(text):
        candidate = m.group(0)
        if not _is_valid_xrp(candidate):
            continue
        start, end = m.span()
        if not _has_crypto_context(text, start, end):
            continue
        if _is_already_classified(text, start, end, _ALREADY_CLASSIFIED_FOR_XRP):
            continue
        out.append(candidate)
    return _dedup(out)


def _extract_solana(text: str) -> list[str]:
    """
    Solana — very broad base58 regex + crypto-context filter.

    Only emit a match when:
      1. The candidate passes basic length check, AND
      2. The surrounding text contains at least one crypto vocabulary term
         within ±200 chars, AND
      3. The candidate is not already classified as another narrower coin
         (BTC, LTC, ZEC, DOGE, XRP, TRX, BCH, DASH, ETH, XMR).  This
         prevents an XRP r-prefix address from also being emitted as SOL.
    """
    out: list[str] = []
    for m in _SOLANA_RE.finditer(text):
        candidate = m.group(0)
        if not candidate or len(candidate) < 32 or len(candidate) > 44:
            continue
        start, end = m.span()
        if not _has_crypto_context(text, start, end):
            continue
        if _is_already_classified(text, start, end, _ALREADY_CLASSIFIED_FOR_SOL):
            continue
        out.append(candidate)
    return _dedup(out)


def _extract_tron(text: str) -> list[str]:
    return _dedup(
        m for m in _findall(_TRON_RE, text) if _is_valid_tron(m)
    )


def _extract_bitcoin_cash(text: str) -> list[str]:
    return _dedup(
        m for m in _findall(_BITCOIN_CASH_RE, text) if _is_valid_bitcoin_cash(m)
    )


def _extract_dash(text: str) -> list[str]:
    return _dedup(
        m for m in _findall(_DASH_RE, text) if _is_valid_dash(m)
    )


def _extract_ens(text: str) -> list[str]:
    """
    ENS domain — emit only matches whose label passes the basic length and
    charset sanity check.  The regex already enforces the surrounding
    ``.eth`` suffix and word boundaries; this function rejects any match
    that does not parse as a valid ENS-shaped label.
    """
    out: list[str] = []
    for m in _ENS_RE.finditer(text):
        candidate = m.group(0)
        if not _is_valid_ens_domain(candidate):
            continue
        out.append(candidate)
    return _dedup(out)


def _extract_onion(text: str) -> list[str]:
    found = _dedup(_findall(_ONION_RE, text))
    # Defanged or split v3 addresses ("[.]onion", " dot onion", spaces or
    # zero-width characters inside the address, "hxxp") that the plain regex
    # cannot see. Only checksum-valid v3 addresses whose host the regex did
    # not already report are added, and each passes the URL safety gate.
    if "onion" not in text.lower():
        return found
    try:
        from utils.onion_sweep import gated_text_onion_urls

        hosts = {
            m.lower().split("://", 1)[-1].split("/", 1)[0] for m in found
        }
        found.extend(gated_text_onion_urls(text, exclude_hosts=hosts))
    except Exception:
        pass
    return found


def _extract_email(text: str) -> list[str]:
    return _dedup(m for m in _findall(_EMAIL_RE, text) if _is_valid_email(m))


def _extract_pgp(text: str) -> list[str]:
    blocks = _findall(_PGP_BLOCK_RE, text)
    fingerprints = _findall(_PGP_FINGERPRINT_RE, text)
    context_hits = _findall(_PGP_CONTEXT_RE, text)
    sha1_hashes = set(_findall(_FILE_HASH_SHA1_RE, text))
    result = []
    for h in blocks:
        if h not in sha1_hashes:
            result.append(h)
    for h in fingerprints:
        if h not in sha1_hashes:
            result.append(h)
    for h in context_hits:
        result.append(h)
    return _dedup(result)


def _extract_md5(text: str) -> list[str]:
    return _dedup(m.group(0) for m in _FILE_HASH_MD5_RE.finditer(text) if _has_hash_context(text, *m.span()))


def _extract_sha1(text: str) -> list[str]:
    return _dedup(m.group(0) for m in _FILE_HASH_SHA1_RE.finditer(text) if _has_hash_context(text, *m.span()))


def _extract_sha256(text: str) -> list[str]:
    return _dedup(m.group(0) for m in _FILE_HASH_SHA256_RE.finditer(text) if _has_hash_context(text, *m.span()))


def _extract_cve(text: str) -> list[str]:
    return _dedup(m.upper() for m in _findall(_CVE_RE, text))


def _extract_mitre(text: str) -> list[str]:
    return _dedup(m.upper() for m in _findall(_MITRE_TECHNIQUE_RE, text))


def _extract_ip(text: str) -> list[str]:
    return _dedup(m for m in _findall(_IP_RE, text) if _is_public_ip(m))


def _extract_phone(text: str) -> list[str]:
    return _dedup(_findall(_PHONE_RE, text))


def _extract_paste(text: str) -> list[str]:
    return _dedup(_findall(_PASTE_RE, text))


# ---------------------------------------------------------------------------
# Credential / token extractors
# ---------------------------------------------------------------------------


def _extract_aws_access_key(text: str) -> list[str]:
    """Extract AWS access keys (AKIA + 16 uppercase alphanumeric)."""
    return _dedup(
        m for m in _findall(_AWS_ACCESS_KEY_RE, text) if _is_valid_aws_access_key(m)
    )


def _extract_aws_secret_key(text: str) -> list[str]:
    """
    Extract AWS secret keys — context-dependent (must follow an
    ``aws_secret_access_key`` / ``SecretAccessKey`` label).
    Captures group 1 (the value) rather than the full match.
    """
    out: list[str] = []
    for m in _AWS_SECRET_KEY_RE.finditer(text):
        candidate = m.group(1)
        if _is_valid_aws_secret_key(candidate):
            out.append(candidate)
    return _dedup(out)


def _extract_github_token(text: str) -> list[str]:
    """Extract GitHub personal access tokens (classic and fine-grained)."""
    return _dedup(
        m for m in _findall(_GITHUB_TOKEN_RE, text) if _is_valid_github_token(m)
    )


def _extract_slack_token(text: str) -> list[str]:
    """Extract Slack bot/user/app tokens."""
    return _dedup(
        m for m in _findall(_SLACK_TOKEN_RE, text) if _is_valid_slack_token(m)
    )


def _extract_discord_token(text: str) -> list[str]:
    """Extract Discord tokens (24.6.27 base64url)."""
    return _dedup(
        m for m in _findall(_DISCORD_TOKEN_RE, text) if _is_valid_discord_token(m)
    )


def _extract_jwt_token(text: str) -> list[str]:
    """Extract JWT tokens (header.payload.signature, header starts eyJ)."""
    return _dedup(
        m for m in _findall(_JWT_TOKEN_RE, text) if _is_valid_jwt_token(m)
    )


def _extract_google_api_key(text: str) -> list[str]:
    """Extract Google API keys (AIza + 35 chars)."""
    return _dedup(
        m for m in _findall(_GOOGLE_API_KEY_RE, text) if _is_valid_google_api_key(m)
    )


def _extract_stripe_key(text: str) -> list[str]:
    """Extract Stripe keys (pk_live_/sk_live_/pk_test_/sk_test_/rk_live_/rk_test_)."""
    return _dedup(
        m for m in _findall(_STRIPE_KEY_RE, text) if _is_valid_stripe_key(m)
    )


def _extract_api_key(text: str) -> list[str]:
    """
    Generic high-entropy API key extractor.

    Returns the *value* (not the label) for any match where the value
    passes the Shannon entropy threshold.  This means the downstream
    normalizer sees a clean value such as ``aB3dE5fG7hI9jK1lM3nO``
    rather than the original ``api_key=aB3dE5fG7hI9jK1lM3nO``.

    Values that look like URLs, emails, or short alpha strings are
    filtered out by the entropy + length checks.
    """
    out: list[str] = []
    for m in _API_KEY_RE.finditer(text):
        value = m.group(1)
        if not value:
            continue
        if not (16 <= len(value) <= 64):
            continue
        # Reject values that are obviously not secrets
        if "@" in value and "." in value:
            # email-like — defer to the EMAIL extractor
            continue
        if value.startswith(("http://", "https://")):
            continue
        if not _has_high_entropy(value, threshold=3.5):
            continue
        out.append(value)
    return _dedup(out)


def _extract_stealer_log(text: str) -> list[str]:
    """
    Stealer-log entry detector.

    The expected format is the three-line dump used by RedLine, Raccoon,
    Vidar, StealC, and most modern info-stealer families::

        URL: https://example.com/login
        LOGIN: victim@example.com
        PASSWORD: secret123

    For each match we emit:

      * a synthetic STEALER_LOG_ENTRY marker (the URL string) so downstream
        consumers can flag the page as ``contains_stealer_logs``;
      * the LOGIN value, separately, when it looks like an email (the
        EMAIL extractor will pick it up; we still emit it here so that
        the URL/LOGIN/PASSWORD grouping stays in one place).

    We **never** emit the PASSWORD value — passwords are PII and storing
    them in the DB is explicitly forbidden by content_safety.py.  The
    password_count is derived from the number of stealer-log matches,
    not stored per-password.
    """
    out: list[str] = []
    for m in _STEALER_LOG_RE.finditer(text):
        url_value = m.group(1).strip().rstrip("/.,;")
        login_value = m.group(2).strip().rstrip("/.,;")
        # The password (group 3) is intentionally discarded.
        if _is_stealer_log_url(url_value):
            out.append(url_value)
        # Surface login as a stealer-log entry too (downstream can route
        # it to EMAIL_ADDRESS or THREAT_ACTOR_HANDLE based on shape).
        if login_value and "@" in login_value and "." in login_value:
            out.append(login_value)
    return _dedup(out)


# ---------------------------------------------------------------------------
# Messaging / identity handle extractors
# ---------------------------------------------------------------------------


def _extract_telegram_handle(text: str) -> list[str]:
    """
    Telegram handle — three sub-patterns:
      a) ``(telegram|tg) [@]username``  (e.g. "telegram: @lockbitsupport")
      b) ``t.me/username``              (link form, e.g. "t.me/lockbitsupport")
      c) ``(contact|reach|dm|...) [@]username`` (broader context form)

    Group 1 always captures the username without the ``@`` prefix.  We
    canonicalise to lowercase so the dedup key is case-insensitive
    (Telegram usernames are case-insensitive in practice).
    """
    out: list[str] = []
    for m in _TELEGRAM_RE.finditer(text):
        username = m.group(1)
        if not username:
            continue
        if not _is_valid_telegram_handle(username):
            continue
        out.append(username.lower())
    return _dedup(out)


def _extract_discord_handle(text: str) -> list[str]:
    """
    Discord handle — three sub-patterns:
      a) legacy ``username#0000`` (still seen on older posts; very specific)
      b) ``discord.gg/<invite-code>`` (server invite link)
      c) ``discord.com/users/<snowflake-id>`` (user profile link)
      d) new-format ``@username`` — only emitted when "discord" appears
         within ±100 chars (the @username shape alone is too broad).

    Canonical values (all lowercase for case-insensitive dedup):
      - legacy: ``username#0000`` (username lowercased; discriminator is digits)
      - invite: ``invite:<code>``
      - user:   ``user:<snowflake>``
      - new @:  ``username``
    """
    out: list[str] = []

    # (a) legacy username#0000 — username is lowercased for dedup;
    # discriminator is 4 digits so case is irrelevant.
    for m in _DISCORD_LEGACY_RE.finditer(text):
        user = m.group(1)
        disc = m.group(2)
        if not _is_valid_discord_legacy(f"{user}#{disc}"):
            continue
        out.append(f"{user.lower()}#{disc}")

    # (b) discord.gg invite code — lowercased so case variations of the
    # same invite code dedup together.
    for m in _DISCORD_INVITE_RE.finditer(text):
        code = m.group(1)
        if code:
            out.append(f"invite:{code.lower()}")

    # (c) discord.com/users/<snowflake> — snowflakes are numeric, no case.
    for m in _DISCORD_USER_RE.finditer(text):
        snowflake = m.group(1)
        if snowflake:
            out.append(f"user:{snowflake}")

    # (d) new-format @username — requires "discord" within ±100 chars
    for m in _DISCORD_AT_RE.finditer(text):
        username = m.group(1)
        if not username:
            continue
        start, end = m.span()
        if not _has_text_within_window(text, start, end, "discord", window=100):
            continue
        out.append(username.lower())

    return _dedup(out)


def _extract_xmpp_jid(text: str) -> list[str]:
    """
    XMPP / Jabber JID — looks like an email but is only emitted when an
    XMPP context keyword precedes it (xmpp / jabber / jid / pidgin / gajim /
    xabber / conversations / delta chat).

    When the same address would also be picked up by the EMAIL extractor
    (which is unavoidable since the shapes overlap), the normalizer's
    TYPE_PRIORITY tiebreak keeps the XMPP_JID (priority 1 vs EMAIL_ADDRESS
    priority 4).  See normalizer.resolve_entity_type_conflicts().
    """
    out: list[str] = []
    for m in _XMPP_JID_RE.finditer(text):
        jid = m.group(1)
        if not jid:
            continue
        if not _is_valid_xmpp_jid(jid):
            continue
        out.append(jid.lower())
    return _dedup(out)


def _extract_tox_id(text: str) -> list[str]:
    """
    Tox ID — exactly 76 hex chars.  The pattern is so specific (76 hex
    chars, all from [A-Fa-f0-9]) that we emit unconditionally.
    """
    out: list[str] = []
    for m in _TOX_ID_RE.finditer(text):
        candidate = m.group(0)
        if _is_valid_tox_id(candidate):
            out.append(candidate.upper())
    return _dedup(out)


def _extract_session_id(text: str) -> list[str]:
    """
    Session messenger ID — 66 hex chars, always starts with "05".  Emitted
    unconditionally because the shape is unambiguous.
    """
    out: list[str] = []
    for m in _SESSION_ID_RE.finditer(text):
        candidate = m.group(0)
        if _is_valid_session_id(candidate):
            # Lowercase for consistency; the leading "05" is preserved.
            out.append(candidate.lower())
    return _dedup(out)


def _extract_matrix_handle(text: str) -> list[str]:
    """
    Matrix handle — ``@username:server.tld``.  Both halves are captured
    so the canonical form preserves original casing of the homeserver
    (lowercased per Matrix spec).
    """
    out: list[str] = []
    for m in _MATRIX_HANDLE_RE.finditer(text):
        user = m.group(1)
        server = m.group(2)
        if not user or not server:
            continue
        # Matrix spec: lowercase the full handle for canonicalisation.
        canonical = f"@{user.lower()}:{server.lower()}"
        if _is_valid_matrix_handle(canonical):
            out.append(canonical)
    return _dedup(out)


def _extract_wire_handle(text: str) -> list[str]:
    """
    Wire messenger handle — context-dependent on ``wire`` or ``wire.com``.
    """
    out: list[str] = []
    for m in _WIRE_HANDLE_RE.finditer(text):
        username = m.group(1)
        if not username:
            continue
        out.append(username.lower())
    return _dedup(out)


def _extract_icq_number(text: str) -> list[str]:
    """
    ICQ UIN — context-dependent on the literal ``icq`` keyword, 5-9 digits.
    """
    out: list[str] = []
    for m in _ICQ_NUMBER_RE.finditer(text):
        number = m.group(1)
        if not number:
            continue
        if _is_valid_icq_number(number):
            out.append(number)
    return _dedup(out)


def _extract_wickr_id(text: str) -> list[str]:
    """
    Wickr ID — context-dependent on ``wickr`` keyword.
    """
    out: list[str] = []
    for m in _WICKR_ID_RE.finditer(text):
        username = m.group(1)
        if not username:
            continue
        out.append(username.lower())
    return _dedup(out)


# ---------------------------------------------------------------------------
# Network / forensic identifier extractors
# ---------------------------------------------------------------------------


def _extract_ipv6(text: str) -> list[str]:
    """
    IPv6 — broad match + per-candidate validation.

    The regex is permissive on purpose: it accepts every documented
    IPv6 form including full, zero-compressed, IPv4-mapped, and
    zone-id suffix.  The validator (ipaddress + is_global) then
    rejects private/loopback/ULA ranges so only public / global
    addresses are emitted — matching the IPv4 public-IP filter.
    """
    out: list[str] = []
    for m in _IPV6_RE.finditer(text):
        candidate = m.group(0)
        if not candidate:
            continue
        if _is_valid_ipv6(candidate):
            out.append(candidate)
    return _dedup(out)


def _extract_mac_address(text: str) -> list[str]:
    """
    MAC address — colon / hyphen / Cisco three-octet forms.

    All matches are canonicalised to uppercase colon-separated
    (AA:BB:CC:DD:EE:FF) so dedup works across the three input forms.
    All-zeros and broadcast are rejected by the validator.
    """
    out: list[str] = []
    for m in _MAC_COLON_HYPHEN_RE.finditer(text):
        candidate = m.group(0)
        if not _is_valid_mac_address(candidate):
            continue
        out.append(_normalize_mac_address(candidate))
    for m in _MAC_CISCO_RE.finditer(text):
        candidate = m.group(0)
        if not _is_valid_mac_address(candidate):
            continue
        out.append(_normalize_mac_address(candidate))
    return _dedup(out)


def _extract_ipfs_cid(text: str) -> list[str]:
    """
    IPFS CID — CIDv0 (Qm + 44 base58), CIDv1 (bafy + 55-60 base32),
    and the /ipfs/ path prefix variant for each.

    Path-prefixed matches are unwrapped to the bare CID before emission
    so dedup is consistent across the inline and URL forms.
    """
    out: list[str] = []
    for m in _IPFS_CID_V0_RE.finditer(text):
        candidate = m.group(0)
        if _is_valid_ipfs_cid(candidate):
            out.append(candidate)
    for m in _IPFS_CID_V1_RE.finditer(text):
        candidate = m.group(0)
        if _is_valid_ipfs_cid(candidate):
            out.append(candidate)
    # /ipfs/<CID> form: extract the bare CID so dedup catches it
    # against the same value found inline elsewhere.
    for m in _IPFS_PATH_V0_RE.finditer(text):
        candidate = m.group(1)
        if _is_valid_ipfs_cid(candidate):
            out.append(candidate)
    for m in _IPFS_PATH_V1_RE.finditer(text):
        candidate = m.group(1)
        if _is_valid_ipfs_cid(candidate):
            out.append(candidate)
    return _dedup(out)


def _extract_yara_rule(text: str) -> list[str]:
    """
    YARA rule name — captured by the regex, with a YARA-context check
    on the surrounding text (must contain at least one of ``strings:``,
    ``condition:``, ``meta:``, ``import "``, or ``yara``).

    The word "rule" is common in prose, so the context check is the
    primary noise filter; the regex is intentionally narrow (it
    requires the rule name + an opening brace) so it rarely matches
    outside actual YARA rule declarations.
    """
    out: list[str] = []
    for m in _YARA_RULE_RE.finditer(text):
        candidate = m.group(1)
        if not candidate or not _is_valid_yara_rule_name(candidate):
            continue
        start, end = m.span()
        if not _has_yara_context(text, start, end):
            continue
        out.append(candidate)
    return _dedup(out)


def _extract_mitre_tactic(text: str) -> list[str]:
    """
    MITRE ATT&CK TACTIC — TA + 4 digits in the published range
    TA0001..TA0043.  Different namespace from MITRE_TECHNIQUE (T1234);
    tactics are the higher-level categories (Initial Access, Execution,
    etc.) and live in a TA-prefixed namespace.
    """
    out: list[str] = []
    for m in _MITRE_TACTIC_RE.finditer(text):
        candidate = m.group(0).upper()
        if _is_valid_mitre_tactic(candidate):
            out.append(candidate)
    return _dedup(out)


def _extract_exploit_db_id(text: str) -> list[str]:
    """
    Exploit-DB EDB-ID — captures just the numeric ID from either
    ``EDB-ID: 12345`` or ``exploit-db.com/exploits/12345`` form.  The
    full URL form is unwrapped so the canonical value is the bare
    number, which is the meaningful identifier.
    """
    out: list[str] = []
    for m in _EXPLOIT_DB_RE.finditer(text):
        # Group 1 = EDB-ID:<num>, Group 2 = URL/<num>
        edb_id = m.group(1) or m.group(2)
        if not edb_id or not _is_valid_exploit_db_id(edb_id):
            continue
        out.append(edb_id)
    return _dedup(out)


def _extract_nuclei_template(text: str) -> list[str]:
    """
    Nuclei template ID — vendor-product-{cve,exposure,tech}-type.yaml
    pattern.  The shape alone is too broad to emit (a file named
    ``docker-compose-dev-test.yaml`` matches the regex), so we require
    the literal ``nuclei`` to appear within ±200 chars of the match.

    The validator ensures the candidate has the right dash-segment
    count; the context check is what actually decides whether to
    emit.
    """
    out: list[str] = []
    for m in _NUCLEI_TEMPLATE_RE.finditer(text):
        candidate = m.group(1)
        if not candidate or not _is_valid_nuclei_template_id(candidate):
            continue
        start, end = m.span()
        if not _has_text_within_window(
            text, start, end, "nuclei", window=200
        ):
            continue
        out.append(candidate)
    return _dedup(out)


def _extract_combo_list_entry(text: str) -> list[str]:
    """
    Credential combo-list entry — detect blocks of 3+ lines matching
    the email:password (or user:password) format used in paste-site
    credential dumps.

    For each matching line we emit the EMAIL side (group 1) so the
    normalizer routes it to the EMAIL_ADDRESS pipeline.  The PASSWORD
    side (group 2) is *intentionally* never stored — content safety.

    When 3+ such lines are present on a page, each line's email is
    emitted as a COMBO_LIST_ENTRY entity so downstream consumers can
    tag the page as ``contains_combo_list`` and count the entries.
    Below the threshold, no entities are emitted (a one-off email:pass
    line in a forum post is not a "combo list dump").
    """
    if not text:
        return []
    matches = list(_COMBO_LINE_RE.finditer(text))
    if len(matches) < 3:
        return []
    out: list[str] = []
    for m in matches:
        identifier = m.group(1)
        # group 2 (password) is intentionally discarded.
        if not identifier:
            continue
        out.append(identifier.lower())
    return _dedup(out)


def _extract_crypto_seed_phrase(text: str) -> list[str]:
    """
    BIP39 seed phrase detection — counts runs of consecutive BIP39
    words in the text.

    Content safety: the actual seed phrase value is NEVER stored.
    The canonical emit is one of:
      - SEED_PHRASE_DETECTED_12_WORDS
      - SEED_PHRASE_DETECTED_15_WORDS
      - SEED_PHRASE_DETECTED_18_WORDS
      - SEED_PHRASE_DETECTED_21_WORDS
      - SEED_PHRASE_DETECTED_24_WORDS

    The wordlist subset covers ~150 common BIP39 words — enough to
    confidently identify a 12+ word run as a seed phrase without
    false-positive-hammering generic English prose (the words are
    uncommon outside the seed-phrase context).

    A page can produce at most one seed-phrase entity (the longest
    run found) — duplicate emits would be noise.
    """
    if not text:
        return []
    # Tokenise: split on whitespace, lowercase, strip punctuation that
    # commonly appears around seed phrases (commas, periods, semicolons).
    tokens = re.findall(r"[A-Za-z][A-Za-z']*", text.lower())
    if not tokens:
        return []

    best_run: int = 0
    current_run: int = 0
    for tok in tokens:
        if tok in _BIP39_WORDLIST:
            current_run += 1
            if current_run > best_run:
                best_run = current_run
        else:
            current_run = 0

    out: list[str] = []
    for length in sorted(_BIP39_SEED_PHRASE_LENGTHS, reverse=True):
        if best_run >= length:
            # Emit the canonical 12/24 marker even when the actual
            # run is 15/18/21 — the canonical 12-word emit covers
            # 12-23 and the 24-word emit covers exactly 24+.  This
            # matches BIP39 conventions (default 12, maximum 24).
            marker = (
                "SEED_PHRASE_DETECTED_24_WORDS"
                if best_run >= 24
                else "SEED_PHRASE_DETECTED_12_WORDS"
            )
            out.append(marker)
            break
    return _dedup(out)


_EXTRACTORS: dict[str, object] = {
    BITCOIN_ADDRESS: _extract_bitcoin,
    ETHEREUM_ADDRESS: _extract_ethereum,
    MONERO_ADDRESS: _extract_monero,
    LITECOIN_ADDRESS: _extract_litecoin,
    ZCASH_ADDRESS: _extract_zcash,
    DOGECOIN_ADDRESS: _extract_dogecoin,
    XRP_ADDRESS: _extract_xrp,
    SOLANA_ADDRESS: _extract_solana,
    TRON_ADDRESS: _extract_tron,
    BITCOIN_CASH_ADDRESS: _extract_bitcoin_cash,
    DASH_ADDRESS: _extract_dash,
    ENS_DOMAIN: _extract_ens,
    ONION_URL: _extract_onion,
    EMAIL_ADDRESS: _extract_email,
    PGP_KEY_BLOCK: _extract_pgp,
    FILE_HASH_MD5: _extract_md5,
    FILE_HASH_SHA1: _extract_sha1,
    FILE_HASH_SHA256: _extract_sha256,
    CVE_NUMBER: _extract_cve,
    MITRE_TECHNIQUE: _extract_mitre,
    IP_ADDRESS: _extract_ip,
    PHONE_NUMBER: _extract_phone,
    PASTE_URL: _extract_paste,
    # Credential / token extractors
    AWS_ACCESS_KEY: _extract_aws_access_key,
    AWS_SECRET_KEY: _extract_aws_secret_key,
    GITHUB_TOKEN: _extract_github_token,
    SLACK_TOKEN: _extract_slack_token,
    DISCORD_TOKEN: _extract_discord_token,
    JWT_TOKEN: _extract_jwt_token,
    API_KEY: _extract_api_key,
    GOOGLE_API_KEY: _extract_google_api_key,
    STRIPE_KEY: _extract_stripe_key,
    STEALER_LOG_ENTRY: _extract_stealer_log,
    # Messaging / identity handle extractors
    TELEGRAM_HANDLE: _extract_telegram_handle,
    DISCORD_HANDLE: _extract_discord_handle,
    XMPP_JID: _extract_xmpp_jid,
    TOX_ID: _extract_tox_id,
    SESSION_ID: _extract_session_id,
    MATRIX_HANDLE: _extract_matrix_handle,
    WIRE_HANDLE: _extract_wire_handle,
    ICQ_NUMBER: _extract_icq_number,
    WICKR_ID: _extract_wickr_id,
    # Network / forensic identifier extractors (Phase 2 — final subphase)
    IPV6_ADDRESS: _extract_ipv6,
    MAC_ADDRESS: _extract_mac_address,
    IPFS_CID: _extract_ipfs_cid,
    COMBO_LIST_ENTRY: _extract_combo_list_entry,
    YARA_RULE: _extract_yara_rule,
    MITRE_TACTIC: _extract_mitre_tactic,
    EXPLOIT_DB_ID: _extract_exploit_db_id,
    NUCLEI_TEMPLATE: _extract_nuclei_template,
    CRYPTO_SEED_PHRASE: _extract_crypto_seed_phrase,
}

# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def extract_all(text: str) -> dict[str, list[str]]:
    """
    Run all entity patterns against *text*.

    Returns a dict keyed by entity-type constant.  Every key is always present;
    types with no matches map to an empty list.  Never raises.
    """
    result: dict[str, list[str]] = {}
    try:
        for entity_type, extractor in _EXTRACTORS.items():
            result[entity_type] = extractor(text)  # type: ignore[operator]
    except Exception:
        logger.exception("extract_all encountered an unexpected error")
        for entity_type in ENTITY_TYPES:
            result.setdefault(entity_type, [])
    return result


def extract_type(text: str, entity_type: str) -> list[str]:
    """
    Extract a single entity type from *text*.

    Raises ValueError for unknown entity_type.
    """
    if entity_type not in _EXTRACTORS:
        raise ValueError(
            f"Unknown entity type {entity_type!r}. "
            f"Valid types: {sorted(ENTITY_TYPES)}"
        )
    return _EXTRACTORS[entity_type](text)  # type: ignore[operator]
