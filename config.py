import os
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)
_OPTIONAL_CONFIG_WARNING_STATE = "_voidaccess_optional_config_warning_shown"


def _clean_env(name, default=None):
	value = os.getenv(name, default)
	if value is None:
		return None
	value = str(value).strip()
	# Support accidentally quoted values copied into .env
	if len(value) >= 2 and (
		(value[0] == value[-1] == '"') or (value[0] == value[-1] == "'")
	):
		value = value[1:-1].strip()
	return value

# Configuration variables loaded from the .env file
OPENAI_API_KEY = _clean_env("OPENAI_API_KEY")
GOOGLE_API_KEY = _clean_env("GOOGLE_API_KEY")
ANTHROPIC_API_KEY = _clean_env("ANTHROPIC_API_KEY")
OLLAMA_BASE_URL = _clean_env("OLLAMA_BASE_URL")
OPENROUTER_BASE_URL = _clean_env("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
OPENROUTER_API_KEY = _clean_env("OPENROUTER_API_KEY")
GROQ_API_KEY = _clean_env("GROQ_API_KEY", "")
LLAMA_CPP_BASE_URL = _clean_env("LLAMA_CPP_BASE_URL")

# Database
DATABASE_URL = _clean_env("DATABASE_URL")

# Tor proxy (configurable so Docker can point to a tor service by name)
TOR_PROXY_HOST = _clean_env("TOR_PROXY_HOST", "127.0.0.1")
TOR_PROXY_PORT = _clean_env("TOR_PROXY_PORT", "9050")

# Optional second SocksPort configured with `IsolateDestAddr`, used only by the
# Playwright renderer.  Every aiohttp caller isolates by handing Tor a distinct
# SOCKS credential per target, but Playwright's driver refuses SOCKS5
# credentials outright, so that path needs Tor to do the keying itself.
# docker/Dockerfile.tor opens 9250 for exactly this.  If the port is absent —
# system tor, Tor Browser, any deployment not using our container — the JS
# render path runs un-isolated and says so once; it is never silently assumed to
# be isolated.  Set to an empty value to disable the probe entirely.
TOR_ISOLATION_SOCKS_PORT = _clean_env("TOR_ISOLATION_SOCKS_PORT", "9250")

# Phase 1D — expanded sources (all optional; missing vars disable that source)
DARKSEARCH_API_KEY = _clean_env("DARKSEARCH_API_KEY")          # optional free-tier key
TELEGRAM_API_ID   = _clean_env("TELEGRAM_API_ID")              # from my.telegram.org
TELEGRAM_API_HASH = _clean_env("TELEGRAM_API_HASH")            # from my.telegram.org
TELEGRAM_PHONE    = _clean_env("TELEGRAM_PHONE")               # E.164, e.g. +12025551234

# Phase 4 — vector store + alert channels (all optional)
CHROMA_PERSIST_DIR = _clean_env("CHROMA_PERSIST_DIR", "./chroma_db")
TELEGRAM_BOT_TOKEN = _clean_env("TELEGRAM_BOT_TOKEN")          # one-way alerts; separate from Telethon API vars
SMTP_HOST          = _clean_env("SMTP_HOST")
SMTP_PORT          = _clean_env("SMTP_PORT", "587")
SMTP_USER          = _clean_env("SMTP_USER")
SMTP_PASS          = _clean_env("SMTP_PASS")

# Phase 5 — REST API server
API_HOST = _clean_env("API_HOST", "0.0.0.0")
API_PORT = _clean_env("API_PORT", "8000")

# Phase 6 — advanced capabilities
DEEPL_API_KEY        = _clean_env("DEEPL_API_KEY")           # optional; translation
# Stylometry decisions are enabled only by a labeled calibration artifact.
STYLOMETRY_CALIBRATION_FILE = _clean_env("STYLOMETRY_CALIBRATION_FILE")

# LLM extraction cache (optional — defaults to enabled)
DISABLE_EXTRACTION_CACHE = _clean_env("DISABLE_EXTRACTION_CACHE")
if DISABLE_EXTRACTION_CACHE is not None:
    DISABLE_EXTRACTION_CACHE = DISABLE_EXTRACTION_CACHE.lower() == "true"
else:
    DISABLE_EXTRACTION_CACHE = False

# i18n / Query Expansion
# Languages to include in query expansion (comma-separated ISO 639-1 codes)
# Default: en, ru, zh (English, Russian, Chinese)
I18N_LANGUAGES = _clean_env("I18N_LANGUAGES", "en,ru,zh")
if I18N_LANGUAGES and isinstance(I18N_LANGUAGES, str):
    I18N_LANGUAGES = [lang.strip() for lang in I18N_LANGUAGES.split(",") if lang.strip()]
else:
    I18N_LANGUAGES = ["en", "ru", "zh"]

# Threat Intelligence API Keys
OTX_API_KEY = _clean_env("OTX_API_KEY", "")  # AlienVault OTX — free at otx.alienvault.com
VT_API_KEY = _clean_env("VT_API_KEY", "")    # VirusTotal — free tier at virustotal.com

# VirusTotal pacing tier.  The public API allows 4 requests/minute (a 15 s gap);
# premium keys have no per-minute limit at all, and a key string is
# indistinguishable between the two, so a paying subscriber was being paced 25x
# slower than their entitlement.  Set VT_API_TIER=premium to opt out of
# free-tier pacing.  Unset or unrecognised means "public" — the safe default,
# since guessing premium wrongly earns a 429.
VT_API_TIER = (_clean_env("VT_API_TIER", "public") or "public").strip().lower()

# IP Reputation Enrichment (all optional — features degrade gracefully without keys)
ABUSEIPDB_API_KEY = _clean_env("ABUSEIPDB_API_KEY", "")   # Community IP abuse reports
GREYNOISE_API_KEY = _clean_env("GREYNOISE_API_KEY", "")   # Suppresses benign scanner IPs
C2_FEED_CACHE_TTL = _clean_env("C2_FEED_CACHE_TTL", "24") # Hours between feed refreshes

# Domain Reputation Enrichment
URLSCAN_API_KEY        = _clean_env("URLSCAN_API_KEY", "")
SECURITYTRAILS_API_KEY = _clean_env("SECURITYTRAILS_API_KEY", "")

# Code Intelligence (GitHub / GitLab scraping)
GITHUB_TOKEN = _clean_env("GITHUB_TOKEN", "")
GITLAB_TOKEN = _clean_env("GITLAB_TOKEN", "")

# Hash Reputation Enrichment
HYBRID_ANALYSIS_API_KEY = _clean_env("HYBRID_ANALYSIS_API_KEY", "")

# Email Reputation Enrichment
HIBP_API_KEY      = _clean_env("HIBP_API_KEY", "")
EMAILREP_API_KEY  = _clean_env("EMAILREP_API_KEY", "")

# Breach-exposure lookup (complements HIBP; all optional / free-tier — no key required)
# XposedOrNot: free breach lookup incl. stealer-log exposure. Optional key = richer results.
XPOSEDORNOT_API_KEY = _clean_env("XPOSEDORNOT_API_KEY", "")
# LeakCheck public tier and Hudson Rock Cavalier (infostealer) need NO key — no config var.

# NVD 2.0 full CVE database (complements CISA KEV). Works without a key; an
# optional free key raises the rate limit (5→50 requests / 30s).
NVD_API_KEY = _clean_env("NVD_API_KEY", "")
# ransomlook.io (2nd ransomware tracker, cross-validates ransomware.live) needs NO key.

# ---------------------------------------------------------------------------
# Page-snapshot object store (P2.1) — S3-compatible, provider-agnostic.
# ---------------------------------------------------------------------------
# The shared-corpus page-snapshot store (snapshot_store/) uploads sanitized page
# content to any S3-compatible backend: Cloudflare R2 in production (zero
# egress, see CC-2), MinIO locally, or any S3 store — same code, configured only
# by endpoint + bucket + credentials. There is NO hard R2/boto SDK dependency;
# the client signs SigV4 over aiohttp.
#
# All four of endpoint/bucket/access-key/secret must be present for the store to
# be "configured"; with any missing, snapshot writes degrade to a graceful
# no-op (the tool never requires object storage to run — CLI $0 path, or a
# private-mode install). Credentials must be supplied by the operator via .env,
# never hardcoded.
S3_ENDPOINT_URL      = _clean_env("S3_ENDPOINT_URL")       # e.g. https://<acct>.r2.cloudflarestorage.com
S3_BUCKET            = _clean_env("S3_BUCKET")             # snapshot bucket name
S3_ACCESS_KEY_ID     = _clean_env("S3_ACCESS_KEY_ID")
S3_SECRET_ACCESS_KEY = _clean_env("S3_SECRET_ACCESS_KEY")
# R2 ignores region and expects the literal "auto"; real S3/MinIO use their own.
S3_REGION            = _clean_env("S3_REGION", "auto") or "auto"

# ---------------------------------------------------------------------------
# Owned persistent index (P3.0 / requirement 1.3) — self-hosted Meilisearch.
# ---------------------------------------------------------------------------
# The owned index (owned_index/) is a central-service / shared-tier component: it
# lives on the Oracle box alongside the shared corpus and gives search a source
# that survives any third-party onion engine's death (req 1.8). It is a clearnet
# HTTP service reached over netpool with pacing-scaled timeouts.
#
# MEILI_HOST is the sole "configured" gate: unset means the index no-ops and the
# tool falls back to live fan-out (the CLI/$0-local path and private-mode installs
# run without it — graceful, never a crash). MEILI_KEY is the master/API key; an
# empty value is valid for a keyless local dev container (the Authorization header
# is then omitted). Credentials come from .env, never hardcoded.
MEILI_HOST  = _clean_env("MEILI_HOST")                    # e.g. http://127.0.0.1:7700
MEILI_KEY   = _clean_env("MEILI_KEY", "")                 # master/API key; "" = keyless local dev
MEILI_INDEX = _clean_env("MEILI_INDEX", "onion_pages")    # index uid


# ---------------------------------------------------------------------------
# Owned-index freshness loop (P3.3 / requirement 1.6) — durable-queue re-crawl.
# ---------------------------------------------------------------------------
# The freshness loop re-crawls previously-seen onions for liveness + content-diff
# on the P2.3 durable queue. It is bounded and cost-controlled: staleness-
# prioritized and capped per cycle so re-crawl volume never balloons on the
# $0/Tor budget. All values env-tunable. The loop is inert unless the owned index
# is configured (MEILI_HOST set) and a durable-queue worker is running (central
# service only) — a local/$0 install never runs it.
def _clean_int(name, default):
    try:
        return int(_clean_env(name, str(default)) or default)
    except (TypeError, ValueError):
        return default


def _clean_float(name, default):
    try:
        return float(_clean_env(name, str(default)) or default)
    except (TypeError, ValueError):
        return default


def _clean_csv_set(name, default):
    """Parse a comma-separated env value into a lowercased set of tokens.

    Empty/unset falls back to *default* (an iterable). Used for tunable
    membership sets like the trust gate's trusted-feed allowlist.
    """
    raw = _clean_env(name, None)
    if not raw:
        return {str(t).strip().lower() for t in default if str(t).strip()}
    return {tok.strip().lower() for tok in raw.split(",") if tok.strip()}

# Seconds between freshness cycles (the self-re-enqueuing scan tick). Default 6h.
FRESHNESS_INTERVAL_SECONDS = _clean_int("FRESHNESS_INTERVAL_SECONDS", 6 * 3600)
# Max onions re-crawled per cycle — the hard per-cycle cap (no exhaustive crawl).
FRESHNESS_BATCH_CAP = _clean_int("FRESHNESS_BATCH_CAP", 20)
# An onion is "due" for re-crawl once its last_seen is older than this. Default 24h.
FRESHNESS_STALE_AFTER_SECONDS = _clean_int("FRESHNESS_STALE_AFTER_SECONDS", 24 * 3600)
# Consecutive dead re-crawls before an onion is dropped from active retrieval and
# re-crawl scheduling (the dead→drop policy).
FRESHNESS_DEAD_DROP_THRESHOLD = _clean_int("FRESHNESS_DEAD_DROP_THRESHOLD", 3)

# ---------------------------------------------------------------------------
# Trust gate — P4.0 scoring machinery (requirement 3.2 / 3.3). All tunable.
# ---------------------------------------------------------------------------
# The automated, deterministic anti-poisoning gate. These thresholds are the
# single tunable surface (CC-4): the gate hardcodes none of them — it reads a
# TrustGateConfig snapshot built from these values. Defaults are the P4.0 brief's
# starting point, calibrated by the red-team suite.
#
# Promotion: an artifact reaches CORROBORATED only with >= this many *independent*
# sources; a single trusted-feed cross-hit reaches FEED_VALIDATED outright.
TRUST_GATE_MIN_INDEPENDENT_SOURCES = _clean_int("TRUST_GATE_MIN_INDEPENDENT_SOURCES", 2)
# Corroboration also requires >= this many distinct CONTRIBUTORS (not just origins).
# This closes the reputation-gaming Sybil path: a single (even trusted) contributor
# claiming one IOC across many fabricated origins supplies only ONE contributor, so
# it can never self-corroborate. In P4.1-local each onion is its own contributor, so
# genuine cross-onion corroboration is unaffected.
TRUST_GATE_MIN_INDEPENDENT_CONTRIBUTORS = _clean_int(
    "TRUST_GATE_MIN_INDEPENDENT_CONTRIBUTORS", 2
)
# The trusted-feed allowlist — a cross-hit against any of these validates an
# artifact regardless of the contributing onion's reputation (feed validation is
# source-independent). Defaults to the abuse.ch / CISA-KEV / NVD family.
TRUST_GATE_TRUSTED_FEEDS = _clean_csv_set(
    "TRUST_GATE_TRUSTED_FEEDS",
    {
        "sslbl", "feodo", "urlhaus", "threatfox", "malwarebazaar", "abuse.ch",
        "kev", "cisa_kev", "cisa", "nvd", "epss", "openphish", "phishtank",
        "ransomwhere",
    },
)
# Flood / rate limit: max artifacts one source may contribute within the window.
TRUST_GATE_SOURCE_RATE_LIMIT = _clean_int("TRUST_GATE_SOURCE_RATE_LIMIT", 50)
TRUST_GATE_RATE_WINDOW_SECONDS = _clean_int("TRUST_GATE_RATE_WINDOW_SECONDS", 60)
# Entity-stuffing: max entities in a single submission before it is flagged.
TRUST_GATE_STUFFING_MAX_ENTITIES = _clean_int("TRUST_GATE_STUFFING_MAX_ENTITIES", 100)
# Templated injection: a submission whose distinct-fingerprint ratio falls below
# this (near-identical records) is flagged as templated.
TRUST_GATE_TEMPLATED_MIN_DISTINCT_RATIO = _clean_float(
    "TRUST_GATE_TEMPLATED_MIN_DISTINCT_RATIO", 0.2
)
TRUST_GATE_TEMPLATED_MIN_SUBMISSION = _clean_int("TRUST_GATE_TEMPLATED_MIN_SUBMISSION", 5)
# Mass-identical: how many byte-identical records from one source before the
# repeats are rejected as a mass-identical flood.
TRUST_GATE_MASS_IDENTICAL_MAX = _clean_int("TRUST_GATE_MASS_IDENTICAL_MAX", 5)
# Source reputation: neutral start; a source drops below the block threshold
# (blocked outright) or the corroborate threshold (contributions no longer count
# toward promotion) as it accrues contradictions/anomalies.
TRUST_GATE_REPUTATION_START = _clean_float("TRUST_GATE_REPUTATION_START", 1.0)
TRUST_GATE_REPUTATION_BLOCK_THRESHOLD = _clean_float(
    "TRUST_GATE_REPUTATION_BLOCK_THRESHOLD", 0.3
)
TRUST_GATE_REPUTATION_MIN_TO_CORROBORATE = _clean_float(
    "TRUST_GATE_REPUTATION_MIN_TO_CORROBORATE", 0.5
)
# How much a contributor's reputation rises each time its claim agrees with
# independently-established trusted data (feed cross-hit or already-corroborated).
# A fresh ingest key must earn several such agreements to cross the corroborate
# threshold — the slow, Sybil-resistant path to earning trust.
TRUST_GATE_REPUTATION_REWARD = _clean_float("TRUST_GATE_REPUTATION_REWARD", 0.25)
TRUST_GATE_CONTRADICTION_DECAY = _clean_float("TRUST_GATE_CONTRADICTION_DECAY", 0.5)
TRUST_GATE_ANOMALY_DECAY = _clean_float("TRUST_GATE_ANOMALY_DECAY", 0.6)
TRUST_GATE_MAX_CONTRADICTIONS = _clean_int("TRUST_GATE_MAX_CONTRADICTIONS", 3)
TRUST_GATE_MAX_ANOMALIES = _clean_int("TRUST_GATE_MAX_ANOMALIES", 3)

# ---------------------------------------------------------------------------
# Cross-install ingest API — P4.3 (central-service only). All tunable.
# ---------------------------------------------------------------------------
# The ingest endpoint is ABSENT on installs not running a central service: set
# VOIDACCESS_INGEST_ENABLED=true only on the central corpus service. A $0/local
# install leaves it off → no /ingest routes, no regression.
INGEST_ENABLED = (
    (_clean_env("VOIDACCESS_INGEST_ENABLED", "false") or "false").strip().lower()
    in ("1", "true", "yes", "on")
)
# A freshly self-registered ingest key starts at LOW reputation — below the
# corroborate threshold — so its claimed origins do not count until the key has
# earned trust by agreeing with independently-corroborated data. This is the
# Sybil defense: a thousand fresh keys promote nothing.
TRUST_GATE_CONTRIBUTOR_START_REPUTATION = _clean_float(
    "TRUST_GATE_CONTRIBUTOR_START_REPUTATION", 0.2
)
# Payload caps (CC-2 — protect the $0 box). Env-tunable.
INGEST_MAX_ARTIFACTS_PER_REQUEST = _clean_int("INGEST_MAX_ARTIFACTS_PER_REQUEST", 100)
INGEST_MAX_VALUE_LENGTH = _clean_int("INGEST_MAX_VALUE_LENGTH", 2048)
# Per-key ingest rate limit (reuses the P2.3 in-process substrate, per-key scope).
INGEST_RATE_LIMIT = _clean_int("INGEST_RATE_LIMIT", 60)
INGEST_RATE_WINDOW_SECONDS = _clean_int("INGEST_RATE_WINDOW_SECONDS", 60)
# Soft anti-key-farming friction: cap new self-registrations per client IP.
INGEST_REGISTER_RATE_LIMIT = _clean_int("INGEST_REGISTER_RATE_LIMIT", 5)
INGEST_REGISTER_WINDOW_SECONDS = _clean_int("INGEST_REGISTER_WINDOW_SECONDS", 3600)

# ---------------------------------------------------------------------------
# Shared-corpus consent / private mode (P2.2 / requirement 2.4)
# ---------------------------------------------------------------------------
# Contribution to the shared corpus is default-ON with a clear opt-out. Set
# VOIDACCESS_PRIVATE_MODE=true to run a fully private install: it reads nothing
# from and writes nothing to the central corpus, INDEPENDENT of whether S3 is
# configured. Read via shared_corpus.consent.contribution_enabled() (which reads
# this value live, so tests and a one-shot override take effect).
PRIVATE_MODE = (
    (_clean_env("VOIDACCESS_PRIVATE_MODE", "false") or "false").strip().lower()
    in ("1", "true", "yes", "on")
)

# Phase 1.6 — optional clearnet proxy.  Read directly by
# sources/proxy_client.py via os.getenv; the module-level constant is
# exposed for code that wants to introspect the value (the same way
# OTX_API_KEY, ABUSEIPDB_API_KEY, etc. are exposed for their consumers).
# Never affects Tor or .onion traffic — only paste sites and RSS feeds.
SCRAPINGANT_API_KEY = _clean_env("SCRAPINGANT_API_KEY", "")

# Phase 1.6 — ScrapingAnt proxy pool type.  Accepts `residential` (default)
# or `datacenter`.  Read directly by sources/proxy_client.py via os.getenv;
# defaults to "residential" if unset or any other value (the chokepoint
# normalizes there).  Per https://docs.scrapingant.com/proxy-mode this is
# passed as a `proxy_type=` parameter in the proxy transport username string
# (built at connection time as "the ScrapingAnt proxy username string").
# This is a value, not a credential, so it stays a plain env var (no
# UserApiKey registration on the API surface).
SCRAPINGANT_PROXY_TYPE = _clean_env("SCRAPINGANT_PROXY_TYPE", "residential")

# Shodan InternetDB publishes NO rate limit and needs no API key (verified
# 2026-07-29) — this is VoidAccess's own courtesy pacing, not a quota.  It is
# still routed through pacing.scale_delay_floor() at the call site in
# sources/shodan.py so the mechanism matches every other enrichment client.
SHODAN_RATE_LIMIT_DELAY = 1.0        # seconds between Shodan requests (InternetDB)
MAX_IPS_PER_INVESTIGATION = 50      # max IPs to query Shodan per investigation
MAX_HASHES_PER_INVESTIGATION = 20    # max file hashes to query VirusTotal per investigation

# Relationship extraction (typed graph edges) — a distinct LLM pass that,
# for entities already extracted from a page, asks which specific typed
# relationship (if any) connects them.  It is bounded exactly like the
# entity-extraction LLM cap (MAX_LLM_PAGES_PER_INV): at most one LLM call per
# selected page and never more than MAX_REL_PAGES_PER_INV pages per
# investigation, so it can never scale unbounded with page count.  Set
# ENABLE_RELATIONSHIP_EXTRACTION=false to disable and fall back to
# co-occurrence-only edges.
ENABLE_RELATIONSHIP_EXTRACTION = (
    _clean_env("ENABLE_RELATIONSHIP_EXTRACTION", "true") or "true"
).strip().lower() not in ("false", "0", "no")
try:
    MAX_REL_PAGES_PER_INV = int(_clean_env("MAX_REL_PAGES_PER_INV", "10") or 10)
except ValueError:
    MAX_REL_PAGES_PER_INV = 10

# Blockchain API Keys (optional — free tiers work without)
BLOCKCYPHER_TOKEN = _clean_env("BLOCKCYPHER_TOKEN", "")
ETHERSCAN_API_KEY = _clean_env("ETHERSCAN_API_KEY", "")

# Auth — REQUIRED when the API/auth stack is actually used.  Do not validate
# this at import time: the CLI injects its runtime environment in its entry
# point before importing dependent modules, and `--help`/`--version` must work
# on a fresh install.  `validate_config()` and the API startup path enforce it
# at the point where authentication is needed.
JWT_SECRET = _clean_env("JWT_SECRET")

# Token blacklist Redis (optional — omit to disable blacklist checks)
REDIS_URL = _clean_env("REDIS_URL")

# Playwright JS rendering for JavaScript-heavy .onion sites
# Set to False to disable (faster startup, lower memory usage)
# Requires: playwright installed + browsers downloaded
PLAYWRIGHT_ENABLED = _clean_env("PLAYWRIGHT_ENABLED", "true")
if PLAYWRIGHT_ENABLED is not None:
    PLAYWRIGHT_ENABLED = PLAYWRIGHT_ENABLED.lower() == "true"
else:
    PLAYWRIGHT_ENABLED = True


DEFAULT_MODELS = {
    "openrouter": "deepseek/deepseek-v4.1-flash",
    "openai":     "gpt-6-luna",
    "anthropic":  "claude-haiku-5-5",
    "google":     "gemini-3.8-flash",
    "groq":       "openai/gpt-oss-120b",
    "ollama":     "gemma4",
}

DEFAULT_MODEL = os.getenv(
    "DEFAULT_MODEL",
    f"openrouter/{DEFAULT_MODELS['openrouter']}"
)

REQUIRED_KEYS = [
    "JWT_SECRET",
]

OPTIONAL_KEYS = [
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "ANTHROPIC_API_KEY",
    "OTX_API_KEY",
    "DEEPL_API_KEY",
    "DARKSEARCH_API_KEY",
    "OLLAMA_BASE_URL",
    "OPENROUTER_API_KEY",
    "LLAMA_CPP_BASE_URL",
    "BLOCKCYPHER_TOKEN",
    "ETHERSCAN_API_KEY",
    "SCRAPINGANT_API_KEY",
    # Page-snapshot object store (P2.1) — unset means the shared-corpus snapshot
    # store no-ops; the tool runs fine without it.
    "S3_ENDPOINT_URL",
    "S3_BUCKET",
    "S3_ACCESS_KEY_ID",
    "S3_SECRET_ACCESS_KEY",
    # Owned persistent index (P3.0) — unset means the owned index no-ops and
    # search falls back to live fan-out; the tool runs fine without it.
    "MEILI_HOST",
]


def validate_config():
    missing_required = []
    for key in REQUIRED_KEYS:
        if _clean_env(key) is None:
            missing_required.append(key)
    if missing_required:
        raise RuntimeError(f"Missing required configuration keys: {', '.join(missing_required)}")
    missing_optional = [
        key for key in OPTIONAL_KEYS
        if (_clean_env(key) is None or _clean_env(key) == "")
    ]
    if missing_optional and not getattr(logging, _OPTIONAL_CONFIG_WARNING_STATE, False):
        logger.warning(
            "Optional configuration keys not set (%d): %s - related features will be disabled",
            len(missing_optional),
            ", ".join(missing_optional),
        )
        # Store the guard on the process-wide logging module so compatibility
        # wrappers/reloads cannot reset it and reintroduce warning spam.
        setattr(logging, _OPTIONAL_CONFIG_WARNING_STATE, True)


