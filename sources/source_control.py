"""Source deny-list (``VOIDACCESS_DISABLED_SOURCES``) and per-run source status.

Two jobs, both opt-in / additive:

1. **Deny-list.** When ``VOIDACCESS_DISABLED_SOURCES`` is a comma-separated list
   of source ids, those sources make NO network call in ANY stage: the search and
   paste stage, the feed matchers, historical intel, credential presence and
   enrichment. Unset or blank means today's behaviour. It composes with the
   enrichment allowlist (``VOIDACCESS_ENRICHMENT_SOURCES``): a source runs only if
   the deny-list does not name it AND the allowlist (when set) permits it.

   An unknown id raises :class:`SourceControlError`. A typo in a deny-list would
   otherwise silently leave a source running, which is the licence risk this
   exists to close.

2. **Run tracker.** ``sources_used`` has to say what really happened to each
   source (``ok`` / ``error`` / ``timed_out`` / ``skipped_by_allowlist`` /
   ``disabled`` / ``no_key``) and how many HTTP calls it made. HTTP is counted at
   the shared chokepoints by mapping the request URL to a source id
   (:data:`SOURCE_URL_RULES`), so no per-module bookkeeping can drift.

Ids are stable. Enrichment ids live in ``sources/enrichment_allowlist.py``; the
search-stage ids are registered here. Both are documented in
``docs/architecture.md``.
"""

from __future__ import annotations

import contextlib
import contextvars
import logging
import os
import threading
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

DISABLED_ENV = "VOIDACCESS_DISABLED_SOURCES"

# Status vocabulary reported in ``sources_used[...]["status"]``.
STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_TIMED_OUT = "timed_out"
STATUS_SKIPPED_BY_ALLOWLIST = "skipped_by_allowlist"
STATUS_DISABLED = "disabled"
STATUS_NO_KEY = "no_key"
# Not run in this mode (for example the onion engines under ``--no-tor``).
STATUS_SKIPPED = "skipped"

SOURCE_STATUSES = (
    STATUS_OK,
    STATUS_ERROR,
    STATUS_TIMED_OUT,
    STATUS_SKIPPED_BY_ALLOWLIST,
    STATUS_DISABLED,
    STATUS_NO_KEY,
    STATUS_SKIPPED,
)

# Search-stage sources (enrichment ids are registered in enrichment_allowlist).
SEARCH_SOURCE_IDS: dict[str, str] = {
    "tor_search": "Tor onion search-engine fan-out (search/search.py)",
    "torch": "Torch onion search engine (sources/engines.py)",
    "haystack": "Haystack onion search engine (sources/engines.py)",
    "paste_sites": "umbrella: all four clearnet paste sites below (sources/paste_scraper.py)",
    "pastebin": "Pastebin search and raw fetch (sources/paste_scraper.py)",
    "paste_ee": "paste.ee search and fetch (sources/paste_scraper.py)",
    "dpaste": "dpaste.org search and fetch (sources/paste_scraper.py)",
    "rentry": "Rentry raw fetch (sources/paste_scraper.py)",
    "github": "GitHub code/repo search (sources/github_scraper.py)",
    "gitlab": "GitLab snippet/project search (sources/gitlab_scraper.py)",
    "rss": "umbrella: every security RSS/press feed (sources/rss_scraper.py)",
    "telegram": "Telegram channels via Telethon (sources/telegram.py)",
}

# Umbrella ids: denying the parent denies every child.
PARENT_IDS: dict[str, str] = {
    "pastebin": "paste_sites",
    "paste_ee": "paste_sites",
    "dpaste": "paste_sites",
    "rentry": "paste_sites",
    "sslbl": "blocklists",
    "openphish": "blocklists",
    "phishtank": "blocklists",
    "ransomwhere": "blocklists",
}
# ``fbi_doj_press`` has no parent: denying ``rss`` also stops the RSS scraper's
# FBI/DOJ feeds (see is_rss_feed_disabled), but not the separate justice.gov
# press-release lookup in historical intel, which is its own call site.

# The recommended hosted-cloud value: sources whose commercial terms are
# unverified or non-commercial on the E0 licence table (platform/docs/baseline/
# E0-LICENCE-TABLE.md). NOT applied by default.
CLOUD_DISABLED_SOURCES = (
    "openphish,sslbl,phishtank,ransomwhere,hibp_pwned_passwords,fbi_doj_press,"
    "pastebin,paste_ee,dpaste,rentry,gitlab,telegram"
)


class SourceControlError(ValueError):
    """VOIDACCESS_DISABLED_SOURCES names one or more unknown source ids."""


def all_source_ids() -> dict[str, str]:
    from sources.enrichment_allowlist import ENRICHMENT_SOURCE_IDS

    return {**ENRICHMENT_SOURCE_IDS, **SEARCH_SOURCE_IDS}


def get_disabled_sources() -> frozenset[str]:
    """The deny-list (empty when the env var is unset/blank). Read at call time."""
    raw = os.environ.get(DISABLED_ENV)
    if raw is None or not raw.strip():
        return frozenset()
    ids = [p.strip().lower() for p in raw.split(",")]
    ids = [p for p in ids if p]
    known = all_source_ids()
    unknown = sorted({p for p in ids if p not in known})
    if unknown:
        raise SourceControlError(
            f"{DISABLED_ENV} contains unknown source id(s): {', '.join(unknown)}. "
            f"Valid ids: {', '.join(sorted(known))}"
        )
    return frozenset(ids)


def validate_disabled_sources() -> frozenset[str]:
    """Validate the env var early (CLI startup / pipeline start)."""
    return get_disabled_sources()


def is_source_disabled(source_id: str) -> bool:
    """True when the deny-list names *source_id* or its umbrella."""
    denied = get_disabled_sources()
    if not denied:
        return False
    if source_id in denied:
        return True
    parent = PARENT_IDS.get(source_id)
    return parent is not None and parent in denied


def is_rss_feed_disabled(feed_name: str) -> bool:
    """Per-feed gate for the RSS scraper (``rss`` umbrella or ``fbi_doj_press``)."""
    if is_source_disabled("rss"):
        return True
    name = (feed_name or "").lower()
    if "fbi" in name or "department of justice" in name:
        return is_source_disabled("fbi_doj_press")
    return False


# --------------------------------------------------------------------------- #
# URL -> source id attribution (per-source request counts)
# --------------------------------------------------------------------------- #
# (host suffix, path prefix, source id). Most specific rule wins.
SOURCE_URL_RULES: tuple[tuple[str, str, str], ...] = (
    ("otx.alienvault.com", "", "otx"),
    ("mb-api.abuse.ch", "", "malwarebazaar"),
    ("threatfox-api.abuse.ch", "", "threatfox"),
    ("urlhaus-api.abuse.ch", "", "urlhaus"),
    ("auth.abuse.ch", "", "urlhaus"),
    ("sslbl.abuse.ch", "", "sslbl"),
    ("feodotracker.abuse.ch", "", "feodo_tracker"),
    ("ransomware.live", "", "ransomware_live"),
    ("ransomlook.io", "", "ransomlook"),
    ("api.ransomwhe.re", "", "ransomwhere"),
    ("ransomwhe.re", "", "ransomwhere"),
    ("cisa.gov", "", "cisa_kev"),
    ("services.nvd.nist.gov", "", "nvd"),
    ("api.first.org", "", "epss"),
    ("gitlab.com", "/exploit-database", "exploitdb"),
    ("raw.githubusercontent.com", "/mitre/", "mitre_attack"),
    ("raw.githubusercontent.com", "/montysecurity/", "c2_tracker"),
    ("raw.githubusercontent.com", "/disposable-email-domains/", "disposable_email"),
    ("justice.gov", "", "fbi_doj_press"),
    ("internetdb.shodan.io", "", "shodan_internetdb"),
    ("virustotal.com", "", "virustotal"),
    ("openphish.com", "", "openphish"),
    ("phishtank.com", "", "phishtank"),
    ("phishtank.org", "", "phishtank"),
    ("api.abuseipdb.com", "", "abuseipdb"),
    ("api.greynoise.io", "", "greynoise"),
    ("crt.sh", "", "crtsh"),
    ("web.archive.org", "", "wayback"),
    ("urlscan.io", "", "urlscan"),
    ("hybrid-analysis.com", "", "hybrid_analysis"),
    ("api.pwnedpasswords.com", "", "hibp_pwned_passwords"),
    ("haveibeenpwned.com", "", "hibp"),
    ("emailrep.io", "", "emailrep"),
    ("xposedornot.com", "", "xposedornot"),
    ("leakcheck.io", "", "leakcheck"),
    ("hudsonrock.com", "", "hudsonrock"),
    ("rdap.org", "", "rdap"),
    ("rdap.arin.net", "", "rdap"),
    ("circl.lu", "", "circl"),
    ("securitytrails.com", "", "securitytrails"),
    ("blockcypher.com", "", "blockcypher"),
    ("etherscan.io", "", "etherscan"),
    ("pastebin.com", "", "pastebin"),
    ("paste.ee", "", "paste_ee"),
    ("dpaste.org", "", "dpaste"),
    ("rentry.co", "", "rentry"),
    ("api.github.com", "", "github"),
    ("gitlab.com", "/api", "gitlab"),
)

# Rules sorted so that the longest (host, path) match is tried first.
_RULES_BY_SPECIFICITY = tuple(
    sorted(SOURCE_URL_RULES, key=lambda r: (len(r[0]), len(r[1])), reverse=True)
)


def source_for_url(url: str) -> Optional[str]:
    """Map a request URL to a source id, or None when it is not a tracked source."""
    try:
        parsed = urlparse(str(url))
    except Exception:
        return None
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    if not host:
        return None
    for suffix, prefix, source_id in _RULES_BY_SPECIFICITY:
        if host == suffix or host.endswith("." + suffix):
            if not prefix or path.startswith(prefix):
                return source_id
    return None


# --------------------------------------------------------------------------- #
# Per-run tracker
# --------------------------------------------------------------------------- #
class SourceTracker:
    """Request counts and explicit states for one investigation run."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests: dict[str, int] = {}
        # Requests that raised, or came back 401/403/429/5xx (see http_pool).
        self.failures: dict[str, int] = {}
        # Explicit non-ok outcomes recorded where they happen (a gate refusing a
        # source, a phase timing out). Later writes win except that a gate
        # outcome is never downgraded to ``ok``.
        self.states: dict[str, str] = {}

    def record_request(self, source_id: str, n: int = 1) -> None:
        with self._lock:
            self.requests[source_id] = self.requests.get(source_id, 0) + n

    def record_failure(self, source_id: str, n: int = 1) -> None:
        with self._lock:
            self.failures[source_id] = self.failures.get(source_id, 0) + n

    def failure_count(self, source_id: str) -> int:
        with self._lock:
            return self.failures.get(source_id, 0)

    def set_state(self, source_id: str, state: str) -> None:
        with self._lock:
            self.states[source_id] = state

    def request_count(self, source_id: str) -> int:
        with self._lock:
            return self.requests.get(source_id, 0)

    def snapshot_requests(self) -> dict[str, int]:
        with self._lock:
            return dict(self.requests)

    def snapshot_states(self) -> dict[str, str]:
        with self._lock:
            return dict(self.states)


# Process-wide default (CLI: one run per process; also the fallback for the
# thread-isolated event loops ``run_async`` uses, which do not inherit
# contextvars) plus a context-local override (API: several runs per process).
_process_tracker = SourceTracker()
_ctx_tracker: contextvars.ContextVar[Optional[SourceTracker]] = contextvars.ContextVar(
    "voidaccess_source_tracker", default=None
)


def get_tracker() -> SourceTracker:
    return _ctx_tracker.get() or _process_tracker


def reset_tracker(*, scoped: bool = False) -> SourceTracker:
    """Start a fresh tracker for a new run and return it.

    ``scoped=True`` binds it to the current context only (several concurrent runs
    in one process); the default replaces the process-wide tracker (the CLI).
    """
    global _process_tracker
    tracker = SourceTracker()
    if scoped:
        _ctx_tracker.set(tracker)
    else:
        _process_tracker = tracker
        _ctx_tracker.set(None)
    return tracker


def record_request(source_id: Optional[str], n: int = 1) -> None:
    if source_id:
        get_tracker().record_request(source_id, n)


def record_failure_for_url(url: str) -> None:
    """Count one failed HTTP call (raised or 401/403/429/5xx). Never raises."""
    try:
        source_id = _attribution_override.get() or source_for_url(url)
        if source_id:
            get_tracker().record_failure(source_id)
    except Exception:  # pragma: no cover
        pass


# A response the source answered with, but that means "the call did not work".
FAILURE_HTTP_STATUSES = frozenset({401, 403, 429})


def is_failure_status(status: int) -> bool:
    return status in FAILURE_HTTP_STATUSES or status >= 500


_attribution_override: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "voidaccess_request_attribution", default=None
)


@contextlib.contextmanager
def attribute_requests_to(source_id: Optional[str]):
    """Count every request made inside the block against *source_id*.

    For a source whose hosts are many and not individually registered (the RSS
    feeds). Task-local, so concurrent feeds do not interfere.
    """
    token = _attribution_override.set(source_id)
    try:
        yield
    finally:
        _attribution_override.reset(token)


def record_request_for_url(url: str) -> None:
    """Count one HTTP call against the source *url* belongs to. Never raises."""
    try:
        source_id = _attribution_override.get() or source_for_url(url)
        if source_id:
            get_tracker().record_request(source_id)
    except Exception:  # pragma: no cover - accounting must never break a request
        pass


def request_trace_config(source_id: Optional[str] = None):
    """An aiohttp ``TraceConfig`` that counts each request against a source.

    For modules that own their ``aiohttp.ClientSession`` (GitHub, GitLab) rather
    than borrowing the shared clearnet handle. ``source_id`` forces the id;
    otherwise the URL is mapped. Redirect hops count as requests (they are).
    """
    import aiohttp

    async def _on_request_start(session, ctx, params):  # noqa: ARG001
        if source_id:
            record_request(source_id)
        else:
            record_request_for_url(str(params.url))

    trace = aiohttp.TraceConfig()
    trace.on_request_start.append(_on_request_start)
    return trace


def source_gate(source_id: str) -> bool:
    """True when *source_id* may run (not denied). Records a refusal otherwise."""
    if is_source_disabled(source_id):
        note_gate_refusal(source_id, STATUS_DISABLED)
        return False
    return True


def note_gate_refusal(source_id: str, reason: str) -> None:
    """Remember why a gate refused *source_id* (``disabled`` / ``skipped_by_allowlist``)."""
    tracker = get_tracker()
    # A deny-list refusal is the stronger statement; never overwrite it.
    if tracker.states.get(source_id) == STATUS_DISABLED:
        return
    tracker.set_state(source_id, reason)


# Env var(s) a source needs; when none is set and the source made no request the
# honest status is ``no_key`` (never ``ok`` with a silent zero).
SOURCE_KEY_ENVS: dict[str, tuple[str, ...]] = {
    "otx": ("OTX_API_KEY",),
    "malwarebazaar": ("ABUSECH_API_KEY",),
    "threatfox": ("ABUSECH_API_KEY",),
    "urlhaus": ("ABUSECH_API_KEY",),
    "virustotal": ("VT_API_KEY",),
    "phishtank": ("PHISHTANK_API_KEY",),
    "abuseipdb": ("ABUSEIPDB_API_KEY",),
    "greynoise": ("GREYNOISE_API_KEY",),
    "hybrid_analysis": ("HYBRID_ANALYSIS_API_KEY",),
    "hibp": ("HIBP_API_KEY",),
    "securitytrails": ("SECURITYTRAILS_API_KEY",),
    "etherscan": ("ETHERSCAN_API_KEY",),
    "telegram": ("TELEGRAM_API_ID", "TELEGRAM_API_HASH"),
}


def missing_key(source_id: str) -> bool:
    envs = SOURCE_KEY_ENVS.get(source_id)
    if not envs:
        return False
    return not all((os.environ.get(e) or "").strip() for e in envs)


def resolve_status(
    source_id: str,
    *,
    ok: bool = True,
    timed_out: bool = False,
    error: bool = False,
) -> str:
    """The honest status of one source for a finished (or aborted) stage.

    Precedence: deny-list, then allowlist refusal recorded by a gate, then a
    timeout/error the caller observed, then a missing key (only when the source
    made no request), else ``ok``.
    """
    if is_source_disabled(source_id):
        return STATUS_DISABLED
    tracker = get_tracker()
    state = tracker.states.get(source_id)
    if state in (STATUS_DISABLED, STATUS_SKIPPED_BY_ALLOWLIST):
        return state
    if timed_out:
        return STATUS_TIMED_OUT
    if error or not ok:
        return STATUS_ERROR
    if state in (STATUS_TIMED_OUT, STATUS_ERROR):
        return state
    made = tracker.request_count(source_id)
    if made and tracker.failure_count(source_id) >= made:
        return STATUS_ERROR  # every call it made failed: not "ok"
    if missing_key(source_id) and made == 0:
        return STATUS_NO_KEY
    return STATUS_OK


def source_entry(
    source_id: str,
    *,
    count: int = 0,
    ok: bool = True,
    timed_out: bool = False,
    error: Optional[str] = None,
    status: Optional[str] = None,
) -> dict:
    """Build one ``sources_used`` entry: status, result count and request count."""
    resolved = status or resolve_status(
        source_id, ok=ok, timed_out=timed_out, error=bool(error)
    )
    entry: dict = {
        "status": resolved,
        "count": int(count),
        "requests": get_tracker().request_count(source_id),
    }
    if error and resolved == STATUS_ERROR:
        entry["error"] = error
    return entry


def disabled_reason(source_id: str) -> str:
    """``disabled`` when the deny-list names it, else ``skipped_by_allowlist``."""
    return STATUS_DISABLED if is_source_disabled(source_id) else STATUS_SKIPPED_BY_ALLOWLIST


def normalize_module_status(source_id: str, raw: object) -> str:
    """Map a module's own status string onto the reported vocabulary.

    The enrichment modules predate it and report ``ok_3_results``,
    ``error_timeout``, ``skipped_no_key``, ``unavailable`` and so on.
    """
    text = str(raw or "").strip().lower()
    if text.startswith("ok"):
        return resolve_status(source_id)
    if text == "disabled":
        return disabled_reason(source_id)
    if text in ("skipped_by_allowlist", STATUS_NO_KEY) or text.startswith("skipped_no_key"):
        return STATUS_NO_KEY if "key" in text else STATUS_SKIPPED_BY_ALLOWLIST
    if text.startswith("skipped"):
        return STATUS_SKIPPED
    if "timeout" in text or "timed_out" in text:
        return STATUS_TIMED_OUT
    if text in SOURCE_STATUSES:
        return text
    return STATUS_ERROR


def finalize_sources_used(sources_used: dict) -> dict:
    """Make a ``sources_used`` dict honest and complete, in place.

    * every id the deny-list names (and every child of a denied umbrella) is
      listed as ``disabled`` with its real request count (zero);
    * when the enrichment allowlist is set, every registered enrichment source it
      excludes is ``skipped_by_allowlist`` and never ``ok``;
    * any source that made HTTP calls but has no entry yet gets one, so a runner
      can report per-source ``enrichment_calls`` for all of them.

    Returns *sources_used* for chaining.
    """
    from sources.enrichment_allowlist import (
        ENRICHMENT_SOURCE_IDS,
        get_enrichment_allowlist,
    )

    tracker = get_tracker()
    known = all_source_ids()

    def _entry(status: str, existing: Optional[dict] = None, source_id: str = "") -> dict:
        entry = dict(existing or {})
        entry["status"] = status
        entry.setdefault("count", 0)
        entry["requests"] = tracker.request_count(source_id)
        if status != STATUS_ERROR:
            entry.pop("error", None)
        return entry

    # Deny-list: direct ids plus the children of denied umbrellas.
    for source_id in known:
        if is_source_disabled(source_id):
            sources_used[source_id] = _entry(
                STATUS_DISABLED, sources_used.get(source_id), source_id
            )

    allow = get_enrichment_allowlist()
    if allow is not None:
        for source_id in ENRICHMENT_SOURCE_IDS:
            if is_source_disabled(source_id):
                continue
            parent = PARENT_IDS.get(source_id)
            permitted = source_id in allow or (parent is not None and parent in allow)
            if not permitted:
                sources_used[source_id] = _entry(
                    STATUS_SKIPPED_BY_ALLOWLIST, sources_used.get(source_id), source_id
                )

    # Sources that spoke on the wire but were not reported elsewhere.
    for source_id, made in tracker.snapshot_requests().items():
        if source_id not in sources_used:
            sources_used[source_id] = source_entry(source_id)
        elif isinstance(sources_used[source_id], dict):
            sources_used[source_id]["requests"] = made

    # Every present entry carries a request count.
    for source_id, entry in sources_used.items():
        if isinstance(entry, dict):
            entry.setdefault("requests", tracker.request_count(source_id))
    return sources_used


def overlay_status_strings(sources_used: dict, aliases: Optional[dict] = None) -> dict:
    """``finalize_sources_used`` for the API's flat ``{key: "status_string"}`` shape.

    Marks denied sources ``disabled`` and allowlist-excluded ones
    ``skipped_by_allowlist`` (it never overwrites a ``skipped_no_key``), using
    this module's own key names where they differ from the registered ids
    (``aliases`` maps registered id -> local key). In place.
    """
    from sources.enrichment_allowlist import (
        ENRICHMENT_SOURCE_IDS,
        get_enrichment_allowlist,
    )

    aliases = aliases or {}
    for source_id in all_source_ids():
        if is_source_disabled(source_id):
            for key in {source_id, aliases.get(source_id, source_id)}:
                sources_used[key] = STATUS_DISABLED
    allow = get_enrichment_allowlist()
    if allow is not None:
        for source_id in ENRICHMENT_SOURCE_IDS:
            if is_source_disabled(source_id):
                continue
            parent = PARENT_IDS.get(source_id)
            if source_id in allow or (parent is not None and parent in allow):
                continue
            for key in {source_id, aliases.get(source_id, source_id)}:
                if key in sources_used and str(sources_used[key]).startswith("skipped_no_key"):
                    continue
                sources_used[key] = STATUS_SKIPPED_BY_ALLOWLIST
    return sources_used


def reset_for_tests() -> None:
    global _process_tracker
    _process_tracker = SourceTracker()
    _ctx_tracker.set(None)
