"""Streamed trace events (progress schema 2).

Opt-in (``VOIDACCESS_TRACE_EVENTS=1`` or ``voidaccess investigate --trace``):
the pipeline reports what happens to each query, URL, page and entity as a
``trace`` event, so a dashboard can animate a live run. See
``progress/README.md`` and ``progress/schema/progress-v2.schema.json``.

Two halves live here:

* :class:`TraceState`: per-run caps and id allocation, owned by a
  :class:`progress.ProgressEmitter` built with ``trace=True``.
* Module-level hooks (:func:`url_found`, :func:`page_fetched`, ...) that the
  pipeline modules call. They look up the active traced emitter the same way
  ``utils.cancel`` looks up the active token (a context variable, then a
  process-wide default for the search stage's thread-isolated event loop) and
  are a no-op when none is bound. Every hook swallows its own exceptions.

Nothing here may carry page text, titles, paths, query strings, raw
credentials, personal data or anything the content-safety filter blocked:
hosts go through :func:`display_host`, entity values through
:func:`mask_entity`, and safety drops carry only an id and a reason.
"""

from __future__ import annotations

import contextvars
import functools
import logging
import os
import re
import threading
from typing import Any, Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 2
TRACE_ENV = "VOIDACCESS_TRACE_EVENTS"
TRACE_CAPS_ENV = "VOIDACCESS_TRACE_CAPS"  # e.g. "url.found=300,entity.found=100"
TRACE_MAX_EVENTS_ENV = "VOIDACCESS_TRACE_MAX_EVENTS"

TRACE_KINDS = (
    "query.refined",
    "search.request",
    "search.result",
    "url.found",
    "url.kept",
    "url.dropped",
    "page.fetched",
    "page.entities",
    "entity.found",
    "enrich.source",
    "graph.progress",
    "summary.status",
    "filter_fallback",
    "trace.truncated",
)
TRUNCATED_KIND = "trace.truncated"

DEFAULT_KIND_CAP = 200
DEFAULT_CAPS: dict[str, int] = {
    "url.found": 600,
    "url.kept": 600,
    "url.dropped": 600,
    "page.fetched": 400,
    "entity.found": 300,
}
DEFAULT_MAX_EVENTS = 3000

URL_DROP_REASONS = (
    "duplicate", "irrelevant", "cap", "invalid", "ssrf", "safety", "disabled_source",
)
PAGE_OUTCOMES = (
    "ok", "http_404", "http_4xx", "http_5xx", "timeout", "tor_error", "too_large",
    "safety_dropped", "empty", "error",
)
SEARCH_STATUSES = ("ok", "error", "timeout", "disabled", "no_key", "rate_limited")
# 23B-B2: per-engine outcome, an extra `search.result` field next to `status`
# (same values as search/engine_status.ENGINE_OUTCOMES).
SEARCH_OUTCOMES = ("ok", "empty", "unreachable", "rate_limited", "error")
ENRICH_STATUSES = ("ok", "error", "timeout", "disabled", "no_key", "skipped")
SUMMARY_KINDS = ("llm", "fallback", "none")

MAX_TEXT = 200
MAX_DISPLAY = 80
MAX_NAME = 40
MAX_BY_TYPE_KEYS = 64


def env_enabled() -> bool:
    return (os.getenv(TRACE_ENV) or "").strip().lower() in ("1", "true", "on", "yes")


def _env_caps() -> dict[str, int]:
    caps: dict[str, int] = {}
    for part in (os.getenv(TRACE_CAPS_ENV) or "").split(","):
        if "=" not in part:
            continue
        kind, _, raw = part.partition("=")
        kind = kind.strip()
        try:
            value = int(raw.strip())
        except ValueError:
            continue
        if kind in TRACE_KINDS and kind != TRUNCATED_KIND and value >= 0:
            caps[kind] = value
    return caps


def _env_max_events() -> Optional[int]:
    raw = (os.getenv(TRACE_MAX_EVENTS_ENV) or "").strip()
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value >= 0 else None


# ---------------------------------------------------------------------------
# Display forms
# ---------------------------------------------------------------------------

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_HOST_RE = re.compile(r"^[a-z0-9._:\-]+$")


def _clip(text: str, limit: int) -> str:
    text = _CTRL_RE.sub(" ", str(text)).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def defang(host: str) -> str:
    """Make a hostname or IP non-clickable: every ``.`` and ``:`` bracketed."""
    return host.replace(".", "[.]").replace(":", "[:]")


def short_onion(label: str) -> str:
    """``lockbit3abc…xyz7``: the first 8 and last 4 characters of an onion label."""
    return label if len(label) <= 12 else f"{label[:8]}…{label[-4:]}"


# Vanity onion prefixes and clearnet hostnames can spell out what a site is.
# When the part of a host a trace would show contains one of these (or a term
# from the content-safety lists), the name is masked; the id still follows it.
# Display only: this never changes what the pipeline fetches. False positives
# (a mixer called "mixxx...") just mask a harmless name.
_DISPLAY_DENY_TERMS = (
    "kid", "child", "teen", "loli", "pedo", "preteen", "underage", "minor", "jailbait",
    "pthc", "hurtcore", "boy", "girl", "baby", "young", "porn", "sex", "xxx", "nude",
    "nsfw", "incest", "rape", "gore", "snuff", "torture", "zoo", "beast", "hitman",
    "murder", "assassin",
)
MASKED_NAME = "********"


@functools.lru_cache(maxsize=1)
def _deny_terms() -> tuple[str, ...]:
    terms = list(_DISPLAY_DENY_TERMS)
    try:
        from utils import content_safety as cs

        for group in (cs.BLOCKED_TERMS, cs.BLOCKED_URL_TERMS, cs.CONTENT_BLOCKLIST):
            terms.extend(str(t).lower() for t in group if t)
    except Exception:
        pass
    return tuple(terms)


def is_sensitive_name(text: str) -> bool:
    """True when *text* (a host part or a result title) must not be shown."""
    if not text:
        return False
    lowered = str(text).lower()
    if any(term in lowered for term in _deny_terms()):
        return True
    try:
        from utils.content_safety import is_blocked_query

        return bool(is_blocked_query(lowered)[0])
    except Exception:
        return True


def display_host(url: str, *, mask: bool = False) -> Optional[str]:
    """The only form in which a URL appears in a trace: its host, shortened
    (onion) or defanged (clearnet). Never a scheme, port, path or query.
    The readable name is masked when *mask* is set or when the part shown is a
    sensitive name. ``None`` when there is no usable host."""
    if not url:
        return None
    raw = str(url).strip()
    if "://" not in raw:
        raw = "http://" + raw
    try:
        host = urlsplit(raw).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower().rstrip(".")
    if not _HOST_RE.match(host):
        return None
    if host.endswith(".onion"):
        label = host[: -len(".onion")].rsplit(".", 1)[-1]
        if not label:
            return None
        if mask or is_sensitive_name(label[:8]):
            return f"{MASKED_NAME}…{label[-4:]}[.]onion"
        return short_onion(label) + "[.]onion"
    if mask or is_sensitive_name(host):
        return f"{MASKED_NAME}[.]{defang(host.rsplit('.', 1)[-1])}"
    return _clip(defang(host), MAX_DISPLAY)


# Entity types shown as observed (public threat-intel identifiers). Anything not
# listed here or handled below is masked, so a new extractor type is safe by
# default.
_PASSTHROUGH_TYPES = frozenset({
    "CVE_NUMBER", "EXPLOIT_DB_ID", "MITRE_TACTIC", "MITRE_TECHNIQUE",
    "FILE_HASH", "FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256", "FILE_HASH_SHA512",
    "MALWARE", "MALWARE_FAMILY", "RANSOMWARE", "RANSOMWARE_GROUP",
    "THREAT_ACTOR", "THREAT_ACTOR_HANDLE", "ORGANIZATION_NAME", "FORUM", "DATE",
    "BITCOIN_ADDRESS", "BITCOIN_CASH_ADDRESS", "ETHEREUM_ADDRESS", "ETH_ADDRESS",
    "MONERO_ADDRESS", "LITECOIN_ADDRESS", "ZCASH_ADDRESS", "DOGECOIN_ADDRESS",
    "DASH_ADDRESS", "XRP_ADDRESS", "TRON_ADDRESS", "SOLANA_ADDRESS", "WALLET",
    "IPFS_CID", "TOX_ID", "TELEGRAM_HANDLE", "DISCORD_HANDLE", "MATRIX_HANDLE",
    "WICKR_ID", "WIRE_HANDLE", "ICQ_NUMBER",
})
_HOST_TYPES = frozenset({"DOMAIN", "DOMAIN_NAME", "ENS_DOMAIN"})
_URL_TYPES = frozenset({"URL", "PASTE_URL", "ONION_URL"})
_IP_TYPES = frozenset({"IP_ADDRESS", "IPV6_ADDRESS"})
_EMAIL_TYPES = frozenset({"EMAIL", "EMAIL_ADDRESS", "XMPP_JID"})
# Credentials and secrets: only a well-known, non-secret prefix survives.
_CREDENTIAL_TYPES = frozenset({
    "API_KEY", "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "GITHUB_TOKEN", "GOOGLE_API_KEY",
    "SLACK_TOKEN", "STRIPE_KEY", "DISCORD_TOKEN", "JWT_TOKEN", "SESSION_ID",
    "COMBO_LIST_ENTRY", "STEALER_LOG_ENTRY", "CRYPTO_SEED_PHRASE", "DATABASE_URL",
    "SEED_PHRASE_DETECTED_12_WORDS", "SEED_PHRASE_DETECTED_24_WORDS", "PASSWORD",
})
_CREDENTIAL_PREFIXES = (
    "github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-",
    "sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_",
    "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "AKIA", "ASIA", "AIza",
)
_BLOB_LABELS = {
    "PGP_KEY": "[PGP key]",
    "PGP_KEY_BLOCK": "[PGP key]",
    "YARA_RULE": "[YARA rule]",
    "NUCLEI_TEMPLATE": "[Nuclei template]",
}
REDACTED = "[REDACTED]"


def _mask_email(value: str) -> str:
    local, sep, domain = value.partition("@")
    if not sep or not domain:
        return REDACTED
    return f"{local[:1]}***[@]{defang(domain.lower())}"


def _mask_name(value: str) -> str:
    words = [w for w in re.split(r"\s+", value) if w]
    return " ".join(f"{w[0]}***" for w in words[:4]) or REDACTED


def _mask_credential(value: str) -> str:
    for prefix in _CREDENTIAL_PREFIXES:
        if value.startswith(prefix):
            return prefix + REDACTED
    return REDACTED


def mask_entity(entity_type: str, value: str) -> str:
    """Display form of an entity for a trace: credentials and personal data
    masked, network indicators defanged, at most 80 characters."""
    etype = str(entity_type or "").upper()
    raw = _CTRL_RE.sub(" ", str(value or "")).strip()
    if not raw:
        return REDACTED
    if etype in _CREDENTIAL_TYPES:
        out = _mask_credential(raw)
    elif etype in _BLOB_LABELS:
        out = _BLOB_LABELS[etype]
    elif etype in _EMAIL_TYPES:
        out = _mask_email(raw)
    elif etype == "PHONE_NUMBER":
        out = "[phone]"
    elif etype == "PERSON_NAME":
        out = _mask_name(raw)
    elif etype == "LOCATION":
        out = "[location]"
    elif etype == "MAC_ADDRESS":
        out = raw[:8] + ":**:**:**" if len(raw) >= 8 else REDACTED
    elif etype in _URL_TYPES:
        out = display_host(raw) or REDACTED
    elif etype in _HOST_TYPES:
        out = display_host(raw) or REDACTED
    elif etype in _IP_TYPES:
        out = defang(raw)
    elif etype in _PASSTHROUGH_TYPES:
        out = raw
    else:
        out = REDACTED
    return _clip(out, MAX_DISPLAY)


def map_source_status(status: Any, *, allow_skipped: bool) -> str:
    """Map a ``sources_used`` status onto the trace vocabulary."""
    text = str(status or "").strip().lower()
    if text == "ok":
        return "ok"
    if text in ("timed_out", "timeout"):
        return "timeout"
    if text == "no_key":
        return "no_key"
    if text == "rate_limited":
        return "rate_limited"
    if text in ("disabled", "skipped_by_allowlist"):
        return "disabled"
    if text == "skipped":
        return "skipped" if allow_skipped else "disabled"
    return "error"


# ---------------------------------------------------------------------------
# Per-run state
# ---------------------------------------------------------------------------


class TraceState:
    """Caps, counters and short ids for one traced run. Thread-safe."""

    def __init__(
        self,
        caps: Optional[dict[str, int]] = None,
        max_events: Optional[int] = None,
    ):
        self.caps = dict(DEFAULT_CAPS)
        self.caps.update(_env_caps())
        self.caps.update(caps or {})
        env_max = _env_max_events()
        self.max_events = (
            max_events if max_events is not None
            else env_max if env_max is not None
            else DEFAULT_MAX_EVENTS
        )
        self.emitted: dict[str, int] = {}
        self.dropped: dict[str, int] = {}
        self.total = 0
        self._lock = threading.Lock()
        self._url_ids: dict[str, str] = {}
        self._entity_ids: dict[tuple[str, str], str] = {}
        # url -> fetch metadata, kept until the safety scan decides the outcome.
        self.pending_fetch: dict[str, dict[str, Any]] = {}
        # url_ids already reported as dropped by the content-safety filter.
        self.safety_ids: set[str] = set()

    def admit(self, kind: str) -> bool:
        """Count one *kind* event; False when its cap (or the run total) is hit."""
        with self._lock:
            if kind == TRUNCATED_KIND:
                return True
            # Room is kept under the total for one truncation marker per kind.
            budget = max(0, self.max_events - (len(TRACE_KINDS) - 1))
            if (
                self.emitted.get(kind, 0) >= self.caps.get(kind, DEFAULT_KIND_CAP)
                or self.total >= budget
            ):
                self.dropped[kind] = self.dropped.get(kind, 0) + 1
                return False
            self.emitted[kind] = self.emitted.get(kind, 0) + 1
            self.total += 1
            return True

    def take_truncations(self) -> list[tuple[str, int]]:
        with self._lock:
            out = sorted(self.dropped.items())
            self.dropped = {}
            return out

    def url_id(self, url: str) -> tuple[str, bool]:
        """``("u17", is_new)`` for *url*; the same URL always maps to one id."""
        key = str(url or "")
        with self._lock:
            existing = self._url_ids.get(key)
            if existing is not None:
                return existing, False
            uid = f"u{len(self._url_ids) + 1}"
            self._url_ids[key] = uid
            return uid, True

    def mark_safety(self, uid: str) -> bool:
        """Record *uid* as dropped by content safety; False if it already was."""
        with self._lock:
            if uid in self.safety_ids:
                return False
            self.safety_ids.add(uid)
            return True

    def known_url_id(self, url: str) -> Optional[str]:
        with self._lock:
            return self._url_ids.get(str(url or ""))

    def entity_id(self, entity_type: str, value: str) -> tuple[str, bool]:
        key = (str(entity_type or "").upper(), str(value or "").strip().lower())
        with self._lock:
            existing = self._entity_ids.get(key)
            if existing is not None:
                return existing, False
            eid = f"e{len(self._entity_ids) + 1}"
            self._entity_ids[key] = eid
            return eid, True


# ---------------------------------------------------------------------------
# Active tracer lookup (mirrors utils.cancel)
# ---------------------------------------------------------------------------

_ctx_tracer: contextvars.ContextVar[Any] = contextvars.ContextVar(
    "voidaccess_tracer", default=None
)
_process_tracer: Any = None


def bind(emitter: Any, *, process_wide: bool = False) -> None:
    """Make *emitter* the target of trace hooks (``None`` unbinds).

    Only an emitter with tracing on is bound; anything else unbinds, so the
    hooks stay no-ops. ``process_wide`` (CLI) also publishes it for threads and
    event loops that do not inherit context variables.
    """
    global _process_tracer
    target = emitter if getattr(emitter, "trace_enabled", False) else None
    _ctx_tracer.set(target)
    if process_wide:
        _process_tracer = target


def current() -> Any:
    return _ctx_tracer.get() or _process_tracer


def active() -> bool:
    return current() is not None


def _query_blocked(text: str) -> bool:
    try:
        from utils.content_safety import is_blocked_query

        return bool(is_blocked_query(text)[0])
    except Exception:
        return True  # fail closed: no trace for a query the gate cannot judge


# ---------------------------------------------------------------------------
# Hooks called by the pipeline. Each is a no-op without a bound tracer and
# never raises.
# ---------------------------------------------------------------------------


def query_refined(stage: str, index: int, text: str) -> None:
    t = current()
    if t is None:
        return
    try:
        if not text or _query_blocked(text):
            return
        t.trace(stage, "query.refined", {"index": int(index), "text": _clip(text, MAX_TEXT)})
    except Exception as exc:
        logger.debug("trace hook failed (ignored): %s", exc)


def search_request(engine: str, query_index: int = 0) -> None:
    t = current()
    if t is None:
        return
    try:
        t.trace("collect", "search.request", {
            "engine": _clip(engine, MAX_NAME), "query_index": int(query_index),
        })
    except Exception as exc:
        logger.debug("trace hook failed (ignored): %s", exc)


def search_result(
    engine: str,
    status: str,
    results: int,
    ms: Optional[int] = None,
    query_index: int = 0,
    outcome: Optional[str] = None,
) -> None:
    t = current()
    if t is None:
        return
    try:
        data: dict[str, Any] = {
            "engine": _clip(engine, MAX_NAME),
            "query_index": int(query_index),
            "status": status if status in SEARCH_STATUSES else "error",
            "results": max(0, int(results or 0)),
        }
        if ms is not None:
            data["ms"] = max(0, int(ms))
        if outcome in SEARCH_OUTCOMES:
            data["outcome"] = outcome
        t.trace("collect", "search.result", data)
    except Exception as exc:
        logger.debug("trace hook failed (ignored): %s", exc)


def _safety_drop(t: Any, stage: str, uid: str) -> None:
    if t.trace_state.mark_safety(uid):
        t.trace(stage, "url.dropped", {"url_id": uid, "reason": "safety"})


def _url_is_unsafe(url: str) -> bool:
    try:
        from utils.content_safety import is_blocked_url

        return bool(is_blocked_url(url)[0])
    except Exception:
        return True  # fail closed: never show a host the gate cannot judge


def url_found(
    stage: str,
    url: str,
    engine: Optional[str] = None,
    depth: int = 0,
    title: Optional[str] = None,
) -> Optional[str]:
    """Report a candidate URL once per run. Returns its id (or ``None``).

    *title* (the search result's title) is only used to decide whether the
    host's name may be shown; it is never emitted."""
    t = current()
    if t is None:
        return None
    try:
        uid, is_new = t.trace_state.url_id(url)
        if not is_new:
            return uid
        # The pure check, not url_is_blocked(): that one writes an audit event,
        # and tracing must not change what the pipeline records.
        if _url_is_unsafe(url):
            _safety_drop(t, stage, uid)
            return uid
        host = display_host(url, mask=is_sensitive_name(title or ""))
        if host is None:
            t.trace(stage, "url.dropped", {"url_id": uid, "reason": "invalid"})
            return uid
        data: dict[str, Any] = {"url_id": uid, "host": host, "depth": max(0, int(depth))}
        if engine:
            data["engine"] = _clip(engine, MAX_NAME)
        t.trace(stage, "url.found", data)
        return uid
    except Exception as exc:
        logger.debug("trace hook failed (ignored): %s", exc)
        return None


def _known(t: Any, url: str) -> Optional[str]:
    uid = t.trace_state.known_url_id(url)
    if uid is None or uid in t.trace_state.safety_ids:
        return None
    return uid


def url_kept(stage: str, url: str, score: Optional[float] = None) -> None:
    t = current()
    if t is None:
        return
    try:
        uid = _known(t, url)
        if uid is None:
            return
        data: dict[str, Any] = {"url_id": uid}
        if isinstance(score, (int, float)):
            data["score"] = round(min(1.0, max(0.0, float(score))), 3)
        t.trace(stage, "url.kept", data)
    except Exception as exc:
        logger.debug("trace hook failed (ignored): %s", exc)


def url_dropped(stage: str, url: str, reason: str) -> None:
    t = current()
    if t is None:
        return
    try:
        if reason == "safety":
            uid, _ = t.trace_state.url_id(url)
            _safety_drop(t, stage, uid)
            return
        uid = _known(t, url)
        if uid is None:
            return
        t.trace(stage, "url.dropped", {
            "url_id": uid,
            "reason": reason if reason in URL_DROP_REASONS else "invalid",
        })
    except Exception as exc:
        logger.debug("trace hook failed (ignored): %s", exc)


def note_fetch(url: str, *, http_status: Optional[int], nbytes: Optional[int], ms: Optional[int]) -> None:
    """Remember a successful fetch until the safety scan decides its outcome."""
    t = current()
    if t is None:
        return
    try:
        t.trace_state.pending_fetch[str(url)] = {
            "http_status": http_status, "bytes": nbytes, "ms": ms,
        }
    except Exception as exc:
        logger.debug("trace hook failed (ignored): %s", exc)


def page_fetched(
    url: str,
    outcome: str,
    *,
    http_status: Optional[int] = None,
    nbytes: Optional[int] = None,
    ms: Optional[int] = None,
) -> None:
    t = current()
    if t is None:
        return
    try:
        if outcome == "safety_dropped":
            uid, _ = t.trace_state.url_id(url)
            t.trace_state.pending_fetch.pop(str(url), None)
            if not t.trace_state.mark_safety(uid):
                return
            # Only the id and the outcome: no host, size, timing or status.
            t.trace("fetch", "page.fetched", {"url_id": uid, "outcome": "safety_dropped"})
            return
        uid = _known(t, url)
        if uid is None:
            return
        pending = t.trace_state.pending_fetch.pop(str(url), None) or {}
        http_status = http_status if http_status is not None else pending.get("http_status")
        nbytes = nbytes if nbytes is not None else pending.get("bytes")
        ms = ms if ms is not None else pending.get("ms")
        data: dict[str, Any] = {
            "url_id": uid,
            "outcome": outcome if outcome in PAGE_OUTCOMES else "error",
        }
        if isinstance(http_status, int):
            data["http_status"] = http_status
        if isinstance(nbytes, int):
            data["bytes"] = max(0, nbytes)
        if isinstance(ms, int):
            data["ms"] = max(0, ms)
        t.trace("fetch", "page.fetched", data)
    except Exception as exc:
        logger.debug("trace hook failed (ignored): %s", exc)


def page_entities(url: str, entities: list, stage: str = "extract") -> None:
    """``page.entities`` for one page plus ``entity.found`` for its new entities.

    *entities* are extractor ``NormalizedEntity`` objects (or dicts with
    ``entity_type`` / ``value`` / ``confidence``). Values the content-safety
    entity gate blocks are skipped before anything is counted.
    """
    t = current()
    if t is None:
        return
    try:
        from utils.content_safety import is_blocked_entity_value

        if url and t.trace_state.known_url_id(url) in t.trace_state.safety_ids:
            return  # a page the safety filter dropped reports nothing more
        uid = _known(t, url) if url else None
        by_type: dict[str, int] = {}
        fresh: list[tuple[str, str, Any]] = []
        for ent in entities or []:
            etype = _attr(ent, "entity_type")
            value = _attr(ent, "value")
            if not etype or not value:
                continue
            try:
                if is_blocked_entity_value(etype, value):
                    continue
            except Exception:
                continue
            etype = etype.upper()
            if len(by_type) < MAX_BY_TYPE_KEYS or etype in by_type:
                by_type[etype] = by_type.get(etype, 0) + 1
            fresh.append((etype, value, _attr(ent, "confidence", None)))
        if uid is not None and by_type:
            t.trace(stage, "page.entities", {"url_id": uid, "by_type": by_type})
        for etype, value, confidence in fresh:
            eid, is_new = t.trace_state.entity_id(etype, value)
            if not is_new:
                continue
            data: dict[str, Any] = {
                "entity_id": eid,
                "type": _clip(etype, MAX_NAME),
                "display": mask_entity(etype, value),
            }
            if isinstance(confidence, (int, float)):
                data["confidence"] = round(min(1.0, max(0.0, float(confidence))), 3)
            if uid is not None:
                data["url_id"] = uid
            t.trace(stage, "entity.found", data)
    except Exception as exc:
        logger.debug("trace hook failed (ignored): %s", exc)


def _attr(obj: Any, name: str, default: Any = "") -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def enrich_source(source: str, status: Any, hits: Optional[int] = None) -> None:
    t = current()
    if t is None:
        return
    try:
        data: dict[str, Any] = {
            "source": _clip(source, MAX_NAME),
            "status": map_source_status(status, allow_skipped=True),
        }
        if hits is not None:
            data["hits"] = max(0, int(hits))
        t.trace("enrich", "enrich.source", data)
    except Exception as exc:
        logger.debug("trace hook failed (ignored): %s", exc)


def graph_progress(nodes: int, edges: int, communities: Optional[int] = None) -> None:
    t = current()
    if t is None:
        return
    try:
        data: dict[str, Any] = {"nodes": max(0, int(nodes)), "edges": max(0, int(edges))}
        if communities is not None:
            data["communities"] = max(0, int(communities))
        t.trace("graph", "graph.progress", data)
    except Exception as exc:
        logger.debug("trace hook failed (ignored): %s", exc)


def filter_fallback(scope: str, candidates: int, kept: int) -> None:
    """The relevance filter returned nothing usable; every candidate was kept (counts only)."""
    t = current()
    if t is None:
        return
    try:
        t.trace("filter", "filter_fallback", {
            "scope": scope if scope in ("onion", "clearnet") else "onion",
            "candidates": max(0, int(candidates)),
            "kept": max(0, int(kept)),
        })
    except Exception as exc:
        logger.debug("trace hook failed (ignored): %s", exc)


def summary_status(kind: str, attempt: Optional[int] = None) -> None:
    t = current()
    if t is None:
        return
    try:
        data: dict[str, Any] = {"kind": kind if kind in SUMMARY_KINDS else "none"}
        if attempt is not None:
            data["attempt"] = max(0, int(attempt))
        t.trace("summarize", "summary.status", data)
    except Exception as exc:
        logger.debug("trace hook failed (ignored): %s", exc)


__all__ = [
    "DEFAULT_CAPS",
    "DEFAULT_MAX_EVENTS",
    "PAGE_OUTCOMES",
    "SCHEMA_VERSION",
    "TRACE_ENV",
    "TRACE_KINDS",
    "TraceState",
    "URL_DROP_REASONS",
    "active",
    "bind",
    "current",
    "defang",
    "display_host",
    "env_enabled",
    "mask_entity",
]
