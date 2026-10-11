"""search package — thin re-export of the canonical fan-out in ``search.search``.

P1.1 consolidation: this file used to carry a *second, divergent* copy of the
fan-out / HTML-link parsing / onion-regex / session helpers. That was a live
correctness hazard — editing engines or parsing in one copy silently left the
other stale. There is now ONE implementation (``search.search``); this module
only re-exports it, so ``from search import X`` and ``from search.search import X``
resolve to the same code.

The stricter `_parse_html_links` / `_ONION_URL_RE` from ``search.search`` are the
keeper (they capture redirect-param + plaintext onion URLs, preserve the full
path, drop self-referential/junk hrefs, and dedup in-place); the previous
package-path copy used a looser parser.
"""

from search.search import (  # noqa: F401
    ENGINE_RETRY_COUNT,
    ENGINE_WEIGHTS,
    MAX_CONCURRENT,
    SEARCH_ENGINES,
    SEARCH_TIMEOUT,
    USER_AGENTS,
    EngineResult,
    _dedupe_links,
    _default_stats,
    _fetch_engine,
    _get_tor_session,
    _is_onion_url,
    _normalize_for_dedup,
    _ONION_URL_RE,
    _search_async,
    close_search_session,
    fetch_with_timeout,
    get_last_search_summary,
    get_search_results,
    get_search_results_async,
    get_search_session,
    get_tor_session,
)
from search.search import _parse_html_links  # noqa: F401
from search.engine_catalog import (  # noqa: F401
    DEFAULT_SEARCH_ENGINES,
    active_engines,
)

# Preserve the `search.search_config` package attribute that tests/test_pacing.py
# asserts. (Do NOT introduce `ENGINE_TIMEOUT`; that same test asserts its absence
# on both `search` and `search.search`.)
from . import config as search_config  # noqa: F401
