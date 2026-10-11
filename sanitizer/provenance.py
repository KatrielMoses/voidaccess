"""
sanitizer/provenance.py — provenance stamping for shared artifacts (3.2 step 3).

Every artifact written to the shared corpus must be attributable to its origin:
the source onion it was captured from, when it was captured, and the scraper
version that captured it. This mirrors and extends the ``feeds/`` provenance
registry (``feeds.provenance`` stamps ``feed``/``license``/``attribution``/``url``
onto feed-derived artifacts); here the stamp is the generic shared-write form.

The stamp is a plain dict persisted in the shared tables' ``provenance`` JSON
column, so any shared record can later be traced to its source and first-seen
(required for trust, disputes, and takedown — 3.4).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional


def scraper_version() -> str:
    """Return the canonical VoidAccess/scraper version string.

    Sourced from ``voidaccess_cli.__version__`` (the runtime source of truth used
    elsewhere, e.g. the IOC package exporter). Degrades to ``"unknown"`` rather
    than raising if the package is unavailable.
    """
    try:
        import voidaccess_cli

        return str(getattr(voidaccess_cli, "__version__", "unknown"))
    except Exception:
        return "unknown"


def provenance_stamp(
    *,
    source: Optional[str] = None,
    captured_at: Optional[datetime] = None,
    scraper: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build a provenance stamp for a shared artifact.

    Args:
        source: the origin — typically the source ``.onion`` address (or feed
            name / seed id). Recorded verbatim; ``None`` becomes ``"unknown"``.
        captured_at: capture timestamp (tz-aware UTC). Defaults to now.
        scraper: scraper/app version; defaults to :func:`scraper_version`.
        extra: optional additional provenance keys (e.g. feed license), merged in.

    Returns:
        A JSON-serializable dict with at least ``source``, ``captured_at`` (ISO
        8601), and ``scraper_version``.
    """
    when = captured_at or datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    stamp: dict[str, Any] = {
        "source": source or "unknown",
        "captured_at": when.isoformat(),
        "scraper_version": scraper or scraper_version(),
    }
    if extra:
        stamp.update(extra)
    return stamp
