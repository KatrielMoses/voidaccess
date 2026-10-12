"""Shared search timeout, retry, and backoff configuration.

Keep these values in one module so the CLI and API search paths cannot drift.
The API path's 30-second timeout is the common baseline.

The constants below are the `normal` pacing baseline.  The accessor functions
apply the active pacing profile (quiet / normal / aggressive) — see
pacing/README.md.  Because both `search/__init__.py` and `search/search.py`
already read every timing value from this module, wiring the profile in here
once is inherited by the CLI and API callers automatically; neither needs its
own pacing wiring.

Call the functions, not the constants, at request time: the profile is
resolved per call, so a profile selected after import (the one-shot `--pace`
flag) still takes effect.
"""

import logging
import os

import pacing

logger = logging.getLogger(__name__)

SEARCH_TIMEOUT = 30
ENGINE_RETRY_COUNT = 2
RETRY_BACKOFF_BASE = 0.5


def search_timeout() -> float:
    """Return the per-request search timeout for the active pacing profile."""
    return pacing.scale_timeout(SEARCH_TIMEOUT)


def engine_retry_count() -> int:
    """Return the per-engine retry count for the active pacing profile."""
    count, _ = pacing.retry_plan(ENGINE_RETRY_COUNT, _backoff_curve())
    return count


def retry_backoff(attempt: int) -> float:
    """Return the delay before retry number *attempt* (zero-based)."""
    return pacing.scale_retry_delay(RETRY_BACKOFF_BASE * (attempt + 1))


def _backoff_curve() -> tuple[float, ...]:
    """The linear backoff expression as an explicit curve, for retry_plan()."""
    return tuple(
        RETRY_BACKOFF_BASE * (i + 1) for i in range(max(ENGINE_RETRY_COUNT, 1))
    )


# Opt-in overall deadline for the search fan-out. Unset (the default) keeps the
# existing behaviour of waiting for the slowest engine. When set, the stage
# returns whatever has arrived once the deadline passes and cancels the rest.
# The value is absolute seconds chosen by the operator, so it is not scaled by
# the pacing profile.
SEARCH_DEADLINE_ENV = "VOIDACCESS_SEARCH_DEADLINE"


def search_deadline() -> "float | None":
    """Return the search-stage deadline in seconds, or None when not set."""
    raw = (os.getenv(SEARCH_DEADLINE_ENV) or "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        logger.warning("Invalid %s=%r - ignoring", SEARCH_DEADLINE_ENV, raw)
        return None
    return value if value > 0 else None
