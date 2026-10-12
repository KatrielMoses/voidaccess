"""Shared cooperative-cancel token for the investigation pipeline.

One helper serves both entry points (the CLI and the API) and every long stage.
A cancel never kills a thread or tears down an in-flight request; it sets a
token, and the long loops look at it between items:

* between engines in the search fan-out,
* between pages in fetch and scrape,
* between sources in enrichment (and between the enrichment sub-steps),
* at every stage boundary in the orchestrators.

Inside a stage, code calls :func:`is_cancelled` and simply stops starting new
work, returning what it already has. At a stage boundary the orchestrator calls
:func:`checkpoint`, which raises :class:`PipelineCancelled`. That exception
derives from ``BaseException`` on purpose: the pipeline is full of
``except Exception`` best-effort handlers that must not swallow a cancel.

The active token is looked up from a context variable first (the API runs
several investigations per process, so it binds a token per task) and then from
a process-wide default (the CLI runs one investigation per process and the
search stage runs on a thread-isolated event loop that does not inherit
context variables).
"""

from __future__ import annotations

import asyncio
import contextvars
import os
import threading
import time
from typing import Any, Awaitable, Optional

# How often a waiting stage looks at the token. Env-configurable; the default is
# the named baseline. A poll period, not a network timeout, so it is not scaled
# by the pacing profile.
CANCEL_POLL_INTERVAL_ENV = "VOIDACCESS_CANCEL_POLL_INTERVAL"
CANCEL_POLL_INTERVAL_DEFAULT_S = 0.25
# After a cancel, in-flight items get this long to finish before they are
# cancelled outright. Lets "finish the current item" hold for fast items without
# letting one slow Tor fetch push the terminal ``cancelled`` event past a
# platform kill deadline (Cloud Run gives 10 s after SIGTERM).
CANCEL_GRACE_ENV = "VOIDACCESS_CANCEL_GRACE"
CANCEL_GRACE_DEFAULT_S = 3.0


def _env_float(name: str, default: float) -> float:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value >= 0 else default


def poll_interval() -> float:
    return max(0.01, _env_float(CANCEL_POLL_INTERVAL_ENV, CANCEL_POLL_INTERVAL_DEFAULT_S))


def grace_period() -> float:
    return _env_float(CANCEL_GRACE_ENV, CANCEL_GRACE_DEFAULT_S)

# A cancel arrives from a signal handler or another thread, so the flag is a
# threading.Event: setting it is async-signal-safe enough for our use and is
# visible to every thread and event loop without any scheduling.


class PipelineCancelled(BaseException):
    """Raised at a checkpoint when the active run was cancelled."""

    def __init__(self, checkpoint: str = ""):
        super().__init__(checkpoint or "cancelled")
        self.checkpoint = checkpoint


class CancelToken:
    def __init__(self) -> None:
        self._event = threading.Event()
        self.reason: Optional[str] = None

    def cancel(self, reason: str = "cancelled") -> None:
        if not self._event.is_set():
            self.reason = reason
            self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self, checkpoint: str = "") -> None:
        if self._event.is_set():
            raise PipelineCancelled(checkpoint)

    def wait(self, timeout: Optional[float] = None) -> bool:
        return self._event.wait(timeout)


_ctx_token: contextvars.ContextVar[Optional[CancelToken]] = contextvars.ContextVar(
    "voidaccess_cancel_token", default=None
)
_process_token: Optional[CancelToken] = None


def set_current(token: Optional[CancelToken], *, process_wide: bool = False) -> None:
    """Make *token* the active token.

    ``process_wide=True`` (CLI) also publishes it for threads and event loops
    that do not inherit this context. The API binds per task and leaves the
    process-wide default alone so concurrent investigations stay independent.
    """
    global _process_token
    _ctx_token.set(token)
    if process_wide:
        _process_token = token


def current() -> Optional[CancelToken]:
    return _ctx_token.get() or _process_token


def is_cancelled() -> bool:
    """True when the active run was cancelled. False when no token is active."""
    token = current()
    return token is not None and token.cancelled


def checkpoint(name: str = "") -> None:
    """Raise :class:`PipelineCancelled` if the active run was cancelled."""
    token = current()
    if token is not None:
        token.raise_if_cancelled(name)


async def wait_cancellable(
    tasks: "set[asyncio.Future] | list[asyncio.Future]",
    timeout: Optional[float] = None,
) -> "tuple[set[asyncio.Future], set[asyncio.Future]]":
    """``asyncio.wait(tasks, timeout=...)`` that also returns once a cancel is set.

    Returns ``(done, pending)``. On a cancel the caller decides what to do with
    ``pending`` (cancel it, or let it finish within the grace period).
    """
    pending = set(tasks)
    if not pending:
        return set(), set()
    deadline = None if timeout is None else time.monotonic() + timeout
    poll = poll_interval()
    while pending:
        if is_cancelled():
            break
        step = poll
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            step = min(poll, remaining)
        _, pending = await asyncio.wait(pending, timeout=step)
    done = set(tasks) - pending
    return done, pending


async def run_cancellable(awaitable: Awaitable[Any], checkpoint_name: str = "") -> Any:
    """Await *awaitable*; on a cancel, give it the grace period, then stop it.

    The work runs as a task. While it runs the token is polled; once set, the
    task gets :func:`grace_period` seconds to finish (the "finish the current
    item" rule) and is then cancelled. A cancel raises
    :class:`PipelineCancelled` (carrying *checkpoint_name*) even when the work
    finished inside the grace period, so the orchestrator stops at this
    boundary instead of starting the next stage. With no active token this is
    a plain ``await``.
    """
    if current() is None:
        return await awaitable
    task = asyncio.ensure_future(awaitable)
    poll = poll_interval()
    cancelled_at: Optional[float] = None
    try:
        while not task.done():
            await asyncio.wait({task}, timeout=poll)
            if task.done():
                break
            if is_cancelled():
                if cancelled_at is None:
                    cancelled_at = time.monotonic()
                if time.monotonic() - cancelled_at >= grace_period():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    break
    except BaseException:
        # The outer task itself was cancelled (or a signal landed): do not leave
        # the inner work running.
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        raise
    if is_cancelled():
        raise PipelineCancelled(checkpoint_name)
    return task.result()


def reset_for_tests() -> None:
    global _process_token
    _process_token = None
    _ctx_token.set(None)
