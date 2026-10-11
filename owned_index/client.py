"""
owned_index/client.py — a thin async Meilisearch REST client.

Deliberately no ``meilisearch`` SDK dependency, exactly like ``snapshot_store``
declines boto3: requests go over the shared clearnet ``aiohttp`` session
(``netpool``), timeouts/retries come from ``pacing`` (CC-4 — nothing hardcoded),
and the whole surface mocks cleanly with ``aioresponses`` (no Meili in CI for the
unit tests). Meilisearch is our own infrastructure (localhost in dev, the Oracle
box in prod), not a third-party quota, so plain timeout/retry scaling applies —
``pacing.scale_timeout`` / ``pacing.retry_plan`` — not ``scale_delay_floor``
(which exists for someone else's published rate limit).

Configuration
-------------
``MeiliConfig.from_config()`` reads ``config.MEILI_HOST`` / ``MEILI_KEY`` /
``MEILI_INDEX`` live (so tests can monkeypatch and a late ``.env`` still takes
effect). ``MEILI_HOST`` is the sole "configured" gate: unset → ``None`` →
``MeiliClient.from_config()`` → ``None`` → callers no-op and search falls back to
live fan-out. An empty ``MEILI_KEY`` is valid for a keyless local dev container
(the ``Authorization`` header is simply omitted).

Meilisearch's write API is asynchronous: index creation, settings updates and
document additions return a *task*; ``wait_for_task`` polls until it succeeds so
a subsequent search sees the write. Read calls (``search`` / ``get_document`` /
``health``) are synchronous on the server side.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Optional

import aiohttp

import pacing
from owned_index import schema

# ``normal`` pacing baselines — scaled per profile at the call site (CC-4). Meili
# is our own infra, so ordinary timeout/retry scaling (not delay-floor) is right.
_MEILI_TIMEOUT = 30.0
_MEILI_MAX_RETRIES = 2
_MEILI_RETRY_DELAYS = (0.5, 1.0)

# Task polling: how long to wait for an async write to finish, and how often to
# check. Also ``normal`` baselines scaled through pacing.
_TASK_POLL_TIMEOUT = 30.0
_TASK_POLL_INTERVAL = 0.2

_TERMINAL_TASK_STATES = frozenset({"succeeded", "failed", "canceled"})


class MeiliError(RuntimeError):
    """A Meilisearch request or task failed unrecoverably."""


@dataclass(frozen=True)
class MeiliConfig:
    host: str
    key: str = ""
    index_uid: str = "onion_pages"

    @classmethod
    def from_config(cls) -> Optional["MeiliConfig"]:
        """Build from ``config`` values, or ``None`` when the index is not set up.

        Read live (not import-time) so tests can monkeypatch ``config.MEILI_*``
        and a key added to the environment after import still takes effect.
        """
        import config

        host = (getattr(config, "MEILI_HOST", None) or "").strip()
        if not host:
            return None
        key = (getattr(config, "MEILI_KEY", None) or "").strip()
        index_uid = (getattr(config, "MEILI_INDEX", None) or "onion_pages").strip()
        return cls(host=host.rstrip("/"), key=key, index_uid=index_uid or "onion_pages")


class MeiliClient:
    """Async keyword+vector client for a single Meilisearch index."""

    def __init__(self, cfg: MeiliConfig):
        self._cfg = cfg

    @classmethod
    def from_config(cls) -> Optional["MeiliClient"]:
        """Return a client, or ``None`` when Meilisearch is not configured."""
        cfg = MeiliConfig.from_config()
        return cls(cfg) if cfg is not None else None

    @property
    def index_uid(self) -> str:
        return self._cfg.index_uid

    # -- transport ---------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._cfg.key:
            headers["Authorization"] = f"Bearer {self._cfg.key}"
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
    ) -> tuple[int, Any]:
        """Issue one request; retry transient 5xx / network errors via pacing."""
        from netpool import get_clearnet_session

        url = f"{self._cfg.host}{path}"
        headers = self._headers()
        timeout = aiohttp.ClientTimeout(total=pacing.scale_timeout(_MEILI_TIMEOUT))
        max_retries, delays = pacing.retry_plan(_MEILI_MAX_RETRIES, _MEILI_RETRY_DELAYS)

        attempt = 0
        while True:
            try:
                session = get_clearnet_session()
                async with session.request(
                    method,
                    url,
                    json=json_body,
                    headers=headers,
                    timeout=timeout,
                ) as resp:
                    status = resp.status
                    if status >= 500 and attempt < max_retries:
                        raise aiohttp.ClientError(f"Meili {status}")
                    try:
                        payload = await resp.json(content_type=None)
                    except Exception:
                        payload = None
                    return status, payload
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt >= max_retries:
                    raise
                if delays:
                    await asyncio.sleep(delays[min(attempt, len(delays) - 1)])
                attempt += 1

    def _task_uid(self, payload: Any) -> Optional[int]:
        if not isinstance(payload, dict):
            return None
        # v0.30+ returns ``taskUid``; older builds used ``uid``.
        uid = payload.get("taskUid", payload.get("uid"))
        return int(uid) if isinstance(uid, int) else None

    # -- provisioning ------------------------------------------------------

    async def health(self) -> bool:
        """True if the Meilisearch instance reports itself available."""
        try:
            status, payload = await self._request("GET", "/health")
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False
        return status == 200 and isinstance(payload, dict) and payload.get(
            "status"
        ) == "available"

    async def ensure_index(self, *, wait: bool = True) -> None:
        """Create the index and apply the 1.3 schema settings (idempotent).

        Core settings (primary key, searchable/filterable/sortable) must apply;
        the user-provided vector embedder is best-effort so the index still
        stands up (keyword-only) on a Meilisearch build where vector search is
        not enabled.
        """
        uid = self._cfg.index_uid

        # Create — an already-existing index (409 / index_already_exists) is fine.
        status, payload = await self._request(
            "POST", "/indexes", json_body={"uid": uid, "primaryKey": schema.PRIMARY_KEY}
        )
        if status not in (200, 201, 202) and status != 409:
            code = payload.get("code") if isinstance(payload, dict) else None
            if code != "index_already_exists":
                raise MeiliError(f"create index {uid} failed: {status} {payload}")
        elif wait:
            task_uid = self._task_uid(payload)
            if task_uid is not None:
                try:
                    await self.wait_for_task(task_uid)
                except MeiliError as exc:
                    # Meili's create-index API is ASYNC: it returns 202 + a task
                    # even when the index already exists, so "already exists"
                    # surfaces as a FAILED task, never a synchronous 409. "ensure"
                    # is idempotent, so that specific task failure is success —
                    # otherwise every startup after the first (index persists)
                    # would crash here.
                    if "index_already_exists" not in str(exc):
                        raise

        # Core attribute settings — must succeed.
        core_settings = {
            "searchableAttributes": list(schema.SEARCHABLE_ATTRIBUTES),
            "filterableAttributes": list(schema.FILTERABLE_ATTRIBUTES),
            "sortableAttributes": list(schema.SORTABLE_ATTRIBUTES),
        }
        status, payload = await self._request(
            "PATCH", f"/indexes/{uid}/settings", json_body=core_settings
        )
        if status not in (200, 202):
            raise MeiliError(f"settings for {uid} failed: {status} {payload}")
        if wait:
            task_uid = self._task_uid(payload)
            if task_uid is not None:
                await self.wait_for_task(task_uid)

        # Vector embedder — best-effort. Older Meili needs the experimental flag;
        # newer Meili has vector search GA. Either failure degrades to keyword-only.
        await self._try_enable_vectors(wait=wait)

    async def _try_enable_vectors(self, *, wait: bool) -> None:
        # Best-effort: turn on the experimental vector store (no-op / error on
        # builds where it is already GA or unknown — swallowed).
        try:
            await self._request(
                "PATCH", "/experimental-features", json_body={"vectorStore": True}
            )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

        embedders = {
            "embedders": {
                schema.EMBEDDER_NAME: {
                    "source": "userProvided",
                    "dimensions": schema.EMBEDDING_DIMENSIONS,
                }
            }
        }
        try:
            status, payload = await self._request(
                "PATCH", f"/indexes/{self._cfg.index_uid}/settings", json_body=embedders
            )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return
        if status in (200, 202) and wait:
            task_uid = self._task_uid(payload)
            if task_uid is not None:
                # A failed embedder task just means keyword-only; don't raise.
                try:
                    await self.wait_for_task(task_uid)
                except MeiliError:
                    pass

    # -- writes ------------------------------------------------------------

    async def add_documents(self, docs: list[dict], *, wait: bool = True) -> Any:
        """Upsert documents (add-or-replace by primary key). Waits for the task.

        Because the primary key is ``content_hash``, re-adding byte-identical
        content replaces the existing document rather than creating a duplicate.
        """
        status, payload = await self._request(
            "POST", f"/indexes/{self._cfg.index_uid}/documents", json_body=docs
        )
        if status not in (200, 202):
            raise MeiliError(f"add_documents failed: {status} {payload}")
        if wait:
            task_uid = self._task_uid(payload)
            if task_uid is not None:
                return await self.wait_for_task(task_uid)
        return payload

    # -- reads -------------------------------------------------------------

    async def get_document(self, doc_id: str) -> Optional[dict]:
        """Fetch a document by id (content hash), or ``None`` if absent."""
        status, payload = await self._request(
            "GET", f"/indexes/{self._cfg.index_uid}/documents/{doc_id}"
        )
        if status == 404:
            return None
        if status == 200 and isinstance(payload, dict):
            return payload
        raise MeiliError(f"get_document {doc_id} failed: {status} {payload}")

    async def search(self, body: dict) -> dict:
        """Run a search; returns the raw Meilisearch response ({'hits': [...]})."""
        status, payload = await self._request(
            "POST", f"/indexes/{self._cfg.index_uid}/search", json_body=body
        )
        if status != 200 or not isinstance(payload, dict):
            raise MeiliError(f"search failed: {status} {payload}")
        return payload

    async def wait_for_task(self, task_uid: int) -> dict:
        """Poll a task until it reaches a terminal state; raise on failure."""
        deadline_interval = pacing.scale_timeout(_TASK_POLL_INTERVAL)
        max_wait = pacing.scale_timeout(_TASK_POLL_TIMEOUT)
        waited = 0.0
        while True:
            status, payload = await self._request("GET", f"/tasks/{task_uid}")
            if status == 200 and isinstance(payload, dict):
                state = payload.get("status")
                if state == "failed":
                    raise MeiliError(f"task {task_uid} failed: {payload.get('error')}")
                if state in _TERMINAL_TASK_STATES:
                    return payload
            if waited >= max_wait:
                raise MeiliError(f"task {task_uid} did not finish within {max_wait}s")
            await asyncio.sleep(deadline_interval)
            waited += deadline_interval

    # -- test / maintenance helpers ---------------------------------------

    async def delete_all_documents(self, *, wait: bool = True) -> Any:
        """Clear every document from the index (used for test isolation).

        Idempotent on a cold index: clearing an index that does not exist yet
        (fresh deploy, or a reset before ``ensure_ready``) is a no-op — there is
        nothing to delete — so it must not crash. Real Meilisearch enqueues a
        deletion task that then fails with ``index_not_found``; we treat only
        that specific terminal error as success.
        """
        status, payload = await self._request(
            "DELETE", f"/indexes/{self._cfg.index_uid}/documents"
        )
        if status not in (200, 202):
            raise MeiliError(f"delete_all_documents failed: {status} {payload}")
        if wait:
            task_uid = self._task_uid(payload)
            if task_uid is not None:
                try:
                    return await self.wait_for_task(task_uid)
                except MeiliError as exc:
                    if "index_not_found" in str(exc):
                        return payload  # nothing to clear — index not created yet
                    raise
        return payload
