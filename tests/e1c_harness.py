"""Shared harness: run the CLI pipeline in-process with every network seam mocked.

Used by the E1C tests (quiet mode, source status, cancel checkpoints, disabled
sources). It mirrors the setup in ``test_summary_fallback`` but is parameterised
so each test can plug in its own side sources and summary behaviour.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Callable, Optional

RSS_PAGE = {
    "url": "https://example.com/lockbit-report",
    "text": "LockBit ransomware exploited CVE-2023-4966 against many organisations. " * 20,
    "source": "rss",
    "source_type": "rss_feed",
    "title": "LockBit report",
}


async def _none(_q):
    return []


async def _rss_page(_q):
    return [dict(RSS_PAGE)]


def prepare(
    tmp_path: Path,
    monkeypatch,
    *,
    generate_summary: Optional[Callable] = None,
    side_sources: Optional[dict] = None,
    summary_timeout: str = "3",
) -> Any:
    """Point the pipeline at a temp DB and stub every network-facing seam.

    ``side_sources`` maps ``_scrape_pastes`` / ``_scrape_github`` /
    ``_scrape_gitlab`` / ``_scrape_rss`` to an async callable. Returns the
    ``investigate`` module.
    """
    import db.session as session_module
    import voidaccess.llm as llm_mod
    import voidaccess_cli.commands.investigate as inv

    db_path = tmp_path / "inv.db"
    monkeypatch.setenv("VOIDACCESS_DB_PATH", str(db_path))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("VOIDACCESS_PRIVATE_MODE", "1")
    monkeypatch.setenv("VOIDACCESS_SUMMARY_TIMEOUT", summary_timeout)
    monkeypatch.setattr(session_module, "DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    session_module._get_engine_cached.cache_clear()
    monkeypatch.setitem(inv.CLI_PHASE_TIMEOUTS, "summary", int(summary_timeout))

    sides = {
        "_scrape_pastes": _none,
        "_scrape_github": _none,
        "_scrape_gitlab": _none,
        "_scrape_rss": _rss_page,
    }
    sides.update(side_sources or {})
    for name, fn in sides.items():
        monkeypatch.setattr(inv, name, fn)

    async def _no_enrich(*_a, **_k):
        return []

    monkeypatch.setattr("sources.enrichment.enrich_investigation", _no_enrich)
    monkeypatch.setattr(llm_mod, "get_llm", lambda *a, **k: object())
    monkeypatch.setattr(llm_mod, "refine_query", lambda llm, q: q)
    monkeypatch.setattr(llm_mod, "filter_results", lambda llm, q, links, n=15: links)
    if generate_summary is not None:
        monkeypatch.setattr(llm_mod, "generate_summary", generate_summary)
    monkeypatch.setattr(inv, "_filter_clearnet_pages", lambda pages, q, n, llm: pages)

    import extractor.pipeline as pipeline

    real = pipeline.extract_entities_from_pages

    async def _extract(*a, **k):
        k["run_llm_extraction"] = False
        return await real(*a, **k)

    monkeypatch.setattr(pipeline, "extract_entities_from_pages", _extract)

    from voidaccess_cli import config as cli_config

    monkeypatch.setattr(cli_config, "get_llm_key", lambda cfg: "k")
    return inv


def run(
    inv,
    tmp_path: Path,
    *,
    query: str = "lockbit ransomware",
    quiet: bool = True,
    no_tor: bool = True,
    no_llm: bool = False,
    fmt: str = "json",
    **kwargs: Any,
) -> None:
    import db.session as session_module

    try:
        asyncio.run(
            inv._run_investigation(
                query=query,
                out_dir=tmp_path,
                model="m",
                no_tor=no_tor,
                no_llm=no_llm,
                depth="shallow",
                fmt=fmt,
                quiet=quiet,
                **kwargs,
            )
        )
    finally:
        session_module._get_engine_cached.cache_clear()


def read_payload(tmp_path: Path) -> dict:
    return json.loads(next(tmp_path.glob("*.json")).read_text())


def read_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
