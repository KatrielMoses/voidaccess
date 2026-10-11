"""P1.1 — search fan-out consolidation + engine lifecycle status.

Offline: no Tor, no network. Verifies there is ONE fan-out implementation (the
package path and the submodule path resolve to the same objects), that every
caller import path still resolves, and that `quarantined` engines are never
dispatched by the fan-out.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

import search
import search.search as search_mod


# --------------------------------------------------------------------------- #
# Scope 1 — one implementation, shared objects
# --------------------------------------------------------------------------- #
def test_parse_and_regex_are_single_shared_objects():
    # Same object => impossible for the two entry points to diverge again.
    assert search._parse_html_links is search_mod._parse_html_links
    assert search._ONION_URL_RE is search_mod._ONION_URL_RE
    assert search.get_search_results_async is search_mod.get_search_results_async


def test_former_entry_points_return_identical_results_on_fixture():
    host_a = "a" * 56
    host_b = "b" * 56
    html = (
        "<html><body>"
        f'<a href="http://{host_a}.onion/thread/1">Forum thread</a>'
        f'<a href="/redir?url=http%3A%2F%2F{host_b}.onion%2Fmarket">Market</a>'
        '<a href="http://example.com/clearnet">Clearnet noise</a>'
        "plaintext http://" + ("c" * 56) + ".onion/leak mentioned in body"
        "</body></html>"
    )
    base = f"http://{'e' * 56}.onion/search?q=x"
    via_pkg = search._parse_html_links(html, base)
    via_sub = search_mod._parse_html_links(html, base)
    assert via_pkg == via_sub
    # Strict parser captured the redirect-param + plaintext onion links.
    links = {d["link"] for d in via_pkg}
    assert any(host_b in link for link in links)
    assert any(("c" * 56) in link for link in links)


def test_public_surface_resolves_on_both_paths():
    # Package path (CLI callers).
    from search import (  # noqa: F401
        close_search_session,
        get_last_search_summary,
        get_search_results_async,
        get_search_session,
        search_config,
    )
    # Submodule path (API / monitor / benchmark / health_check callers).
    from search.search import (  # noqa: F401
        ENGINE_WEIGHTS,
        EngineResult,
        SEARCH_ENGINES,
        USER_AGENTS,
        _dedupe_links,
        _fetch_engine,
        _search_async,
        get_search_results,
        get_tor_session,  # was a broken import before P1.1
    )
    assert callable(get_tor_session)


def test_no_engine_timeout_attribute():
    # Pins the invariant tests/test_pacing.py asserts, on both paths.
    assert not hasattr(search, "ENGINE_TIMEOUT")
    assert not hasattr(search_mod, "ENGINE_TIMEOUT")
    assert search.search_config is search_mod.search_config


# --------------------------------------------------------------------------- #
# Scope 2 — quarantined engines are never dispatched
# --------------------------------------------------------------------------- #
def test_quarantined_engine_never_dispatched(monkeypatch):
    active = {"name": "ActiveEngine", "url": "http://{}.onion/s?q={{query}}".format("a" * 56), "status": "active"}
    quarantined = {"name": "DeadEngine", "url": "http://{}.onion/s?q={{query}}".format("b" * 56), "status": "quarantined"}

    dispatched: list[str] = []

    async def fake_fetch(engine, query, session, sem):
        dispatched.append(engine["name"])
        return search_mod.EngineResult(name=engine["name"], links=[])

    # Neutralize DB + Tor so the test is offline.
    monkeypatch.setattr(search_mod, "_fetch_engine", fake_fetch)
    monkeypatch.setattr(search_mod, "get_all_engine_stats_async", AsyncMock(return_value=[]))
    monkeypatch.setattr(search_mod, "should_skip_engine_async", AsyncMock(return_value=False))
    monkeypatch.setattr(search_mod, "record_engine_attempt_async", lambda *a, **k: None)
    monkeypatch.setattr(search_mod.tor_isolation, "acquire_engine_session", lambda url: (object(), "k"))
    monkeypatch.setattr(search_mod.tor_isolation, "release_engine_session", lambda key: None)

    asyncio.run(
        search_mod._search_async("q", engines=[active, quarantined], allow_diversify=False)
    )

    assert dispatched == ["ActiveEngine"]
    assert "DeadEngine" not in dispatched


def test_active_engines_helper_and_catalog():
    from search.engine_catalog import SEARCH_ENGINES, active_engines

    # darksearch.io physically removed.
    assert not any("darksearch" in e["url"].lower() for e in SEARCH_ENGINES)
    # Every catalog entry carries a status; all currently active.
    assert all("status" in e for e in SEARCH_ENGINES)
    assert active_engines() == [e for e in SEARCH_ENGINES if e["status"] == "active"]
