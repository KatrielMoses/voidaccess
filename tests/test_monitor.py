"""
tests/test_monitor.py — Phase 4 monitor module (config, diff, alerts, jobs, scheduler).
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


class TestConfig(unittest.TestCase):
    def test_load_missing_file(self):
        import monitor.config as cfg

        with patch.object(cfg, "_yaml_path", return_value=Path("/___nonexistent___/m.yaml")):
            self.assertEqual(cfg.load_yaml_watches(), [])

    def test_load_valid(self):
        import monitor.config as cfg

        content = """
watches:
  - name: w1
    type: keyword
    query: test query
    interval_hours: 1.0
    alert_on: new_results
    enabled: true
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            path = f.name
        try:
            with patch.object(cfg, "_yaml_path", return_value=Path(path)):
                watches = cfg.load_yaml_watches()
        finally:
            os.unlink(path)
        self.assertEqual(len(watches), 1)
        self.assertEqual(watches[0]["name"], "w1")
        self.assertEqual(watches[0]["type"], "keyword")

    def test_skip_invalid(self):
        import monitor.config as cfg

        content = """
watches:
  - name: bad
    type: keyword
    interval_hours: 0.1
    alert_on: new_results
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            path = f.name
        try:
            with patch.object(cfg, "_yaml_path", return_value=Path(path)):
                with self.assertLogs("monitor.config", level="WARNING"):
                    watches = cfg.load_yaml_watches()
        finally:
            os.unlink(path)
        self.assertEqual(watches, [])

    def test_get_watch_by_name(self):
        import monitor.config as cfg

        content = """
watches:
  - name: alpha
    type: keyword
    query: q
    interval_hours: 2
    alert_on: any_change
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            path = f.name
        try:
            with patch.object(cfg, "_yaml_path", return_value=Path(path)):
                w = cfg.get_watch_by_name("alpha")
                self.assertIsNotNone(w)
                assert w is not None
                self.assertEqual(w["query"], "q")
                self.assertIsNone(cfg.get_watch_by_name("nope"))
        finally:
            os.unlink(path)


class TestDiff(unittest.TestCase):
    def test_identical(self):
        from monitor.diff import compute_diff

        d = compute_diff("same", "same")
        self.assertFalse(d["changed"])
        self.assertEqual(d["change_ratio"], 0.0)

    def test_completely_different(self):
        from monitor.diff import compute_diff

        d = compute_diff("", "hello completely new content here")
        self.assertTrue(d["changed"])
        self.assertEqual(d["change_ratio"], 1.0)

    def test_partial_lines(self):
        from monitor.diff import compute_diff

        old = "line1\nline2\nline3\n"
        new = "line1\nline2 changed\nline3\nextra\n"
        d = compute_diff(old, new)
        self.assertTrue(d["changed"])
        self.assertGreater(d["lines_added"] + d["lines_removed"], 0)

    def test_significant_threshold(self):
        from monitor.diff import compute_diff, is_significant_change

        d = compute_diff("a", "a")
        self.assertFalse(is_significant_change(d, threshold=0.1))
        d2 = compute_diff("", "bbbbbbbbbb")
        self.assertTrue(is_significant_change(d2, threshold=0.1))


class TestAlerts(unittest.IsolatedAsyncioTestCase):
    async def test_webhook_200(self):
        from monitor import alerts

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_sess = MagicMock()
        mock_sess.post = MagicMock(return_value=mock_cm)
        mock_session_cm = MagicMock()
        mock_session_cm.__aenter__ = AsyncMock(return_value=mock_sess)
        mock_session_cm.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session_cm):
            ok = await alerts.send_webhook("http://example.com/h", {"a": 1})
        self.assertTrue(ok)

    async def test_webhook_error_false(self):
        from monitor import alerts

        with patch("aiohttp.ClientSession", side_effect=OSError("boom")):
            ok = await alerts.send_webhook("http://x", {})
        self.assertFalse(ok)

    async def test_telegram_no_token(self):
        from monitor import alerts

        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": ""}, clear=False):
            self.assertFalse(await alerts.send_telegram_alert("1", "m"))

    async def test_email_no_smtp(self):
        from monitor import alerts

        with patch.dict(os.environ, {"SMTP_HOST": ""}, clear=False):
            self.assertFalse(await alerts.send_email_alert("a@b", "s", "b"))

    async def test_dispatch_all_channels(self):
        from monitor import alerts

        watch = {
            "name": "w",
            "webhook_url": "http://hook",
            "telegram_chat_id": "123",
            "email": "e@e.com",
        }
        job_result = {"changed": True}

        with patch.object(alerts, "send_webhook", new_callable=AsyncMock) as wh:
            with patch.object(alerts, "send_telegram_alert", new_callable=AsyncMock) as tg:
                with patch.object(alerts, "send_email_alert", new_callable=AsyncMock) as em:
                    wh.return_value = True
                    tg.return_value = True
                    em.return_value = True
                    delivered = await alerts.dispatch_alerts(watch, job_result)
        wh.assert_awaited_once()
        tg.assert_awaited_once()
        em.assert_awaited_once()
        self.assertEqual(set(delivered), {"webhook", "telegram", "email"})


class TestJobs(unittest.IsolatedAsyncioTestCase):
    async def test_keyword_pipeline_order_and_result(self):
        import monitor.jobs as jobs

        search_results = [{"link": "http://u1.onion", "title": "t"}]
        scraped = {"http://u1.onion": "page body text"}

        with patch.object(
            jobs.search, "get_search_results", return_value=search_results
        ) as m_search:
            with patch.object(
                jobs.scrape, "scrape_multiple", return_value=scraped
            ) as m_scrape:
                with patch.object(jobs.vector, "is_duplicate", return_value=False):
                    with patch.object(jobs.vector, "upsert_page", return_value=True):
                        mock_er = MagicMock()
                        mock_er.entity_count = 2
                        mock_er.errors = []
                        with patch.object(
                            jobs,
                            "extract_entities_from_pages",
                            new_callable=AsyncMock,
                            return_value=[mock_er],
                        ) as ex:
                            with patch("db.session.get_session") as get_session:
                                session = MagicMock()
                                session.get.return_value = None
                                get_session.return_value.__enter__.return_value = session
                                with patch.object(jobs.graph, "build_graph_from_db") as bg:
                                    watch = {
                                        "name": "kw",
                                        "query": "q",
                                        "type": "keyword",
                                    }
                                    result = await jobs.run_keyword_watch(watch, llm=None)
        m_search.assert_called_once_with("q")
        m_scrape.assert_called_once()
        ex.assert_awaited_once()
        bg.assert_called_once()
        self.assertEqual(result["name"], "kw")
        self.assertEqual(result["new_pages"], 1)
        self.assertEqual(result["new_entities"], 2)
        self.assertEqual(result["duplicate_pages_skipped"], 0)

    async def test_keyword_skips_duplicates(self):
        import monitor.jobs as jobs

        search_results = [{"link": "http://u.onion", "title": "x"}]
        scraped = {"http://u.onion": "dup"}

        with patch.object(jobs.search, "get_search_results", return_value=search_results):
            with patch.object(jobs.scrape, "scrape_multiple", return_value=scraped):
                with patch.object(jobs.vector, "is_duplicate", return_value=True):
                    with patch.object(
                        jobs,
                        "extract_entities_from_pages",
                        new_callable=AsyncMock,
                    ) as ex:
                        with patch.object(jobs.graph, "build_graph_from_db"):
                            r = await jobs.run_keyword_watch({"name": "n", "query": "q"})
        ex.assert_not_called()
        self.assertEqual(r["duplicate_pages_skipped"], 1)
        self.assertEqual(r["new_pages"], 0)

    async def test_url_no_change(self):
        import monitor.jobs as jobs

        with patch.object(jobs._db, "get_last_cleaned_text_for_url", return_value="same"):
            with patch.object(jobs.scrape, "scrape_multiple", return_value={"http://x.onion": "same"}):
                with patch.object(jobs.vector, "upsert_page") as up:
                    with patch.object(
                        jobs,
                        "extract_entities_from_page",
                        new_callable=AsyncMock,
                    ) as ex:
                        r = await jobs.run_url_watch(
                            {"name": "uw", "url": "http://x.onion"}
                        )
        self.assertFalse(r["changed"])
        up.assert_not_called()
        ex.assert_not_called()

    async def test_url_change_triggers_extract(self):
        import monitor.jobs as jobs

        with patch.object(jobs._db, "get_last_cleaned_text_for_url", return_value="old"):
            with patch.object(
                jobs.scrape,
                "scrape_multiple",
                return_value={"http://x.onion": "new content here"},
            ):
                with patch.object(jobs.vector, "upsert_page", return_value=True):
                    with patch.object(jobs._db, "update_source_watch_fingerprint"):
                        mock_er = MagicMock()
                        mock_er.entity_count = 3
                        with patch.object(
                            jobs,
                            "extract_entities_from_page",
                            new_callable=AsyncMock,
                            return_value=mock_er,
                        ) as ex:
                            r = await jobs.run_url_watch(
                                {"name": "uw", "url": "http://x.onion"}
                            )
        ex.assert_awaited_once()
        self.assertTrue(r["changed"])
        self.assertEqual(r["new_entities"], 3)


class TestScheduler(unittest.TestCase):
    def test_start_returns_none_when_import_fails(self):
        import monitor.scheduler as scheduler

        real_import = __import__

        def fake_import(name, *args, **kwargs):
            if name.startswith("apscheduler"):
                raise ImportError("no")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            self.assertIsNone(scheduler.start_scheduler())

    def test_get_job_status_structure(self):
        from monitor import scheduler

        mock_job = MagicMock()
        mock_job.id = "j1"
        mock_job.next_run_time = None
        mock_job.last_run_time = None
        mock_sched = MagicMock()
        mock_sched.get_jobs.return_value = [mock_job]
        rows = scheduler.get_job_status(mock_sched)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "j1")

    def test_trigger_unknown(self):
        from monitor import scheduler

        mock_sched = MagicMock()
        mock_sched.get_job.return_value = None
        self.assertFalse(scheduler.trigger_job_now(mock_sched, "none"))


if __name__ == "__main__":
    unittest.main()
