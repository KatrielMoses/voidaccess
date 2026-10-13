"""
Alert delivery (webhook, Telegram bot, SMTP) and persisted monitor_alerts records.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import smtplib
from email.mime.text import MIMEText
from typing import Any, Optional

from monitor.diff import is_significant_change

logger = logging.getLogger(__name__)


def _summarize_job_result(job_result: dict) -> str:
    parts: list[str] = []
    for key in ("query", "url", "changed", "new_pages", "new_entities", "duplicate_pages_skipped"):
        if key in job_result:
            parts.append(f"{key}={job_result[key]!r}")
    if not parts:
        parts.append(str(job_result)[:500])
    return "; ".join(parts)[:1500]


async def send_webhook(url: str, payload: dict) -> bool:
    """POST JSON to *url*; True on HTTP 2xx."""
    try:
        import aiohttp  # noqa: PLC0415

        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            ) as resp:
                return 200 <= resp.status < 300
    except Exception as exc:
        logger.error("send_webhook failed: %s", exc)
        return False


async def send_telegram_alert(chat_id: str, message: str) -> bool:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        return False
    try:
        import aiohttp  # noqa: PLC0415

        api = f"https://api.telegram.org/bot{token}/sendMessage"
        timeout = aiohttp.ClientTimeout(total=10)
        payload = {"chat_id": chat_id, "text": message[:4096]}
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(api, json=payload) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.error("Telegram API %s: %s", resp.status, body[:200])
                return resp.status == 200
    except Exception as exc:
        logger.error("send_telegram_alert failed: %s", exc)
        return False


async def send_email_alert(to: str, subject: str, body: str) -> bool:
    host = os.getenv("SMTP_HOST", "").strip()
    if not host:
        return False
    port = int(os.getenv("SMTP_PORT", "587") or "587")
    user = os.getenv("SMTP_USER", "").strip()
    password = os.getenv("SMTP_PASS", "").strip()

    def _send_sync() -> bool:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = user or "voidaccess@localhost"
        msg["To"] = to
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            smtp.ehlo()
            if user and password:
                smtp.starttls()
                smtp.ehlo()
                smtp.login(user, password)
            smtp.sendmail(msg["From"], [to], msg.as_string())
        return True

    try:
        return await asyncio.to_thread(_send_sync)
    except Exception as exc:
        logger.error("send_email_alert failed: %s", exc)
        return False


def _derive_severity(change_type: str, diff: dict) -> str:
    """Derive alert severity from change type and magnitude."""
    entity_mag = int(
        diff.get("new_entity_count", 0)
        or diff.get("entity_count", 0)
        or diff.get("new_entities", 0)
        or len(diff.get("new_entities", []) if isinstance(diff.get("new_entities"), list) else [])
        or 0
    )
    if change_type in ("new_entities",) and entity_mag >= 10:
        return "critical"
    if change_type in ("new_entities", "new_page", "first_result"):
        return "warning"
    if change_type in ("significant_change",):
        return "warning"
    if change_type == "content_change":
        return "info"
    return "info"


def _count_entity_delta(diff: dict) -> int:
    """Extract entity count delta from diff result."""
    v = (
        diff.get("new_entity_count")
        if diff.get("new_entity_count") is not None
        else None
    )
    if v is not None:
        return int(v)
    v = diff.get("entity_count")
    if v is not None:
        return int(v)
    ne = diff.get("new_entities")
    if isinstance(ne, list):
        return len(ne)
    if isinstance(ne, int):
        return ne
    return 0


def _sanitize_diff(diff: dict) -> dict:
    """
    Ensure diff data is JSON-serializable and not too large.
    Truncate large text fields; strip angle-bracket tags from strings.
    """
    sanitized: dict[str, Any] = {}
    for k, v in diff.items():
        if isinstance(v, str):
            s = re.sub(r"<[^>]+>", "", v)
            if len(s) > 500:
                sanitized[k] = s[:500] + "..."
            else:
                sanitized[k] = s
        elif isinstance(v, list) and len(v) > 50:
            sanitized[k] = v[:50]
        elif isinstance(v, (str, int, float, bool, list, dict)) or v is None:
            sanitized[k] = v
    return sanitized


def build_alert_context(watch: dict, job_result: dict) -> Optional[dict[str, Any]]:
    """
    If this job should produce an alert, return change_type, summary, diff_result.
    Otherwise None.
    """
    alert_on = watch.get("alert_on") or "new_results"
    wtype = watch.get("type", "keyword")

    if wtype == "keyword":
        np = int(job_result.get("new_pages") or 0)
        ne = int(job_result.get("new_entities") or 0)
        should = False
        if alert_on == "new_results":
            should = np > 0 or ne > 0
        elif alert_on == "any_change":
            should = np > 0 or ne > 0
        elif alert_on == "any_appearance":
            should = ne > 0
        if not should:
            return None
        if ne > 0:
            ct = "new_entities"
        elif np > 0:
            ct = "new_page"
        else:
            ct = "new_entities"
        summary = f"{ct}: {np} new page(s), {ne} new entities (query={job_result.get('query', '')!r})"
        diff_result = {
            "query": job_result.get("query"),
            "new_pages": np,
            "new_entities": ne,
            "entity_count": ne,
            "duplicate_pages_skipped": job_result.get("duplicate_pages_skipped"),
        }
        return {"change_type": ct, "summary": summary, "diff_result": diff_result}

    # URL watch
    changed = bool(job_result.get("changed"))
    if not changed:
        return None

    ne = int(job_result.get("new_entities") or 0)
    cr = float(job_result.get("change_ratio") or 0.0)
    is_first = bool(job_result.get("is_first_scrape"))
    sig = is_significant_change({"change_ratio": cr}, threshold=0.1)

    should = False
    if alert_on == "new_results":
        should = is_first or (ne > 0)
    elif alert_on == "any_change":
        should = sig or is_first
    elif alert_on == "any_appearance":
        should = ne > 0
    if not should:
        return None

    if is_first:
        ct = "first_result"
    elif ne > 0 and sig:
        ct = "significant_change"
    elif ne > 0:
        ct = "new_entities"
    elif sig:
        ct = "significant_change"
    else:
        ct = "content_change"

    summary = (
        f"{ct}: {job_result.get('url', '')!r} — "
        f"entities={ne}, change_ratio={cr:.3f}"
    )
    diff_result = {
        "url": job_result.get("url"),
        "new_entities": ne,
        "entity_count": ne,
        "change_ratio": cr,
        "lines_added": job_result.get("lines_added"),
        "lines_removed": job_result.get("lines_removed"),
        "diff_summary": job_result.get("diff_summary"),
        "is_first_scrape": is_first,
    }
    return {"change_type": ct, "summary": summary, "diff_result": diff_result}


async def dispatch_alerts(watch: dict, job_result: dict) -> list[str]:
    """
    Dispatch to all configured external channels concurrently.
    Returns channel names that succeeded (webhook, telegram, email).
    """
    name = watch.get("name", "watch")
    summary = _summarize_job_result(job_result)
    text = f"[VoidAccess Alert] {name}: {summary}"
    payload = {
        "watch": name,
        "job_result": job_result,
        "message": text,
    }

    tasks: list[Any] = []
    labels: list[str] = []

    wu = watch.get("webhook_url")
    if wu and isinstance(wu, str) and wu.strip():
        tasks.append(send_webhook(wu.strip(), payload))
        labels.append("webhook")

    tc = watch.get("telegram_chat_id")
    if tc and isinstance(tc, str) and tc.strip():
        tasks.append(send_telegram_alert(tc.strip(), text))
        labels.append("telegram")

    em = watch.get("email")
    if em and isinstance(em, str) and em.strip():
        tasks.append(
            send_email_alert(
                em.strip(),
                f"[VoidAccess Alert] {name}",
                json.dumps(job_result, indent=2, default=str)[:20000],
            )
        )
        labels.append("email")

    if not tasks:
        return []

    results = await asyncio.gather(*tasks, return_exceptions=True)
    delivered: list[str] = []
    for label, res in zip(labels, results):
        if res is True:
            delivered.append(label)
        elif isinstance(res, Exception):
            logger.error("alert channel %s failed: %s", label, res)
    return delivered


def _persist_alert_record(
    watch: dict,
    change_type: str,
    summary: str,
    diff_result: dict,
    delivered_channels: list[str],
) -> None:
    from db.queries import create_monitor_alert
    from db.session import get_session

    severity = _derive_severity(change_type, diff_result)
    entity_delta = _count_entity_delta(diff_result)
    with get_session() as session:
        create_monitor_alert(
            session=session,
            monitor_name=str(watch.get("name", "watch")),
            user_id=watch.get("user_id"),
            change_type=change_type,
            summary=summary,
            diff_data=_sanitize_diff(diff_result),
            severity=severity,
            entity_count_delta=entity_delta,
            delivery_channels=delivered_channels,
        )


async def evaluate_and_dispatch_alerts(watch: dict, job_result: dict) -> None:
    """
    If the watch policy says we should alert, send external notifications
    and persist a MonitorAlert row. DB failures never block delivery.
    """
    ctx = build_alert_context(watch, job_result)
    if ctx is None:
        return

    delivered_channels: list[str] = []
    try:
        delivered_channels = await dispatch_alerts(watch, job_result)
    except Exception as exc:
        logger.error("dispatch_alerts failed for %s: %s", watch.get("name"), exc)

    try:
        _persist_alert_record(
            watch,
            ctx["change_type"],
            ctx["summary"],
            ctx.get("diff_result") or {},
            delivered_channels,
        )
    except Exception as exc:
        logger.warning(
            "Failed to persist alert for %s: %s", watch.get("name"), exc
        )
