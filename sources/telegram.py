"""
sources/telegram.py — Telegram public channel monitor via Telethon.

Telegram is clearnet (NOT routed through Tor) but carries enormous threat
actor activity in public groups and channels.

Credentials are loaded from config.py and treated as optional:
  TELEGRAM_API_ID    integer app id from my.telegram.org
  TELEGRAM_API_HASH  string hash from my.telegram.org
  TELEGRAM_PHONE     E.164 phone number (for initial interactive session auth)

If any credential is missing the function returns [] immediately with a
warning — Telegram is always optional and must never block the pipeline.

Initial session setup requires running an interactive auth once (Telethon
sends a verification code to the phone).  Subsequent calls reuse the saved
session file ("voidaccess_telegram.session" in the working directory).

Public API:
    async def fetch_telegram_messages(
        channel_usernames, query, limit_per_channel=100
    ) -> list[dict]

Each result dict has: channel, message_id, text, date, url.
Matching messages are also persisted to the DB pages table.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import timezone
from typing import List

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy Telethon import — keeps the module importable even if telethon is not
# installed (tests can still mock it; real calls will fail with ImportError
# which is caught and returns []).
# ---------------------------------------------------------------------------

def _import_telethon():
    """Import Telethon; raise ImportError with a clear message if missing."""
    try:
        from telethon import TelegramClient
        from telethon.errors import SessionPasswordNeededError
        return TelegramClient, SessionPasswordNeededError
    except ImportError as exc:
        raise ImportError(
            "telethon is required for Telegram integration. "
            "Install it with: pip install telethon"
        ) from exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _matches(text: str, query: str) -> bool:
    """Case-insensitive: every whitespace-separated query term must appear."""
    text_lower = text.lower()
    return all(term in text_lower for term in query.lower().split())


def _t_me_url(channel: str, message_id: int) -> str:
    return f"https://t.me/{channel.lstrip('@')}/{message_id}"


def _persist_message(url: str, text: str) -> None:
    """Write a matching Telegram message to the DB pages table. Silent on failure."""
    try:
        from config import DATABASE_URL as _db_url
        if not _db_url:
            return
        from db.queries import create_page, get_page_by_hash
        from db.session import get_session
    except ImportError:
        return

    content_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    try:
        with get_session() as session:
            if get_page_by_hash(session, content_hash):
                return
            # Telegram messages have no .onion source — source_id stays None
            create_page(
                session,
                url=url,
                source_id=None,
                cleaned_text=text,
                raw_content_hash=content_hash,
                byte_size=len(text.encode("utf-8", errors="replace")),
            )
    except Exception as exc:
        _logger.debug("Telegram DB persist failed url=%s: %s", url, exc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def fetch_telegram_messages(
    channel_usernames: List[str],
    query: str,
    limit_per_channel: int = 100,
) -> List[dict]:
    """
    Fetch recent messages from public Telegram channels/groups and return
    those that keyword-match *query*.

    Args:
        channel_usernames:  list of "@handle" or "username" strings.
        query:              investigation query; all space-separated terms
                            must appear in the message text.
        limit_per_channel:  max messages to fetch per channel before filtering.

    Returns list[dict] with keys: channel, message_id, text, date, url.
    Returns [] immediately (with a warning) when credentials are not set.
    Telethon errors per channel are logged and skipped; the function never
    raises.
    """
    from sources.source_control import source_gate

    if not source_gate("telegram"):
        return []
    # Lazy import credentials here so config changes in tests propagate
    try:
        from config import TELEGRAM_API_ID, TELEGRAM_API_HASH, TELEGRAM_PHONE
    except ImportError:
        _logger.warning("config.py not importable; skipping Telegram.")
        return []

    if not TELEGRAM_API_ID or not TELEGRAM_API_HASH:
        _logger.warning(
            "TELEGRAM_API_ID and TELEGRAM_API_HASH are required for Telegram "
            "integration.  Set them in .env and restart."
        )
        return []

    try:
        api_id = int(TELEGRAM_API_ID)
    except (ValueError, TypeError):
        _logger.warning("TELEGRAM_API_ID must be an integer.  Skipping Telegram.")
        return []

    try:
        TelegramClient, SessionPasswordNeededError = _import_telethon()
    except ImportError as exc:
        _logger.warning("%s", exc)
        return []

    results: List[dict] = []

    try:
        # "voidaccess_telegram" = session file name; StringSession("") = fresh in-memory
        # For persistent auth: use "voidaccess_telegram" (creates voidaccess_telegram.session)
        async with TelegramClient("voidaccess_telegram", api_id, TELEGRAM_API_HASH) as client:
            if not await client.is_user_authorized():
                _logger.warning(
                    "Telegram session not authorized.  Run interactive auth once: "
                    "the client will send a code to TELEGRAM_PHONE=%s",
                    TELEGRAM_PHONE or "<not set>",
                )
                return []

            for raw_channel in channel_usernames:
                channel = raw_channel.lstrip("@")
                try:
                    async for msg in client.iter_messages(
                        channel, limit=limit_per_channel
                    ):
                        text = msg.text or ""
                        if not text or not _matches(text, query):
                            continue

                        url = _t_me_url(channel, msg.id)
                        date = (
                            msg.date.astimezone(timezone.utc)
                            if msg.date
                            else None
                        )

                        entry = {
                            "channel": channel,
                            "message_id": msg.id,
                            "text": text,
                            "date": date,
                            "url": url,
                        }
                        results.append(entry)
                        _persist_message(url, text)

                except Exception as exc:
                    _logger.debug(
                        "Telegram channel %s fetch failed: %s", channel, exc
                    )

    except Exception as exc:
        _logger.warning("Telegram client error: %s", exc)

    return results
