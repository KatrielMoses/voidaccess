"""
Database helpers for monitor jobs (URL watch state). Not imported by tests as pipeline mocks.
"""

from __future__ import annotations

import logging
import os
from urllib.parse import urlparse

from db.models import SourceType

logger = logging.getLogger(__name__)


def _onion_key_for_url(url: str) -> str:
    """Stable key for Source.onion_address (max 255)."""
    u = (url or "").strip()
    if not u:
        return ""
    try:
        p = urlparse(u)
        host = (p.netloc or p.path or "").split("/")[0]
        if host:
            return host[:255]
    except Exception:
        pass
    return u[:255]


def get_last_cleaned_text_for_url(url: str, investigation_id=None) -> str:
    """Return latest cleaned_text for *url* from pages table, or ''. Never raises."""
    if not os.getenv("DATABASE_URL"):
        return ""
    try:
        from db.queries import get_page_by_url  # noqa: PLC0415
        from db.session import get_session  # noqa: PLC0415

        with get_session() as session:
            page = get_page_by_url(session, url, investigation_id=investigation_id)
            if page is None or not page.cleaned_text:
                return ""
            return str(page.cleaned_text)
    except Exception as exc:
        logger.warning("get_last_cleaned_text_for_url failed: %s", exc)
        return ""


def update_source_watch_fingerprint(url: str, content_hash_hex: str) -> None:
    """
    Upsert Source row and store a short content fingerprint in status (VARCHAR(20)).
    """
    if not os.getenv("DATABASE_URL"):
        return
    fp = (content_hash_hex or "")[:20]
    if not fp:
        return
    key = _onion_key_for_url(url)
    if not key:
        return
    try:
        from db.queries import get_or_create_source, update_source_status  # noqa: PLC0415
        from db.session import get_session  # noqa: PLC0415

        with get_session() as session:
            src, _created = get_or_create_source(
                session,
                onion_address=key,
                source_type=SourceType.CRAWLED.value,
            )
            session.flush()
            update_source_status(session, src.id, fp)
    except Exception as exc:
        logger.warning("update_source_watch_fingerprint failed: %s", exc)
