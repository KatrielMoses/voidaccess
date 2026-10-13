"""
Load and validate monitor watch definitions from monitors.yaml.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_ALERT_ON = frozenset({"new_results", "any_change", "any_appearance"})
_TYPES = frozenset({"keyword", "url"})


def _yaml_path() -> Path:
    env_path = os.getenv("MONITORS_CONFIG_PATH")
    if env_path:
        return Path(env_path)
    return Path(__file__).resolve().parent.parent / "data" / "monitors.yaml"


def _as_float(val: Any, default: Optional[float] = None) -> Optional[float]:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _validate_and_normalize(raw: dict) -> dict | None:
    name = raw.get("name")
    if not name or not isinstance(name, str):
        logger.warning("Monitor entry skipped: missing or invalid 'name'")
        return None
    wtype = raw.get("type")
    if wtype not in _TYPES:
        logger.warning("Monitor %r skipped: invalid type %r", name, wtype)
        return None
    interval = _as_float(raw.get("interval_hours"))
    if interval is None or interval < 0.5:
        logger.warning("Monitor %r skipped: interval_hours must be >= 0.5", name)
        return None
    alert_on = raw.get("alert_on")
    if alert_on not in _ALERT_ON:
        logger.warning("Monitor %r skipped: invalid alert_on %r", name, alert_on)
        return None

    if wtype == "keyword":
        q = raw.get("query")
        if not q or not isinstance(q, str):
            logger.warning("Monitor %r skipped: keyword watch needs query", name)
            return None
    else:
        u = raw.get("url")
        if not u or not isinstance(u, str):
            logger.warning("Monitor %r skipped: url watch needs url", name)
            return None

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        enabled = bool(enabled)
    use_llm = raw.get("use_llm", False)
    if not isinstance(use_llm, bool):
        use_llm = bool(use_llm)

    out: dict[str, Any] = {
        "name": name.strip(),
        "type": wtype,
        "interval_hours": interval,
        "alert_on": alert_on,
        "enabled": enabled,
        "webhook_url": raw.get("webhook_url"),
        "telegram_chat_id": raw.get("telegram_chat_id"),
        "email": raw.get("email"),
        "use_llm": use_llm,
    }
    if wtype == "keyword":
        out["query"] = str(raw["query"]).strip()
    else:
        out["url"] = str(raw["url"]).strip()

    return out


def load_yaml_watches() -> list[dict]:
    """Parse monitors.yaml; invalid entries are skipped. Returns [] if missing."""
    path = _yaml_path()
    if not path.is_file():
        return []
    try:
        import yaml  # noqa: PLC0415
    except ImportError:
        logger.warning("PyYAML not installed; no watches loaded")
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to read monitors.yaml: %s", exc)
        return []
    if not data or not isinstance(data, dict):
        return []
    watches_raw = data.get("watches")
    if not watches_raw or not isinstance(watches_raw, list):
        return []
    out: list[dict] = []
    for item in watches_raw:
        if not isinstance(item, dict):
            logger.warning("Monitor entry skipped: not a mapping")
            continue
        norm = _validate_and_normalize(item)
        if norm:
            out.append(norm)
    return out


def get_watch_by_name(name: str) -> dict | None:
    for w in load_watches():
        if w.get("name") == name:
            return w
    return None


def load_watches() -> list[dict]:
    if not os.getenv("DATABASE_URL"):
        return load_yaml_watches()
    from db.session import get_session
    from db.models import Monitor
    from monitor.migration import import_legacy_watches
    with get_session() as session:
        import_legacy_watches(session)
        return [dict(row.config, name=row.name, user_id=row.user_id,
                     scheduler_id=str(row.id), enabled=row.enabled)
                for row in session.query(Monitor).filter_by(deleted=False).all()]
