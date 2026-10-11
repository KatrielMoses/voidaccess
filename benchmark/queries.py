"""Load and validate the versioned benchmark query set.

The query set lives in ``data/benchmark_queries.json`` (version-controlled, not
hardcoded in a test) so it can be extended without code changes and so every
harness and test loads the same canonical set.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

DEFAULT_QUERY_SET_PATH = Path(__file__).resolve().parent / "data" / "benchmark_queries.json"

# The categories the P1.0 brief requires the set to span.
VALID_CATEGORIES = frozenset({
    "ransomware",
    "actor_handle",
    "malware_family",
    "infra_indicator",
    "credential_breach",
    "multilingual",
})


@dataclass(frozen=True)
class BenchmarkQuery:
    id: str
    query: str
    category: str
    lang: str = "en"


@dataclass(frozen=True)
class QuerySet:
    version: str
    description: str
    queries: tuple[BenchmarkQuery, ...]

    def __len__(self) -> int:
        return len(self.queries)


def load_query_set(path: Optional[Union[Path, str]] = None) -> QuerySet:
    """Parse and validate the query set. Raises ValueError on any malformed entry
    so a broken set fails fast rather than silently skewing a benchmark."""
    p = Path(path) if path else DEFAULT_QUERY_SET_PATH
    if not p.exists():
        raise FileNotFoundError(f"benchmark query set not found: {p}")

    raw = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("query set root must be a JSON object")

    version = raw.get("version")
    if not version:
        raise ValueError("query set missing 'version'")

    items = raw.get("queries")
    if not isinstance(items, list) or not items:
        raise ValueError("query set 'queries' must be a non-empty list")

    seen_ids: set[str] = set()
    parsed: list[BenchmarkQuery] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"query #{i} is not an object")
        for field in ("id", "query", "category"):
            if not item.get(field):
                raise ValueError(f"query #{i} missing required field '{field}'")
        qid = str(item["id"])
        if qid in seen_ids:
            raise ValueError(f"duplicate query id '{qid}'")
        seen_ids.add(qid)
        category = str(item["category"])
        if category not in VALID_CATEGORIES:
            raise ValueError(
                f"query '{qid}' has unknown category '{category}' "
                f"(valid: {sorted(VALID_CATEGORIES)})"
            )
        parsed.append(
            BenchmarkQuery(
                id=qid,
                query=str(item["query"]),
                category=category,
                lang=str(item.get("lang", "en")),
            )
        )

    return QuerySet(
        version=str(version),
        description=str(raw.get("description", "")),
        queries=tuple(parsed),
    )
