# `feeds/` — reusable bulk blocklist-feed matcher + provenance stamping

Generalizes the P1.3 `sources/exploitdb.py` shape into one reusable abstraction:
**download a bulk blocklist once → index in memory → match investigation entities by
membership → flag them**, with **zero per-entity network**. Introduced for the P1.4
abuse/phishing feeds; reused again in P3 (index seeding) and P4 (feed cross-validation).

## `BlocklistFeed`

```
BlocklistFeed(name, cache_path, ttl_seconds, parser, match_entity_types, license_id,
              flag_tags, *, url | url_factory, header_factory, requires_key, key_env)
```

- `index()` → `CachedFeed(parse="text")` fetch (cached) + parse, memoized by raw text
  length (re-parse only when the feed content changes).
- `match(entities)` → membership-test each entity of a `match_entity_type` against the
  index; returns `[(entity, tags)]`. The feed is fetched **once** regardless of entity
  count.
- `status()` → `ok` / `skipped_no_key` / `unavailable` — never a silent `ok` with a
  zero count when a required key is missing or the fetch failed.

## The feeds

| Feed | Match types | Tags | Key | License |
|---|---|---|---|---|
| **SSLBL** (abuse.ch) | `FILE_HASH_SHA1` | `malicious_cert`, `feed:sslbl` | optional `ABUSECH_API_KEY` (Auth-Key) | CC0-1.0 |
| **OpenPhish** | `DOMAIN`, `IP_ADDRESS` | `phishing`, `feed:openphish` | none | Community (non-commercial) |
| **PhishTank** | `DOMAIN`, `IP_ADDRESS` | `phishing`, `feed:phishtank` | **required** `PHISHTANK_API_KEY` → `skipped_no_key` | PhishTank ToU |

**abuse.ch key note:** abuse.ch blocklist *CSV downloads* (Feodo, SSLBL) are public —
`sources/ip_reputation.py` fetches the Feodo CSV keyless today. Only the abuse.ch
*search APIs* (MalwareBazaar/ThreatFox/URLhaus) require the `Auth-Key`. SSLBL therefore
sends `Auth-Key` only if `ABUSECH_API_KEY` is set and is **not** hard-gated. If abuse.ch
later mandates auth for the SSLBL download, set `requires_key=True` on the `SSLBL` feed.

## Provenance + license stamping

Every feed-derived artifact is stamped at ingest:
- **Page** dicts carry a structured `provenance: {feed, license, attribution, url}`.
- **Matched entities** get a durable `feed:<name>` tag in `corroborating_sources`.
- `LICENSES` is the authoritative feed→license registry P4's trust gate reads (so it
  never re-derives origin). CC-BY feeds also emit an attribution line in page content.

This is **stamping only** — ToS/redistribution *enforcement* lands in P4 with the trust
gate.

## Hygiene

All feed IOCs pass the P1.3 `hygiene` helper: values are defanged for display
(`defang_ioc`) and page free-text is PII-stripped (`strip_pii`). Blocklist entries are
normalized (lowercased hosts/fingerprints) at parse.

## Not migrated here

The existing `sources/ip_reputation.py` Feodo + C2IntelFeeds loaders (hand-rolled cache)
share this shape and could be unified onto `BlocklistFeed` later; left as-is in P1.4 to
avoid touching working, suppression-coupled code.

## Tests

`pytest tests/test_feeds.py` — offline: one fetch serves N-entity matching (zero
per-entity network), phishing/cert flagging, provenance+license on every artifact,
`skipped_no_key` for PhishTank, feed-down degradation, entity write-back.
