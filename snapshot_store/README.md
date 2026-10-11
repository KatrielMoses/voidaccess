# snapshot_store — page-snapshot object store (P2.1)

Stands up the storage behind P2.0's `page_snapshots.storage_ref`: sanitized page
content lives in S3-compatible object storage, the DB row holds the ref +
`content_hash`, and identical content is stored once.

## Provider-agnostic by construction

Configured by **endpoint + bucket + credentials** only, so the same code runs
against:

- **Cloudflare R2** in production (zero egress — CC-2),
- **MinIO** or any S3 store locally / in dev,
- a **mocked S3** in tests (no cloud in CI).

There is **no boto3 / aioboto3 / minio dependency**. Requests go over the shared
clearnet `aiohttp` session (`netpool`); auth is **AWS SigV4, hand-rolled with
stdlib `hmac`/`hashlib`** (~40 lines in `s3.py`). The signer is verified
byte-for-byte against botocore's `S3SigV4Auth` in the test suite (skipped when
botocore is absent), so there is no lock-in and nothing cloud-specific to mock.

Config (all optional; see `config.py`):

```
S3_ENDPOINT_URL       https://<acct>.r2.cloudflarestorage.com
S3_BUCKET             snapshot bucket
S3_ACCESS_KEY_ID      operator-supplied
S3_SECRET_ACCESS_KEY  operator-supplied
S3_REGION             "auto" for R2
```

## The write path

`store_snapshot(session, url, content, …)`:

1. **Sanitize (mandatory legal gate).** `sanitize_page(content)` — composes the
   existing sanitizers: `content_safety.sanitize_content` (drops CSAM/gore
   pages), credential-line redaction (reusing the extractor's
   `COMBO_LIST_PATTERN` / `STEALER_LOG_PATTERN` → `CREDENTIAL_PRESENT`), and
   `hygiene.strip_pii` (emails/phones). Returns `None` to skip storage. **No raw
   credential or PII ever reaches object storage.** P2.2 will formalize/expand
   this sanitizer; here it is wired as the choke point.
2. **Content-address.** Key = SHA-256 of the *sanitized* bytes, sharded:
   `snapshots/<ab>/<hash>`.
3. **Dedup.** HEAD the key; upload (PUT) only if absent. Identical content is
   never re-uploaded — the ref is reused. DB dedup is P2.0's
   `uq_page_snapshot_content_hash`.
4. **Record.** `shared_corpus.record_page_snapshot(…)` writes the ref row
   (`storage_ref`, `content_hash`, `byte_size`, `language`, timestamps).

`read_snapshot(ref)` fetches the bytes back by `storage_ref` (or a bare content
hash).

## Unconfigured = graceful no-op

With no store configured (`S3ObjectStore.from_config()` → `None`: CLI $0 path or
a private-mode install), `store_snapshot` uploads nothing, records nothing, and
returns `None` — never raises. Object storage is never required to run the tool.
`read_snapshot` returns `None`.

## TTL / refresh policy — and why growth is bounded here

Every snapshot carries `captured_at`. `SNAPSHOT_TTL` (default **14 days**) is the
refresh cadence.

- `is_stale(snapshot)` — the programmatic **staleness marker**.
- `stale_snapshots(session)` — enumerates refresh candidates.

This is a deliberate contrast with the ChromaDB page cache (`vector/store.py`),
whose 24h TTL is checked **only on read** and which **never evicts** — an audit
finding of unbounded growth. Here the growth story is explicit:

- **Dedup bounds writes.** Content-hash addressing means re-observed content adds
  neither a row nor an object.
- **Staleness is queryable now.** `stale_snapshots` identifies what P3's
  freshness loop should re-crawl. The *enforcement* (re-capture updated content,
  or delete object + row for a dead onion) lands in P3; the marker and query
  exist now so that sweeper is a thin consumer, not a redesign.

## Convergence with the ChromaDB cache — considered, deliberately not forced

The tool has two "store page content" mechanisms:

| | ChromaDB cache (`vector/`) | `page_snapshots` (this module) |
|---|---|---|
| Tier | **local** per-user scrape cache | **shared** corpus |
| Key | SHA-256 of **URL** | SHA-256 of **content** |
| Body | truncated text + embedding, inline | full bytes in R2, DB holds ref |
| Lifecycle | 24h read-TTL, embeddings for similarity | refresh cadence, content-addressed dedup |

They serve different tiers and lifecycles (private local cache vs. sanitized
shared corpus), and their keys differ (URL vs. content). Collapsing them would
entangle a private, embedding-bearing cache with the shared, sanitized,
object-backed store — so they are kept separate per the brief's guidance. A
future clean convergence (e.g. the shared store growing an embedding index) can
be revisited without the two lifecycles being coupled now.

## Out of scope (later phases)

- Pipeline wiring that writes snapshots during investigations through the trust
  gate (P4).
- The formal/expanded sanitizer (P2.2) and the consent/opt-out switch (P2.2).
- The freshness re-crawl/eviction loop (P3).
- Live R2 credentials / deploy (P2 end-stage).

## Tests

`tests/test_snapshot_store.py` — dedup (one upload, ref reused), the legal gate
(no creds/PII in the stored object), read-back, the unconfigured no-op, the
TTL/staleness marker, and the botocore SigV4 cross-check. S3 is mocked at the
HTTP layer with `aioresponses`; zero cloud dependency.
