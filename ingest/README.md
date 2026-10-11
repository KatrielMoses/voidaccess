# ingest — cross-install ingest API + Sybil-resistant corroboration (P4.3)

Opens the corpus to contributions from **any install** via low-friction
self-registered keys (owner decision: max contribution, no manual minting). Mounted
only on a central-service install (`VOIDACCESS_INGEST_ENABLED=true`); absent/inert
on $0/local installs.

## The Sybil problem and the three-part defense

Corroboration promotes an entity on ≥ N independent sources. If "source" were the
ingest key, an attacker would self-register N keys, submit one false IOC from each,
and forge corroboration. The moat would be trivially breakable. The defense:

1. **Corroboration independence is keyed on the artifact's ORIGIN** (the onion/host
   it was observed on), **never** the ingest key. The same IOC from one origin via
   100 keys is still **one** origin (set dedup). See the origin-vs-contributor split
   below.
2. **A claim counts only when the CONTRIBUTING KEY has earned reputation.** A fresh
   self-registered key starts at low reputation (`TRUST_GATE_CONTRIBUTOR_START_REPUTATION`,
   below the corroborate threshold); per the P4.0 reputation veto its claimed
   origins do not count and stay `unconfirmed`. A key earns reputation only by
   agreeing with independently-corroborated data (a trusted feed, or origins already
   contributed by other eligible contributors) — slowly. A fresh attacker key, or a
   thousand of them, promotes nothing.
3. **`feed_validated` is unforgeable** because `feed_hits` are re-derived
   **server-side** from the platform's own `feeds/` matching (`feeds.derive_feed_hits`);
   any submitter-supplied `feed_hits` are discarded.

## The origin-vs-contributor split (the crux)

This sub-phase required making the P4.0/P4.1 single "source" concept explicit as two
layers, cleanly, in the gate:

| | `origin` | `contributor` |
|---|---|---|
| **is** | where it was observed (onion/host) | who submitted it (ingest key / `"local"`) |
| **unit for** | corroboration independence | reputation, rate-limit, revocation |
| **P4.1 local** | the onion | the onion (`source` sets both) |
| **P4.3 ingest** | claimed onion | the authenticated key_id |

`Artifact` / `EntityObservation` carry both; `source` remains a back-compat alias
that sets both (so P4.0/P4.1 behave identically). The gate keys `CorpusState.
corroborations` on origin and reputation/anomaly windows on contributor. A trusted
key can only lie about origins it *claims*, and a contradicted/anomalous key is
downweighted and revocable — becoming trusted is the expensive, revocable gate.

## Endpoints

- `POST /ingest/register` → `{key_id, secret}`. No manual approval. Soft
  anti-key-farming: a per-IP new-key rate cap (`INGEST_REGISTER_RATE_LIMIT`).
- `POST /ingest/observations` — authenticated (`X-Ingest-Key-Id` + `X-Ingest-Secret`).
  No unauthenticated writes. Payload caps (`INGEST_MAX_ARTIFACTS_PER_REQUEST`,
  `INGEST_MAX_VALUE_LENGTH`) + per-key rate limit (`INGEST_RATE_LIMIT`, reusing the
  P2.3 substrate). Every artifact flows through the **one write path** —
  `ingest.service.promote_ingest` → P4.1 `promote_entities` → the P4.0 gate. Grep
  confirms no second write path (no direct `upsert_global_entity(` in this module).

## Fail-closed kill-switch

Both revocation and the global pause are **authoritative and fail-closed** (the
opposite of the session blacklist's fail-open, per the P2.3 constraint):

- `ingest.keys.verify_key` — unknown / revoked key, bad secret, **or an unreadable
  key store** all raise `IngestAuthError` → reject.
- `ingest.control.is_paused` — a globally-paused **or unreadable** control store →
  ingest refused.

## Stores

- `ingest_keys` (migration 0033) — key_id + secret **hash** (never plaintext) +
  authoritative revocation status. The key's *reputation* lives in the shared-tier
  `source_reputations` keyed by `key_id`, read through the normal gate load path.
- `ingest_control` (0033) — single-row global pause.
- `global_entities.disposition` (0034) — the established-disposition baseline that
  wires the P4.1 contradiction seam: an external claim conflicting with it
  downweights the contributor.

## Tests

`tests/test_ingest.py` drives the real HTTP boundary: self-registration + unauth
rejection, unconfirmed-by-default, the **Sybil red-team** (many keys / many
fabricated origins move nothing), forged-feed-hit discard vs genuine server-derived
promotion, fail-closed revocation + pause (incl. unreachable store), per-key rate
limit + payload caps + malformed rejection, single-write-path grep, and the
contradiction downweight.
