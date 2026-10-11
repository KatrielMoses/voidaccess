# sanitizer — the single shared-write choke point (P2.2)

The blocking half of the Epic-3 trust gate (3.2 steps 1–3 + 3.5). Object storage
and the shared corpus are **legal surfaces**: per requirement 5.L the guarantee
is *"no raw creds, no PII, ever."* Every path that writes to the shared corpus
routes through **one** of two functions here — there is no second sanitize path
(grep-provable):

| Function | For | Returns |
|---|---|---|
| `sanitize_page(text)` | page-content bytes (snapshot store) | sanitized text, or `None` to **not store** |
| `sanitize_entity(type, value)` | a single shared entity/IOC value (global-entity tier) | value safe to store, or `None` to **drop** |

> **Governing principle: over-redact, never leak.** A false-positive redaction is
> cosmetic; a missed raw credential or PII string is a legal failure. Every
> ambiguous case biases to redaction/drop.

## `sanitize_page` — coverage

1. **Content-safety drop** — `utils.content_safety.sanitize_content` drops
   CSAM/gore pages entirely (`None`).
2. **Credentials → presence-only** (`detectors.redact_credentials`): every
   structured secret detector in `extractor.regex_patterns` (API keys,
   AWS/GitHub/Slack/Discord/Stripe/Google tokens, JWTs, PGP key blocks, combo
   lists, stealer logs) **plus prose heuristics** (`the password is X`,
   `creds: X`, `user/pass`) that the structured/entropy detectors miss. Every
   match becomes `CREDENTIAL_PRESENT`; the raw secret is never emitted.
3. **PII strip** (`detectors.redact_pii`): emails/phones via the existing
   `hygiene.strip_pii` regexes, plus **free-form-prose personal names and
   locations** via the existing spaCy NER (`extractor.ner.get_nlp` → PERSON /
   GPE / LOC) → `[redacted-pii]`.

### Fail-closed on NER

Prose name/location redaction depends on the spaCy model. If it is unavailable,
`redact_pii` returns `None` and `sanitize_page` **refuses to store the page**
rather than storing text whose names/addresses could not be verified as removed.
This is the deliberate fail-closed posture (the model is a documented
dependency: `python -m spacy download en_core_web_sm`).

**Residual gap, flagged for P4:** prose credential/PII detection is heuristic +
NER-based, tuned for recall. A credential in an exotic phrasing the heuristics
don't match, or a name spaCy misses, could slip a page-text redaction. The
design defaults ambiguous/uncovered cases to redaction (whole-page drop when NER
is down; broad credential-keyword spans), but P4's trust gate should treat
shared page content as *sanitized-best-effort*, not *proven-clean*, and keep the
quarantine tier for anything downstream re-derives from it.

## `sanitize_entity` — coverage

Drops (returns `None`): empty values; **inherently-PII entity types**
(`PERSON`/`PERSON_NAME`/`LOCATION`/`GPE`/`ADDRESS`/`PHONE` — victim identity
never enters the shared corpus; an actor's own name travels as a
`THREAT_ACTOR`/`ORGANIZATION` entity instead); **raw secrets** (matches any
secret detector — kept presence-only, never stored raw); and **malformed/noise**
artifacts (`validate.is_valid_shape` → `extractor.entity_shape` + `gazetteer`,
the same junk-rejection the extraction normalizer uses).

## Provenance stamping (3.2 step 3)

`provenance_stamp(source=…, captured_at=…)` builds the `{source, captured_at,
scraper_version}` dict stamped onto every shared write (persisted in the shared
tables' `provenance` JSON column, migration 0028). `scraper_version()` reads the
canonical `voidaccess_cli.__version__`. Extends the `feeds.provenance` registry
pattern to all shared writes; makes any shared record traceable to its origin
(3.4).

## Reuse only — no new ML

spaCy NER, `credential_presence`/`hygiene`, `extractor.regex_patterns`,
`extractor.entity_shape` + `gazetteer` are all reused. No new model or heavy
dependency is added.

## Consent / private-mode (2.4)

Consent is a **separate** concern from sanitization and lives in
`shared_corpus.consent.contribution_enabled()` (backed by `config.PRIVATE_MODE`).
A private-mode install reads/writes nothing central, independent of whether S3 is
configured. The wired shared I/O (`snapshot_store.store_snapshot` /
`read_snapshot`) gates on it; P4's write-to-shared / read-from-shared pipeline
must too.

## Tests

`tests/test_sanitizer.py` — per-class redaction (structured + prose credentials,
emails/phones, NER names/locations), the NER fail-closed path, shape/noise
rejection, the entity gate (PII types / secrets / malformed), provenance stamps,
and consent/private-mode. The snapshot-store and global-entity write paths are
tested end-to-end in `tests/test_snapshot_store.py` and `tests/test_shared_corpus.py`.
