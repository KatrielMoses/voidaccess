# `hygiene/` — reusable IOC-hygiene helper (Epic-3 sanitizer seed)

A pure, unit-testable normalization choke point that every new data source's output
passes through before storage/display. Built once here as a function module so the
Epic-3 trust-gate sanitizer can consume the same primitives instead of each source
re-inlining them.

## API

| Function | Concern | Notes |
|---|---|---|
| `defang_ioc(entity_type, value)` | display | Dispatches to `utils/defang.py`. |
| `defang_text(text)` | display | Defang URLs/IPs in free text. |
| `redact_email(email)` | display/log | `joh***@domain`; consolidates the triplicated `_safe_log_email`. |
| `strip_pii(text)` | storage | Redact emails + phones from free text. |
| `is_blocked_value(entity_type, value)` | storage | Backstop — re-export of `content_safety.is_blocked_entity_value`. |
| `redact_credential(value)` | display | Re-export of `export.redact_credential`; never emits the raw secret. |
| `sanitize_for_storage(entity_type, value)` | storage | Returns canonical value, or `None` if it must be dropped (store a presence marker). |

## Design decisions (flagged per the brief's latitude)

- **Defang strategy: store-canonical, display-defang.** VoidAccess already stores
  canonical IOC values and defangs at the API/export boundary (`utils/defang.py` is
  called in `api/routes/*`). Keeping stored values canonical means they stay
  queryable and joinable across sources; defanging is a presentation transform, so
  `defang_ioc`/`defang_text` live here for display and `sanitize_for_storage` does
  **not** defang.
- **Reuse, not reinvent.** Defang → `utils/defang.py`; credential redaction →
  `export.redact_credential`; the common-password/prohibited-content backstop →
  `content_safety.is_blocked_entity_value`; email redaction consolidates the three
  `_safe_log_email` copies in `sources/`.
- **Known divergence, not consolidated here:** `export/ioc_package.py:_defang_ip`
  uses an all-octet defang (`1[.]2[.]3[.]4`) vs `utils/defang.py`'s last-octet form
  (`1.2.3[.]4`). This module standardises on the `utils/defang` convention;
  reconciling the export path is left as separate cleanup.

## Out of scope (deferred)

- **Personal-name / postal-address PII** — needs NER; deferred to the fuller Epic-3
  sanitizer. `strip_pii` covers the pattern-matchable classes (emails, phones).
- **ToS / redistribution "derived-indicators-only" enforcement** — only bites when
  republishing to the shared tier, so it lands in **P4** with the trust gate.

## Tests

`pytest tests/test_hygiene.py` — per attack class: IOC defanging, PII (email/phone)
stripping, and credential presence-only (raw creds / common passwords never returned
by `sanitize_for_storage`; `redact_credential` never emits the raw secret).
