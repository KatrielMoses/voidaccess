# `credential_presence/` — HIBP Pwned Passwords (k-anonymity, presence-only)

The operational enforcement of requirement **5.L** — *"presence flags/hashes only,
never raw credential corpora."* Reports **"this leaked password appears in N known
breaches"** without ever storing, logging, or transmitting the credential.

## The raw-credential-never-leaves contract

This module exists to make that guarantee auditable in one place:

1. A credential is **transiently observed** from collected page text (reusing the
   extractor's `_COMBO_LINE_RE` / `_STEALER_LOG_RE`), read into a loop-local variable.
2. It is **SHA-1'd in memory**; **only the first 5 hex chars** (`prefix`) leave the
   process — sent to `https://api.pwnedpasswords.com/range/{prefix}` (k-anonymity).
   The remaining suffix is matched **locally** against the returned `SUFFIX:COUNT` list.
3. The password — and its full hash — are **never logged, never stored, never
   returned, never sent in full**. Only a boolean presence flag + integer breach
   count persist, as tags on the associated **email entity**
   (`pwned_password`, `pwned_password_count_{n}`, `feed:hibp_pwned_passwords`) via the
   `corroborating_sources` write-back.
4. The raw value is dropped (`pw = ""`) immediately after the check.

Free, unlimited, no key. Clearnet via `netpool`; timeout via `pacing` (CC-4).
Per-investigation cap `MAX_CREDENTIAL_CHECKS`. Graceful: HIBP down → nothing flagged,
status `unavailable`, never a crash. Artifacts carry `provenance` (via `feeds.LICENSES`)
and pass the `hygiene` helper.

## API

| Function | Role |
|---|---|
| `check_password_presence(password) -> {present, breach_count, status}` | The k-anonymity primitive. Only the 5-char prefix leaves. |
| `scan_pages_for_pwned_credentials(pages) -> (summary_page|None, stats)` | Scans page text, checks each password, flags the email entity — counts only. |

## Hook point

Called **after extraction** (so the email entities exist to flag) while the scraped
page text is still in memory — CLI (`scraped_pages`) and API (`page_records`), before
the presence flag is persisted. See `tests/test_credential_presence.py` for the
per-attack-class proof that the raw value has no path to disk/log/network-in-full.
