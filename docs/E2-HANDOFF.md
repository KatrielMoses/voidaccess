# E2 multi-user security handoff

Branch: `e2-multiuser-security`, based on `0dd59daad2dfe48ec5843726a672138d28a67d6e` (`main`).

## What changed

E2 makes the self-hosted engine safe for multiple authenticated users while retaining the existing CLI workflow. API object routes resolve ownership before reading or mutating investigations, entities, actor annotations, monitors, and exports. Foreign object IDs return 404. Shared canonical entities retain global identity, while confidence, evidence snippets, source pages, investigation counts, and relationship views are projected from the requesting user's investigation links. Actor notes and aliases are user-owned; monitor definitions and alerts are stored and queried by owner. Database-backed monitors replace API YAML mutation, and legacy YAML watches import idempotently for the first administrator.

The database migration adds roles, per-investigation page and entity-link context, owner IDs, and monitor storage. It promotes the earliest existing user to administrator and assigns legacy actor notes, aliases, and alerts to that user. Existing cross-investigation links are retained; where the old schema cannot establish the rightful owner of shared context, the migration does not invent one. SQLite CLI databases gain the new compatible columns on initialization. Downgrade is intentionally refused because it would lose ownership and private context; take a database backup before upgrading.

Vector queries and counts accept an owner filter. The backfill assigns legacy vector records to the first administrator without changing vector IDs or document content. The authenticated API bypasses the global vector cache where its owner cannot be established. The API also avoids global style comparisons and inferred alias candidates; the CLI keeps those shared historical features. Per-user API limits layer over IP limits. Forwarded IP headers count only across the explicitly trusted proxy hops, and the supplied Uvicorn commands disable automatic proxy-header trust.

Web authentication now uses an HttpOnly session cookie. Server-side API proxies read that cookie and ignore client-provided authorization headers. Logout revokes the token before clearing the cookie. RSS collection can opt into summary-only storage with `VOIDACCESS_RSS_SNIPPET_ONLY=1`. Package metadata and release notes move to 2.1.0, and the security advisory documents affected versions and upgrade steps.

## Validation

The handoff validation used isolated copies and a throwaway PostgreSQL cluster. No production, development, or platform database was used. Results from the final run are recorded here after completion:

- Python suite: 1,782 passed, 5 skipped, with only the pre-existing NVD pacing test failing. The package install test passed separately with network access because isolated build dependencies require DNS.
- Two-user security suite: 57 tests pass on both SQLite and PostgreSQL.
- PostgreSQL upgrade test: one test passes, including a repeat upgrade and idempotent YAML/vector imports.
- Web session tests: 5 pass.
- CLI smoke: baseline and updated versions both completed the same shallow investigation; a recursive JSON and JSONL event shape comparison found no added or removed keys/event types.
- `git diff --check`: clean.

The existing NVD pacing test is the sole known baseline failure. The baseline `main` suite also had an unrelated packaging test failure when it attempted an offline package build; the isolated environment was later provisioned and the package test passed.

## Review notes and remaining limitations

- `CLAUDE.md` requests consultation of `concept.md`, but that file is absent from the repository.
- Route enumeration intentionally leaves only user-scoped API key lookup, administrator-only circuit-breaker reset, and administrator-only seed validation as route-specific cases; see `tests/test_multiuser_security.py` for the rationale and guard coverage.
- The existing TypeScript check reports two errors in untouched `GraphVisualization.tsx` (the `Set` target and `drawLabel` typing). No E2 changes are in that file.
- Chroma was not installed in the isolated environment. Vector ownership/backfill behavior is verified with a collection stub; the optional dependency is called out in the advisory.
- The migration increases the Alembic version-table string width during fresh PostgreSQL bootstrap because the existing baseline revision identifier exceeds PostgreSQL's default 32-character version column.
- Two-user route tests use actual auth tokens and relational fixtures. Unit tests that target handler behavior override ownership explicitly, and the new route-security suite covers the real guards.

## Release and rollout

Review `docs/SECURITY-ADVISORY-2026-10.md` and `docs/self-hosting.md` before deploying. Back up the database, stop the old service, upgrade to 2.1.0, confirm the first existing user is the intended administrator, import legacy monitor YAML, and run the vector-owner backfill if a Chroma collection is present. Configure trusted proxy hops only for infrastructure you control. Users should sign in again after deployment. No push, merge, PyPI upload, or platform change is part of this work.
