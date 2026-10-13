# Multi-user self-hosted security advisory — October 2026

The FastAPI and Next.js self-hosted stack through 2.0.3 is affected when several
users share an installation. Investigation graph and analysis routes lacked
owner checks. Shared entity context, actor annotations, YAML monitor definitions,
and vector search could expose another user's data. Authenticated users could
access administrative operations. Forged forwarding headers could bypass IP
limits, and browser-readable session tokens increased token theft risk. Web
logout did not revoke the backend JWT.

2.1.0 adds resource ownership checks, per-investigation entity and page context,
owned actor annotations and monitors, filtered vector queries, admin roles,
explicit proxy trust, authenticated-user limits, and server-only session cookies
with backend revocation. Foreign resources return 404. CLI and disposable cloud
jobs do not use this shared multi-user API session path.

## Upgrade

1. Stop the API and monitor scheduler. Back up Postgres, the Chroma directory,
   and `data/monitors.yaml` (or `MONITORS_CONFIG_PATH`). Keep the backup private.
2. Install 2.1.0 and rebuild the web UI. Run `alembic upgrade head` against the
   self-hosted database. Revision `0036_multiuser_security` is additive; it does
   not delete investigations, shared entities, pages, annotations, or vectors.
3. Run `python -m scripts.migrate_multiuser` from the installed source checkout.
   This idempotently imports valid YAML monitors and assigns previously unowned
   vector metadata to the first administrator. It requires the optional Chroma
   package when an existing Chroma store is present. Check the reported counts.
4. The lowest existing user ID becomes the first administrator. Additional
   accounts keep the `user` role. Use `voidaccess admin promote --email EMAIL`
   to grant another administrator role; the password-reset script keeps the
   first user as administrator. A fresh install's default seeded account is
   promoted by the same migration.
5. Restart the API and web UI. Have users log out and sign in again. Consider
   rotating `JWT_SECRET` to invalidate sessions issued before this upgrade.
   Review existing webhooks, email/Telegram targets and historical access logs.

Existing actor notes and aliases and historical monitor alerts are assigned to
the first administrator. The original actor notes blob remains intact as an
internal legacy record; API responses use the owned note table. Owners can
annotate an actor visible through their own investigations; administrators can
inspect all actor evidence and annotations.

Entity link rows now hold snippet, confidence, page ID, and extraction method.
Original investigation links recover their stored context. A legacy link to a
shared entity in another user's investigation cannot safely recover a historical
snippet from the last writer's global row; it remains linked, with unknown
context/confidence until re-extraction. Existing shared rows are retained for
administrative recovery. Previously mixed evidence cannot be reconstructed by
this migration; review backups where original attribution matters.

YAML is a read-only, validated import to the first administrator. API edits affect
the database only. Imported names are idempotent, and deleted monitors retain a
private tombstone so restarting cannot resurrect a deleted YAML watch. Names
remain reserved for the owner after deletion. Jobs use database IDs and carry
owner IDs through investigation creation and alert persistence.

New vectors use separate IDs per user/investigation/URL and carry string
`user_id` and `investigation_id` metadata. Unowned legacy metadata is assigned to
the first administrator; missing investigation metadata becomes `legacy`.
API semantic, reference-URL and cross-investigation queries filter by user;
non-admin stats count only that user's vectors. Admin stats are global.

API caches do not reuse the global CLI page cache. Global actor-style comparisons
and globally inferred alias candidates are not exposed through the API: profiles,
notes, infrastructure and persisted owned aliases remain available. This avoids
serving conclusions derived from another user's text. CLI global comparisons
remain available.

The ownership migration has no destructive downgrade. Restore the pre-upgrade
backup if rollback is required. Never restore a multi-user deployment to an
unpatched version while allowing untrusted users to access it.

## Reverse proxies and limits

Run Uvicorn with `--no-proxy-headers` so this application's trust policy sees the
actual socket peer. Both Docker API images now do this. Set
`VOIDACCESS_TRUSTED_PROXIES=0` (default) to ignore forwarding headers. A positive
integer trusts that many right-most hops, including the direct peer. A
comma-separated CIDR list walks trusted addresses from right to left and selects
the right-most untrusted address. Invalid configuration or malformed IP headers
fall back to the direct peer. For example, one controlled proxy uses `1`, or an
explicit proxy network can use `10.20.0.0/24,2001:db8:20::/64`. With hop counts,
ensure clients cannot bypass the proxy or provide a shorter trusted path.

`VOIDACCESS_GLOBAL_RATE_LIMIT` defaults to 120 requests/minute per IP.
`VOIDACCESS_USER_RATE_LIMIT` defaults to 120 authenticated requests/minute per
user, alongside the IP cap. Existing stricter endpoint limits still apply.
`DISABLE_RATE_LIMIT=true` disables both. Limits are per process; use an external
shared ingress limit for deployments running several API workers.

Web JWTs are set only by the server in an httpOnly, SameSite=Lax cookie, Secure
in production. Proxies ignore browser-supplied Authorization headers and read the
cookie server-side. Logout revokes the JWT's `jti` before clearing the cookie;
a failed revoke keeps the cookie for retry. Redis or database revocation outages
fail authentication closed. With no revocation backend configured the library's
legacy disabled behavior remains, but an authenticated API installation requires
a database.
