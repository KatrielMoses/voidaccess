# Auth Module

JWT authentication and token blacklist for VoidAccess API.

## Components

- `token_blacklist.py` — token revocation for logout and account disable.
  Backends: **Redis** (opt-in) or the **database** (zero-Redis, P2.3).

## Usage

```python
from auth.token_blacklist import revoke_token, is_token_revoked
from api.auth import get_current_user, CurrentUser
```

## Configuration & backend selection (P2.3)

The blacklist works **with zero Redis** — the service boots and enforces
revocation on a single box with only a database. The backend is chosen at call
time:

- **`REDIS_URL` nonempty** → Redis backend (see availability behaviour below).
- **`REDIS_URL` blank or unset, `DATABASE_URL` set** → **DB backend**: a revoked `jti`
  is stored in the `revoked_tokens` table with its natural expiry and checked on
  each request. Revocation works with no Redis. The `redis` Python package is
  imported lazily (only when `REDIS_URL` is set), so the module boots on a host
  without it.
- **Neither set** → blacklist disabled (fail-open by design); tokens remain
  valid until natural expiry.

There is **no 503-because-Redis-absent**: with only `DATABASE_URL`, auth serves
and revokes normally.

## Behaviour on store availability (deliberate design decision)

- **Redis backend, Redis unreachable** — revocation was explicitly opted into,
  so it is a required control and the API **fails closed**: `is_token_revoked()`
  raises `BlacklistUnavailableError` and `get_current_user` returns
  `503 Service Unavailable`, rather than silently accepting a possibly-revoked
  token. Enforcement resumes automatically once Redis recovers.

- **DB backend, DB error** — fails closed in the same way: `is_token_revoked()`
  raises `BlacklistUnavailableError` and authentication returns `503` until the
  database revocation store is available again.

- **No store configured** — disabled by design (tokens valid until expiry).

Both configured backends preserve revocation enforcement during an outage.
The DB backend allows a deployment without a separate Redis service.
