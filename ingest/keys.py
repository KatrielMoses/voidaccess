"""
ingest/keys.py — self-registration, verification, and revocation of ingest keys.

Low-friction (owner decision): an install self-registers and gets a key with no
manual approval. That is only safe because a fresh key is powerless — it starts at
LOW reputation (seeded here into the shared-tier ``SourceReputation`` store keyed
by ``key_id``), so per the trust gate's contributor-reputation veto its claimed
origins do not count toward corroboration until it has *earned* trust.

Security properties:
* Only a SHA-256 hash of the secret is stored; verification is constant-time.
* Verification is **fail-closed**: a store that can't be read raises
  ``IngestAuthError`` (reject), never a silent pass — the opposite of the
  session-blacklist's fail-open posture (P2.3 constraint).
* Revocation is authoritative: a ``revoked`` key is rejected.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Optional

import sqlalchemy as sa
from sqlalchemy.orm import Session

from ingest.models import IngestKey, IngestKeyStatus

_KEY_ID_BYTES = 16
_SECRET_BYTES = 32


class IngestAuthError(Exception):
    """Raised on any authentication failure — including a fail-closed store error."""


def _hash_secret(secret: str) -> str:
    return hashlib.sha256((secret or "").encode("utf-8")).hexdigest()


def register_key(session: Session, *, created_ip: Optional[str] = None) -> tuple[str, str]:
    """Self-register a new ingest key. Returns ``(key_id, secret)`` — the secret is
    shown once and never stored (only its hash).

    Seeds the contributor's reputation at the LOW starting score so the key cannot
    corroborate anything until it earns trust.
    """
    import config

    key_id = secrets.token_urlsafe(_KEY_ID_BYTES)
    secret = secrets.token_urlsafe(_SECRET_BYTES)
    session.add(
        IngestKey(
            key_id=key_id,
            secret_hash=_hash_secret(secret),
            status=IngestKeyStatus.ACTIVE.value,
            created_at=datetime.now(timezone.utc),
            created_ip=created_ip,
        )
    )
    session.flush()

    # Seed low/neutral contributor reputation (shared-tier store, keyed by key_id).
    from shared_corpus.access import upsert_source_reputation

    upsert_source_reputation(
        session,
        key_id,
        score=float(getattr(config, "TRUST_GATE_CONTRIBUTOR_START_REPUTATION", 0.2)),
        blocked=False,
        contributed=0,
        corroborated=0,
        contradicted=0,
        anomalies=0,
    )
    return key_id, secret


def verify_key(session: Session, key_id: str, secret: str) -> IngestKey:
    """Return the active ``IngestKey`` for *(key_id, secret)*, else raise.

    **Fail-closed**: a store read error raises ``IngestAuthError`` (reject), never a
    pass. Unknown key, revoked status, or a bad secret all raise.
    """
    if not key_id or not secret:
        raise IngestAuthError("missing credentials")
    try:
        row = session.execute(
            sa.select(IngestKey).where(IngestKey.key_id == key_id)
        ).scalar_one_or_none()
    except Exception as exc:  # store unreachable → fail CLOSED
        raise IngestAuthError("ingest key store unreachable") from exc

    if row is None:
        raise IngestAuthError("unknown ingest key")
    if row.status != IngestKeyStatus.ACTIVE.value:
        raise IngestAuthError("ingest key revoked")
    if not hmac.compare_digest(row.secret_hash, _hash_secret(secret)):
        raise IngestAuthError("invalid ingest secret")
    return row


def touch_key(session: Session, key_id: str) -> None:
    """Best-effort ``last_used_at`` update — never fatal."""
    try:
        session.execute(
            sa.update(IngestKey)
            .where(IngestKey.key_id == key_id)
            .values(last_used_at=datetime.now(timezone.utc))
        )
    except Exception:
        pass


def revoke_key(session: Session, key_id: str) -> bool:
    """Revoke *key_id* (authoritative). Returns True if a key was revoked."""
    result = session.execute(
        sa.update(IngestKey)
        .where(IngestKey.key_id == key_id)
        .values(status=IngestKeyStatus.REVOKED.value)
    )
    return bool(result.rowcount)
