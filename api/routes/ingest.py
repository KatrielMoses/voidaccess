"""
api/routes/ingest.py — the P4.3 cross-install ingest HTTP surface.

Two endpoints, mounted only when ``config.INGEST_ENABLED`` (central-service only):

* ``POST /ingest/register`` — self-register (no manual approval) → ``{key_id,
  secret}``. Soft anti-key-farming friction: a per-IP new-key rate cap.
* ``POST /ingest/observations`` — authenticated (``X-Ingest-Key-Id`` +
  ``X-Ingest-Secret``) artifact submission. No unauthenticated writes. Every
  artifact flows through the ONE write path — ``ingest.service.promote_ingest`` →
  P4.1 ``promote_entities`` → the P4.0 gate. Submitter ``feed_hits`` are discarded
  and re-derived server-side; corroboration is keyed on origin and gated by the
  contributing key's reputation (the Sybil defense).

Auth is fail-closed: a globally-paused or unreadable control store, an unknown /
revoked key, or a bad secret all reject. Per-key rate limits + payload caps (CC-2)
reuse the P2.3 substrate / env-tunable config.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

import config
import ratelimit
from api.rate_limit import rate_limit
from db.session import get_db
from ingest import IngestAuthError, is_paused, register_key, touch_key, verify_key
from ingest.service import promote_ingest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])

# Soft anti-key-farming friction (owner decision: keep low-friction). A per-IP cap
# on new self-registrations — cheap to run, no PoW, tunable.
register_limit = rate_limit(
    config.INGEST_REGISTER_RATE_LIMIT,
    float(config.INGEST_REGISTER_WINDOW_SECONDS),
    scope="ingest_register",
)


class RegisterResponse(BaseModel):
    key_id: str
    secret: str
    note: str = (
        "New keys start at low reputation; contributions stay unconfirmed until the "
        "key earns trust by agreeing with independently-corroborated data."
    )


class IngestArtifactIn(BaseModel):
    entity_type: str = Field(..., min_length=1, max_length=64)
    value: str = Field(..., min_length=1)
    # The onion/host the submitter claims to have observed it on — the
    # corroboration-independence unit (NOT the contributor key).
    origin: Optional[str] = Field(None, max_length=255)
    disposition: Optional[str] = Field(None, max_length=64)
    # Accepted for forward-compat but DISCARDED — feed_hits are re-derived
    # server-side, so a forged value never yields feed_validated.
    feed_hits: Optional[List[str]] = None


class ObservationsRequest(BaseModel):
    artifacts: List[IngestArtifactIn]


class ObservationsResponse(BaseModel):
    considered: int
    promoted: int
    corroborated: int
    feed_validated: int
    quarantined: int
    rejected: int


@router.post("/register", response_model=RegisterResponse)
async def register(
    request: Request,
    db: Session = Depends(get_db),
    _rl: None = Depends(register_limit),
):
    ip = ratelimit.client_key(request)
    key_id, secret = register_key(db, created_ip=ip)
    db.commit()
    logger.info("ingest: new key self-registered from %s", ip)
    return RegisterResponse(key_id=key_id, secret=secret)


async def require_ingest_key(
    request: Request,
    db: Session = Depends(get_db),
    x_ingest_key_id: Optional[str] = Header(default=None),
    x_ingest_secret: Optional[str] = Header(default=None),
) -> str:
    """Authenticate an ingest request — fail-closed. Returns the contributor key_id."""
    # Global kill-switch first — fail-closed (a paused/unreadable store rejects).
    if is_paused(db):
        raise HTTPException(status_code=503, detail="Ingest is currently paused")

    if not x_ingest_key_id or not x_ingest_secret:
        raise HTTPException(status_code=401, detail="Missing ingest credentials")

    try:
        key = verify_key(db, x_ingest_key_id, x_ingest_secret)
    except IngestAuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    # Per-key rate limit — reuse the P2.3 in-process substrate, keyed on the key.
    if not ratelimit.is_rate_limiting_disabled():
        if not ratelimit.default_limiter().allow(
            f"ingest:{key.key_id}",
            config.INGEST_RATE_LIMIT,
            float(config.INGEST_RATE_WINDOW_SECONDS),
        ):
            raise HTTPException(
                status_code=429,
                detail="Ingest rate limit exceeded",
                headers={"Retry-After": str(config.INGEST_RATE_WINDOW_SECONDS)},
            )

    touch_key(db, key.key_id)
    return key.key_id


@router.post("/observations", response_model=ObservationsResponse)
async def ingest_observations(
    request: Request,
    body: ObservationsRequest,
    db: Session = Depends(get_db),
    key_id: str = Depends(require_ingest_key),
):
    # Payload caps (CC-2) — protect the $0 box.
    if len(body.artifacts) > config.INGEST_MAX_ARTIFACTS_PER_REQUEST:
        raise HTTPException(
            status_code=413,
            detail=f"Too many artifacts (max {config.INGEST_MAX_ARTIFACTS_PER_REQUEST})",
        )
    max_len = config.INGEST_MAX_VALUE_LENGTH
    artifacts: list[dict] = []
    for a in body.artifacts:
        if len(a.value) > max_len:
            raise HTTPException(status_code=422, detail="Artifact value too long")
        artifacts.append(
            {
                "entity_type": a.entity_type,
                "value": a.value,
                "origin": a.origin,
                "disposition": a.disposition,
                # a.feed_hits deliberately dropped — re-derived server-side.
            }
        )

    report = await promote_ingest(db, key_id, artifacts)
    db.commit()
    return ObservationsResponse(
        considered=report.considered,
        promoted=report.promoted,
        corroborated=report.corroborated,
        feed_validated=report.feed_validated,
        quarantined=report.quarantined,
        rejected=report.rejected,
    )
