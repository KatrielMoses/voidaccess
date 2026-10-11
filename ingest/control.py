"""
ingest/control.py — the authoritative, fail-closed global ingest kill-switch.

A single ``IngestControl`` row holds ``paused``. Reads are **fail-closed**: if the
control store can't be read, ``is_paused`` returns ``True`` (ingest refused) — the
opposite of the session-blacklist's fail-open design, per the P2.3 constraint. A
paused (or unreadable) control store must never let a write through.
"""

from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.orm import Session

from ingest.models import IngestControl


def is_paused(session: Session) -> bool:
    """True if ingest is globally paused — or if the control store can't be read.

    Fail-closed: any error reading the control row is treated as *paused*.
    """
    try:
        row = session.execute(
            sa.select(IngestControl).where(IngestControl.id == IngestControl.SINGLETON_ID)
        ).scalar_one_or_none()
    except Exception:
        return True  # unreadable control store → refuse ingest (fail-closed)
    return bool(row and row.paused)


def set_paused(session: Session, paused: bool) -> None:
    """Set the global ingest pause flag (upserts the singleton control row)."""
    now = datetime.now(timezone.utc)
    row = session.execute(
        sa.select(IngestControl).where(IngestControl.id == IngestControl.SINGLETON_ID)
    ).scalar_one_or_none()
    if row is None:
        session.add(IngestControl(id=IngestControl.SINGLETON_ID, paused=paused, updated_at=now))
    else:
        row.paused = paused
        row.updated_at = now
    session.flush()
