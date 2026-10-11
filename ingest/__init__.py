"""
ingest — the cross-install ingest API's server-side machinery (P4.3).

Opens the corpus to contributions from any install via low-friction self-registered
keys. Safe only because of the **Sybil defense**: corroboration independence is
keyed on the artifact's ORIGIN (never the ingest key), and a claim counts only once
the CONTRIBUTING KEY has earned reputation — a fresh self-registered key, or a
thousand of them, promotes nothing. ``feed_validated`` is unforgeable because
``feed_hits`` are re-derived server-side.

* ``keys`` — self-registration / fail-closed verification / revocation.
* ``control`` — the authoritative, fail-closed global pause.
* ``service`` — build ``EntityObservation``s and hand them to the ONE write path
  (P4.1 ``promote_entities`` → the P4.0 gate). No second write path.

The HTTP surface (``api/routes/ingest.py``) is mounted only when
``config.INGEST_ENABLED`` — absent/inert on installs not running a central service.
See ``ingest/README.md``.
"""

from ingest.control import is_paused, set_paused
from ingest.keys import (
    IngestAuthError,
    register_key,
    revoke_key,
    touch_key,
    verify_key,
)
from ingest.models import IngestControl, IngestKey, IngestKeyStatus

# NB: ``ingest.service.promote_ingest`` is intentionally NOT imported here. This
# package's models are registered on ``db.models.Base`` via a bottom-of-file
# import in ``db.models``; importing ``service`` (which pulls the trust_gate +
# promote stack) at that point would be a heavy/fragile import cycle. The HTTP
# route imports ``from ingest.service import promote_ingest`` directly instead.

__all__ = [
    "IngestAuthError",
    "IngestControl",
    "IngestKey",
    "IngestKeyStatus",
    "is_paused",
    "register_key",
    "revoke_key",
    "set_paused",
    "touch_key",
    "verify_key",
]
