"""
shared_corpus/consent.py — the private-mode / contribution switch (2.4).

Contribution to the shared corpus is opt-in. A private-mode install reads
nothing from and writes nothing to the central corpus. Search, enrichment,
hosted LLM requests, and local investigation storage are separate operations.

This is the single predicate every shared read/write path consults. It is
deliberately **independent of whether S3 is configured**: an operator can run
privately even with object storage set up, and the snapshot store already
no-ops when unconfigured — this makes the posture explicit and switchable.

The predicate reads the current value of ``config.PRIVATE_MODE``. Configure
``VOIDACCESS_PRIVATE_MODE`` before importing the application.
"""

from __future__ import annotations


def contribution_enabled() -> bool:
    """True when this install may read from / write to the shared corpus.

    False in private mode. Every shared-corpus read/write path (the snapshot
    store now; the P4 write-to-shared / read-from-shared pipeline later) must
    gate on this.
    """
    import config

    return not bool(getattr(config, "PRIVATE_MODE", True))
