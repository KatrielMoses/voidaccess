"""
shared_corpus/consent.py — the private-mode / contribution switch (2.4).

Contribution to the shared corpus is **default-on with a clear opt-out** (the
owner decision that every install feeds the corpus by default). A private-mode
install reads nothing from and writes nothing to the central corpus.

This is the single predicate every shared read/write path consults. It is
deliberately **independent of whether S3 is configured**: an operator can run
privately even with object storage set up, and the snapshot store already
no-ops when unconfigured — this makes the posture explicit and switchable.

The flag is read *live* from ``config`` (which reads the environment), so a test
or a one-shot ``VOIDACCESS_PRIVATE_MODE`` override takes effect without a
re-import.
"""

from __future__ import annotations


def contribution_enabled() -> bool:
    """True when this install may read from / write to the shared corpus.

    False in private mode. Every shared-corpus read/write path (the snapshot
    store now; the P4 write-to-shared / read-from-shared pipeline later) must
    gate on this.
    """
    import config

    return not bool(getattr(config, "PRIVATE_MODE", False))
