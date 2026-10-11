"""
sanitizer/validate.py — schema / structural validation (3.2 step 2).

Rejects malformed / noise artifacts before they reach the shared corpus, by
reusing the existing shape-and-gazetteer machinery
(``extractor.entity_shape`` + ``extractor.gazetteer``) — the same gate the
extraction pipeline's normalizer already uses to drop junk entities. No new
rules are invented here.
"""

from __future__ import annotations


def is_valid_shape(entity_type: str, value: str, context_text: str | None = None) -> bool:
    """True if *(entity_type, value)* is a well-formed, non-noise artifact.

    Delegates to ``extractor.entity_shape.evaluate(...).accept``. For the
    shape-validated name types (threat-actor handle / org / malware / ransomware)
    this rejects bare dictionary words and malformed handles; a gazetteer hit
    short-circuits to accept. For all other types ``evaluate`` accepts by shape
    (their own precise regexes validated them upstream), so this never
    over-rejects IOC types. Also rejects values that read as ordinary prose.
    """
    if not value or not value.strip():
        return False

    from extractor import entity_shape

    # entity_shape.evaluate already folds in gazetteer membership and the
    # common-language / bare-ordinary noise guards for the shape-validated name
    # types, and accepts precise IOC types (validated by their own regexes
    # upstream). Relying on its verdict avoids over-rejecting legitimate IOC
    # values (e.g. an email or IP) that a blanket common-language check would
    # wrongly flag.
    return entity_shape.evaluate(entity_type, value, context_text=context_text).accept
