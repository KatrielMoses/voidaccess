"""Measurement foundation (Engineering Requirements P1.0).

This package is the project's *ruler*: a fixed benchmark query set, a metrics
harness that runs that set through the real SQLite pipeline and captures a
diffable artifact, and a read-only live engine health probe (requirement 1.1).

It is measurement-only — nothing here removes an engine (that is P1.1) or changes
extraction/ranking/pipeline behavior. See ``benchmark/README.md``.
"""

__version__ = "1.0.0"
