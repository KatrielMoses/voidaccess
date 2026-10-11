"""
observability — corpus-health surfacing for the single maintainer (P4.4 / CC-5).

One low-ops aggregation (``corpus_health``) over the counters the gate / promote /
read paths already emit — no parallel metrics pipeline, no time-series store, no
Prometheus/Grafana. Surfaced via a protected admin JSON endpoint
(``GET /admin/corpus-health``). Inert (zeros) on a $0/local install with no central
corpus. See ``observability/README.md``.
"""

from observability.corpus_health import corpus_health

__all__ = ["corpus_health"]
