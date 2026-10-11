"""Canonical Tor search-engine catalog shared by the CLI and API."""

from __future__ import annotations


# Keep engine metadata in one place.  Runtime health, circuit-breaker state,
# and priority are applied by the consumers; this catalog is deliberately
# stateless so both interfaces see the same candidates.
#
# Engine lifecycle `status` (P1.1) — a STATIC, declarative field, distinct from
# the DYNAMIC DB circuit breaker in db/search_engine_stats.py:
#   - "active"      — in the fan-out.
#   - "quarantined" — excluded from the active fan-out, but RETAINED so a P3
#                     freshness re-probe can revive it if it comes back. The
#                     circuit breaker re-tests every 7 days forever; quarantine
#                     is how a permanently-dead engine stops burning a Tor circuit
#                     every cycle without losing the record of it.
#   - "removed"     — tombstone for an engine confirmed defunct that we keep for
#                     provenance instead of deleting outright.
# The fan-out (search.search._search_async) iterates `active` only, before the
# circuit-breaker check. Cull dispositions are traceable to the P1.0 baseline
# artifact via benchmark/engine_cull.py; see search/ENGINE_CULL.md.
#
# darksearch.io was REMOVED here (independently confirmed defunct) rather than
# quarantined — see the ledger.
SEARCH_ENGINES = [
    {"name": "Ahmia (Clearnet Proxy)", "url": "https://ahmia.fi/search/?q={query}", "status": "active"},
    {"name": "Ahmia", "url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}", "status": "active"},
    {"name": "OnionLand", "url": "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}", "status": "active"},
    {"name": "Torgle", "url": "http://iy3544gmoeclh5de6gez2256v6pjh4omhpqdh2wpeeppjtvqmjhkfwad.onion/torgle/?query={query}", "status": "active"},
    {"name": "Amnesia", "url": "http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion/search?query={query}", "status": "active"},
    # quarantined 2026-09-05 — 0% success over 12 probe attempts (timeouts) in the
    # end-stage live-Tor baseline (benchmark/artifacts/INT-B1_probe.json); retained
    # for P3 freshness re-probe. See INT-B2_cull_dispositions.md.
    {"name": "Kaizer", "url": "http://kaizerwfvp5gxu6cppibp7jhcqptavq3iqef66wbxenh6a2fklibdvid.onion/search?q={query}", "status": "quarantined"},
    {"name": "Anima", "url": "http://anima4ffe27xmakwnseih3ic2y7y3l6e7fucwk4oerdn4odf7k74tbid.onion/search?q={query}", "status": "quarantined"},
    {"name": "Tornado", "url": "http://tornadoxn3viscgz647shlysdy7ea5zqzwda7hierekeuokh5eh5b3qd.onion/search?q={query}", "status": "quarantined"},
    {"name": "TorNet", "url": "http://tornetupfu7gcgidt33ftnungxzyfq2pygui5qdoyss34xbgx2qruzid.onion/search?q={query}", "status": "active"},
    {"name": "Torland", "url": "http://torlbmqwtudkorme6prgfpmsnile7ug2zm4u3ejpcncxuhpu4k2j4kyd.onion/index.php?a=search&q={query}", "status": "active"},
    # quarantined 2026-09-05 — 0% success over 12 probe attempts (timeouts) in the
    # end-stage live-Tor baseline (benchmark/artifacts/INT-B1_probe.json). See ledger.
    {"name": "Find Tor", "url": "http://findtorroveq5wdnipkaojfpqulxnkhblymc7aramjzajcvpptd4rjqd.onion/search?q={query}", "status": "quarantined"},
    {"name": "Excavator", "url": "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search?query={query}", "status": "active"},
    {"name": "Onionway", "url": "http://oniwayzz74cv2puhsgx4dpjwieww4wdphsydqvf5q7eyz4myjvyw26ad.onion/search.php?s={query}", "status": "active"},
    {"name": "Tor66", "url": "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}", "status": "active"},
    {"name": "OSS", "url": "http://3fzh7yuupdfyjhwt3ugzqqof6ulbcl27ecev33knxe3u7goi3vfn2qqd.onion/oss/index.php?search={query}", "status": "active"},
    {"name": "Torgol", "url": "http://torgolnpeouim56dykfob6jh5r2ps2j73enc42s2um4ufob3ny4fcdyd.onion/?q={query}", "status": "active"},
    {"name": "The Deep Searches", "url": "http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/search?q={query}", "status": "active"},
]

# Valid lifecycle states for an engine's `status`.
ENGINE_STATUSES = ("active", "quarantined", "removed")


def active_engines() -> list[dict]:
    """Engines in the active fan-out (``status == "active"``). Engines with a
    missing status default to active, so older catalog edits stay safe."""
    return [e for e in SEARCH_ENGINES if e.get("status", "active") == "active"]


DEFAULT_SEARCH_ENGINES = [engine["url"] for engine in active_engines()]
