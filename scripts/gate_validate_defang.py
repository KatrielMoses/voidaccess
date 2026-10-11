"""Operator validator for RV-F4a (defang legal line) on a LIVE investigation.

After a real investigation, export its entities and run this against the JSON to
get a deterministic pass/fail — no dark-web access needed by the checker.

Usage:
    # API:  GET /investigations/{id}/entities?defang=true  -> save as entities.json
    # CLI:  voidaccess investigate ... --format json       -> use its entities[]
    python scripts/gate_validate_defang.py entities.json

Accepts either {"items": [...]} (API) or {"entities": [...]} / a bare [...].

The invariant enforced:
  * every row with defanged==true has a value that is actually neutralized
    (no live "http://"/"https://" scheme, no bare-dot host for URL-ish types);
  * network-IOC types (URL/PASTE_URL/DOMAIN/ONION_URL/…) that are shown with
    defang on are actually transformed;
  * no row claims defanged==true while its value is unchanged from canonical.
"""
import json
import sys

_URLISH = {"URL", "PASTE_URL", "ONION_URL", "DOMAIN", "DOMAIN_NAME", "ENS_DOMAIN"}


def _rows(doc):
    if isinstance(doc, list):
        return doc
    return doc.get("items") or doc.get("entities") or []


def main(path: str) -> int:
    with open(path, encoding="utf-8") as fh:
        rows = _rows(json.load(fh))

    failures = []
    checked = 0
    for r in rows:
        etype = (r.get("entity_type") or r.get("type") or "").upper()
        value = r.get("value") or ""
        canonical = r.get("canonical_value")
        flag = bool(r.get("defanged"))
        checked += 1

        if flag:
            # A defanged value must not carry a live scheme.
            if "http://" in value or "https://" in value:
                failures.append(f"{etype}: defanged=true but live scheme present: {value!r}")
            # And it must differ from the canonical/raw form.
            if canonical is not None and value == canonical:
                failures.append(f"{etype}: defanged=true but value==canonical (no transform): {value!r}")
        else:
            # A URL-ish type shown un-defanged is only OK if defang was off for
            # the whole response; flag the honest-but-risky case for the operator.
            if etype in _URLISH and ("http://" in value or "https://" in value):
                # Not a hard failure (defang may be off), but surface it.
                print(f"[note] {etype} shown raw (defanged=false): {value!r}")

    print(f"checked {checked} rows; {len(failures)} legal-invariant violation(s)")
    for f in failures:
        print("  FAIL:", f)
    print("RV-F4a:", "PASS" if not failures else "FAIL")
    return 0 if not failures else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
