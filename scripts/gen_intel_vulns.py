#!/usr/bin/env python3
"""Writes one public card per vulnerability from a merged view (`python3 -m intel vulns merge`), but ONLY from the sources the registry clears
(redistribution status allowed / allowed-with-conditions AND owner_confirmed). Data of a source that is not cleared is dropped from the card,
even when another source on the same vulnerability is cleared. With the registry as it is today no source is cleared, so this writes nothing
and the site publishes no card (web/api/v1/vulns.json says so).

usage: gen_intel_vulns.py --merged merged.json --out DIR [--registry config/intel/sources.registry.json]
Standard library only; no network."""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from intel import registry as reg  # noqa: E402
from intel.vulns import ids  # noqa: E402

SCHEMA = "macguard.vuln-card/1"


def card_for(entry, registry):
    cleared = sorted(s for s in entry["sources"] if reg.clearance(registry, [s])[0])
    if not cleared:
        return None
    key = ids.normalise(entry["key"])
    if key is None:
        return None
    expl = {s: entry["exploitation"][s] for s in cleared}
    asserted = sorted(s for s, e in expl.items() if e["asserted"])
    current = sorted(s for s in asserted if not expl[s].get("stale"))
    since = sorted(expl[s]["since"] for s in asserted if expl[s].get("since"))
    return {
        "schema": SCHEMA, "key": key[1], "ids": entry["ids"], "sources": {s: entry["sources"][s] for s in cleared}, "exploitation": expl,
        "exploitation_summary": {"asserted_by": asserted, "asserted_by_current": current, "earliest_since": since[0] if since else None,
                                 "independent_confirmation": "unknown" if len(asserted) > 1 else "not-applicable"},
        "regions": sorted({entry["sources"][s]["region"] for s in cleared if entry["sources"][s].get("region")}),
        "attribution": {s: registry[s]["attribution"] for s in cleared}, "flags": entry["flags"],
        "withheld_sources": len(entry["sources"]) - len(cleared),
        "note": "Severity is not exploitation. Affected and fixed versions are the source's own text; they say nothing about a Linux distribution package.",
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--merged", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--registry", default=reg.DEFAULT_PATH)
    a = ap.parse_args(argv)
    registry = reg.load(a.registry)
    doc = json.load(open(a.merged, encoding="utf-8"))
    cards, skipped = [], 0
    for e in doc["entries"]:
        c = card_for(e, registry)
        if c is None:
            skipped += 1
        else:
            cards.append(c)
    os.makedirs(a.out, exist_ok=True)
    for c in cards:
        with open(os.path.join(a.out, c["key"] + ".json"), "w", encoding="utf-8") as f:
            f.write(json.dumps(c, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    with open(os.path.join(a.out, "index.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"schema": "macguard.vuln-card-index/1", "cards": sorted(c["key"] for c in cards), "skipped_not_cleared": skipped}, indent=2, sort_keys=True) + "\n")
    print(f"gen_intel_vulns: {len(cards)} cards written, {skipped} entries skipped (no cleared source)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
