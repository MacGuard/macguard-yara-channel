"""python3 -m intel ...   (mgctl calls this; it can be used on its own)

  ioc build     --source ID:FILE[:FORMAT[:COLUMN]] ... --out DIR --version N [--previous MANIFEST] [--now ISO] [--registry FILE] [--allowlist FILE]
  catalog build --channel MANIFEST ... --version N --out DIR [--legacy-yara MANIFEST,RELEASE_JSON[,BUNDLE]] [--include-draft]
  catalog verify CATALOG --root DIR [--bundle F --identity ID --issuer URL | --key PUB --signature SIG] [--allow-draft] [--json]
  registry list [--registry FILE]
  channels [--json]                     honest status of every channel family
  live SOURCE --out ROOT --version N    download a wired real source (abusech-feodo, cisa-kev), keep the original, validate, build the channel (never publishes)
  provenance file PATH [--json] [--redact] [--follow-symlinks] [--out FILE]   per-file provenance, read-only and offline
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from datetime import datetime, timezone

from . import VERSION, catalog, channel, ioc, live, registry as reg, status
from .canonical import canonical_bytes


def _now(s):
    return ioc.parse_time(s) if s else datetime.now(timezone.utc).replace(microsecond=0)


def cmd_ioc_build(a) -> int:
    registry = reg.load(a.registry)
    allow = json.load(open(a.allowlist)) if a.allowlist else None
    now = _now(a.now)
    items, source_ids = [], []
    for spec in a.source:
        parts = spec.split(":")
        sid, path = parts[0], parts[1] if len(parts) > 1 else ""
        fmt = parts[2] if len(parts) > 2 else "plain"
        col = parts[3] if len(parts) > 3 else "value"
        if sid not in registry:
            print(f"error: source '{sid}' is not in the registry", file=sys.stderr)
            return 3
        reader = {"plain": lambda: ioc.read_plain(path), "csv": lambda: ioc.read_csv(path, col, None), "jsonl": lambda: ioc.read_jsonl(path)}.get(fmt)
        if reader is None:
            print(f"error: format '{fmt}' is not one of plain, csv, jsonl", file=sys.stderr)
            return 3
        source_ids.append(sid)
        items.extend((sid, it) for it in reader())
    records, report = ioc.build(items, registry, now, allow)
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    by = {}
    for r in records:
        by.setdefault(r["type"], []).append(r)
    for t, rs in by.items():
        with open(os.path.join(out, f"ioc-{t}.jsonl"), "wb") as f:
            for r in rs:
                f.write(canonical_bytes(r) + b"\n")
    with open(os.path.join(out, "build-report.json"), "wb") as f:
        f.write(canonical_bytes(report) + b"\n")
    previous = json.load(open(a.previous)) if a.previous else None
    m = channel.build_manifest("ioc", "ioc", a.version, out, source_ids, registry, ioc.iso(now), previous=previous, stats=report, approval_state=a.state)
    channel.write_manifest(m, out)
    print(json.dumps({"out": out, "published_indicators": report["published"], "dropped": report["dropped"], "expired": report["expired"],
                      "publishable": m["approval"]["publishable"], "blocking_reasons": m["approval"]["blocking_reasons"], "state": m["approval"]["state"]}, indent=2, sort_keys=True))
    return 0


def cmd_catalog_build(a) -> int:
    refs = []
    for p in a.channel:
        r = catalog.channel_ref(p)
        r["manifest"]["path"] = os.path.relpath(p, a.rel_to) if a.rel_to else p
        refs.append(r)
    if a.legacy_yara:
        parts = a.legacy_yara.split(",")
        refs.append(catalog.legacy_yara_ref(parts[0], parts[1], parts[2] if len(parts) > 2 else None))
    prev = json.load(open(a.previous)) if a.previous else None
    doc = catalog.build_catalog(a.version, ioc.iso(_now(a.now)), refs, previous=prev, include_draft=a.include_draft)
    print(catalog.write_catalog(doc, a.out))
    return 0


def cmd_catalog_verify(a) -> int:
    res = verify_catalog_cli(a)
    if a.json:
        print(json.dumps(res, indent=2, sort_keys=True))
    else:
        for c in res["checks"]:
            print(f"  [{c['status']:^4}] {c['check']}: {c['detail']}")
        print(f"\n{res['result']} (exit {res['exit_code']})")
        if res["exit_code"] == 5:
            print("The files are consistent with the catalog, but nothing proves WHO published them until the signature is checked.")
    return res["exit_code"]


def verify_catalog_cli(a):
    from .verify import verify_catalog
    return verify_catalog(a.catalog, a.root, signature_bundle=a.bundle, key=a.key, signature=a.signature, identity=a.identity, issuer=a.issuer,
                          previous_catalog=a.previous, min_catalog_version=a.min_version, allow_draft=a.allow_draft)


def cmd_registry_list(a) -> int:
    r = reg.load(a.registry)
    for sid, s in sorted(r.items()):
        ok, why = reg.clearance(r, [sid])
        print(f"{sid:<14} {s['redistribution_status']:<24} {'publishable' if ok else 'NOT publishable'}  {s.get('upstream_url', '')}")
    return 0


def cmd_live(a) -> int:
    from .fetch import FetchError
    registry = reg.load(a.registry)
    previous = json.load(open(a.previous)) if a.previous else None
    try:
        res = live.build_live(a.source, os.path.abspath(a.out), a.version, registry, _now(a.now), url=a.url, previous=previous, allow_http_localhost=a.allow_http_localhost)
    except FetchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 4
    print(json.dumps(res, indent=2, sort_keys=True))
    return 0


def _channel_inputs(dirs, registry):
    from .canonical import doc_sha256
    from .vulns import live_eu
    recs, snaps, inputs, sources = [], {}, [], []
    for d in dirs:
        d = os.path.abspath(d)
        m = json.load(open(os.path.join(d, "manifest.json")))
        if m["channel"]["family"] != "vulns":
            raise ValueError(f"{d} is not a vulnerabilities channel")
        sids = [x["id"] for x in m["sources"]]
        sources += sids
        recs += live_eu.load_records(d)
        for sid in sids:
            snaps[sid] = live_eu.snapshot_of(d, sid, registry.get(sid, {}).get("max_snapshot_age_days"))
        inputs.append({"channel": m["channel"]["id"], "version": m["channel"]["version"], "manifest_sha256": doc_sha256(m), "artifacts_root": m["artifacts_root"],
                       "publishable": m["approval"]["publishable"]})
    return recs, snaps, sorted(inputs, key=lambda i: i["channel"]), sorted(set(sources))


def cmd_vulns_build(a) -> int:
    from .fetch import FetchError
    from .vulns import live_eu
    registry = reg.load(a.registry)
    previous = json.load(open(a.previous)) if a.previous else None
    try:
        if a.source in live.SOURCES:
            res = live.build_live(a.source, os.path.abspath(a.out), a.version, registry, _now(a.now), url=a.url, previous=previous, allow_http_localhost=a.allow_http_localhost)
        else:
            res = live_eu.build_eu(a.source, os.path.abspath(a.out), a.version, registry, _now(a.now), base_url=a.url, window_days=a.window_days, max_pages=a.max_pages,
                                   pause=a.pause, previous=previous, allow_http_localhost=a.allow_http_localhost)
    except FetchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 4
    print(json.dumps(res, indent=2, sort_keys=True))
    return 0


def cmd_vulns_merge(a) -> int:
    from .vulns import merge as vmerge
    registry = reg.load(a.registry)
    recs, snaps, inputs, sources = _channel_inputs(a.channel, registry)
    now = _now(a.now)
    merged = vmerge.merge(recs, snaps, now, registry)
    out = os.path.join(os.path.abspath(a.out), "vulns-merged", str(a.version))
    os.makedirs(out)
    with open(os.path.join(out, "merged.json"), "wb") as f:
        f.write(canonical_bytes(merged) + b"\n")
    with open(os.path.join(out, "inputs.json"), "wb") as f:
        f.write(canonical_bytes({"schema": "macguard.vuln-merge-inputs/1", "inputs": inputs, "snapshots": {k: {x: y for x, y in v.items()} for k, v in sorted(snaps.items())}}) + b"\n")
    previous = json.load(open(a.previous)) if a.previous else None
    m = channel.build_manifest("vulns-merged", "vulns", a.version, out, sources, registry, _now(a.now).strftime("%Y-%m-%dT%H:%M:%SZ"), previous=previous, stats=merged["stats"])
    bad = [i["channel"] for i in inputs if not i["publishable"]]
    if bad:
        m["approval"]["publishable"] = False
        m["approval"]["blocking_reasons"].append("input channels that are not publishable: " + ", ".join(bad))
    channel.write_manifest(m, out)
    print(json.dumps({"dir": out, "stats": merged["stats"], "conflicts": len(merged["conflicts"]), "stale_sources": merged["stale_sources"], "publishable": m["approval"]["publishable"],
                      "blocking_reasons": m["approval"]["blocking_reasons"]}, indent=2, sort_keys=True))
    return 0


def cmd_vulns_assess(a) -> int:
    from .vulns import assess
    rows = assess.load_rows(open(a.rows, "rb").read()) if a.rows else []
    res = assess.assess_package(a.cve, a.package, a.installed, a.distro, a.release, rows, a.scheme)
    print(json.dumps(res, indent=2, sort_keys=True))
    return 0 if res["verdict"] in ("PATCHED", "NOT_AFFECTED") else (1 if res["verdict"] == "AFFECTED_UNPATCHED" else 5)


def cmd_vulns_sources(a) -> int:
    from .vulns import live_eu
    registry = reg.load(a.registry)
    wired = set(live.SOURCES) | set(live_eu.SOURCES)
    rows = []
    for sid, src in sorted(registry.items()):
        if "vulns" not in src.get("families", []):
            continue
        ok, why = reg.clearance(registry, [sid])
        rows.append({"id": sid, "region": src.get("region", "unknown"), "redistribution_status": src["redistribution_status"], "owner_confirmed": bool(src.get("owner_confirmed")),
                     "publishable": ok, "adapter": sid in wired, "exploitation_field": src.get("exploitation_field", "unknown"), "blocking_reasons": why})
    if a.json:
        print(json.dumps({"schemaVersion": 1, "sources": rows}, indent=2, sort_keys=True))
    else:
        for r in rows:
            print(f"{r['id']:<22} {r['region']:<7} {r['redistribution_status']:<24} adapter={'yes' if r['adapter'] else 'no':<3} {'publishable' if r['publishable'] else 'NOT publishable'}")
    return 0


def cmd_vulns_lookup(a) -> int:
    from .vulns import ids as vids
    n = vids.normalise(a.id)
    if n is None:
        print("error: not a CVE, EUVD or GHSA identifier", file=sys.stderr)
        return 3
    doc = json.load(open(a.merged))
    hit = [e for e in doc["entries"] if n[1] in e["ids"].get(n[0], [])]
    print(json.dumps({"query": n[1], "found": bool(hit), "entries": hit}, indent=2, sort_keys=True))
    return 0 if hit else 1


def cmd_channels(a) -> int:
    if a.json:
        print(json.dumps({"schemaVersion": 1, "channels": status.CHANNELS}, indent=2, sort_keys=True))
    else:
        for c in status.CHANNELS:
            print(f"{c['id']:<11} {c['status']:<13} {c['detail']}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python3 -m intel", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"intel {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("ioc").add_subparsers(dest="sub", required=True).add_parser("build")
    s.add_argument("--source", action="append", required=True, help="ID:FILE[:plain|csv|jsonl[:COLUMN]]")
    s.add_argument("--out", required=True); s.add_argument("--version", type=int, required=True); s.add_argument("--previous"); s.add_argument("--now")
    s.add_argument("--registry", default=reg.DEFAULT_PATH); s.add_argument("--allowlist"); s.add_argument("--state", default="draft", choices=channel.APPROVAL_STATES)
    s.set_defaults(fn=cmd_ioc_build)
    c = sub.add_parser("catalog").add_subparsers(dest="sub", required=True)
    b = c.add_parser("build")
    b.add_argument("--channel", action="append", default=[]); b.add_argument("--version", type=int, required=True); b.add_argument("--out", required=True)
    b.add_argument("--legacy-yara"); b.add_argument("--previous"); b.add_argument("--now"); b.add_argument("--include-draft", action="store_true"); b.add_argument("--rel-to")
    b.set_defaults(fn=cmd_catalog_build)
    v = c.add_parser("verify")
    v.add_argument("catalog"); v.add_argument("--root", required=True); v.add_argument("--bundle"); v.add_argument("--identity"); v.add_argument("--issuer")
    v.add_argument("--key"); v.add_argument("--signature"); v.add_argument("--previous"); v.add_argument("--min-version", type=int); v.add_argument("--allow-draft", action="store_true")
    v.add_argument("--json", action="store_true"); v.set_defaults(fn=cmd_catalog_verify)
    lv = sub.add_parser("live", help="download a wired real source, keep the original, validate, build the channel")
    lv.add_argument("source", choices=sorted(live.SOURCES)); lv.add_argument("--out", required=True); lv.add_argument("--version", type=int, required=True)
    lv.add_argument("--now"); lv.add_argument("--previous"); lv.add_argument("--registry", default=reg.DEFAULT_PATH)
    lv.add_argument("--url", help="TEST ONLY: replace the upstream URL (HTTPS, or http://127.0.0.1 with --allow-http-localhost)"); lv.add_argument("--allow-http-localhost", action="store_true", help="TEST ONLY")
    lv.set_defaults(fn=cmd_live)
    vl = sub.add_parser("vulns", help="vulnerability sources (CISA, ENISA, CERT-EU): build, merge, assess").add_subparsers(dest="sub", required=True)
    vb = vl.add_parser("build", help="download one source, keep the originals, validate, build its channel")
    vb.add_argument("source", choices=sorted(set(live.SOURCES) | {"enisa-euvd", "enisa-euvd-exploited", "cert-eu-advisories"}))
    vb.add_argument("--out", required=True); vb.add_argument("--version", type=int, required=True); vb.add_argument("--now"); vb.add_argument("--previous"); vb.add_argument("--registry", default=reg.DEFAULT_PATH)
    vb.add_argument("--window-days", type=int, default=3); vb.add_argument("--max-pages", type=int, default=60); vb.add_argument("--pause", type=float, default=1.0)
    vb.add_argument("--url", help="TEST ONLY: replace the upstream base URL"); vb.add_argument("--allow-http-localhost", action="store_true", help="TEST ONLY")
    vb.set_defaults(fn=cmd_vulns_build)
    vm = vl.add_parser("merge", help="merge built channels into one deduplicated view that pins each input version")
    vm.add_argument("--channel", action="append", required=True); vm.add_argument("--out", required=True); vm.add_argument("--version", type=int, required=True)
    vm.add_argument("--now"); vm.add_argument("--previous"); vm.add_argument("--registry", default=reg.DEFAULT_PATH); vm.set_defaults(fn=cmd_vulns_merge)
    va = vl.add_parser("assess", help="is this Linux package affected? answers only from distribution data")
    va.add_argument("cve"); va.add_argument("--package", required=True); va.add_argument("--installed", required=True); va.add_argument("--distro", required=True); va.add_argument("--release", required=True)
    va.add_argument("--rows", help="a macguard.distro-fixes/1 file"); va.add_argument("--scheme", default="dpkg", choices=("dpkg", "rpm")); va.set_defaults(fn=cmd_vulns_assess)
    vs = vl.add_parser("sources", help="vulnerability sources with region, licence status and whether an adapter exists")
    vs.add_argument("--registry", default=reg.DEFAULT_PATH); vs.add_argument("--json", action="store_true"); vs.set_defaults(fn=cmd_vulns_sources)
    vk = vl.add_parser("lookup", help="find a CVE/EUVD/GHSA id in a merged view"); vk.add_argument("id"); vk.add_argument("--merged", required=True); vk.set_defaults(fn=cmd_vulns_lookup)
    ch = sub.add_parser("channels")
    ch.add_argument("--json", action="store_true"); ch.set_defaults(fn=cmd_channels)
    r = sub.add_parser("registry").add_subparsers(dest="sub", required=True).add_parser("list")
    r.add_argument("--registry", default=reg.DEFAULT_PATH); r.set_defaults(fn=cmd_registry_list)
    from .provenance import cli as provenance_cli
    provenance_cli.add_parser(sub)
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except (channel.ChannelError, catalog.CatalogError, reg.RegistryError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
