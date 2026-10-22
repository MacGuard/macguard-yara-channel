"""python3 -m intel ...   (mgctl calls this; it can be used on its own)

  ioc build     --source ID:FILE[:FORMAT[:COLUMN]] ... --out DIR --version N [--previous MANIFEST] [--now ISO] [--registry FILE] [--allowlist FILE]
  catalog build --channel MANIFEST ... --version N --out DIR [--legacy-yara MANIFEST,RELEASE_JSON[,BUNDLE]] [--include-draft]
  catalog verify CATALOG --root DIR [--bundle F --identity ID --issuer URL | --key PUB --signature SIG] [--allow-draft] [--json]
  registry list [--registry FILE]
  channels [--json]                     honest status of every channel family
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from datetime import datetime, timezone

from . import VERSION, catalog, channel, ioc, registry as reg, status
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
    ch = sub.add_parser("channels")
    ch.add_argument("--json", action="store_true"); ch.set_defaults(fn=cmd_channels)
    r = sub.add_parser("registry").add_subparsers(dest="sub", required=True).add_parser("list")
    r.add_argument("--registry", default=reg.DEFAULT_PATH); r.set_defaults(fn=cmd_registry_list)
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except (channel.ChannelError, catalog.CatalogError, reg.RegistryError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
