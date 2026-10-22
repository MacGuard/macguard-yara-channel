"""python3 -m alerts <command>: the operator interface of the reference backend.

  ingest    read built vulnerability channels and the YARA release log into the alert store
  match     match new events against subscriptions, build digests, deliver what is due
  status    sources, freshness, counts and measured latencies
  feeds     write the public feeds and the static data of the web explorer
  serve     run the API and the static site on 127.0.0.1
  purge     apply the retention policy

Nothing here talks to the internet except the SMTP relay you configure (default: write .eml files to a directory) and webhooks you registered.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

from intel import registry as reg

from . import api, delivery, engine, mail, matching, model, privacy, rss, server, sources, store, VERSION


def _now(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) if s else datetime.now(timezone.utc)


def _registry(a):
    return reg.load(a.registry) if a.registry else reg.load()


def cmd_ingest(a) -> int:
    registry, now = _registry(a), _now(a.now)
    db = store.connect(a.db)
    contents, runs = [], []
    if a.vuln_channel:
        c, r, merged = sources.vulnerability_contents(a.vuln_channel, registry, now)
        contents += c
        runs += r
        print(f"merged {merged['stats']['records_in']} records into {merged['stats']['entries']} entries, {len(merged['conflicts'])} conflicts")
    if a.yara_log:
        c, r = sources.yara_release_contents(a.yara_log, registry)
        contents += c
        runs += r
    print(json.dumps(engine.ingest(db, contents, store.utc(now), runs), sort_keys=True))
    print(f"views built: {engine.warm_views(db, registry)}")
    return 0


def cmd_match(a) -> int:
    registry, now = _registry(a), _now(a.now)
    db = store.connect(a.db)
    st = engine.source_status(db, registry, now)
    out = {"match": matching.match_pending(db, registry, now, engine.stale_sources(st))}
    out["digests_created"] = matching.build_digests(db, now)
    cfg = delivery.Config(base_url=a.public_url, email_transport=mail.FileTransport(a.outbox) if a.outbox else None)
    out["delivery"] = delivery.run_due(db, registry, now, cfg)
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0


def cmd_status(a) -> int:
    registry, now = _registry(a), _now(a.now)
    db = store.connect(a.db)
    st = engine.source_status(db, registry, now)
    doc = {"alerts": db.execute("SELECT COUNT(*) n FROM alerts").fetchone()["n"], "subscriptions_active": db.execute("SELECT COUNT(*) n FROM subscriptions WHERE state='active'").fetchone()["n"],
           "deliveries": {r["state"]: r["n"] for r in db.execute("SELECT state, COUNT(*) n FROM notification_deliveries GROUP BY state")},
           "sources": sources.source_catalog(registry, st),
           "metrics": {n: store.metric_summary(db, n) for n in ("match.latency_ms.p50", "match.latency_ms.p95", "match.latency_ms.p99", "ingest_to_match.seconds", "ingest_to_notify.seconds", "duplicates_avoided",
                                                              "delivery.failed", "immediate_limit_hit", "ingest.seconds")},
           "audit_chain": store.verify_audit(db)}
    print(json.dumps(doc, indent=1, sort_keys=True))
    return 0


def cmd_feeds(a) -> int:
    from . import sitegen
    registry, now = _registry(a), _now(a.now)
    try:
        n_feeds, n_alerts = sitegen.generate(a.db, registry, a.out, now, a.public_url)
    except sitegen.InvalidFeed as e:
        print(f"INVALID {e}", file=sys.stderr)
        return 1
    print(f"feeds: {n_feeds} files, alerts in snapshot: {n_alerts}")
    return 0


def cmd_serve(a) -> int:
    registry = _registry(a)
    outbox = a.outbox or os.path.join(os.path.dirname(os.path.abspath(a.db)), "outbox")
    app = api.App(a.db, registry, delivery.Config(email_transport=mail.FileTransport(outbox)), site_dir=a.site, public_url=a.public_url, secure_cookies=not a.insecure_cookies,
                  require_mfa_for_org_admin=not a.no_mfa_for_admin)
    if a.host not in ("127.0.0.1", "localhost", "::1") and not a.allow_public_bind:
        print("refusing to bind a non-loopback address without --allow-public-bind (this server has no TLS)", file=sys.stderr)
        return 3
    db = store.connect(a.db)
    print(f"views built at start-up: {engine.warm_views(db, registry)}")
    db.close()
    srv, url = server.serve(app, a.host, a.port)
    print(f"serving {url} (db {a.db}, mail outbox {outbox}); Ctrl-C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("stopped")
    return 0


def cmd_purge(a) -> int:
    print(json.dumps(privacy.purge(store.connect(a.db), _now(a.now)), sort_keys=True))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python3 -m alerts", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"alerts {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, db=True):
        if db:
            sp.add_argument("--db", required=True)
        sp.add_argument("--registry", help="a source registry file (default: config/intel/sources.registry.json)")
        sp.add_argument("--now", help="UTC time YYYY-MM-DDTHH:MM:SSZ (tests and replays)")
    s = sub.add_parser("ingest"); common(s); s.add_argument("--vuln-channel", action="append", default=[]); s.add_argument("--yara-log"); s.set_defaults(fn=cmd_ingest)
    s = sub.add_parser("match"); common(s); s.add_argument("--outbox", help="directory for .eml files (no mail is sent anywhere)"); s.add_argument("--public-url"); s.set_defaults(fn=cmd_match)
    s = sub.add_parser("status"); common(s); s.set_defaults(fn=cmd_status)
    s = sub.add_parser("feeds"); common(s); s.add_argument("--out", required=True, help="the web directory (feeds/ and intelligence/alerts/data/ are written under it)"); s.add_argument("--public-url"); s.set_defaults(fn=cmd_feeds)
    s = sub.add_parser("serve"); common(s); s.add_argument("--site"); s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8080); s.add_argument("--outbox")
    s.add_argument("--public-url"); s.add_argument("--insecure-cookies", action="store_true", help="local development over plain http only"); s.add_argument("--allow-public-bind", action="store_true")
    s.add_argument("--no-mfa-for-admin", action="store_true", help="local development only"); s.set_defaults(fn=cmd_serve)
    s = sub.add_parser("purge"); common(s); s.set_defaults(fn=cmd_purge)
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except (reg.RegistryError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
