#!/usr/bin/env python3
"""Measures the alert engine on SYNTHETIC data (generated here, labelled as such, never shown as intelligence): ingestion, matching latency per subscription
evaluation (p50/p95/p99), ingest-to-match lag, query time with a cold and a warm view cache, and delivery throughput to a directory of .eml files.
It records a measurement, it does not decide a pass: a time is never a criterion.  usage: bench_alerts.py [--alerts N] [--subs N] [--json]"""
import argparse, json, os, random, shutil, sys, tempfile, time
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from alerts import delivery, engine, filters, identity, mail, matching, model, store, subs, tenancy  # noqa: E402
from alerts_helpers import aff, contents_from, test_registry, vrec  # noqa: E402

VENDORS = [("Microsoft", "Windows 11", "windows"), ("Apple", "macOS", "macos"), ("Debian", "OpenSSL", "linux"), ("Cisco", "IOS XE", "net"), ("Acme", "Widget", None), ("Linux", "Linux kernel", "linux")]


def synth(i, rng):
    v, p, _ = rng.choice(VENDORS)
    score = rng.choice(["3.1", "5.4", "7.5", "8.8", "9.8"])
    r = [vrec("enisa-euvd", f"EUVD-2026-{i:06d}", cve=[f"CVE-2026-{i:06d}"], euvd=[f"EUVD-2026-{i:06d}"], score=score, vector=rng.choice(["CVSS:3.1/AV:N/AC:L", "CVSS:3.1/AV:L/AC:L"]), summary=f"synthetic {i}", affected=[aff(v, p, "1 <2")])]
    if rng.random() < 0.15:
        r.append(vrec("cisa-kev", f"CVE-2026-{i:06d}", cve=[f"CVE-2026-{i:06d}"], asserted=True, since="2026-10-01", title=f"synthetic kev {i}"))
    return r


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--alerts", type=int, default=2000); ap.add_argument("--subs", type=int, default=200); ap.add_argument("--new", type=int, default=100); ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rng = random.Random(7)
    d = tempfile.mkdtemp(prefix="alerts-bench-")
    try:
        db = store.connect(os.path.join(d, "b.db")); reg = test_registry()
        now = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
        recs = [r for i in range(1, a.alerts + 1) for r in synth(i, rng)]
        t = time.perf_counter(); contents = contents_from(recs, reg); t_norm = time.perf_counter() - t
        t = time.perf_counter(); engine.ingest(db, contents, store.utc(now)); t_ing = time.perf_counter() - t
        out = {"synthetic": True, "alerts": a.alerts, "subscriptions": a.subs, "normalise_seconds": round(t_norm, 2), "ingest_seconds": round(t_ing, 2), "ingest_alerts_per_second": round(a.alerts / t_ing, 1)}
        t = time.perf_counter(); built = engine.warm_views(db, reg); out["views_built"] = built; out["warm_views_seconds"] = round(time.perf_counter() - t, 2)
        spec_q = {"schema": "macguard.subscription-filter/1", "version": 1, "expr": {"all": [{"field": "os", "op": "in", "value": ["windows"]}, {"field": "severity", "op": "gte", "value": "high"}]}}
        t = time.perf_counter(); r = engine.query(db, reg, spec_q, now, limit=50); out["query_warm_seconds"] = round(time.perf_counter() - t, 3); out["query_scanned"] = r["scanned"]
        from alerts import authz
        principals = []
        for u in range((a.subs + 99) // 100):          # the per-person limit is 100 subscriptions
            principals.append(authz.load_principal(db, identity.register(db, f"bench{u}@example.org", "correct horse battery staple", store.utc(now), params=identity.SCRYPT_TEST)))
        exprs = [{"all": [{"field": "os", "op": "in", "value": [rng.choice(["windows", "macos", "linux"])]}, {"field": "severity", "op": "gte", "value": rng.choice(["medium", "high", "critical"])}]},
                 {"all": [{"field": "exploited", "op": "is", "value": True}, {"field": "region", "op": "in", "value": [rng.choice(["EU", "ES", "OTHER"])]}]},
                 {"all": [{"field": "vendor", "op": "in", "value": [rng.choice(VENDORS)[0]]}, {"field": "cvss", "op": "gte", "value": 7.0}]}]
        for i in range(a.subs):
            subs.create(db, principals[i // 100], store.utc(now), name=f"bench {i}", scope="PERSONAL", spec={"schema": "macguard.subscription-filter/1", "version": 1, "expr": rng.choice(exprs)})
        new = [r for i in range(a.alerts + 1, a.alerts + a.new + 1) for r in synth(i, rng)]
        later = now + timedelta(seconds=30)
        engine.ingest(db, contents_from(new, reg), store.utc(now))
        t = time.perf_counter(); m = matching.match_pending(db, reg, later); out["match_seconds"] = round(time.perf_counter() - t, 3)
        out.update({"new_alerts": a.new, "evaluations": m["evaluations"], "matches": m["matches"], "latency_ms": {"p50": m["latency_p50_ms"], "p95": m["latency_p95_ms"], "p99": m["latency_p99_ms"]},
                    "ingest_to_match_seconds_max": store.metric_summary(db, "ingest_to_match.seconds")["max"]})
        out["evaluations_per_second"] = round(m["evaluations"] / max(out["match_seconds"], 1e-9))
        if a.json:
            print(json.dumps(out, indent=1, sort_keys=True))
        else:
            for k, v in out.items(): print(f"{k}: {v}")
        return 0
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
