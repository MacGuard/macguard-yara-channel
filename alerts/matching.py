"""Matching and queueing. For every MATERIAL event that nobody has matched yet, evaluate each active subscription against the publish view of the alert;
a match is stored once per (subscription, alert, record version, kind); each stored match is queued for the subscription's confirmed channels.

Delivery modes: 'immediate' (one message per match, rate-limited per subscription) or a digest (one message listing the matches of a window). A
subscription with critical_immediate gets a message at once for a critical alert or for newly asserted exploitation even if its frequency is a digest.
Matches that exceed the hourly immediate limit are not lost: they go into the next digest.
"""
from __future__ import annotations
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from . import engine, filters, model, store

IMMEDIATE_PER_HOUR = engine.IMMEDIATE_LIMIT_PER_HOUR
DIGEST_PERIOD = {"daily": timedelta(days=1), "weekly": timedelta(days=7)}
OVERFLOW_PERIOD = timedelta(hours=1)


def _active_subs(db) -> List[Dict[str, Any]]:
    out = []
    for r in db.execute("SELECT s.*, f.spec_json FROM subscriptions s JOIN subscription_filters f ON f.sub_id=s.sub_id AND f.version=s.filter_version WHERE s.state='active'"):
        n = json.loads(r["notify_on_json"])
        out.append({"sub_id": r["sub_id"], "after": r["activated_after_seq"], "spec": json.loads(r["spec_json"]), "filter_version": r["filter_version"], "kinds": set(n["kinds"]),
                    "critical_immediate": n["critical_immediate"], "frequency": r["frequency"]})
    return out


def _channels(db, sub_id: str) -> List[Dict[str, Any]]:
    return [dict(r) for r in db.execute("SELECT c.* FROM subscription_recipients sr JOIN notification_channels c ON c.channel_id=sr.channel_id WHERE sr.sub_id=? AND c.state='active'", (sub_id,))]


def _is_critical_now(view: Dict[str, Any], changes: List[str]) -> bool:
    return view["severity"]["band"] == "critical" or "exploitation_added" in changes


def match_pending(db, registry: Dict[str, Dict[str, Any]], now: datetime, stale: Optional[List[str]] = None) -> Dict[str, Any]:
    t0 = time.perf_counter()
    row = db.execute("SELECT value FROM meta WHERE key='matched_seq'").fetchone()
    last = int(row["value"]) if row else 0
    events = db.execute("SELECT * FROM alert_events WHERE seq>? ORDER BY seq", (last,)).fetchall()
    subs = _active_subs(db)
    counts = {"events": len(events), "material": 0, "evaluations": 0, "matches": 0, "duplicates_avoided": 0, "not_distributable": 0, "queued": 0}
    lat: List[float] = []
    nowt = store.utc(now)
    for ev in events:
        if not ev["material"]:
            continue
        counts["material"] += 1
        a = engine.load_alert(db, ev["alert_id"])
        view = model.publish_view(a, registry)
        if view is None:
            counts["not_distributable"] += 1
            continue
        changes = json.loads(ev["changes_json"])
        ctx = filters.Ctx(now, changes, stale)
        for s in subs:
            if s["after"] >= ev["seq"] or not (s["kinds"] & set(changes)):
                continue
            t1 = time.perf_counter()
            ok, reasons = filters.evaluate(s["spec"], view, ctx)
            lat.append(time.perf_counter() - t1)
            counts["evaluations"] += 1
            if not ok:
                continue
            mid = store.new_id("mt")
            with store.tx(db):
                cur = db.execute("INSERT OR IGNORE INTO alert_matches(match_id, sub_id, alert_id, event_seq, record_version, filter_version, kind, changes_json, reasons_json, created_utc) VALUES(?,?,?,?,?,?,?,?,?,?)",
                                 (mid, s["sub_id"], ev["alert_id"], ev["seq"], ev["record_version"], s["filter_version"], ev["kind"], json.dumps(changes), json.dumps(reasons, sort_keys=True), nowt))
                if cur.rowcount == 0:
                    counts["duplicates_avoided"] += 1
                    continue
                counts["matches"] += 1
                counts["queued"] += _queue(db, s, mid, view, changes, now)
        store.metric(db, "match.event_seconds", time.perf_counter() - t0, nowt)
    with store.tx(db):
        if events:
            db.execute("INSERT INTO meta(key, value) VALUES('matched_seq', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(events[-1]["seq"]),))
        # lag: how long the newest handled events waited between ingestion and being matched
        for ev in events[-50:]:
            store.metric(db, "ingest_to_match.seconds", max(0.0, (now - datetime.strptime(ev["at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=now.tzinfo)).total_seconds()), nowt)
        if counts["duplicates_avoided"]:
            store.metric(db, "duplicates_avoided", counts["duplicates_avoided"], nowt)
    counts["latency_p50_ms"] = None if not lat else round(store.percentile(lat, 50) * 1000, 4)
    counts["latency_p95_ms"] = None if not lat else round(store.percentile(lat, 95) * 1000, 4)
    counts["latency_p99_ms"] = None if not lat else round(store.percentile(lat, 99) * 1000, 4)
    for q, name in ((50, "match.latency_ms.p50"), (95, "match.latency_ms.p95"), (99, "match.latency_ms.p99")):
        if lat:
            store.metric(db, name, store.percentile(lat, q) * 1000, nowt)
    return counts


def _queue(db, s: Dict[str, Any], match_id: str, view: Dict[str, Any], changes: List[str], now: datetime) -> int:
    n = 0
    immediate = s["frequency"] == "immediate" or (s["critical_immediate"] and _is_critical_now(view, changes))
    for ch in _channels(db, s["sub_id"]):
        if not immediate:
            continue                                     # a digest picks it up
        since = store.utc(now - timedelta(hours=1))
        sent = db.execute("SELECT COUNT(*) n FROM notification_deliveries WHERE sub_id=? AND channel_id=? AND mode='immediate' AND created_utc>?", (s["sub_id"], ch["channel_id"], since)).fetchone()["n"]
        if sent >= IMMEDIATE_PER_HOUR:
            store.metric(db, "immediate_limit_hit", 1, store.utc(now), s["sub_id"])
            continue                                     # stays uncovered: the next digest carries it
        did = store.new_id("d")
        cur = db.execute("INSERT OR IGNORE INTO notification_deliveries(delivery_id, sub_id, channel_id, match_ids_json, mode, state, next_attempt_utc, idempotency_key, created_utc) VALUES(?,?,?,?,?,?,?,?,?)",
                         (did, s["sub_id"], ch["channel_id"], json.dumps([match_id]), "immediate", "pending", store.utc(now), f"imm:{s['sub_id']}:{ch['channel_id']}:{match_id}", store.utc(now)))
        if cur.rowcount:
            db.execute("INSERT INTO delivery_matches(delivery_id, match_id) VALUES(?,?)", (did, match_id))
            n += 1
    return n


def build_digests(db, now: datetime) -> int:
    """Creates digest deliveries for matches no delivery covers yet. daily/weekly subscriptions use their period; an immediate subscription that hit its
    hourly limit gets an hourly 'overflow' digest. One digest per (subscription, channel, window): safe to call repeatedly."""
    made = 0
    nowt = store.utc(now)
    for s in db.execute("SELECT sub_id, frequency FROM subscriptions WHERE state='active'").fetchall():
        period = DIGEST_PERIOD.get(s["frequency"], OVERFLOW_PERIOD)
        window = int(now.timestamp() // period.total_seconds())
        for ch in _channels(db, s["sub_id"]):
            rows = db.execute("SELECT m.match_id FROM alert_matches m WHERE m.sub_id=? AND NOT EXISTS (SELECT 1 FROM delivery_matches dm JOIN notification_deliveries d ON d.delivery_id=dm.delivery_id "
                              "WHERE dm.match_id=m.match_id AND d.channel_id=?) ORDER BY m.created_utc", (s["sub_id"], ch["channel_id"])).fetchall()
            if not rows:
                continue
            last = db.execute("SELECT MAX(created_utc) t FROM notification_deliveries WHERE sub_id=? AND channel_id=? AND mode='digest'", (s["sub_id"], ch["channel_id"])).fetchone()["t"]
            if last and datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=now.tzinfo) + period > now:
                continue
            ids = [r["match_id"] for r in rows][:200]
            did = store.new_id("d")
            with store.tx(db):
                cur = db.execute("INSERT OR IGNORE INTO notification_deliveries(delivery_id, sub_id, channel_id, match_ids_json, mode, state, next_attempt_utc, idempotency_key, created_utc) VALUES(?,?,?,?,?,?,?,?,?)",
                                 (did, s["sub_id"], ch["channel_id"], json.dumps(ids), "digest", "pending", nowt, f"dig:{s['sub_id']}:{ch['channel_id']}:{window}", nowt))
                if cur.rowcount:
                    db.executemany("INSERT INTO delivery_matches(delivery_id, match_id) VALUES(?,?)", [(did, i) for i in ids])
                    made += 1
    return made
