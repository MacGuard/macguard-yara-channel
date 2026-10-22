"""The engine, independent of any frontend:  INGEST -> NORMALISE -> DEDUPLICATE -> VALIDATE -> MATCH -> QUEUE (-> DELIVER, delivery.py) -> AUDIT.

  * ingest: an alert is created the first time any of its identifiers is seen; later observations of the same vulnerability UPDATE it (a new record
    version, never a new alert). An identifier that would join two existing alerts is a conflict: nothing is merged and it is audited.
  * a change is MATERIAL only when it changes what a reader would act on: new alert, exploitation asserted, a new source asserting it, a fix became
    available, the severity band moved, a new source or product was added, a mitigation appeared. Anything else (wording, one more reference) bumps the
    record version and notifies nobody.
  * matching is incremental: only events newer than the last matched one are evaluated, only against active subscriptions, and only on the PUBLISH VIEW
    of the alert (the part that may leave the system). (subscription, alert, record version, kind) is unique, so running it twice sends nothing twice.
"""
from __future__ import annotations
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from intel import registry as reg

from . import filters, model, store, taxonomy

MATERIAL = ("new", "exploitation_added", "exploitation_source_added", "fix_available", "severity_up", "severity_down", "scope_added", "affected_changed", "mitigation_added")
DEFAULT_NOTIFY = ["new", "exploitation_added", "exploitation_source_added", "fix_available", "severity_up"]
IMMEDIATE_LIMIT_PER_HOUR = 20


def _ident_list(content: Dict[str, Any]) -> List[Tuple[str, str]]:
    return [(k, v) for k in ("cve", "euvd", "ghsa") for v in content["ids"].get(k, [])]


def detect_changes(old: Dict[str, Any], new: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    oe, ne = old["exploitation"], new["exploitation"]
    if oe["status"] != "exploited" and ne["status"] == "exploited":
        out.append("exploitation_added")
    elif ne["status"] == "exploited" and set(ne["asserted_by"]) - set(oe["asserted_by"]):
        out.append("exploitation_source_added")
    if old["fix"]["available"] is not True and new["fix"]["available"] is True:
        out.append("fix_available")
    ob, nb = old["severity"]["band"], new["severity"]["band"]
    if ob != nb:
        up = taxonomy.BANDS.index(nb) > taxonomy.BANDS.index(ob)
        out.append("severity_up" if up else "severity_down")
    if set(new["observations"]) - set(old["observations"]):
        out.append("scope_added")
    prod = lambda c: {(a["vendor_slug"], a["product_slug"]) for a in c["affected"]}      # noqa: E731
    if prod(new) - prod(old):
        out.append("affected_changed")
    if new["mitigations"] and not old["mitigations"]:
        out.append("mitigation_added")
    return out


def upsert(db, content: Dict[str, Any], now: str) -> Optional[Dict[str, Any]]:
    """Stores one alert content. Returns the event (dict) or None when nothing changed. Raises ValueError on an identifier conflict."""
    idents = [v for _k, v in _ident_list(content)]
    found = set()
    for i in idents:
        r = db.execute("SELECT alert_id FROM alert_identifiers WHERE identifier=?", (i,)).fetchone()
        if r:
            found.add(r["alert_id"])
    if not found:
        r = db.execute("SELECT alert_id FROM alerts WHERE key=?", (content["key"],)).fetchone()
        if r:
            found.add(r["alert_id"])
    if len(found) > 1:
        store.audit(db, now, None, None, "alert.identifier_conflict", content["key"], {"alerts": sorted(found), "ids": idents})
        raise ValueError(f"identifiers of {content['key']} belong to {len(found)} different alerts: not merged")
    h = model.content_hash(content)
    if not found:
        aid = model.new_alert_id(content)
        db.execute("INSERT INTO alerts(alert_id, key, alert_type, first_ingested_utc, last_changed_utc, record_version, record_hash, content_json) VALUES(?,?,?,?,?,?,?,?)",
                   (aid, content["key"], content["alert_type"], now, now, 1, h, json.dumps(content, sort_keys=True, ensure_ascii=False)))
        db.execute("INSERT INTO alert_versions(alert_id, record_version, record_hash, content_json, at) VALUES(?,?,?,?,?)", (aid, 1, h, json.dumps(content, sort_keys=True, ensure_ascii=False), now))
        for k, v in _ident_list(content):
            db.execute("INSERT OR IGNORE INTO alert_identifiers(identifier, kind, alert_id) VALUES(?,?,?)", (v, k, aid))
        changes, kind, version = ["new"], "new", 1
    else:
        aid = next(iter(found))
        row = db.execute("SELECT * FROM alerts WHERE alert_id=?", (aid,)).fetchone()
        if row["record_hash"] == h:
            return None
        old = json.loads(row["content_json"])
        changes = detect_changes(old, content) or ["other"]
        version = row["record_version"] + 1
        db.execute("UPDATE alerts SET key=?, last_changed_utc=?, record_version=?, record_hash=?, content_json=? WHERE alert_id=?",
                   (content["key"], now, version, h, json.dumps(content, sort_keys=True, ensure_ascii=False), aid))
        db.execute("INSERT INTO alert_versions(alert_id, record_version, record_hash, content_json, at) VALUES(?,?,?,?,?)", (aid, version, h, json.dumps(content, sort_keys=True, ensure_ascii=False), now))
        for k, v in _ident_list(content):
            db.execute("INSERT OR IGNORE INTO alert_identifiers(identifier, kind, alert_id) VALUES(?,?,?)", (v, k, aid))
        kind = "update"
    for src in content["observations"]:
        db.execute("INSERT OR IGNORE INTO alert_sources(alert_id, source_id) VALUES(?,?)", (aid, src))
    material = int(any(c in MATERIAL for c in changes))
    cur = db.execute("INSERT INTO alert_events(alert_id, record_version, kind, changes_json, material, at) VALUES(?,?,?,?,?,?)", (aid, version, kind, json.dumps(changes), material, now))
    return {"seq": cur.lastrowid, "alert_id": aid, "record_version": version, "kind": kind, "changes": changes, "material": bool(material)}


def ingest(db, contents: Iterable[Dict[str, Any]], now: str, source_runs: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Ingests alert contents (already normalised by alerts.model). One transaction per call. Returns counts."""
    t0 = time.perf_counter()
    counts = {"new": 0, "updated_material": 0, "updated_other": 0, "unchanged": 0, "conflicts": 0, "partial_validation": 0, "refused": 0}
    with store.tx(db):
        for run in source_runs or []:
            db.execute("INSERT INTO import_runs(id, source_id, started_utc, retrieved_utc, status, records_in, accepted, rejected, error, manifest_sha256) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (store.new_id("run"), run["source_id"], now, run.get("retrieved_utc"), run.get("status", "ok"), run.get("records_in", 0), run.get("accepted", 0), run.get("rejected", 0),
                        run.get("error"), run.get("manifest_sha256")))
        for c in contents:
            if c["alert_type"] == "vulnerability" and not any(c["ids"].values()):
                counts["refused"] += 1                      # a vulnerability alert needs an identifier: it cannot be deduplicated without one
                continue
            if c["validation"]["state"] != "validated":
                counts["partial_validation"] += 1
            try:
                ev = upsert(db, c, now)
            except ValueError:
                counts["conflicts"] += 1
                continue
            if ev is None:
                counts["unchanged"] += 1
            elif ev["kind"] == "new":
                counts["new"] += 1
            elif ev["material"]:
                counts["updated_material"] += 1
            else:
                counts["updated_other"] += 1
        store.audit(db, now, None, None, "alerts.ingest", None, counts)
        store.metric(db, "ingest.seconds", time.perf_counter() - t0, now)
    return counts


# ---- reading alerts -------------------------------------------------------------------------------------------------------------
def clearance_key(registry: Dict[str, Dict[str, Any]]) -> str:
    """Identifies WHICH sources may be redistributed right now: a cached view is valid only for the clearance it was built under."""
    cleared = sorted(s for s in registry if reg.clearance(registry, [s])[0])
    return hashlib.sha256(",".join(cleared).encode()).hexdigest()[:16]


def view_of(db, alert_id: str, record_version: int, registry: Dict[str, Dict[str, Any]], ck: str) -> Optional[Dict[str, Any]]:
    """The publish view of an alert, from the cache when the same version was already built under the same clearance."""
    r = db.execute("SELECT view_json FROM alert_view_cache WHERE alert_id=? AND record_version=? AND clearance_key=?", (alert_id, record_version, ck)).fetchone()
    if r is not None:
        return json.loads(r["view_json"])
    a = load_alert(db, alert_id)
    v = model.publish_view(a, registry) if a else None
    db.execute("INSERT OR REPLACE INTO alert_view_cache(alert_id, record_version, clearance_key, view_json) VALUES(?,?,?,?)", (alert_id, record_version, ck, json.dumps(v, sort_keys=True, ensure_ascii=False)))
    return v


def warm_views(db, registry: Dict[str, Dict[str, Any]]) -> int:
    """Builds the publish view of every alert that has none cached under the current clearance (after an ingest, a start-up, or an owner decision), so the first
    reader does not pay for it. Returns how many were built."""
    ck = clearance_key(registry)
    todo = db.execute("SELECT a.alert_id, a.record_version FROM alerts a LEFT JOIN alert_view_cache c ON c.alert_id=a.alert_id AND c.record_version=a.record_version AND c.clearance_key=? WHERE c.alert_id IS NULL", (ck,)).fetchall()
    own_tx = not db.in_transaction
    if own_tx:
        db.execute("BEGIN")
    try:
        for r in todo:
            view_of(db, r["alert_id"], r["record_version"], registry, ck)
    finally:
        if own_tx:
            db.execute("COMMIT")
    return len(todo)


def load_alert(db, alert_id: str) -> Optional[Dict[str, Any]]:
    r = db.execute("SELECT * FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
    if r is None:
        return None
    c = json.loads(r["content_json"])
    c.update(alert_id=r["alert_id"], record_version=r["record_version"], record_hash=r["record_hash"], first_ingested_utc=r["first_ingested_utc"], last_changed_utc=r["last_changed_utc"])
    return c


def source_status(db, registry: Dict[str, Dict[str, Any]], now: datetime) -> Dict[str, Dict[str, Any]]:
    """Per source: last successful import, age against the source's limit, failures since. 'stale' sources are excluded from 'currently exploited'."""
    out: Dict[str, Dict[str, Any]] = {}
    for sid, src in sorted(registry.items()):
        if not ({"vulns", "yara"} & set(src.get("families", []))) and sid != "macguard-yara-releases":
            continue
        ok = db.execute("SELECT * FROM import_runs WHERE source_id=? AND status='ok' ORDER BY started_utc DESC LIMIT 1", (sid,)).fetchone()
        bad = db.execute("SELECT COUNT(*) n FROM import_runs WHERE source_id=? AND status!='ok' AND started_utc>?", (sid, ok["started_utc"] if ok else "")).fetchone()["n"]
        limit = src.get("max_snapshot_age_days")
        age_days = None
        state = "never-imported"
        if ok:
            t = ok["retrieved_utc"] or ok["started_utc"]
            age = now - datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=now.tzinfo)
            age_days = round(age.total_seconds() / 86400, 2)
            state = "stale" if (limit is not None and age > timedelta(days=limit)) else "fresh"
        n_alerts = db.execute("SELECT COUNT(*) n FROM alert_sources WHERE source_id=?", (sid,)).fetchone()["n"]
        ok_pub, why = reg.clearance(registry, [sid])
        out[sid] = {"state": state, "last_ok_retrieved_utc": (ok["retrieved_utc"] or ok["started_utc"]) if ok else None, "age_days": age_days, "max_age_days": limit,
                    "failed_runs_since_last_ok": bad, "alerts": n_alerts, "redistributable": ok_pub, "blocking_reasons": why, "region": src.get("region")}
    return out


def stale_sources(status: Dict[str, Dict[str, Any]]) -> List[str]:
    return sorted(s for s, v in status.items() if v["state"] == "stale")


def query(db, registry: Dict[str, Dict[str, Any]], spec: Dict[str, Any], now: datetime, *, limit: int = 50, cursor: Optional[str] = None, stale: Optional[List[str]] = None,
          changes_for: bool = False) -> Dict[str, Any]:
    """Alerts whose PUBLISH VIEW matches the filter, newest change first, with the reasons. Keyset pagination: cursor = 'last_changed|alert_id'."""
    filters.parse(spec)
    limit = max(1, min(int(limit), 200))
    q = "SELECT alert_id, record_version FROM alerts"
    args: List[Any] = []
    if cursor:
        try:
            ts, aid = cursor.split("|", 1)
            datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise ValueError("invalid cursor")
        q += " WHERE (last_changed_utc < ? OR (last_changed_utc = ? AND alert_id < ?))"
        args += [ts, ts, aid]
    q += " ORDER BY last_changed_utc DESC, alert_id DESC"
    items, scanned, nxt = [], 0, None
    ck = clearance_key(registry)
    own_tx = not db.in_transaction
    if own_tx:
        db.execute("BEGIN")                       # one transaction for the cache writes of a cold scan
    try:
        rows = db.execute(q, args).fetchall()
        for r in rows:
            scanned += 1
            v = view_of(db, r["alert_id"], r["record_version"], registry, ck)
            if v is None:
                continue
            changes = None
            if changes_for:
                e = db.execute("SELECT changes_json FROM alert_events WHERE alert_id=? ORDER BY seq DESC LIMIT 1", (v["alert_id"],)).fetchone()
                changes = json.loads(e["changes_json"]) if e else None
            ok, reasons = filters.evaluate(spec, v, filters.Ctx(now, changes, stale))
            if ok:
                if len(items) == limit:
                    nxt = f"{items[-1]['last_changed_utc']}|{items[-1]['alert_id']}"
                    break
                items.append(dict(v, match_reasons=reasons))
    finally:
        if own_tx:
            db.execute("COMMIT")
    return {"items": items, "next_cursor": nxt, "scanned": scanned}
