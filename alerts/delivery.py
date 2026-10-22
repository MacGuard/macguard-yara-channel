"""Delivery worker: takes due deliveries from the queue, renders them for their channel, sends, and records what happened.

States: pending -> sent | retry (with backoff) -> ... -> dead (dead-letter: attempts exhausted or a permanent refusal) | cancelled (nothing left that may be sent).
A delivery is CLAIMED with a conditional update before it is sent, so two workers never send the same one; its idempotency key is unique, and a webhook
receiver gets the same event id on every retry.

What is sent is rebuilt at send time from the PUBLISH VIEW of each alert, so a source that stopped being redistributable since the match is not sent.
"""
from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from . import engine, mail, model, rss, store, subs, webhook

EMAIL_PER_HOUR = 10
EMAIL_PER_DAY = 50
MAX_ITEMS_PER_MESSAGE = 50


@dataclass
class Config:
    base_url: Optional[str] = None
    from_addr: str = "MacGuard alerts <alerts@macguard.invalid>"
    email_transport: Any = None
    webhook_send: Callable = webhook.send
    webhook_kwargs: Dict[str, Any] = field(default_factory=dict)         # tests inject a resolver / TLS context here


def _items(db, registry, match_ids: List[str]) -> List[Dict[str, Any]]:
    out = []
    for mid in match_ids:
        m = db.execute("SELECT * FROM alert_matches WHERE match_id=?", (mid,)).fetchone()
        if m is None:
            continue
        a = engine.load_alert(db, m["alert_id"])
        v = model.publish_view(a, registry) if a else None
        if v is None:
            continue
        out.append({"view": v, "match": {"match_id": mid, "kind": m["kind"], "changes": json.loads(m["changes_json"]), "reasons": json.loads(m["reasons_json"]), "created_utc": m["created_utc"],
                                       "event_seq": m["event_seq"]}})
    return out


def webhook_payload(delivery_id: str, sub: Dict[str, Any], items: List[Dict[str, Any]], now: datetime, test: bool = False) -> bytes:
    def slim(v: Dict[str, Any]) -> Dict[str, Any]:
        return {"alert_id": v["alert_id"], "record_version": v["record_version"], "key": v["key"], "title": v["title"], "alert_type": v["alert_type"], "ids": v["ids"], "severity": v["severity"],
                "exploitation": {"status": v["exploitation"]["status"], "asserted_by": v["exploitation"]["asserted_by"], "earliest_since": v["exploitation"]["earliest_since"]},
                "affected": [{"vendor": a["vendor"], "product": a["product"]} for a in v["affected"][:10]], "references": v["references"][:10], "sources": sorted(v["observations"]),
                "attribution": sorted({s["attribution"] for s in v["license"]["sources"].values() if s.get("attribution")})}
    body = {"id": delivery_id, "type": "test" if test else "alert.match", "created_utc": store.utc(now), "subscription": {"id": sub["sub_id"], "name": sub["name"]},
            "matches": [{"match_id": i["match"]["match_id"], "kind": i["match"]["kind"], "changes": i["match"]["changes"], "reasons": i["match"]["reasons"], "alert": slim(i["view"])} for i in items]}
    return json.dumps(body, sort_keys=True, ensure_ascii=False).encode()


def _fail(db, d, ch, now: datetime, error: str, *, permanent: bool = False) -> str:
    attempts = d["attempts"] + 1
    wait = None if permanent else webhook.backoff_seconds(attempts)
    state = "dead" if wait is None else "retry"
    nxt = store.utc(now + timedelta(seconds=wait)) if wait is not None else None
    db.execute("UPDATE notification_deliveries SET state=?, attempts=?, next_attempt_utc=?, last_error=? WHERE delivery_id=?", (state, attempts, nxt, error[:200], d["delivery_id"]))
    fails = ch["consecutive_failures"] + (1 if state == "dead" or permanent else 0)
    if permanent and ch["kind"] == "email":
        db.execute("UPDATE notification_channels SET state='bounced', disabled_reason=?, consecutive_failures=? WHERE channel_id=?", (error[:100], fails, ch["channel_id"]))
    elif permanent or fails >= webhook.DISABLE_AFTER:
        db.execute("UPDATE notification_channels SET state='disabled', disabled_reason=?, consecutive_failures=? WHERE channel_id=?", ("destination refused or too many failures: " + error[:80], fails, ch["channel_id"]))
        store.audit(db, store.utc(now), None, ch["org_id"], "channel.disabled", ch["channel_id"], {"reason": error[:80]})
    else:
        db.execute("UPDATE notification_channels SET consecutive_failures=? WHERE channel_id=?", (fails, ch["channel_id"]))
    store.metric(db, "delivery.failed", 1, store.utc(now), ch["kind"])
    return state


def run_due(db, registry: Dict[str, Dict[str, Any]], now: datetime, cfg: Config, limit: int = 200) -> Dict[str, int]:
    out = {"sent": 0, "retry": 0, "dead": 0, "cancelled": 0, "deferred": 0}
    nowt = store.utc(now)
    due = db.execute("SELECT * FROM notification_deliveries WHERE state IN ('pending','retry') AND next_attempt_utc<=? ORDER BY next_attempt_utc, created_utc LIMIT ?", (nowt, limit)).fetchall()
    for d in due:
        claimed = db.execute("UPDATE notification_deliveries SET state='sending' WHERE delivery_id=? AND state IN ('pending','retry')", (d["delivery_id"],)).rowcount
        if not claimed:
            continue
        ch = db.execute("SELECT * FROM notification_channels WHERE channel_id=?", (d["channel_id"],)).fetchone()
        sub = db.execute("SELECT * FROM subscriptions WHERE sub_id=?", (d["sub_id"],)).fetchone()
        if ch is None or ch["state"] != "active" or sub is None or sub["state"] not in ("active",):
            db.execute("UPDATE notification_deliveries SET state='cancelled', last_error='channel or subscription is no longer active' WHERE delivery_id=?", (d["delivery_id"],))
            out["cancelled"] += 1
            continue
        items = _items(db, registry, json.loads(d["match_ids_json"]))[:MAX_ITEMS_PER_MESSAGE]
        if not items:
            db.execute("UPDATE notification_deliveries SET state='cancelled', last_error='nothing distributable is left in this delivery' WHERE delivery_id=?", (d["delivery_id"],))
            out["cancelled"] += 1
            continue
        t0 = time.perf_counter()
        if ch["kind"] == "email":
            hour = db.execute("SELECT COUNT(*) n FROM notification_deliveries WHERE channel_id=? AND state='sent' AND sent_utc>?", (ch["channel_id"], store.utc(now - timedelta(hours=1)))).fetchone()["n"]
            day = db.execute("SELECT COUNT(*) n FROM notification_deliveries WHERE channel_id=? AND state='sent' AND sent_utc>?", (ch["channel_id"], store.utc(now - timedelta(days=1)))).fetchone()["n"]
            if hour >= EMAIL_PER_HOUR or day >= EMAIL_PER_DAY:
                db.execute("UPDATE notification_deliveries SET state='pending', next_attempt_utc=? WHERE delivery_id=?", (store.utc(now + timedelta(hours=1)), d["delivery_id"]))
                out["deferred"] += 1
                continue
            msg = mail.render_alerts(ch["address"], cfg.from_addr, ch["locale"], sub["name"], items, d["mode"], d["delivery_id"], cfg.base_url, subs.unsubscribe_token(db, ch["channel_id"]), now)
            kind, detail = (cfg.email_transport.send(msg) if cfg.email_transport else ("temporary", "no mail transport configured"))
            ok, permanent, err = kind == "ok", kind == "permanent", detail
            payload_hash = hashlib.sha256(bytes(msg)).hexdigest()
        elif ch["kind"] == "webhook":
            sub_view = {"sub_id": sub["sub_id"], "name": sub["name"]}
            body = webhook_payload(d["delivery_id"], sub_view, items, now)
            secrets_hex = subs.active_webhook_secrets(db, ch["channel_id"], nowt)
            ts = int(now.timestamp())
            headers = {"X-MacGuard-Signature": webhook.sign(secrets_hex, body, ts), "X-MacGuard-Event-Id": d["delivery_id"], "X-MacGuard-Delivery-Id": d["delivery_id"], "X-MacGuard-Attempt": str(d["attempts"] + 1)}
            res = cfg.webhook_send(ch["address"], body, headers, **cfg.webhook_kwargs)
            ok, permanent, err = res.ok, (res.gone or (res.status is not None and 400 <= res.status < 500 and res.status not in (408, 425, 429))), (res.error or f"HTTP {res.status}")
            payload_hash = hashlib.sha256(body).hexdigest()
        else:
            ok, permanent, err, payload_hash = False, True, f"channel kind {ch['kind']} has no sender", None
        with store.tx(db):
            if ok:
                db.execute("UPDATE notification_deliveries SET state='sent', attempts=attempts+1, sent_utc=?, last_error=NULL, payload_sha256=? WHERE delivery_id=?", (nowt, payload_hash, d["delivery_id"]))
                db.execute("UPDATE notification_channels SET consecutive_failures=0 WHERE channel_id=?", (ch["channel_id"],))
                for it in items:
                    ev = db.execute("SELECT at FROM alert_events WHERE seq=?", (it["match"]["event_seq"],)).fetchone()
                    if ev:
                        store.metric(db, "ingest_to_notify.seconds", max(0.0, (now - datetime.strptime(ev["at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=now.tzinfo)).total_seconds()), nowt, ch["kind"])
                store.metric(db, "delivery.seconds", time.perf_counter() - t0, nowt, ch["kind"])
                out["sent"] += 1
            else:
                st = _fail(db, d, ch, now, err, permanent=permanent)
                out[st] += 1
    return out


def send_test(db, registry, channel_id: str, sub_id: str, now: datetime, cfg: Config) -> Dict[str, Any]:
    """A clearly labelled test to one channel: never counted as a match, never an alert. Uses a synthetic body."""
    ch = db.execute("SELECT * FROM notification_channels WHERE channel_id=? AND state='active'", (channel_id,)).fetchone()
    if ch is None:
        return {"ok": False, "error": "channel is not active"}
    did = store.new_id("d")
    if ch["kind"] == "email":
        msg = mail.build(ch["address"], cfg.from_addr, "[MacGuard] " + ("Prueba" if ch["locale"] == "es" else "Test"), mail.S[ch["locale"]]["test"], lang=ch["locale"], delivery_id=did, now=now)
        kind, detail = cfg.email_transport.send(msg) if cfg.email_transport else ("temporary", "no mail transport configured")
        return {"ok": kind == "ok", "detail": detail}
    body = json.dumps({"id": did, "type": "test", "created_utc": store.utc(now), "message": "MacGuard test event"}).encode()
    secrets_hex = subs.active_webhook_secrets(db, channel_id, store.utc(now))
    res = cfg.webhook_send(ch["address"], body, {"X-MacGuard-Signature": webhook.sign(secrets_hex, body, int(now.timestamp())), "X-MacGuard-Event-Id": did, "X-MacGuard-Delivery-Id": did}, **cfg.webhook_kwargs)
    return {"ok": res.ok, "status": res.status, "error": res.error}
