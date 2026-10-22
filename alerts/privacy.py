"""Export, erasure and retention of personal data.

Personal data in this system: the e-mail address and display name of an account, the addresses of e-mail channels, the webhook URLs, the names people give
their subscriptions, and their delivery history. Erasure removes or anonymises all of it. The audit log keeps ONLY ids and states (never an address,
a token or a secret), so it can stay append-only and hash-chained after an erasure; that is the documented exception to deleting everything.
"""
from __future__ import annotations
import json
from datetime import datetime, timedelta
from typing import Any, Dict

from . import identity, store, subs

RETENTION_DAYS = {"matches": 400, "deliveries": 400, "metrics": 90, "sessions_expired": 0, "import_runs": 400}


def export_user(db, user_id: str) -> Dict[str, Any]:
    u = db.execute("SELECT user_id, email, display_name, locale, created_utc FROM users WHERE user_id=?", (user_id,)).fetchone()
    return {
        "schema": "macguard.user-export/1", "user": dict(u),
        "memberships": [dict(r) for r in db.execute("SELECT org_id, role, unit_id, state, created_utc FROM memberships WHERE user_id=?", (user_id,))],
        "subscriptions": [dict(r) for r in db.execute("SELECT sub_id, scope, org_id, name, state, frequency, created_utc FROM subscriptions WHERE owner_user_id=?", (user_id,))],
        "filters": [dict(r) for r in db.execute("SELECT f.sub_id, f.version, f.spec_json, f.created_utc FROM subscription_filters f JOIN subscriptions s ON s.sub_id=f.sub_id WHERE s.owner_user_id=?", (user_id,))],
        "channels": [dict(r) for r in db.execute("SELECT channel_id, kind, label, address, state, locale, confirmed_utc, created_utc FROM notification_channels WHERE owner_user_id=? AND state!='deleted'", (user_id,))],
        "feed_tokens": [dict(r) for r in db.execute("SELECT token_id, label, org_id, sub_id, created_utc, expires_utc, revoked_utc, last_used_utc, use_count FROM rss_tokens WHERE owner_user_id=?", (user_id,))],
        "matches": [dict(r) for r in db.execute("SELECT m.match_id, m.sub_id, m.alert_id, m.kind, m.created_utc, m.read_utc FROM alert_matches m JOIN subscriptions s ON s.sub_id=m.sub_id WHERE s.owner_user_id=?", (user_id,))],
        "note": "Feed token values and webhook secrets are not stored in readable form and cannot be exported.",
    }


def erase_user(db, user_id: str, now: str) -> None:
    """Right to erasure. Organisations the person owned alone are NOT deleted here: the call is refused until another owner exists (an organisation must not be orphaned silently)."""
    for r in db.execute("SELECT org_id FROM memberships WHERE user_id=? AND role='owner' AND unit_id IS NULL AND state='active'", (user_id,)).fetchall():
        others = db.execute("SELECT COUNT(*) n FROM memberships WHERE org_id=? AND role='owner' AND unit_id IS NULL AND state='active' AND user_id!=?", (r["org_id"], user_id)).fetchone()["n"]
        if not others:
            raise ValueError("you are the only owner of an organisation: transfer ownership or close it first")
    with store.tx(db):
        db.execute("UPDATE subscriptions SET state='deleted', updated_utc=? WHERE owner_user_id=?", (now, user_id))
        db.execute("DELETE FROM subscription_recipients WHERE sub_id IN (SELECT sub_id FROM subscriptions WHERE owner_user_id=?)", (user_id,))
        db.execute("DELETE FROM webhook_keys WHERE channel_id IN (SELECT channel_id FROM notification_channels WHERE owner_user_id=?)", (user_id,))
        db.execute("UPDATE notification_channels SET state='deleted', address=NULL, confirm_hash=NULL, label='deleted' WHERE owner_user_id=?", (user_id,))
        db.execute("UPDATE rss_tokens SET revoked_utc=COALESCE(revoked_utc, ?) WHERE owner_user_id=?", (now, user_id))
        db.execute("UPDATE memberships SET state='removed' WHERE user_id=?", (user_id,))
        db.execute("DELETE FROM credentials WHERE user_id=?", (user_id,))
        identity.revoke_all_sessions(db, user_id)
        db.execute("UPDATE users SET email=?, display_name=NULL, state='deleted' WHERE user_id=?", (f"deleted-{user_id}@erased.invalid", user_id))
        store.audit(db, now, user_id, None, "user.erase", user_id, {})


def purge(db, now: datetime, policy: Dict[str, int] = None) -> Dict[str, int]:
    p = dict(RETENTION_DAYS, **(policy or {}))
    cut = lambda days: store.utc(now - timedelta(days=days))      # noqa: E731
    out = {}
    with store.tx(db):
        db.execute("CREATE TEMP TABLE IF NOT EXISTS old_matches(match_id TEXT PRIMARY KEY)")
        db.execute("DELETE FROM old_matches")
        db.execute("INSERT INTO old_matches SELECT match_id FROM alert_matches WHERE created_utc<? AND match_id NOT IN "
                   "(SELECT dm.match_id FROM delivery_matches dm JOIN notification_deliveries d ON d.delivery_id=dm.delivery_id WHERE d.state IN ('pending','retry','sending'))", (cut(p["matches"]),))
        db.execute("DELETE FROM delivery_matches WHERE match_id IN (SELECT match_id FROM old_matches)")
        out["matches"] = db.execute("DELETE FROM alert_matches WHERE match_id IN (SELECT match_id FROM old_matches)").rowcount
        out["deliveries"] = db.execute("DELETE FROM notification_deliveries WHERE created_utc<? AND state IN ('sent','dead','cancelled') AND delivery_id NOT IN (SELECT delivery_id FROM delivery_matches)", (cut(p["deliveries"]),)).rowcount
        out["metrics"] = db.execute("DELETE FROM metrics WHERE at<?", (cut(p["metrics"]),)).rowcount
        out["sessions"] = db.execute("DELETE FROM sessions WHERE expires_utc<?", (store.utc(now),)).rowcount
        out["import_runs"] = db.execute("DELETE FROM import_runs WHERE started_utc<?", (cut(p["import_runs"]),)).rowcount
        out["revoked_tokens"] = db.execute("DELETE FROM rss_tokens WHERE revoked_utc IS NOT NULL AND revoked_utc<?", (cut(30),)).rowcount
        store.audit(db, store.utc(now), None, None, "retention.purge", None, out)
    return out
