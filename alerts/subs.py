"""Subscriptions, their filters (versioned), recipients and delivery channels, private RSS tokens, and the match history.

Authorisation is done here, on the server, for every call, with a Principal built from the session. A subscription has an owner and ONE scope:

  PERSONAL           the owner only
  ORGANIZATION       the whole organisation            needs subscriptions.manage_organization (+ the action permission) organisation-wide
  ORGANIZATION_UNIT  one unit (and its sub-units)      needs the action permission inside that unit
  DEVICE_GROUP       one device group                  needs the action permission and device_groups.read in the group's unit
  MSP_CUSTOMER       held by an MSP for one customer   needs an ACTIVE link and the role the customer delegated

Reading follows the same rules; an object the caller may not read is reported as not found.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from . import authz, filters, store, taxonomy, webhook
from .authz import Principal
from .tenancy import Denied, Invalid, NotFound

WRITE_PERMS = ("subscriptions.create", "subscriptions.update", "subscriptions.delete")
FREQUENCIES = ("immediate", "daily", "weekly")
STATES = ("draft", "active", "suspended", "deleted")
MAX_SUBS_PER_USER = 100
MAX_SUBS_PER_ORG = 500
MAX_CHANNELS_PER_USER = 20
MAX_TOKENS_PER_USER = 20
EMAIL_CONFIRM_HOURS = 48


def _name(n: Any) -> str:
    n = (n or "").strip() if isinstance(n, str) else ""
    if not 1 <= len(n) <= 120:
        raise Invalid("the name needs 1 to 120 characters")
    return n


def _notify(frequency: str, kinds: Any, critical_immediate: Any) -> str:
    if frequency not in FREQUENCIES:
        raise Invalid(f"frequency must be one of {FREQUENCIES}")
    from .engine import DEFAULT_NOTIFY
    kinds = DEFAULT_NOTIFY if kinds is None else kinds
    if not isinstance(kinds, list) or not kinds or any(k not in filters.CHANGE_KINDS or k == "other" for k in kinds):
        raise Invalid("notify_on must be a non-empty list of change kinds")
    if not isinstance(critical_immediate, bool):
        raise Invalid("critical_immediate must be true or false")
    return json.dumps({"kinds": sorted(set(kinds)), "critical_immediate": critical_immediate}, sort_keys=True)


# ---- scope and authorisation ------------------------------------------------------------------------------------------------------
def _check_scope(db, p: Principal, perm: str, scope: str, org_id: Optional[str], unit_id: Optional[str], group_id: Optional[str], customer_org_id: Optional[str]) -> Dict[str, Optional[str]]:
    """Validates that the named ids belong together and that the caller holds `perm` for exactly this scope. Returns the normalised ids."""
    if scope not in authz.SCOPES:
        raise Invalid(f"scope must be one of {authz.SCOPES}")
    ids = dict(org_id=org_id, unit_id=unit_id, group_id=group_id, customer_org_id=customer_org_id)
    if scope == "PERSONAL":
        if any(ids.values()):
            raise Invalid("a personal subscription names no organisation")
        if perm not in authz.PERSONAL_PERMS:
            raise Denied(perm)
        return ids
    if not org_id:
        raise Invalid("this scope needs an organisation")
    if not db.execute("SELECT 1 FROM organizations WHERE org_id=? AND state='active'", (org_id,)).fetchone():
        raise Denied(perm)                                            # the same answer whether the organisation exists or not
    if scope == "ORGANIZATION":
        if unit_id or group_id or customer_org_id:
            raise Invalid("an organisation-wide subscription names no unit, group or customer")
        if not (authz.can(p, perm, org_id) and (perm not in WRITE_PERMS or authz.can(p, "subscriptions.manage_organization", org_id))):
            raise Denied(perm)
    elif scope == "ORGANIZATION_UNIT":
        if not unit_id or group_id or customer_org_id:
            raise Invalid("a unit subscription names exactly one unit")
        if not db.execute("SELECT 1 FROM org_units WHERE unit_id=? AND org_id=?", (unit_id, org_id)).fetchone():
            raise Denied(perm)
        if not authz.can(p, perm, org_id, unit_id):
            raise Denied(perm)
    elif scope == "DEVICE_GROUP":
        if not group_id or unit_id or customer_org_id:
            raise Invalid("a device-group subscription names exactly one device group")
        g = db.execute("SELECT unit_id FROM device_groups WHERE group_id=? AND org_id=?", (group_id, org_id)).fetchone()
        if g is None or not (authz.can(p, perm, org_id, g["unit_id"]) and authz.can(p, "device_groups.read", org_id, g["unit_id"])):
            raise Denied(perm)
    else:   # MSP_CUSTOMER: org_id is the MSP organisation, customer_org_id the customer
        if not customer_org_id or unit_id or group_id:
            raise Invalid("an MSP subscription names the customer organisation")
        role = authz.is_msp_admin_of(p, org_id, customer_org_id)
        if role is None or not authz.can(p, perm, customer_org_id) or (perm in WRITE_PERMS and not authz.can(p, "subscriptions.manage_organization", customer_org_id)):
            raise Denied(perm)
    return ids


def _row_perm(db, p: Principal, row, perm: str) -> bool:
    if row["scope"] == "PERSONAL":
        return row["owner_user_id"] == p.user_id and perm in authz.PERSONAL_PERMS
    if row["scope"] == "MSP_CUSTOMER" and perm == "subscriptions.read" and any(m.org_id == row["customer_org_id"] and m.role != "msp_administrator" and m.unit_ids is None for m in p.memberships) \
            and authz.can(p, perm, row["customer_org_id"]):
        return True                       # a customer can always see what an MSP subscribed to on its behalf (read only)
    try:
        _check_scope(db, p, perm, row["scope"], row["org_id"], row["unit_id"], row["group_id"], row["customer_org_id"])
    except (Denied, Invalid):
        return False
    return True


def _visible(db, p: Principal, sub_id: str, perm: str = "subscriptions.read"):
    r = db.execute("SELECT * FROM subscriptions WHERE sub_id=? AND state!='deleted'", (sub_id,)).fetchone()
    if r is None or not _row_perm(db, p, r, perm):
        raise NotFound("subscription")
    return r


def _present(db, r) -> Dict[str, Any]:
    f = db.execute("SELECT spec_json, spec_hash, version FROM subscription_filters WHERE sub_id=? ORDER BY version DESC LIMIT 1", (r["sub_id"],)).fetchone()
    n = json.loads(r["notify_on_json"])
    chans = [x["channel_id"] for x in db.execute("SELECT channel_id FROM subscription_recipients WHERE sub_id=?", (r["sub_id"],))]
    return {"sub_id": r["sub_id"], "name": r["name"], "scope": r["scope"], "org_id": r["org_id"], "unit_id": r["unit_id"], "group_id": r["group_id"], "customer_org_id": r["customer_org_id"],
            "owner_user_id": r["owner_user_id"], "state": r["state"], "frequency": r["frequency"], "notify_on": n["kinds"], "critical_immediate": n["critical_immediate"],
            "filter": json.loads(f["spec_json"]), "filter_version": f["version"], "filter_hash": f["spec_hash"], "channel_ids": sorted(chans), "created_utc": r["created_utc"], "updated_utc": r["updated_utc"]}


def _max_seq(db) -> int:
    return db.execute("SELECT COALESCE(MAX(seq),0) m FROM alert_events").fetchone()["m"]


def _spec_hash(spec: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ---- subscriptions ------------------------------------------------------------------------------------------------------------------
def create(db, p: Principal, now: str, *, name: Any, scope: str, spec: Any, org_id: Optional[str] = None, unit_id: Optional[str] = None, group_id: Optional[str] = None,
           customer_org_id: Optional[str] = None, frequency: str = "immediate", notify_on: Any = None, critical_immediate: Any = True, channel_ids: Optional[List[str]] = None,
           state: str = "active") -> Dict[str, Any]:
    ids = _check_scope(db, p, "subscriptions.create", scope, org_id, unit_id, group_id, customer_org_id)
    name = _name(name)
    filters.parse(spec)
    notify = _notify(frequency, notify_on, critical_immediate)
    if state not in ("draft", "active"):
        raise Invalid("a new subscription is a draft or active")
    sid = store.new_id("s")
    with store.tx(db):
        n_user = db.execute("SELECT COUNT(*) n FROM subscriptions WHERE owner_user_id=? AND state!='deleted'", (p.user_id,)).fetchone()["n"]
        if n_user >= MAX_SUBS_PER_USER:
            raise Invalid(f"at most {MAX_SUBS_PER_USER} subscriptions per person")
        if ids["org_id"]:
            if db.execute("SELECT COUNT(*) n FROM subscriptions WHERE org_id=? AND state!='deleted'", (ids["org_id"],)).fetchone()["n"] >= MAX_SUBS_PER_ORG:
                raise Invalid(f"at most {MAX_SUBS_PER_ORG} subscriptions per organisation")
        db.execute("INSERT INTO subscriptions(sub_id, scope, owner_user_id, org_id, unit_id, group_id, customer_org_id, name, state, frequency, notify_on_json, filter_version, created_utc, updated_utc, activated_after_seq) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (sid, scope, p.user_id, ids["org_id"], ids["unit_id"], ids["group_id"], ids["customer_org_id"], name, state, frequency, notify, 1, now, now, _max_seq(db)))
        db.execute("INSERT INTO subscription_filters(sub_id, version, spec_json, spec_hash, created_utc, created_by) VALUES(?,?,?,?,?,?)",
                   (sid, 1, json.dumps(spec, sort_keys=True), _spec_hash(spec), now, p.user_id))
        for cid in channel_ids or []:
            _attach(db, p, sid, cid)
        store.audit(db, now, p.user_id, ids["org_id"] or ids["customer_org_id"], "subscription.create", sid, {"scope": scope, "state": state, "filter_hash": _spec_hash(spec)})
    return get(db, p, sid)


def get(db, p: Principal, sub_id: str) -> Dict[str, Any]:
    return _present(db, _visible(db, p, sub_id))


def list_visible(db, p: Principal) -> List[Dict[str, Any]]:
    """Every non-deleted subscription the caller may read. Candidate rows are narrowed in SQL by the organisations the caller belongs to, and each row is
    then checked again with the full rule (defence in depth)."""
    orgs = sorted(p.orgs() | {c for links in p.msp.values() for c, _r in links})
    q = "SELECT * FROM subscriptions WHERE state!='deleted' AND ((scope='PERSONAL' AND owner_user_id=?)"
    args: List[Any] = [p.user_id]
    if orgs:
        ph = ",".join("?" * len(orgs))
        q += f" OR (scope!='PERSONAL' AND (org_id IN ({ph}) OR customer_org_id IN ({ph})))"
        args += orgs + orgs
    q += ") ORDER BY created_utc DESC, sub_id"
    return [_present(db, r) for r in db.execute(q, args).fetchall() if _row_perm(db, p, r, "subscriptions.read")]


def update(db, p: Principal, sub_id: str, now: str, *, name: Any = None, spec: Any = None, frequency: Optional[str] = None, notify_on: Any = None, critical_immediate: Any = None) -> Dict[str, Any]:
    r = _visible(db, p, sub_id, "subscriptions.update")
    cur = _present(db, r)
    notify = _notify(frequency or cur["frequency"], notify_on if notify_on is not None else cur["notify_on"], cur["critical_immediate"] if critical_immediate is None else critical_immediate)
    nm = _name(name) if name is not None else r["name"]
    with store.tx(db):
        fv = r["filter_version"]
        if spec is not None:
            filters.parse(spec)
            if _spec_hash(spec) != cur["filter_hash"]:
                fv += 1
                db.execute("INSERT INTO subscription_filters(sub_id, version, spec_json, spec_hash, created_utc, created_by) VALUES(?,?,?,?,?,?)", (sub_id, fv, json.dumps(spec, sort_keys=True), _spec_hash(spec), now, p.user_id))
        db.execute("UPDATE subscriptions SET name=?, frequency=?, notify_on_json=?, filter_version=?, updated_utc=? WHERE sub_id=?", (nm, frequency or r["frequency"], notify, fv, now, sub_id))
        store.audit(db, now, p.user_id, r["org_id"] or r["customer_org_id"], "subscription.update", sub_id, {"filter_version": fv})
    return get(db, p, sub_id)


def set_state(db, p: Principal, sub_id: str, state: str, now: str) -> Dict[str, Any]:
    if state not in ("active", "suspended"):
        raise Invalid("state must be active or suspended")
    r = _visible(db, p, sub_id, "subscriptions.update")
    with store.tx(db):
        # reactivation does not replay what happened while it was off
        db.execute("UPDATE subscriptions SET state=?, updated_utc=?, activated_after_seq=? WHERE sub_id=?", (state, now, _max_seq(db) if state == "active" else r["activated_after_seq"], sub_id))
        store.audit(db, now, p.user_id, r["org_id"] or r["customer_org_id"], "subscription." + ("resume" if state == "active" else "suspend"), sub_id, {})
    return get(db, p, sub_id)


def delete(db, p: Principal, sub_id: str, now: str) -> None:
    r = _visible(db, p, sub_id, "subscriptions.delete")
    with store.tx(db):
        db.execute("UPDATE subscriptions SET state='deleted', updated_utc=? WHERE sub_id=?", (now, sub_id))
        db.execute("DELETE FROM subscription_recipients WHERE sub_id=?", (sub_id,))
        db.execute("UPDATE rss_tokens SET revoked_utc=? WHERE sub_id=? AND revoked_utc IS NULL", (now, sub_id))
        store.audit(db, now, p.user_id, r["org_id"] or r["customer_org_id"], "subscription.delete", sub_id, {})


def duplicate(db, p: Principal, sub_id: str, now: str, name: Optional[str] = None) -> Dict[str, Any]:
    cur = get(db, p, sub_id)
    return create(db, p, now, name=name or (cur["name"] + " (copia)")[:120], scope=cur["scope"], spec=cur["filter"], org_id=cur["org_id"], unit_id=cur["unit_id"], group_id=cur["group_id"],
                  customer_org_id=cur["customer_org_id"], frequency=cur["frequency"], notify_on=cur["notify_on"], critical_immediate=cur["critical_immediate"], channel_ids=[], state="draft")


# ---- channels ---------------------------------------------------------------------------------------------------------------------
def server_secret(db) -> bytes:
    r = db.execute("SELECT value FROM meta WHERE key='server_secret'").fetchone()
    if r is None:
        db.execute("INSERT INTO meta(key, value) VALUES('server_secret', ?)", (secrets.token_hex(32),))
        r = db.execute("SELECT value FROM meta WHERE key='server_secret'").fetchone()
    return bytes.fromhex(r["value"])


def unsubscribe_token(db, channel_id: str) -> str:
    return channel_id + "." + hmac.new(server_secret(db), b"unsub|" + channel_id.encode(), hashlib.sha256).hexdigest()[:40]


def unsubscribe(db, token: str, now: str) -> bool:
    try:
        cid, mac = token.rsplit(".", 1)
    except ValueError:
        return False
    if not hmac.compare_digest(unsubscribe_token(db, cid).rsplit(".", 1)[1], mac):
        return False
    r = db.execute("SELECT * FROM notification_channels WHERE channel_id=?", (cid,)).fetchone()
    if r is None:
        return False
    with store.tx(db):
        db.execute("UPDATE notification_channels SET state='unsubscribed', disabled_reason='recipient unsubscribed' WHERE channel_id=?", (cid,))
        store.audit(db, now, None, r["org_id"], "channel.unsubscribe", cid, {})
    return True


def _channel_scope(db, p: Principal, org_id: Optional[str], perm: str) -> None:
    if org_id is None:
        if perm not in authz.PERSONAL_PERMS and perm != "webhooks.manage":
            raise Denied(perm)
        return
    if not authz.can(p, perm, org_id):
        raise Denied(perm)


def add_email_channel(db, p: Principal, address: str, now: str, *, label: Optional[str] = None, locale: str = "es", org_id: Optional[str] = None) -> Dict[str, Any]:
    """Creates a PENDING channel and returns the confirmation token (the caller sends it by e-mail; only its hash is kept). Nothing is sent to an
    address until its owner has followed the link."""
    from .identity import normalise_email
    addr = normalise_email(address)
    if locale not in ("es", "en"):
        raise Invalid("locale must be es or en")
    _channel_scope(db, p, org_id, "notifications.manage")
    token = secrets.token_urlsafe(32)
    cid = store.new_id("c")
    with store.tx(db):
        if db.execute("SELECT COUNT(*) n FROM notification_channels WHERE owner_user_id=? AND state NOT IN ('deleted','unsubscribed')", (p.user_id,)).fetchone()["n"] >= MAX_CHANNELS_PER_USER:
            raise Invalid(f"at most {MAX_CHANNELS_PER_USER} channels per person")
        db.execute("INSERT INTO notification_channels(channel_id, kind, owner_user_id, org_id, label, address, state, confirm_hash, confirm_expires_utc, locale, created_utc) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                   (cid, "email", p.user_id, org_id, (label or addr)[:80], addr, "pending", hashlib.sha256(token.encode()).hexdigest(),
                    store.utc(datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ") + timedelta(hours=EMAIL_CONFIRM_HOURS)), locale, now))
        store.audit(db, now, p.user_id, org_id, "channel.add_email", cid, {})          # never the address: it is personal data
    return {"channel_id": cid, "confirm_token": token, "address": addr}


def confirm_channel(db, token: str, now: str) -> Optional[str]:
    if not isinstance(token, str) or not 20 <= len(token) <= 100:
        return None
    r = db.execute("SELECT * FROM notification_channels WHERE confirm_hash=? AND state='pending'", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
    if r is None or r["confirm_expires_utc"] <= now:
        return None
    with store.tx(db):
        db.execute("UPDATE notification_channels SET state='active', confirmed_utc=?, confirm_hash=NULL WHERE channel_id=?", (now, r["channel_id"]))
        store.audit(db, now, r["owner_user_id"], r["org_id"], "channel.confirm_email", r["channel_id"], {})
    return r["channel_id"]


def add_webhook_channel(db, p: Principal, url: str, now: str, *, label: Optional[str] = None, org_id: Optional[str] = None, resolver=None) -> Dict[str, Any]:
    """Validates the destination (https, public name, every resolved address public) and creates the channel with its first signing key. The secret is
    returned ONCE; it is stored because signing needs it (the database file is 0600; a hosted deployment keeps it in a secret store)."""
    _channel_scope(db, p, org_id, "webhooks.manage")
    kw = {"resolver": resolver} if resolver else {}
    try:
        dest = webhook.validate_destination(url, **kw)
    except webhook.UnsafeDestination as e:
        raise Invalid(f"webhook destination refused: {e}")
    cid, kid, secret = store.new_id("c"), store.new_id("k"), secrets.token_hex(32)
    with store.tx(db):
        if db.execute("SELECT COUNT(*) n FROM notification_channels WHERE owner_user_id=? AND state NOT IN ('deleted','unsubscribed')", (p.user_id,)).fetchone()["n"] >= MAX_CHANNELS_PER_USER:
            raise Invalid(f"at most {MAX_CHANNELS_PER_USER} channels per person")
        db.execute("INSERT INTO notification_channels(channel_id, kind, owner_user_id, org_id, label, address, state, confirmed_utc, created_utc) VALUES(?,?,?,?,?,?,?,?,?)",
                   (cid, "webhook", p.user_id, org_id, (label or dest["host"])[:80], url, "active", now, now))
        db.execute("INSERT INTO webhook_keys(key_id, channel_id, secret, state, created_utc) VALUES(?,?,?,?,?)", (kid, cid, secret, "active", now))
        store.audit(db, now, p.user_id, org_id, "channel.add_webhook", cid, {"host": dest["host"]})
    return {"channel_id": cid, "key_id": kid, "secret": secret, "host": dest["host"]}


def rotate_webhook_key(db, p: Principal, channel_id: str, now: str, overlap_hours: int = 24) -> Dict[str, Any]:
    ch = _own_channel(db, p, channel_id, "webhooks.manage")
    if ch["kind"] != "webhook":
        raise Invalid("not a webhook channel")
    kid, secret = store.new_id("k"), secrets.token_hex(32)
    retire = store.utc(datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ") + timedelta(hours=max(0, min(overlap_hours, 168))))
    with store.tx(db):
        db.execute("UPDATE webhook_keys SET state='retiring', retired_utc=? WHERE channel_id=? AND state='active'", (retire, channel_id))
        db.execute("INSERT INTO webhook_keys(key_id, channel_id, secret, state, created_utc) VALUES(?,?,?,?,?)", (kid, channel_id, secret, "active", now))
        store.audit(db, now, p.user_id, ch["org_id"], "channel.rotate_webhook_key", channel_id, {"key_id": kid, "overlap_until": retire})
    return {"channel_id": channel_id, "key_id": kid, "secret": secret, "previous_key_valid_until": retire}


def active_webhook_secrets(db, channel_id: str, now: str) -> List[str]:
    return [r["secret"] for r in db.execute("SELECT secret FROM webhook_keys WHERE channel_id=? AND (state='active' OR (state='retiring' AND retired_utc>?))", (channel_id, now))]


def _own_channel(db, p: Principal, channel_id: str, perm: str):
    r = db.execute("SELECT * FROM notification_channels WHERE channel_id=? AND state!='deleted'", (channel_id,)).fetchone()
    if r is None:
        raise NotFound("channel")
    if r["org_id"] is None:
        if r["owner_user_id"] != p.user_id:
            raise NotFound("channel")
    elif not authz.can(p, perm, r["org_id"]):
        raise NotFound("channel")
    return r


def list_channels(db, p: Principal) -> List[Dict[str, Any]]:
    out = []
    for r in db.execute("SELECT * FROM notification_channels WHERE state!='deleted' ORDER BY created_utc"):
        if (r["org_id"] is None and r["owner_user_id"] == p.user_id) or (r["org_id"] is not None and authz.can(p, "notifications.manage", r["org_id"])):
            host = None
            if r["kind"] == "webhook":
                host = webhook.check_url_syntax(r["address"])[0] if r["address"].startswith("https") else None
            out.append({"channel_id": r["channel_id"], "kind": r["kind"], "label": r["label"], "state": r["state"], "org_id": r["org_id"], "locale": r["locale"],
                        "address": (re.sub(r"^(.).*(@.*)$", r"\1***\2", r["address"]) if r["kind"] == "email" else host), "disabled_reason": r["disabled_reason"], "confirmed_utc": r["confirmed_utc"]})
    return out


def delete_channel(db, p: Principal, channel_id: str, now: str) -> None:
    ch = _own_channel(db, p, channel_id, "notifications.manage")
    with store.tx(db):
        db.execute("UPDATE notification_channels SET state='deleted', address=NULL, confirm_hash=NULL WHERE channel_id=?", (channel_id,))       # the address is personal data: gone
        db.execute("DELETE FROM subscription_recipients WHERE channel_id=?", (channel_id,))
        db.execute("DELETE FROM webhook_keys WHERE channel_id=?", (channel_id,))
        store.audit(db, now, p.user_id, ch["org_id"], "channel.delete", channel_id, {})


def _attach(db, p: Principal, sub_id: str, channel_id: str) -> None:
    sub = db.execute("SELECT * FROM subscriptions WHERE sub_id=?", (sub_id,)).fetchone()
    ch = _own_channel(db, p, channel_id, "notifications.manage")
    if sub["scope"] == "PERSONAL":
        if ch["org_id"] is not None or ch["owner_user_id"] != p.user_id:
            raise Invalid("a personal subscription can only use your own personal channels")
    else:
        target = sub["customer_org_id"] if sub["scope"] == "MSP_CUSTOMER" else sub["org_id"]
        if ch["org_id"] not in (sub["org_id"], target):
            raise Invalid("an organisational subscription can only use that organisation's channels")
    db.execute("INSERT OR IGNORE INTO subscription_recipients(sub_id, channel_id) VALUES(?,?)", (sub_id, channel_id))


def set_recipients(db, p: Principal, sub_id: str, channel_ids: List[str], now: str) -> Dict[str, Any]:
    r = _visible(db, p, sub_id, "subscriptions.update")
    with store.tx(db):
        db.execute("DELETE FROM subscription_recipients WHERE sub_id=?", (sub_id,))
        for cid in channel_ids:
            _attach(db, p, sub_id, cid)
        store.audit(db, now, p.user_id, r["org_id"] or r["customer_org_id"], "subscription.set_recipients", sub_id, {"count": len(channel_ids)})
    return get(db, p, sub_id)


# ---- private RSS tokens --------------------------------------------------------------------------------------------------------------
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_rss_token(db, p: Principal, now: str, *, label: str, sub_id: Optional[str] = None, org_id: Optional[str] = None, expires_days: Optional[int] = 90) -> Dict[str, Any]:
    """256 random bits (secrets.token_urlsafe(32)); nothing derived from a name or id. Returned ONCE; only its SHA-256 is stored.
    Scope: one subscription, an organisation (needs alerts.read there), or the person's personal subscriptions."""
    label = _name(label)
    if sub_id:
        r = _visible(db, p, sub_id, "subscriptions.read")
        org_id = r["org_id"]
    elif org_id and not authz.can(p, "alerts.read", org_id):
        raise Denied("alerts.read")
    if expires_days is not None and (not isinstance(expires_days, int) or isinstance(expires_days, bool) or not 1 <= expires_days <= 730):
        raise Invalid("expires_days must be 1..730 (or null for no expiry)")
    token, tid = secrets.token_urlsafe(32), store.new_id("t")
    with store.tx(db):
        if db.execute("SELECT COUNT(*) n FROM rss_tokens WHERE owner_user_id=? AND revoked_utc IS NULL", (p.user_id,)).fetchone()["n"] >= MAX_TOKENS_PER_USER:
            raise Invalid(f"at most {MAX_TOKENS_PER_USER} active feed tokens per person")
        exp = store.utc(datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ") + timedelta(days=expires_days)) if expires_days else None
        db.execute("INSERT INTO rss_tokens(token_id, token_hash, owner_user_id, org_id, sub_id, label, created_utc, expires_utc) VALUES(?,?,?,?,?,?,?,?)", (tid, _hash_token(token), p.user_id, org_id, sub_id, label, now, exp))
        store.audit(db, now, p.user_id, org_id, "rss_token.create", tid, {"scope": "subscription" if sub_id else "organization" if org_id else "personal"})     # never the token
    return {"token_id": tid, "token": token, "expires_utc": exp}


def list_rss_tokens(db, p: Principal) -> List[Dict[str, Any]]:
    return [dict(r) for r in db.execute("SELECT token_id, label, org_id, sub_id, created_utc, expires_utc, revoked_utc, last_used_utc, use_count FROM rss_tokens WHERE owner_user_id=? ORDER BY created_utc DESC", (p.user_id,))]


def revoke_rss_token(db, p: Principal, token_id: str, now: str) -> None:
    r = db.execute("SELECT * FROM rss_tokens WHERE token_id=? AND owner_user_id=?", (token_id, p.user_id)).fetchone()
    if r is None:
        raise NotFound("token")
    with store.tx(db):
        db.execute("UPDATE rss_tokens SET revoked_utc=COALESCE(revoked_utc, ?) WHERE token_id=?", (now, token_id))
        store.audit(db, now, p.user_id, r["org_id"], "rss_token.revoke", token_id, {})


def rotate_rss_token(db, p: Principal, token_id: str, now: str, grace_minutes: int = 0) -> Dict[str, Any]:
    r = db.execute("SELECT * FROM rss_tokens WHERE token_id=? AND owner_user_id=? AND revoked_utc IS NULL", (token_id, p.user_id)).fetchone()
    if r is None:
        raise NotFound("token")
    new = create_rss_token(db, p, now, label=r["label"], sub_id=r["sub_id"], org_id=r["org_id"] if not r["sub_id"] else None, expires_days=None)
    old_end = store.utc(datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ") + timedelta(minutes=max(0, min(int(grace_minutes), 1440))))
    with store.tx(db):
        db.execute("UPDATE rss_tokens SET revoked_utc=?, replaced_by=? WHERE token_id=?", (old_end, new["token_id"], token_id))
        if r["expires_utc"]:
            db.execute("UPDATE rss_tokens SET expires_utc=? WHERE token_id=?", (r["expires_utc"], new["token_id"]))
        store.audit(db, now, p.user_id, r["org_id"], "rss_token.rotate", token_id, {"new_token_id": new["token_id"], "grace_minutes": grace_minutes})
    return new


def resolve_rss_token(db, token: str, now: str) -> Optional[Dict[str, Any]]:
    """The token row if the token exists, is not revoked or expired. A 'revoked_utc' in the future is a rotation grace period. Updates last use."""
    if not isinstance(token, str) or not 20 <= len(token) <= 100 or not re.match(r"^[A-Za-z0-9_-]+$", token):
        return None
    r = db.execute("SELECT * FROM rss_tokens WHERE token_hash=?", (_hash_token(token),)).fetchone()
    if r is None or (r["revoked_utc"] and r["revoked_utc"] <= now) or (r["expires_utc"] and r["expires_utc"] <= now):
        return None
    db.execute("UPDATE rss_tokens SET last_used_utc=?, use_count=use_count+1 WHERE token_id=?", (now, r["token_id"]))
    return dict(r)


# ---- matches (the web inbox and the history) -------------------------------------------------------------------------------------------------
def list_matches(db, p: Principal, *, sub_id: Optional[str] = None, limit: int = 50, before: Optional[str] = None, unread_only: bool = False) -> Dict[str, Any]:
    visible = {s["sub_id"]: s for s in list_visible(db, p)}
    if sub_id is not None:
        if sub_id not in visible:
            raise NotFound("subscription")
        ids = [sub_id]
    else:
        ids = sorted(visible)
    if not ids:
        return {"items": [], "next_before": None}
    ph = ",".join("?" * len(ids))
    q = f"SELECT m.*, a.key, a.alert_type FROM alert_matches m JOIN alerts a ON a.alert_id=m.alert_id WHERE m.sub_id IN ({ph})"
    args: List[Any] = list(ids)
    if before:
        q += " AND (m.created_utc < ?)"
        args.append(before)
    if unread_only:
        q += " AND m.read_utc IS NULL"
    q += " ORDER BY m.created_utc DESC, m.match_id DESC LIMIT ?"
    limit = max(1, min(int(limit), 200))
    args.append(limit + 1)
    rows = db.execute(q, args).fetchall()
    items = [{"match_id": r["match_id"], "sub_id": r["sub_id"], "sub_name": visible[r["sub_id"]]["name"], "alert_id": r["alert_id"], "key": r["key"], "kind": r["kind"], "changes": json.loads(r["changes_json"]),
              "record_version": r["record_version"], "reasons": json.loads(r["reasons_json"]), "created_utc": r["created_utc"], "read_utc": r["read_utc"], "acknowledged_utc": r["acknowledged_utc"]} for r in rows[:limit]]
    return {"items": items, "next_before": items[-1]["created_utc"] if len(rows) > limit else None}


def mark_match(db, p: Principal, match_id: str, now: str, *, acknowledge: bool = False) -> None:
    r = db.execute("SELECT sub_id FROM alert_matches WHERE match_id=?", (match_id,)).fetchone()
    if r is None:
        raise NotFound("match")
    _visible(db, p, r["sub_id"], "subscriptions.read")
    db.execute("UPDATE alert_matches SET read_utc=COALESCE(read_utc, ?), acknowledged_utc=CASE WHEN ? THEN COALESCE(acknowledged_utc, ?) ELSE acknowledged_utc END WHERE match_id=?", (now, int(acknowledge), now, match_id))


def delivery_history(db, p: Principal, *, sub_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    visible = {s["sub_id"] for s in list_visible(db, p)}
    if sub_id is not None and sub_id not in visible:
        raise NotFound("subscription")
    ids = [sub_id] if sub_id else sorted(visible)
    if not ids:
        return []
    ph = ",".join("?" * len(ids))
    return [{"delivery_id": r["delivery_id"], "sub_id": r["sub_id"], "channel_id": r["channel_id"], "mode": r["mode"], "state": r["state"], "attempts": r["attempts"], "created_utc": r["created_utc"],
             "sent_utc": r["sent_utc"], "last_error": r["last_error"], "matches": len(json.loads(r["match_ids_json"]))}
            for r in db.execute(f"SELECT * FROM notification_deliveries WHERE sub_id IN ({ph}) ORDER BY created_utc DESC LIMIT ?", ids + [max(1, min(int(limit), 200))])]
