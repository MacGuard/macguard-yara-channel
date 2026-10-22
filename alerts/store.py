"""The SQLite store (standard library): schema, connection, and the parts that have no tenant: alerts, versions, events, import runs, metrics and the
hash-chained audit log. Everything that belongs to a person or an organisation is in identity.py, tenancy.py and subs.py and is always reached through
a Principal, never by a bare id.

Times are UTC text 'YYYY-MM-DDTHH:MM:SSZ'. Identifiers of people, organisations, subscriptions and so on are random (never sequential, never derived from a
name). The database file is created with mode 0600. SQLite is the reference implementation: a hosted service would use a server database with
row-level security and the same schema.
"""
from __future__ import annotations
import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from intel.canonical import canonical_bytes

SCHEMA_VERSION = 1

DDL = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY, key TEXT NOT NULL, alert_type TEXT NOT NULL, first_ingested_utc TEXT NOT NULL, last_changed_utc TEXT NOT NULL,
  record_version INTEGER NOT NULL, record_hash TEXT NOT NULL, content_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS alerts_changed ON alerts(last_changed_utc);
CREATE TABLE IF NOT EXISTS alert_identifiers (identifier TEXT PRIMARY KEY, kind TEXT NOT NULL, alert_id TEXT NOT NULL REFERENCES alerts(alert_id));
CREATE TABLE IF NOT EXISTS alert_versions (
  alert_id TEXT NOT NULL REFERENCES alerts(alert_id), record_version INTEGER NOT NULL, record_hash TEXT NOT NULL, content_json TEXT NOT NULL, at TEXT NOT NULL,
  PRIMARY KEY (alert_id, record_version));
CREATE TABLE IF NOT EXISTS alert_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL REFERENCES alerts(alert_id), record_version INTEGER NOT NULL, kind TEXT NOT NULL,
  changes_json TEXT NOT NULL, material INTEGER NOT NULL, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alert_sources (alert_id TEXT NOT NULL REFERENCES alerts(alert_id), source_id TEXT NOT NULL, PRIMARY KEY (alert_id, source_id));
CREATE INDEX IF NOT EXISTS alert_sources_source ON alert_sources(source_id);
CREATE TABLE IF NOT EXISTS alert_view_cache (
  alert_id TEXT NOT NULL REFERENCES alerts(alert_id), record_version INTEGER NOT NULL, clearance_key TEXT NOT NULL, view_json TEXT NOT NULL, PRIMARY KEY (alert_id, record_version, clearance_key));
CREATE TABLE IF NOT EXISTS import_runs (
  id TEXT PRIMARY KEY, source_id TEXT NOT NULL, started_utc TEXT NOT NULL, retrieved_utc TEXT, status TEXT NOT NULL, records_in INTEGER NOT NULL DEFAULT 0,
  accepted INTEGER NOT NULL DEFAULT 0, rejected INTEGER NOT NULL DEFAULT 0, error TEXT, manifest_sha256 TEXT);
CREATE INDEX IF NOT EXISTS import_runs_source ON import_runs(source_id, started_utc);
CREATE TABLE IF NOT EXISTS metrics (name TEXT NOT NULL, at TEXT NOT NULL, value REAL NOT NULL, labels TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS metrics_name ON metrics(name, at);

CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, email_verified INTEGER NOT NULL DEFAULT 0, display_name TEXT, locale TEXT NOT NULL DEFAULT 'es',
  state TEXT NOT NULL DEFAULT 'active', created_utc TEXT NOT NULL, failed_logins INTEGER NOT NULL DEFAULT 0, locked_until_utc TEXT);
CREATE TABLE IF NOT EXISTS credentials (
  user_id TEXT PRIMARY KEY REFERENCES users(user_id), scheme TEXT NOT NULL, salt BLOB NOT NULL, hash BLOB NOT NULL, params TEXT NOT NULL,
  totp_secret TEXT, totp_confirmed INTEGER NOT NULL DEFAULT 0, updated_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  session_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(user_id), csrf TEXT NOT NULL, created_utc TEXT NOT NULL, expires_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL, mfa_verified INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS organizations (
  org_id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'organization', created_by TEXT NOT NULL REFERENCES users(user_id), created_utc TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'active');
CREATE TABLE IF NOT EXISTS org_units (
  unit_id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(org_id), name TEXT NOT NULL, parent_unit_id TEXT REFERENCES org_units(unit_id), created_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS device_groups (
  group_id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(org_id), unit_id TEXT REFERENCES org_units(unit_id), name TEXT NOT NULL, created_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memberships (
  membership_id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(org_id), user_id TEXT NOT NULL REFERENCES users(user_id), role TEXT NOT NULL,
  unit_id TEXT REFERENCES org_units(unit_id), state TEXT NOT NULL DEFAULT 'active', created_utc TEXT NOT NULL, created_by TEXT NOT NULL,
  UNIQUE (org_id, user_id, unit_id));
CREATE INDEX IF NOT EXISTS memberships_user ON memberships(user_id, state);
CREATE TABLE IF NOT EXISTS msp_links (
  link_id TEXT PRIMARY KEY, msp_org_id TEXT NOT NULL REFERENCES organizations(org_id), customer_org_id TEXT NOT NULL REFERENCES organizations(org_id),
  delegated_role TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending', created_utc TEXT NOT NULL, accepted_by TEXT, UNIQUE (msp_org_id, customer_org_id));

CREATE TABLE IF NOT EXISTS subscriptions (
  sub_id TEXT PRIMARY KEY, scope TEXT NOT NULL, owner_user_id TEXT NOT NULL REFERENCES users(user_id), org_id TEXT REFERENCES organizations(org_id),
  unit_id TEXT REFERENCES org_units(unit_id), group_id TEXT REFERENCES device_groups(group_id), customer_org_id TEXT REFERENCES organizations(org_id),
  name TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'active', frequency TEXT NOT NULL DEFAULT 'immediate', notify_on_json TEXT NOT NULL,
  filter_version INTEGER NOT NULL, created_utc TEXT NOT NULL, updated_utc TEXT NOT NULL, activated_after_seq INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS subs_owner ON subscriptions(owner_user_id, state);
CREATE INDEX IF NOT EXISTS subs_org ON subscriptions(org_id, state);
CREATE TABLE IF NOT EXISTS subscription_filters (
  sub_id TEXT NOT NULL REFERENCES subscriptions(sub_id), version INTEGER NOT NULL, spec_json TEXT NOT NULL, spec_hash TEXT NOT NULL, created_utc TEXT NOT NULL, created_by TEXT NOT NULL,
  PRIMARY KEY (sub_id, version));
CREATE TABLE IF NOT EXISTS notification_channels (
  channel_id TEXT PRIMARY KEY, kind TEXT NOT NULL, owner_user_id TEXT NOT NULL REFERENCES users(user_id), org_id TEXT REFERENCES organizations(org_id), label TEXT NOT NULL,
  address TEXT, state TEXT NOT NULL DEFAULT 'pending', confirm_hash TEXT, confirm_expires_utc TEXT, confirmed_utc TEXT, locale TEXT NOT NULL DEFAULT 'es',
  consecutive_failures INTEGER NOT NULL DEFAULT 0, bounces INTEGER NOT NULL DEFAULT 0, disabled_reason TEXT, created_utc TEXT NOT NULL, unsubscribe_hash TEXT);
CREATE INDEX IF NOT EXISTS channels_owner ON notification_channels(owner_user_id, state);
CREATE TABLE IF NOT EXISTS webhook_keys (
  key_id TEXT PRIMARY KEY, channel_id TEXT NOT NULL REFERENCES notification_channels(channel_id), secret TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'active',
  created_utc TEXT NOT NULL, retired_utc TEXT);
CREATE TABLE IF NOT EXISTS subscription_recipients (
  sub_id TEXT NOT NULL REFERENCES subscriptions(sub_id), channel_id TEXT NOT NULL REFERENCES notification_channels(channel_id), PRIMARY KEY (sub_id, channel_id));
CREATE TABLE IF NOT EXISTS rss_tokens (
  token_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, owner_user_id TEXT NOT NULL REFERENCES users(user_id), org_id TEXT REFERENCES organizations(org_id),
  sub_id TEXT REFERENCES subscriptions(sub_id), label TEXT NOT NULL, created_utc TEXT NOT NULL, expires_utc TEXT, revoked_utc TEXT, last_used_utc TEXT,
  use_count INTEGER NOT NULL DEFAULT 0, replaced_by TEXT);

CREATE TABLE IF NOT EXISTS alert_matches (
  match_id TEXT PRIMARY KEY, sub_id TEXT NOT NULL REFERENCES subscriptions(sub_id), alert_id TEXT NOT NULL REFERENCES alerts(alert_id), event_seq INTEGER NOT NULL,
  record_version INTEGER NOT NULL, filter_version INTEGER NOT NULL, kind TEXT NOT NULL, changes_json TEXT NOT NULL, reasons_json TEXT NOT NULL, created_utc TEXT NOT NULL,
  read_utc TEXT, acknowledged_utc TEXT, UNIQUE (sub_id, alert_id, record_version, kind));
CREATE INDEX IF NOT EXISTS matches_sub ON alert_matches(sub_id, created_utc);
CREATE TABLE IF NOT EXISTS notification_deliveries (
  delivery_id TEXT PRIMARY KEY, sub_id TEXT NOT NULL REFERENCES subscriptions(sub_id), channel_id TEXT NOT NULL REFERENCES notification_channels(channel_id),
  match_ids_json TEXT NOT NULL, mode TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_utc TEXT, last_error TEXT,
  idempotency_key TEXT NOT NULL UNIQUE, created_utc TEXT NOT NULL, sent_utc TEXT, payload_sha256 TEXT);
CREATE INDEX IF NOT EXISTS deliveries_due ON notification_deliveries(state, next_attempt_utc);
CREATE TABLE IF NOT EXISTS delivery_matches (
  delivery_id TEXT NOT NULL REFERENCES notification_deliveries(delivery_id), match_id TEXT NOT NULL REFERENCES alert_matches(match_id), PRIMARY KEY (delivery_id, match_id));
CREATE INDEX IF NOT EXISTS delivery_matches_match ON delivery_matches(match_id);

CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor_user_id TEXT, org_id TEXT, action TEXT NOT NULL, target TEXT, detail_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_org ON audit_log(org_id, seq);
"""


def utc(now: Optional[datetime] = None) -> str:
    return (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id(prefix: str) -> str:
    return prefix + "_" + secrets.token_hex(10)


def connect(path: str) -> sqlite3.Connection:
    fresh = path != ":memory:" and not os.path.exists(path)
    if fresh:
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
    db = sqlite3.connect(path, timeout=15, isolation_level=None, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    if path != ":memory:":
        db.execute("PRAGMA journal_mode=WAL")
    db.executescript(DDL)
    row = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    if row is None:
        db.execute("INSERT INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))
    elif int(row["value"]) != SCHEMA_VERSION:
        raise RuntimeError(f"the database has schema version {row['value']}, this code expects {SCHEMA_VERSION}: migrate first")
    return db


class tx:
    """with tx(db): ... runs the block in one transaction (BEGIN IMMEDIATE) and rolls back on any exception."""

    def __init__(self, db: sqlite3.Connection):
        self.db = db

    def __enter__(self):
        self.db.execute("BEGIN IMMEDIATE")
        return self.db

    def __exit__(self, et, ev, tb):
        self.db.execute("ROLLBACK" if et else "COMMIT")
        return False


# ---- audit log: append-only, each row hashes the previous one ----------------------------------------------------------------------
GENESIS = "0" * 64


def audit(db: sqlite3.Connection, now: str, actor: Optional[str], org_id: Optional[str], action: str, target: Optional[str] = None, detail: Optional[Dict[str, Any]] = None) -> int:
    """Records who did what. `detail` must not contain secrets or tokens (callers pass ids and states only)."""
    d = json.dumps(detail or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    last = db.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    prev = last["hash"] if last else GENESIS
    h = hashlib.sha256((prev + "|" + canonical_bytes({"at": now, "actor": actor, "org": org_id, "action": action, "target": target}).decode() + "|" + d).encode()).hexdigest()
    cur = db.execute("INSERT INTO audit_log(at, actor_user_id, org_id, action, target, detail_json, prev_hash, hash) VALUES(?,?,?,?,?,?,?,?)", (now, actor, org_id, action, target, d, prev, h))
    return int(cur.lastrowid)


def verify_audit(db: sqlite3.Connection) -> Dict[str, Any]:
    prev, n = GENESIS, 0
    for r in db.execute("SELECT * FROM audit_log ORDER BY seq"):
        h = hashlib.sha256((prev + "|" + canonical_bytes({"at": r["at"], "actor": r["actor_user_id"], "org": r["org_id"], "action": r["action"], "target": r["target"]}).decode() + "|" + r["detail_json"]).encode()).hexdigest()
        if r["prev_hash"] != prev or r["hash"] != h:
            return {"ok": False, "first_bad_seq": r["seq"], "checked": n}
        prev, n = h, n + 1
    return {"ok": True, "checked": n, "head": prev}


# ---- metrics ---------------------------------------------------------------------------------------------------------------------
def metric(db: sqlite3.Connection, name: str, value: float, now: str, labels: str = "") -> None:
    db.execute("INSERT INTO metrics(name, at, value, labels) VALUES(?,?,?,?)", (name, now, float(value), labels))


def percentile(values: List[float], p: float) -> Optional[float]:
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(p / 100.0 * (len(s) - 1)))))
    return s[k]


def metric_summary(db: sqlite3.Connection, name: str) -> Dict[str, Any]:
    vals = [r["value"] for r in db.execute("SELECT value FROM metrics WHERE name=?", (name,))]
    return {"count": len(vals), "p50": percentile(vals, 50), "p95": percentile(vals, 95), "p99": percentile(vals, 99), "max": max(vals) if vals else None}


def rows(cur: Iterable[sqlite3.Row]) -> List[Dict[str, Any]]:
    return [dict(r) for r in cur]
