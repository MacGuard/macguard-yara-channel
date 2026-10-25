-- macguard-intel (its own D1 database, bound to the panel Worker as INTEL): promoted intelligence data. Separate from the panel database so that its volume never enters the panel's backups.
-- Everything here arrives through scripts/intel_promote.py after an integrity check against the channel manifests; nothing is written by the Worker. Triggers are on ONE line each.
CREATE TABLE IF NOT EXISTS intel_sources (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  organization TEXT,
  url TEXT,
  family TEXT NOT NULL,
  grp TEXT NOT NULL CHECK (grp IN ('detections','indicators','vulnerabilities','context')),
  data_type TEXT,
  adapter TEXT,
  adapter_version TEXT,
  license_id TEXT,
  redistribution TEXT,
  auth TEXT NOT NULL DEFAULT 'none' CHECK (auth IN ('none','api_key','unknown')),
  configured INTEGER NOT NULL DEFAULT 1,
  integration TEXT NOT NULL DEFAULT 'CONNECTED' CHECK (integration IN ('CONNECTED','NOT_INTEGRATED','BLOCKED')),
  status_reason TEXT,
  evidence_ref TEXT,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS intel_runs (
  id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL,
  retrieved_at TEXT,
  http_status INTEGER,
  bytes INTEGER,
  expected_bytes INTEGER,
  etag TEXT,
  last_modified TEXT,
  upstream_version TEXT,
  content_sha256 TEXT,
  declared INTEGER,
  accepted INTEGER NOT NULL DEFAULT 0,
  rejected INTEGER NOT NULL DEFAULT 0,
  duplicates INTEGER NOT NULL DEFAULT 0,
  retained INTEGER NOT NULL DEFAULT 0,
  approved INTEGER NOT NULL DEFAULT 0,
  published INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL CHECK (state IN ('COMPLETE','PARTIAL','FAILED')),
  publishable INTEGER NOT NULL DEFAULT 0,
  blocking TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(blocking)),
  duration_ms INTEGER,
  evidence TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(evidence)),
  promoted_at TEXT NOT NULL,
  promoted_by TEXT NOT NULL,
  promotion_sha256 TEXT NOT NULL CHECK (length(promotion_sha256) = 64),
  log_leaf TEXT
);
CREATE INDEX IF NOT EXISTS intel_runs_source ON intel_runs (source_id, retrieved_at DESC);
CREATE TABLE IF NOT EXISTS intel_records (
  id TEXT PRIMARY KEY,
  family TEXT NOT NULL,
  source_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  key TEXT NOT NULL,
  title TEXT,
  severity TEXT,
  score REAL,
  state TEXT,
  validated TEXT,
  functional TEXT,
  performance TEXT,
  held_back INTEGER,
  first_seen TEXT,
  last_seen TEXT,
  updated_at TEXT,
  body TEXT,
  doc TEXT NOT NULL CHECK (json_valid(doc)),
  doc_sha256 TEXT NOT NULL CHECK (length(doc_sha256) = 64)
);
CREATE INDEX IF NOT EXISTS intel_records_family ON intel_records (family, source_id, id);
CREATE INDEX IF NOT EXISTS intel_records_key ON intel_records (key);
CREATE INDEX IF NOT EXISTS intel_records_state ON intel_records (family, state, id);
CREATE TABLE IF NOT EXISTS intel_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  level TEXT NOT NULL CHECK (level IN ('DEBUG','INFO','WARN','ERROR','FATAL')),
  component TEXT NOT NULL,
  module TEXT NOT NULL,
  message TEXT NOT NULL,
  run_id TEXT,
  trace_id TEXT,
  family TEXT,
  source_id TEXT,
  artifact_id TEXT,
  outcome TEXT,
  duration_ms INTEGER,
  actor_id TEXT,
  evidence_ref TEXT
);
CREATE INDEX IF NOT EXISTS intel_events_ts ON intel_events (ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS intel_events_run ON intel_events (run_id, id);
CREATE TRIGGER IF NOT EXISTS intel_events_no_update BEFORE UPDATE ON intel_events BEGIN SELECT RAISE(ABORT, 'intel events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS intel_events_no_delete BEFORE DELETE ON intel_events BEGIN SELECT RAISE(ABORT, 'intel events are append-only'); END;
