-- 0008: publication requests (desired state) for the scheduled daily run and the expedited run. Additive only: no existing table or row is touched.
-- A request records WHAT should become the effective state, never the effective state itself: the panel only syncs the effective state from a verified release. Rows are never deleted; every transition is
-- an append-only event. Execution is ONLY by GitHub Actions: nothing in this database publishes anything.
CREATE TABLE IF NOT EXISTS publication_requests (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  mode TEXT NOT NULL DEFAULT 'SCHEDULED' CHECK (mode IN ('SCHEDULED','EXPEDITED')),
  action TEXT NOT NULL CHECK (action IN ('PUBLISH','QUARANTINE','WITHDRAW','REVOKE','REPLACE','ADD_IOC','RETIRE_IOC','SOURCE_CHANGE','PACKAGE_PROFILE')),
  criticality TEXT NOT NULL CHECK (criticality IN ('STANDARD','CRITICAL')),
  resource_kind TEXT NOT NULL CHECK (resource_kind IN ('yara_rule','policy','intel_record','source','package')),
  resource_id TEXT NOT NULL CHECK (length(resource_id) BETWEEN 3 AND 200),
  resource_version INTEGER NOT NULL,
  desired_state TEXT NOT NULL CHECK (length(desired_state) BETWEEN 3 AND 40),
  effective_state_at_request TEXT,
  reason TEXT NOT NULL CHECK (length(trim(reason)) >= 5),
  dedupe_key TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('PENDING','AWAITING_APPROVAL','AUTHORIZED','QUEUED','RUNNING','VALIDATING','SIGNING','PUBLISHING','VERIFYING','APPLIED','SYNC_PENDING','BLOCKED','FAILED','CANCELLED')),
  state_reason TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  over_budget INTEGER NOT NULL DEFAULT 0 CHECK (over_budget IN (0,1)),
  requested_by TEXT NOT NULL,
  requested_by_id INTEGER NOT NULL,
  requested_roles TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  approval_id TEXT,
  authorized_by TEXT,
  authorized_by_id INTEGER,
  authorized_at TEXT,
  authorization_sha256 TEXT,
  authorization_expires_at TEXT,
  dispatched_at TEXT,
  run_id TEXT,
  run_url TEXT,
  commit_sha TEXT,
  release_tag TEXT,
  evidence TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(evidence)),
  cost_minutes REAL,
  applied_at TEXT,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS publication_requests_state ON publication_requests (state, mode, requested_at);
CREATE INDEX IF NOT EXISTS publication_requests_resource ON publication_requests (resource_kind, resource_id);
CREATE UNIQUE INDEX IF NOT EXISTS publication_requests_open_dedupe ON publication_requests (dedupe_key) WHERE state NOT IN ('APPLIED','FAILED','CANCELLED');
CREATE TABLE IF NOT EXISTS publication_request_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL,
  at TEXT NOT NULL,
  from_state TEXT,
  to_state TEXT NOT NULL,
  actor TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail))
);
CREATE INDEX IF NOT EXISTS publication_request_events_request ON publication_request_events (request_id, seq);
CREATE TRIGGER IF NOT EXISTS publication_requests_no_delete BEFORE DELETE ON publication_requests BEGIN SELECT RAISE(ABORT, 'publication requests are never deleted'); END;
CREATE TRIGGER IF NOT EXISTS publication_requests_identity_frozen BEFORE UPDATE OF id, request_id, mode, action, criticality, resource_kind, resource_id, resource_version, desired_state, requested_by, requested_by_id, requested_at, dedupe_key ON publication_requests BEGIN SELECT RAISE(ABORT, 'what was requested cannot be edited'); END;
CREATE TRIGGER IF NOT EXISTS publication_requests_version_step BEFORE UPDATE ON publication_requests WHEN NEW.version != OLD.version + 1 BEGIN SELECT RAISE(ABORT, 'version must increase by exactly one'); END;
CREATE TRIGGER IF NOT EXISTS publication_requests_final BEFORE UPDATE ON publication_requests WHEN OLD.state IN ('APPLIED','FAILED','CANCELLED') BEGIN SELECT RAISE(ABORT, 'a closed publication request is final'); END;
CREATE TRIGGER IF NOT EXISTS publication_request_events_no_update BEFORE UPDATE ON publication_request_events BEGIN SELECT RAISE(ABORT, 'publication request events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS publication_request_events_no_delete BEFORE DELETE ON publication_request_events BEGIN SELECT RAISE(ABORT, 'publication request events are append-only'); END;
-- The post-execution review of an emergency (review F4): its own append-only record, one per request, so it can be written after the request closed (a closed request row is final).
CREATE TABLE IF NOT EXISTS publication_request_reviews (
  request_id TEXT PRIMARY KEY,
  at TEXT NOT NULL,
  by_login TEXT NOT NULL,
  by_id INTEGER NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('APPROPRIATE','INAPPROPRIATE')),
  reason TEXT NOT NULL CHECK (length(trim(reason)) >= 5)
);
CREATE TRIGGER IF NOT EXISTS publication_request_reviews_no_update BEFORE UPDATE ON publication_request_reviews BEGIN SELECT RAISE(ABORT, 'publication request reviews are append-only'); END;
CREATE TRIGGER IF NOT EXISTS publication_request_reviews_no_delete BEFORE DELETE ON publication_request_reviews BEGIN SELECT RAISE(ABORT, 'publication request reviews are append-only'); END;
