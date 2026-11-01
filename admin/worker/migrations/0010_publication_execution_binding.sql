-- 0010: binding of an expedited request to ONE authorised workflow execution (review F6) and the authorised release pin (review F3). Additive and idempotent.
-- Every dispatch of a request is recorded with its own dispatch_id (the workflow carries it in its run-name). A run claims a dispatch ONCE: the dispatch is the
-- primary key and the run id is unique, so two runs cannot claim the same dispatch and one run cannot claim two requests. Both tables are append-only.
CREATE TABLE IF NOT EXISTS publication_request_dispatches (
  dispatch_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  at TEXT NOT NULL,
  by_login TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS publication_request_dispatches_request ON publication_request_dispatches (request_id, at);
CREATE TABLE IF NOT EXISTS publication_request_claims (
  dispatch_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  run_id TEXT NOT NULL UNIQUE,
  run_attempt INTEGER NOT NULL,
  actor_id TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS publication_request_dispatches_no_update BEFORE UPDATE ON publication_request_dispatches BEGIN SELECT RAISE(ABORT, 'publication request dispatches are append-only'); END;
CREATE TRIGGER IF NOT EXISTS publication_request_dispatches_no_delete BEFORE DELETE ON publication_request_dispatches BEGIN SELECT RAISE(ABORT, 'publication request dispatches are append-only'); END;
CREATE TRIGGER IF NOT EXISTS publication_request_claims_no_update BEFORE UPDATE ON publication_request_claims BEGIN SELECT RAISE(ABORT, 'publication request claims are append-only'); END;
CREATE TRIGGER IF NOT EXISTS publication_request_claims_no_delete BEFORE DELETE ON publication_request_claims BEGIN SELECT RAISE(ABORT, 'publication request claims are append-only'); END;
-- The release that may satisfy publication requests: the latest public release, unless an authorised operation PINNED another verified release (rollback) until UNPIN.
CREATE TABLE IF NOT EXISTS publication_release_pins (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('PIN','UNPIN')),
  tag TEXT,
  manifest_sha256 TEXT,
  previous_tag TEXT,
  by_login TEXT NOT NULL,
  by_id INTEGER NOT NULL,
  by_role TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (length(trim(reason)) >= 10),
  CHECK ((kind = 'PIN' AND tag IS NOT NULL AND manifest_sha256 IS NOT NULL) OR (kind = 'UNPIN' AND tag IS NULL))
);
CREATE TRIGGER IF NOT EXISTS publication_release_pins_no_update BEFORE UPDATE ON publication_release_pins BEGIN SELECT RAISE(ABORT, 'release pins are append-only'); END;
CREATE TRIGGER IF NOT EXISTS publication_release_pins_no_delete BEFORE DELETE ON publication_release_pins BEGIN SELECT RAISE(ABORT, 'release pins are append-only'); END;
