-- 0007: requests to add or to retire a source of ANY family (feed, API, CSV, repository...). Additive only: no existing table or row is touched.
-- A request records what is wanted and why; it is never fetched by the Worker. Accepting it authorises building the connector (a reviewed code change); it does not enable anything.
-- States: REQUESTED -> ACCEPTED | REJECTED | CANCELLED. Rows are never deleted.
CREATE TABLE IF NOT EXISTS source_requests (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL DEFAULT 'ADD' CHECK (kind IN ('ADD','RETIRE')),
  target_source TEXT CHECK (target_source IS NULL OR length(target_source) BETWEEN 2 AND 80),
  family TEXT NOT NULL CHECK (family IN ('yara','suricata','sigma','ioc','hash','cve','epss','kev','attack','advisory')),
  name TEXT NOT NULL CHECK (length(name) BETWEEN 2 AND 80),
  url TEXT NOT NULL CHECK (length(url) BETWEEN 12 AND 300 AND url LIKE 'https://%'),
  format TEXT NOT NULL CHECK (format IN ('json','csv','xml','rss','text','api','git','other')),
  auth TEXT NOT NULL CHECK (auth IN ('none','api_key','unknown')),
  license_note TEXT CHECK (license_note IS NULL OR length(license_note) <= 500),
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 5 AND 2000),
  state TEXT NOT NULL DEFAULT 'REQUESTED' CHECK (state IN ('REQUESTED','ACCEPTED','REJECTED','CANCELLED')),
  version INTEGER NOT NULL DEFAULT 1,
  requested_by TEXT NOT NULL,
  requested_by_id INTEGER NOT NULL,
  requested_at TEXT NOT NULL,
  decided_by TEXT,
  decided_by_id INTEGER,
  decided_at TEXT,
  decision_reason TEXT
);
CREATE INDEX IF NOT EXISTS source_requests_state ON source_requests (state, requested_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS source_requests_open_url ON source_requests (kind, url) WHERE state = 'REQUESTED';
CREATE TRIGGER IF NOT EXISTS source_requests_no_delete BEFORE DELETE ON source_requests BEGIN SELECT RAISE(ABORT, 'source requests are never deleted'); END;
CREATE TRIGGER IF NOT EXISTS source_requests_final BEFORE UPDATE ON source_requests WHEN OLD.state != 'REQUESTED' BEGIN SELECT RAISE(ABORT, 'a decided source request is final'); END;
CREATE TRIGGER IF NOT EXISTS source_requests_identity_frozen BEFORE UPDATE OF id, request_id, kind, target_source, family, name, url, format, auth, license_note, reason, requested_by, requested_by_id, requested_at ON source_requests BEGIN SELECT RAISE(ABORT, 'what was requested cannot be edited'); END;
