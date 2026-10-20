-- Private quarantine store (Cloudflare D1). Nothing here is ever served by a static file.
CREATE TABLE IF NOT EXISTS candidates (
  id TEXT PRIMARY KEY,
  sha256 TEXT NOT NULL,
  path TEXT NOT NULL,
  name TEXT NOT NULL,
  source TEXT NOT NULL,
  upstream_commit TEXT,
  bytes INTEGER NOT NULL DEFAULT 0,
  detected_at TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('PENDING','UNDER_REVIEW','APPROVED_PENDING_VALIDATION','REJECTED','RELEASED')),
  reasons TEXT NOT NULL DEFAULT '[]',
  metrics TEXT NOT NULL DEFAULT '{}',
  depends_on TEXT NOT NULL DEFAULT '[]',
  related TEXT NOT NULL DEFAULT '[]',
  version INTEGER NOT NULL DEFAULT 1,
  previous_id TEXT,
  release_tag TEXT,
  retest_requested INTEGER NOT NULL DEFAULT 0,
  revalidation_failed TEXT,
  updated_at TEXT NOT NULL,
  archived_at TEXT,   -- set = hidden from every operational view; decisions and audit are never touched
  UNIQUE (sha256, path)
);
CREATE INDEX IF NOT EXISTS candidates_state ON candidates (state);
CREATE INDEX IF NOT EXISTS candidates_path ON candidates (path);
CREATE TABLE IF NOT EXISTS blobs (sha256 TEXT PRIMARY KEY, content TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  candidate_id TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  action TEXT NOT NULL,
  from_state TEXT NOT NULL,
  to_state TEXT NOT NULL,
  candidate_version INTEGER NOT NULL,
  actor TEXT NOT NULL,
  actor_id INTEGER,
  role TEXT NOT NULL,
  reason TEXT NOT NULL,
  batch_id TEXT,
  request_id TEXT NOT NULL,
  at TEXT NOT NULL,
  UNIQUE (request_id, candidate_id)
);
-- A member is identified by the immutable GitHub account id. `login` is only the name seen at the last change; a row with user_id NULL is a legacy
-- grant by name that is honoured but flagged "unbound" until an ADMIN resolves it to an account (see migrations/0002).
CREATE TABLE IF NOT EXISTS members (login TEXT PRIMARY KEY, role TEXT NOT NULL CHECK (role IN ('VIEWER','REVIEWER','ADMIN')), granted_by TEXT NOT NULL, at TEXT NOT NULL, user_id INTEGER, updated_at TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS members_user_id ON members (user_id) WHERE user_id IS NOT NULL;
-- Append-only, hash-chained: hash = SHA-256(prev_hash || canonical entry). Any edit or deletion breaks the chain.
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  role TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  detail TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pipeline_runs (run_id TEXT PRIMARY KEY, workflow TEXT NOT NULL, at TEXT NOT NULL, summary TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS metrics (day TEXT NOT NULL, name TEXT NOT NULL, value REAL NOT NULL, PRIMARY KEY (day, name));
CREATE UNIQUE INDEX IF NOT EXISTS audit_prev ON audit (prev_hash);   -- forces one linear chain even under concurrent writers
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, login TEXT NOT NULL, user_id INTEGER NOT NULL, token TEXT NOT NULL, csrf TEXT NOT NULL,
  perm TEXT, perm_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_states (state TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);

-- The audit trail and the decision history are append-only for the service itself: an UPDATE or DELETE aborts. (Someone with direct database
-- access can still drop a trigger; the hash chain is what makes that visible.)
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS decisions_no_update BEFORE UPDATE ON decisions BEGIN SELECT RAISE(ABORT, 'decisions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS decisions_no_delete BEFORE DELETE ON decisions BEGIN SELECT RAISE(ABORT, 'decisions are append-only'); END;
