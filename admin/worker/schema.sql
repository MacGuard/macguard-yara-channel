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

-- >>> 0005 source proposals: exact mirror of migrations/0005_source_proposals.sql (a test keeps them identical)
-- 0005: source proposals (a front door for a reviewed pull request; nothing here edits config/sources.json). Additive only: no existing table or row is touched.
-- States: proposed -> verified -> approved -> pr_open -> active -> retired; rejected is terminal. Only an ADMIN moves a proposal to approved.
CREATE TABLE IF NOT EXISTS source_proposals (
  id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL CHECK (length(source_id) BETWEEN 2 AND 32 AND source_id GLOB '[a-z0-9]*' AND source_id NOT GLOB '*[^a-z0-9-]*'),
  repo TEXT NOT NULL CHECK (length(repo) BETWEEN 3 AND 140 AND repo GLOB '*/*'),
  repo_lc TEXT NOT NULL CHECK (repo_lc = lower(repo_lc)),
  repo_id INTEGER,
  kind TEXT NOT NULL CHECK (kind = 'rules'),
  paths TEXT NOT NULL CHECK (json_valid(paths) AND json_type(paths) = 'array' AND json_array_length(paths) BETWEEN 1 AND 20),
  state TEXT NOT NULL CHECK (state IN ('proposed','verified','approved','rejected','pr_open','active','retired')),
  state_reason TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 5 AND 2000),
  proposer TEXT NOT NULL,
  proposer_id INTEGER NOT NULL,
  request_id TEXT NOT NULL UNIQUE,
  verification TEXT CHECK (verification IS NULL OR json_valid(verification)),
  verified_at TEXT,
  verified_commit TEXT CHECK (verified_commit IS NULL OR (length(verified_commit) = 40 AND verified_commit NOT GLOB '*[^0-9a-f]*')),
  license_spdx TEXT,
  license_sha256 TEXT CHECK (license_sha256 IS NULL OR (length(license_sha256) = 64 AND license_sha256 NOT GLOB '*[^0-9a-f]*')),
  findings TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(findings)),
  acks TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(acks)),
  payload TEXT CHECK (payload IS NULL OR json_valid(payload)),
  payload_sha256 TEXT CHECK (payload_sha256 IS NULL OR (length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*')),
  approved_by TEXT,
  approved_by_id INTEGER,
  approved_at TEXT,
  pr_number INTEGER,
  pr_url TEXT,
  pr_branch TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS source_proposals_state ON source_proposals (state);
CREATE INDEX IF NOT EXISTS source_proposals_repo ON source_proposals (repo_lc);
-- one open proposal per repository and per source id
CREATE UNIQUE INDEX IF NOT EXISTS source_proposals_open_repo ON source_proposals (repo_lc) WHERE state IN ('proposed','verified','approved','pr_open');
CREATE UNIQUE INDEX IF NOT EXISTS source_proposals_open_id ON source_proposals (source_id) WHERE state IN ('proposed','verified','approved','pr_open');

CREATE TABLE IF NOT EXISTS source_proposal_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  proposal_id TEXT NOT NULL,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  actor_id INTEGER,
  role TEXT NOT NULL,
  event TEXT NOT NULL CHECK (event IN ('proposed','verify.ok','verify.rejected','verify.unavailable','approved','rejected','pr.opened','pr.closed','activated','retired')),
  from_state TEXT,
  to_state TEXT NOT NULL,
  version INTEGER NOT NULL,
  request_id TEXT,
  detail TEXT NOT NULL CHECK (json_valid(detail)),
  audit_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS source_proposal_events_p ON source_proposal_events (proposal_id, seq);
CREATE UNIQUE INDEX IF NOT EXISTS source_proposal_events_req ON source_proposal_events (request_id) WHERE request_id IS NOT NULL;
CREATE TRIGGER IF NOT EXISTS spe_no_update BEFORE UPDATE ON source_proposal_events BEGIN SELECT RAISE(ABORT, 'source proposal events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS spe_no_delete BEFORE DELETE ON source_proposal_events BEGIN SELECT RAISE(ABORT, 'source proposal events are append-only'); END;
-- <<< 0005
