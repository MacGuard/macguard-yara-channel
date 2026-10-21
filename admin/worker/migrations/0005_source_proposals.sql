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
