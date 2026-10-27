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
CREATE TABLE IF NOT EXISTS members (login TEXT PRIMARY KEY, role TEXT NOT NULL CHECK (role IN ('VIEWER','REVIEWER','PUBLISHER','SECURITY_ADMIN','ADMIN')), granted_by TEXT NOT NULL, at TEXT NOT NULL, user_id INTEGER, updated_at TEXT);
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

-- ---- migration 0003 (policies): the same statements as migrations/0003_policies.sql, so a fresh database equals a migrated one ----
-- 0003: persistent administrative policy (withdrawal of a published rule), its lift state machine (second authorization, break-glass) and its append-only history.
-- Additive only: three new tables, their indexes and triggers. No existing table or row is touched; the previous Worker version ignores them.
-- NOT RUN by the task that wrote it. Apply once:  wrangler d1 execute <db> --remote --file migrations/0003_policies.sql
-- Triggers are on ONE line each (wrangler and the test splitter cut statements at ';' + newline).
CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL CHECK (scope IN ('path','content')),
  scope_key TEXT NOT NULL,
  source TEXT NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
  candidate_id TEXT NOT NULL,
  criticality TEXT NOT NULL CHECK (criticality IN ('STANDARD','CRITICAL')),
  kind TEXT NOT NULL DEFAULT 'WITHDRAWAL' CHECK (kind IN ('WITHDRAWAL','SUSPENSION','REVOCATION')),
  author TEXT NOT NULL,
  author_id INTEGER NOT NULL,
  author_role TEXT NOT NULL CHECK (author_role IN ('ADMIN','PUBLISHER','SECURITY_ADMIN')),
  reason TEXT NOT NULL CHECK (length(trim(reason)) >= 5),
  created_at TEXT NOT NULL,
  request_id TEXT NOT NULL UNIQUE,
  baseline_tag TEXT NOT NULL,
  baseline_published_at TEXT NOT NULL,
  baseline_manifest_sha256 TEXT NOT NULL,
  baseline_rules_root TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','LIFTED')),
  withdrawal TEXT NOT NULL DEFAULT 'REQUESTED' CHECK (withdrawal IN ('REQUESTED','CONFIRMED','CANCELLED')),
  version INTEGER NOT NULL DEFAULT 1,
  confirmed_tag TEXT,
  confirmed_published_at TEXT,
  confirmed_manifest_sha256 TEXT,
  confirmed_rules_root TEXT,
  confirmed_at TEXT,
  lifted_by TEXT,
  lifted_by_id INTEGER,
  lifted_reason TEXT,
  lifted_at TEXT,
  lifted_via TEXT,
  lift_id TEXT,
  updated_at TEXT NOT NULL,
  CHECK (scope_key = CASE scope WHEN 'content' THEN 'content:' || sha256 ELSE 'path:' || lower(source) || ':' || lower(path) END),
  CHECK (withdrawal != 'CONFIRMED' OR (confirmed_tag IS NOT NULL AND confirmed_published_at IS NOT NULL AND confirmed_manifest_sha256 IS NOT NULL AND confirmed_rules_root IS NOT NULL AND confirmed_at IS NOT NULL)),
  CHECK (status != 'LIFTED' OR (lifted_by IS NOT NULL AND lifted_by_id IS NOT NULL AND lifted_reason IS NOT NULL AND length(trim(lifted_reason)) >= 5 AND lifted_at IS NOT NULL AND lifted_via IN ('DIRECT','DUAL','BREAKGLASS') AND lift_id IS NOT NULL)),
  CHECK (status != 'ACTIVE' OR (lifted_via IS NULL AND lift_id IS NULL AND lifted_at IS NULL)),
  CHECK (status = 'LIFTED' OR withdrawal IN ('REQUESTED','CONFIRMED')),
  CHECK (withdrawal != 'CANCELLED' OR status = 'LIFTED')
);
CREATE UNIQUE INDEX IF NOT EXISTS policies_active_key ON policies (scope_key) WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS policies_candidate ON policies (candidate_id);
CREATE INDEX IF NOT EXISTS policies_status ON policies (status, withdrawal);
-- One row per attempt to lift a policy. DIRECT = one ADMIN, STANDARD policies only. DUAL = requested by one ADMIN, authorized by a DIFFERENT ADMIN (login and account id).
-- BREAKGLASS = emergency path for a CRITICAL policy when no second ADMIN is available: mandatory reason, mandatory delay (not_before), a closing time (expires_at) and a post-hoc review by another ADMIN.
CREATE TABLE IF NOT EXISTS policy_lifts (
  id TEXT PRIMARY KEY,
  policy_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('DIRECT','DUAL','BREAKGLASS')),
  state TEXT NOT NULL CHECK (state IN ('REQUESTED','APPLIED','CANCELLED','EXPIRED')),
  requested_by TEXT NOT NULL,
  requested_by_id INTEGER NOT NULL,
  requested_role TEXT NOT NULL CHECK (requested_role IN ('ADMIN','PUBLISHER','SECURITY_ADMIN')),
  reason TEXT NOT NULL CHECK (length(trim(reason)) >= 5 AND (kind != 'BREAKGLASS' OR length(trim(reason)) >= 20)),
  requested_at TEXT NOT NULL,
  request_id TEXT NOT NULL UNIQUE,
  not_before TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  authorized_by TEXT,
  authorized_by_id INTEGER,
  authorized_reason TEXT,
  authorized_at TEXT,
  applied_at TEXT,
  closed_by TEXT,
  closed_by_id INTEGER,
  closed_reason TEXT,
  closed_at TEXT,
  review_due_at TEXT,
  reviewed_by TEXT,
  reviewed_by_id INTEGER,
  reviewed_at TEXT,
  review_outcome TEXT CHECK (review_outcome IS NULL OR review_outcome IN ('APPROPRIATE','INAPPROPRIATE')),
  review_note TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL,
  CHECK (kind != 'DUAL' OR authorized_by_id IS NULL OR (authorized_by_id != requested_by_id AND lower(authorized_by) != lower(requested_by))),
  CHECK (kind != 'BREAKGLASS' OR (julianday(not_before) - julianday(requested_at)) * 86400 >= 21599),
  CHECK (state != 'APPLIED' OR applied_at IS NOT NULL),
  CHECK (state != 'APPLIED' OR kind = 'DIRECT' OR (kind = 'DUAL' AND authorized_by_id IS NOT NULL AND authorized_reason IS NOT NULL AND length(trim(authorized_reason)) >= 5 AND applied_at < expires_at) OR (kind = 'BREAKGLASS' AND applied_at >= not_before AND applied_at < expires_at AND review_due_at IS NOT NULL)),
  CHECK (kind = 'BREAKGLASS' OR review_due_at IS NULL),
  CHECK (reviewed_by_id IS NULL OR (kind = 'BREAKGLASS' AND state = 'APPLIED' AND reviewed_by_id != requested_by_id AND reviewed_at IS NOT NULL AND review_outcome IS NOT NULL AND length(trim(review_note)) >= 5)),
  CHECK (state NOT IN ('CANCELLED','EXPIRED') OR (closed_at IS NOT NULL AND closed_by IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS policy_lifts_open ON policy_lifts (policy_id) WHERE state = 'REQUESTED';
CREATE INDEX IF NOT EXISTS policy_lifts_policy ON policy_lifts (policy_id);
CREATE INDEX IF NOT EXISTS policy_lifts_review ON policy_lifts (kind, state, reviewed_at);
CREATE TABLE IF NOT EXISTS policy_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  policy_id TEXT NOT NULL,
  policy_version INTEGER NOT NULL,
  event TEXT NOT NULL CHECK (event IN ('WITHDRAWAL_REQUESTED','WITHDRAWAL_CONFIRMED','LIFT_REQUESTED','LIFT_CANCELLED','LIFT_EXPIRED','LIFTED','BREAKGLASS_REQUESTED','BREAKGLASS_EXECUTED','BREAKGLASS_REVIEWED','REVOCATION_CONFIRMED')),
  actor TEXT NOT NULL,
  actor_id INTEGER,
  role TEXT NOT NULL,
  reason TEXT NOT NULL,
  release_tag TEXT,
  evidence TEXT NOT NULL DEFAULT '{}',
  request_id TEXT NOT NULL,
  at TEXT NOT NULL,
  UNIQUE (policy_id, event, request_id)
);
CREATE INDEX IF NOT EXISTS policy_events_policy ON policy_events (policy_id);
CREATE TRIGGER IF NOT EXISTS policy_events_no_update BEFORE UPDATE ON policy_events BEGIN SELECT RAISE(ABORT, 'policy events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS policy_events_no_delete BEFORE DELETE ON policy_events BEGIN SELECT RAISE(ABORT, 'policy events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS policies_no_delete BEFORE DELETE ON policies BEGIN SELECT RAISE(ABORT, 'policies are never deleted'); END;
CREATE TRIGGER IF NOT EXISTS policies_identity_frozen BEFORE UPDATE OF id, scope, scope_key, source, path, sha256, candidate_id, criticality, author, author_id, author_role, reason, created_at, request_id, baseline_tag, baseline_published_at, baseline_manifest_sha256, baseline_rules_root ON policies BEGIN SELECT RAISE(ABORT, 'policy identity and provenance are immutable'); END;
CREATE TRIGGER IF NOT EXISTS policies_version_step BEFORE UPDATE ON policies WHEN NEW.version != OLD.version + 1 BEGIN SELECT RAISE(ABORT, 'policy version must increase by exactly one'); END;
CREATE TRIGGER IF NOT EXISTS policies_lifted_is_final BEFORE UPDATE ON policies WHEN OLD.status = 'LIFTED' BEGIN SELECT RAISE(ABORT, 'a lifted policy is final'); END;
CREATE TRIGGER IF NOT EXISTS policies_withdrawal_forward BEFORE UPDATE ON policies WHEN NEW.withdrawal != OLD.withdrawal AND NOT (OLD.withdrawal = 'REQUESTED' AND NEW.withdrawal IN ('CONFIRMED','CANCELLED')) BEGIN SELECT RAISE(ABORT, 'withdrawal only moves forward'); END;
CREATE TRIGGER IF NOT EXISTS policies_lift_needs_recorded_authorization BEFORE UPDATE ON policies WHEN NEW.status = 'LIFTED' AND OLD.status = 'ACTIVE' AND NOT EXISTS (SELECT 1 FROM policy_lifts l WHERE l.id = NEW.lift_id AND l.policy_id = NEW.id AND l.kind = NEW.lifted_via AND l.state = 'APPLIED' AND (l.kind != 'DIRECT' OR NEW.criticality = 'STANDARD')) BEGIN SELECT RAISE(ABORT, 'a lift needs its recorded authorization'); END;
CREATE TRIGGER IF NOT EXISTS policy_lifts_no_delete BEFORE DELETE ON policy_lifts BEGIN SELECT RAISE(ABORT, 'policy lifts are never deleted'); END;
CREATE TRIGGER IF NOT EXISTS policy_lifts_identity_frozen BEFORE UPDATE OF id, policy_id, kind, requested_by, requested_by_id, requested_role, reason, requested_at, request_id, not_before, expires_at ON policy_lifts BEGIN SELECT RAISE(ABORT, 'lift identity and provenance are immutable'); END;
CREATE TRIGGER IF NOT EXISTS policy_lifts_version_step BEFORE UPDATE ON policy_lifts WHEN NEW.version != OLD.version + 1 BEGIN SELECT RAISE(ABORT, 'lift version must increase by exactly one'); END;
CREATE TRIGGER IF NOT EXISTS policy_lifts_closed_is_final BEFORE UPDATE ON policy_lifts WHEN OLD.state IN ('CANCELLED','EXPIRED') OR (OLD.state = 'APPLIED' AND (NEW.state != 'APPLIED' OR NEW.applied_at IS NOT OLD.applied_at OR NEW.authorized_by_id IS NOT OLD.authorized_by_id OR NEW.authorized_at IS NOT OLD.authorized_at)) OR OLD.reviewed_at IS NOT NULL BEGIN SELECT RAISE(ABORT, 'a closed lift is final'); END;
CREATE TRIGGER IF NOT EXISTS policy_lifts_two_step_born_open BEFORE INSERT ON policy_lifts WHEN NEW.kind IN ('DUAL','BREAKGLASS') AND NEW.state != 'REQUESTED' BEGIN SELECT RAISE(ABORT, 'a two-step lift is born requested'); END;
CREATE TRIGGER IF NOT EXISTS policy_lifts_direct_standard_only BEFORE INSERT ON policy_lifts WHEN NEW.kind = 'DIRECT' AND (SELECT criticality FROM policies WHERE id = NEW.policy_id) IS NOT 'STANDARD' BEGIN SELECT RAISE(ABORT, 'a critical policy cannot be lifted by one administrator'); END;
CREATE TRIGGER IF NOT EXISTS policy_lifts_breakglass_needs_critical BEFORE INSERT ON policy_lifts WHEN NEW.kind = 'BREAKGLASS' AND (SELECT criticality FROM policies WHERE id = NEW.policy_id) IS NOT 'CRITICAL' BEGIN SELECT RAISE(ABORT, 'break-glass applies to critical policies only'); END;
CREATE TRIGGER IF NOT EXISTS policy_lifts_breakglass_review_overdue BEFORE INSERT ON policy_lifts WHEN NEW.kind = 'BREAKGLASS' AND EXISTS (SELECT 1 FROM policy_lifts b WHERE b.kind = 'BREAKGLASS' AND b.state = 'APPLIED' AND b.reviewed_at IS NULL AND b.review_due_at < NEW.requested_at) BEGIN SELECT RAISE(ABORT, 'a break-glass review is overdue'); END;

-- Mirrored from migrations/0004_audit_anchor.sql (a test keeps the two identical).
-- BEGIN audit_anchor (0004)
CREATE TABLE IF NOT EXISTS audit_anchor (
  seq INTEGER PRIMARY KEY,          -- last audit seq of the sealed segment
  hash TEXT NOT NULL,               -- head hash of that segment (the hash the next retained entry links to)
  rows INTEGER NOT NULL CHECK (rows > 0),   -- entries in the segment
  seal_sha256 TEXT NOT NULL,        -- SHA-256 of the seal document
  created_at TEXT NOT NULL,
  author TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_anchor_no_update BEFORE UPDATE ON audit_anchor BEGIN SELECT RAISE(ABORT, 'audit anchors are append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_anchor_no_delete BEFORE DELETE ON audit_anchor BEGIN SELECT RAISE(ABORT, 'audit anchors are append-only'); END;
-- An anchor cannot disagree with an audit row that still exists at its position.
CREATE TRIGGER IF NOT EXISTS audit_anchor_matches_audit BEFORE INSERT ON audit_anchor
  WHEN EXISTS (SELECT 1 FROM audit WHERE seq = NEW.seq AND hash <> NEW.hash)
  BEGIN SELECT RAISE(ABORT, 'anchor hash does not match the audit entry at that seq'); END;
-- END audit_anchor (0004)
-- approvals: one row per operation that needs a second, DIFFERENT identity (privileged role grants, real recoveries, confirmation of a definitive revocation). The database itself refuses an approver who is the requester.
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  op TEXT NOT NULL CHECK (op IN ('role.grant','restore.real','policy.revoke_confirm')),
  params TEXT NOT NULL CHECK (json_valid(params)),
  params_sha256 TEXT NOT NULL CHECK (length(params_sha256) = 64),
  mode TEXT NOT NULL CHECK (mode IN ('DUAL','BREAKGLASS')),
  state TEXT NOT NULL CHECK (state IN ('REQUESTED','APPROVED','EXECUTED','CANCELLED','EXPIRED')),
  reason TEXT NOT NULL CHECK (length(trim(reason)) >= 5 AND (mode != 'BREAKGLASS' OR length(trim(reason)) >= 40)),
  requested_by TEXT NOT NULL,
  requested_by_id INTEGER NOT NULL,
  requested_roles TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  not_before TEXT,
  approved_by TEXT,
  approved_by_id INTEGER,
  approved_roles TEXT,
  approved_at TEXT,
  approval_reason TEXT,
  executed_by TEXT,
  executed_by_id INTEGER,
  executed_at TEXT,
  reviewed_by TEXT,
  reviewed_by_id INTEGER,
  reviewed_at TEXT,
  review_outcome TEXT CHECK (review_outcome IS NULL OR review_outcome IN ('APPROPRIATE','INAPPROPRIATE')),
  request_id TEXT NOT NULL UNIQUE,
  version INTEGER NOT NULL DEFAULT 1,
  CHECK (approved_by_id IS NULL OR approved_by_id != requested_by_id),
  CHECK (reviewed_by_id IS NULL OR (reviewed_by_id != requested_by_id AND reviewed_by_id IS NOT executed_by_id)),
  CHECK (mode != 'DUAL' OR not_before IS NULL),
  CHECK (mode != 'BREAKGLASS' OR (not_before IS NOT NULL AND approved_by_id IS NULL)),
  CHECK (state NOT IN ('APPROVED','EXECUTED') OR mode = 'BREAKGLASS' OR approved_by_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS approvals_state ON approvals (state, op);
CREATE TRIGGER IF NOT EXISTS approvals_no_delete BEFORE DELETE ON approvals BEGIN SELECT RAISE(ABORT, 'approvals are never deleted'); END;
CREATE TRIGGER IF NOT EXISTS approvals_identity_frozen BEFORE UPDATE OF id, op, params, params_sha256, mode, reason, requested_by, requested_by_id, requested_roles, requested_at, expires_at, not_before, request_id ON approvals BEGIN SELECT RAISE(ABORT, 'what was requested cannot change'); END;
CREATE TRIGGER IF NOT EXISTS approvals_version_step BEFORE UPDATE ON approvals WHEN NEW.version != OLD.version + 1 BEGIN SELECT RAISE(ABORT, 'approval version must increase by exactly one'); END;
CREATE TRIGGER IF NOT EXISTS approvals_closed_is_final BEFORE UPDATE ON approvals WHEN OLD.state IN ('CANCELLED','EXPIRED') OR (OLD.state = 'EXECUTED' AND (NEW.state != 'EXECUTED' OR NEW.executed_at IS NOT OLD.executed_at OR NEW.approved_by_id IS NOT OLD.approved_by_id)) BEGIN SELECT RAISE(ABORT, 'a closed approval is final'); END;
CREATE TRIGGER IF NOT EXISTS approvals_breakglass_not_before BEFORE UPDATE ON approvals WHEN NEW.state = 'EXECUTED' AND OLD.mode = 'BREAKGLASS' AND NEW.executed_at < OLD.not_before BEGIN SELECT RAISE(ABORT, 'an emergency approval cannot be executed before its delay'); END;


-- >>> 0007 source requests: exact mirror of migrations/0007_source_requests.sql (a test keeps them identical)
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
-- <<< 0007

-- >>> 0008 publication requests: exact mirror of migrations/0008_publication_requests.sql (a test keeps them identical)
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
-- <<< 0008
