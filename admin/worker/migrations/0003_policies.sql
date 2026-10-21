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
  author TEXT NOT NULL,
  author_id INTEGER NOT NULL,
  author_role TEXT NOT NULL CHECK (author_role = 'ADMIN'),
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
  requested_role TEXT NOT NULL CHECK (requested_role = 'ADMIN'),
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
  event TEXT NOT NULL CHECK (event IN ('WITHDRAWAL_REQUESTED','WITHDRAWAL_CONFIRMED','LIFT_REQUESTED','LIFT_CANCELLED','LIFT_EXPIRED','LIFTED','BREAKGLASS_REQUESTED','BREAKGLASS_EXECUTED','BREAKGLASS_REVIEWED')),
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
