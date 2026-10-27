-- Rollback of 0006: back to the three-role constraints. It REFUSES (the first statement fails) while any member, policy or lift carries a role the old constraints do not allow: re-assign or revoke those first.
SELECT CASE WHEN (SELECT COUNT(*) FROM members WHERE role IN ('PUBLISHER','SECURITY_ADMIN')) + (SELECT COUNT(*) FROM policies WHERE author_role != 'ADMIN') + (SELECT COUNT(*) FROM policy_lifts WHERE requested_role != 'ADMIN') + (SELECT COUNT(*) FROM approvals) + (SELECT COUNT(*) FROM policy_events WHERE event = 'REVOCATION_CONFIRMED') + (SELECT COUNT(*) FROM policies WHERE kind != 'WITHDRAWAL') = 0 THEN 1 ELSE json('not-json') END;
DROP TRIGGER IF EXISTS approvals_breakglass_not_before;
DROP TRIGGER IF EXISTS approvals_closed_is_final;
DROP TRIGGER IF EXISTS approvals_version_step;
DROP TRIGGER IF EXISTS approvals_identity_frozen;
DROP TRIGGER IF EXISTS approvals_no_delete;
DROP INDEX IF EXISTS approvals_state;
DROP TABLE IF EXISTS approvals;
DROP TRIGGER IF EXISTS policy_lifts_breakglass_review_overdue;
DROP TRIGGER IF EXISTS policy_lifts_breakglass_needs_critical;
DROP TRIGGER IF EXISTS policy_lifts_direct_standard_only;
DROP TRIGGER IF EXISTS policy_lifts_two_step_born_open;
DROP TRIGGER IF EXISTS policy_lifts_closed_is_final;
DROP TRIGGER IF EXISTS policy_lifts_version_step;
DROP TRIGGER IF EXISTS policy_lifts_identity_frozen;
DROP TRIGGER IF EXISTS policy_lifts_no_delete;
DROP TRIGGER IF EXISTS policies_lift_needs_recorded_authorization;
DROP TRIGGER IF EXISTS policies_withdrawal_forward;
DROP TRIGGER IF EXISTS policies_lifted_is_final;
DROP TRIGGER IF EXISTS policies_version_step;
DROP TRIGGER IF EXISTS policies_identity_frozen;
DROP TRIGGER IF EXISTS policies_no_delete;
DROP INDEX IF EXISTS policy_lifts_review;
DROP INDEX IF EXISTS policy_lifts_policy;
DROP INDEX IF EXISTS policy_lifts_open;
DROP INDEX IF EXISTS policies_status;
DROP INDEX IF EXISTS policies_candidate;
DROP INDEX IF EXISTS policies_active_key;
DROP TABLE IF EXISTS policy_lifts;
DROP TABLE IF EXISTS policies;
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
-- policy_events: keep the rows aside, recreate under the same name with the wider vocabulary, put the rows back
CREATE TABLE policy_events_keep AS SELECT * FROM policy_events;
DROP TRIGGER IF EXISTS policy_events_no_update;
DROP TRIGGER IF EXISTS policy_events_no_delete;
DROP INDEX IF EXISTS policy_events_policy;
DROP TABLE policy_events;
CREATE TABLE policy_events (
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
INSERT INTO policy_events (id, policy_id, policy_version, event, actor, actor_id, role, reason, release_tag, evidence, request_id, at) SELECT id, policy_id, policy_version, event, actor, actor_id, role, reason, release_tag, evidence, request_id, at FROM policy_events_keep;
DROP TABLE policy_events_keep;
CREATE INDEX IF NOT EXISTS policy_events_policy ON policy_events (policy_id);
CREATE TRIGGER IF NOT EXISTS policy_events_no_update BEFORE UPDATE ON policy_events BEGIN SELECT RAISE(ABORT, 'policy events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS policy_events_no_delete BEFORE DELETE ON policy_events BEGIN SELECT RAISE(ABORT, 'policy events are append-only'); END;
-- members: keep the rows aside, recreate under the same name, put the rows back, restore the unique index
CREATE TABLE members_keep AS SELECT * FROM members;
DROP INDEX IF EXISTS members_user_id;
DROP TABLE members;
CREATE TABLE members (login TEXT PRIMARY KEY, role TEXT NOT NULL CHECK (role IN ('VIEWER','REVIEWER','ADMIN')), granted_by TEXT NOT NULL, at TEXT NOT NULL, user_id INTEGER, updated_at TEXT);
INSERT INTO members (login, role, granted_by, at, user_id, updated_at) SELECT login, role, granted_by, at, user_id, updated_at FROM members_keep;
DROP TABLE members_keep;
CREATE UNIQUE INDEX IF NOT EXISTS members_user_id ON members (user_id) WHERE user_id IS NOT NULL;
