-- Additive migration: durable outbox for operational events sent to GuardOps (apply once, remote only with the owner's authorisation).
CREATE TABLE IF NOT EXISTS guardops_outbox (event_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, envelope TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('pending','sent','dead')), attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL, last_error TEXT, sent_at TEXT);
CREATE INDEX IF NOT EXISTS guardops_outbox_due ON guardops_outbox(state, next_attempt_at);
