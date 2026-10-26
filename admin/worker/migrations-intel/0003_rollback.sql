-- Rollback of 0003 (the decisions themselves stay in intel_decisions; the Worker falls back to the join over intel_current).
DROP TRIGGER IF EXISTS intel_records_keep_decision; DROP TRIGGER IF EXISTS intel_decisions_apply; DROP INDEX IF EXISTS intel_records_decided; DROP TABLE IF EXISTS intel_snapshot;
ALTER TABLE intel_records DROP COLUMN decided_state;
