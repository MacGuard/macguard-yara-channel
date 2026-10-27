-- Rollback of 0003 (the decisions themselves stay in intel_decisions; the Worker falls back to the join over intel_current).
DROP TRIGGER IF EXISTS intel_decisions_apply; DROP TABLE IF EXISTS intel_decided; DROP TABLE IF EXISTS intel_snapshot;
