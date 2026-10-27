-- Rollback of 0002 (only after exporting intel_decisions: this drops the human decisions).
DROP TRIGGER IF EXISTS intel_decisions_audit_only; DROP TRIGGER IF EXISTS intel_decisions_no_delete; DROP VIEW IF EXISTS intel_current; DROP TABLE IF EXISTS intel_decisions;
