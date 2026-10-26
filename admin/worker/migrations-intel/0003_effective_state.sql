-- 0003 (INTEL): cheap reads. Requires 0002. The panel used to scan the whole table (75,148 rows) on every Intelligence screen; D1 bills every row scanned, and that exhausted the free daily quota.
-- 1) intel_records.decided_state: the effective state set by the latest human decision (NULL = nothing decided). A trigger keeps it in step with intel_decisions, and a second trigger keeps it
--    when a re-import REPLACEs a row. The partial index starts EMPTY, so creating it writes no rows. 2) intel_snapshot: one row of precomputed counts, rebuilt only when a promotion changes the data.
-- ALTER TABLE ... ADD COLUMN is not idempotent: apply once (tools/migration_trial2.sh and the runbook check pragma_table_info first).
ALTER TABLE intel_records ADD COLUMN decided_state TEXT;
UPDATE intel_records SET decided_state = (SELECT c.state FROM intel_current c WHERE c.record_id = intel_records.id) WHERE id IN (SELECT record_id FROM intel_decisions);
CREATE INDEX IF NOT EXISTS intel_records_decided ON intel_records (decided_state) WHERE decided_state IS NOT NULL;
CREATE TRIGGER IF NOT EXISTS intel_decisions_apply AFTER INSERT ON intel_decisions BEGIN UPDATE intel_records SET decided_state = NEW.to_state WHERE id = NEW.record_id; END;
CREATE TRIGGER IF NOT EXISTS intel_records_keep_decision AFTER INSERT ON intel_records WHEN EXISTS (SELECT 1 FROM intel_decisions WHERE record_id = NEW.id) BEGIN UPDATE intel_records SET decided_state = (SELECT state FROM intel_current WHERE record_id = NEW.id) WHERE id = NEW.id; END;
CREATE TABLE IF NOT EXISTS intel_snapshot (id INTEGER PRIMARY KEY CHECK (id = 1), marker TEXT NOT NULL, json TEXT NOT NULL CHECK (json_valid(json)), generated_at TEXT NOT NULL, rows_read INTEGER);
