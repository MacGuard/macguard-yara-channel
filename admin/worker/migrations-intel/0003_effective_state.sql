-- 0003 (INTEL): cheap reads. Requires 0002. The panel used to scan the whole table (75,148 rows) on every Intelligence screen; D1 bills every row scanned, and that exhausted the free daily quota.
-- 1) intel_decided: ONE small row per decided record with its effective state, kept in step with intel_decisions by a trigger. It is a SEPARATE table on purpose: nothing is altered or rewritten in
--    the 75k-row intel_records (no ALTER TABLE, no index over the records), a re-import that REPLACEs a record cannot lose a decision, and the migration writes only as many rows as there are decisions.
-- 2) intel_snapshot: one row of precomputed counts, rebuilt only when a promotion changes the data.
CREATE TABLE IF NOT EXISTS intel_decided (record_id TEXT PRIMARY KEY, state TEXT NOT NULL, decision_id INTEGER NOT NULL) WITHOUT ROWID;
INSERT OR REPLACE INTO intel_decided (record_id, state, decision_id) SELECT d.record_id, d.to_state, d.id FROM intel_decisions d WHERE d.id = (SELECT MAX(x.id) FROM intel_decisions x WHERE x.record_id = d.record_id);
CREATE TRIGGER IF NOT EXISTS intel_decisions_apply AFTER INSERT ON intel_decisions BEGIN INSERT OR REPLACE INTO intel_decided (record_id, state, decision_id) VALUES (NEW.record_id, NEW.to_state, NEW.id); END;
CREATE TABLE IF NOT EXISTS intel_snapshot (id INTEGER PRIMARY KEY CHECK (id = 1), marker TEXT NOT NULL, json TEXT NOT NULL CHECK (json_valid(json)), generated_at TEXT NOT NULL, rows_read INTEGER);
