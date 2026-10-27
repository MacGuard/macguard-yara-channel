-- Human decisions about promoted records (hold, quarantine, reject, approve). They live in the INTEL database so that the effective state of a record is computed in one query, but they are
-- a separate append-only table: the imported rows are never edited, a re-import cannot erase a decision, and the history of a record is its list of decisions. Triggers are on ONE line each.
-- `audited` flips from 0 to 1 once the matching entry exists in the panel's hash-chained audit log (a different database); a row left at 0 is visible as an anomaly, never hidden.
CREATE TABLE IF NOT EXISTS intel_decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  record_id TEXT NOT NULL,
  family TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('hold','quarantine','reject','approve')),
  from_state TEXT,
  to_state TEXT NOT NULL CHECK (to_state IN ('RETENIDA','QUARANTINED','REJECTED','APPROVED')),
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 5 AND 2000),
  actor TEXT NOT NULL,
  actor_id INTEGER NOT NULL,
  at TEXT NOT NULL,
  request_id TEXT NOT NULL,
  audited INTEGER NOT NULL DEFAULT 0 CHECK (audited IN (0, 1)),
  UNIQUE (request_id, record_id)
);
CREATE INDEX IF NOT EXISTS intel_decisions_record ON intel_decisions (record_id, id DESC);
CREATE INDEX IF NOT EXISTS intel_decisions_request ON intel_decisions (request_id);
CREATE VIEW IF NOT EXISTS intel_current AS SELECT d.record_id AS record_id, d.to_state AS state, d.at AS at, d.actor AS actor FROM intel_decisions d WHERE d.id = (SELECT MAX(x.id) FROM intel_decisions x WHERE x.record_id = d.record_id);
CREATE TRIGGER IF NOT EXISTS intel_decisions_no_delete BEFORE DELETE ON intel_decisions BEGIN SELECT RAISE(ABORT, 'intel decisions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS intel_decisions_audit_only BEFORE UPDATE ON intel_decisions WHEN NOT (OLD.audited = 0 AND NEW.audited = 1 AND NEW.id = OLD.id AND NEW.record_id = OLD.record_id AND NEW.family = OLD.family AND NEW.action = OLD.action AND NEW.to_state = OLD.to_state AND NEW.reason = OLD.reason AND NEW.actor = OLD.actor AND NEW.actor_id = OLD.actor_id AND NEW.at = OLD.at AND NEW.request_id = OLD.request_id AND COALESCE(NEW.from_state, '') = COALESCE(OLD.from_state, '')) BEGIN SELECT RAISE(ABORT, 'intel decisions are append-only; only the audit flag may be set'); END;
