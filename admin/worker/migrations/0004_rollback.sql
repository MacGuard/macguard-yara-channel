-- Rollback of 0004 (schema only; audit, decisions and every other table are untouched). Roll the Worker back first (wrangler rollback), then run this.
-- WARNING: this drops the anchors. Run it ONLY while no audit row has been pruned; after a prune the anchors are what let the chain verify, and the
-- archived segments (not D1) are then the only copy of the older history. Never run it after a prune without restoring those segments first.
DROP TRIGGER IF EXISTS audit_anchor_matches_audit;
DROP TRIGGER IF EXISTS audit_anchor_no_delete;
DROP TRIGGER IF EXISTS audit_anchor_no_update;
DROP TABLE IF EXISTS audit_anchor;
