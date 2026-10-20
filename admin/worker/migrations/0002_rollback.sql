-- Rollback of 0002 (schema only; nothing in audit or decisions is touched). Roll the Worker back first (wrangler rollback), then run this.
-- Members bound to an id keep their login and role, so the previous version still honours them by name.
UPDATE candidates SET archived_at = NULL WHERE archived_at IS NOT NULL;
DROP INDEX IF EXISTS members_user_id;
ALTER TABLE members DROP COLUMN user_id;
ALTER TABLE members DROP COLUMN updated_at;
ALTER TABLE candidates DROP COLUMN archived_at;
