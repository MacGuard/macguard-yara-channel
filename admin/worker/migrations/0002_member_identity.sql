-- 0002: bind panel members to the immutable GitHub account id, and let candidates be archived without deleting anything.
-- Additive only: the previous Worker version keeps working against this schema (it ignores the new columns).
-- Apply once to a database created from schema.sql v1:  wrangler d1 execute <db> --remote --file migrations/0002_member_identity.sql
ALTER TABLE members ADD COLUMN user_id INTEGER;
ALTER TABLE members ADD COLUMN updated_at TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS members_user_id ON members (user_id) WHERE user_id IS NOT NULL;
ALTER TABLE candidates ADD COLUMN archived_at TEXT;
-- Decision 5: the four synthetic acceptance-test candidates leave the operational views. Their rows, decisions and audit entries stay.
UPDATE candidates SET archived_at = '2026-10-20T00:00:00.000Z' WHERE source = 'synthetic-test' AND path LIKE 'synthetic-quarantine-test/%' AND archived_at IS NULL;
