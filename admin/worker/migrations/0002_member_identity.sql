-- 0002: bind panel members to the immutable GitHub account id, and let candidates be archived without deleting anything.
-- Additive only: the previous Worker version keeps working against this schema (it ignores the new columns).
-- Apply once to a database created from schema.sql v1:  wrangler d1 execute <db> --remote --file migrations/0002_member_identity.sql
ALTER TABLE members ADD COLUMN user_id INTEGER;
ALTER TABLE members ADD COLUMN updated_at TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS members_user_id ON members (user_id) WHERE user_id IS NOT NULL;
ALTER TABLE candidates ADD COLUMN archived_at TEXT;
-- The four synthetic acceptance-test candidates leave the operational views. Their rows, decisions and audit entries stay.
-- Matched by exact id AND sha256 (as exported in docs/audit/evidence/quarantine-acceptance-synthetic-2026-10-20.json): nothing else can be archived.
UPDATE candidates SET archived_at = '2026-10-20T00:00:00.000Z'
  WHERE source = 'synthetic-test' AND path LIKE 'synthetic-quarantine-test/%'
  AND (id, sha256) IN (VALUES
  ('680aae67-48ce-4bd1-bbd3-627f4bee53da', '4fa1288eb21c0c29772c5da12cde20a357536ad16f491d1206f8ec35b9e87ad7'),
  ('e4bcc33a-cc1e-4dd1-b8ce-7ce0dae47379', 'e54fb21f53ec406b1083d6575c61c110fa69d336d3abbba2dce43a1afc8200da'),
  ('621e4ade-f4f9-47e6-beaa-2f743f29928d', '55ba01dd805b6d3cf8b90c7e24c8749a95c79fc567edad651b9be6393a04d66f'),
  ('b922891f-4683-407b-9434-c97eb49c6fa2', 'fa4fa1a5b0a1008cfb84ab7ada3d27912649d2e52f5ff682f8439863d2c1b250'))
  AND archived_at IS NULL;
