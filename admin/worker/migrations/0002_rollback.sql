-- Rollback of 0002 (schema only; nothing in audit or decisions is touched). Roll the Worker back first (wrangler rollback), then run this.
-- Members bound to an id keep their login and role, so the previous version still honours them by name.
-- Only the four rows that 0002 archived are restored, by the same exact id and sha256.
UPDATE candidates SET archived_at = NULL
  WHERE source = 'synthetic-test' AND path LIKE 'synthetic-quarantine-test/%'
  AND (id, sha256) IN (VALUES
  ('680aae67-48ce-4bd1-bbd3-627f4bee53da', '4fa1288eb21c0c29772c5da12cde20a357536ad16f491d1206f8ec35b9e87ad7'),
  ('e4bcc33a-cc1e-4dd1-b8ce-7ce0dae47379', 'e54fb21f53ec406b1083d6575c61c110fa69d336d3abbba2dce43a1afc8200da'),
  ('621e4ade-f4f9-47e6-beaa-2f743f29928d', '55ba01dd805b6d3cf8b90c7e24c8749a95c79fc567edad651b9be6393a04d66f'),
  ('b922891f-4683-407b-9434-c97eb49c6fa2', 'fa4fa1a5b0a1008cfb84ab7ada3d27912649d2e52f5ff682f8439863d2c1b250'));
DROP INDEX IF EXISTS members_user_id;
ALTER TABLE members DROP COLUMN user_id;
ALTER TABLE members DROP COLUMN updated_at;
ALTER TABLE candidates DROP COLUMN archived_at;
