-- 0004: audit anchors. Additive only: no existing table, column, trigger or row is touched; the previous Worker version ignores the new table.
-- Apply once (NOT executed by this change):  wrangler d1 execute <db> --remote --file migrations/0004_audit_anchor.sql
-- Rows are written only by src/anchor.js writeAnchor(), after the sealed audit segment is proven archived in three providers. Nothing is pruned by this migration.
-- BEGIN audit_anchor (0004)
CREATE TABLE IF NOT EXISTS audit_anchor (
  seq INTEGER PRIMARY KEY,          -- last audit seq of the sealed segment
  hash TEXT NOT NULL,               -- head hash of that segment (the hash the next retained entry links to)
  rows INTEGER NOT NULL CHECK (rows > 0),   -- entries in the segment
  seal_sha256 TEXT NOT NULL,        -- SHA-256 of the seal document
  created_at TEXT NOT NULL,
  author TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_anchor_no_update BEFORE UPDATE ON audit_anchor BEGIN SELECT RAISE(ABORT, 'audit anchors are append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_anchor_no_delete BEFORE DELETE ON audit_anchor BEGIN SELECT RAISE(ABORT, 'audit anchors are append-only'); END;
-- An anchor cannot disagree with an audit row that still exists at its position.
CREATE TRIGGER IF NOT EXISTS audit_anchor_matches_audit BEFORE INSERT ON audit_anchor
  WHEN EXISTS (SELECT 1 FROM audit WHERE seq = NEW.seq AND hash <> NEW.hash)
  BEGIN SELECT RAISE(ABORT, 'anchor hash does not match the audit entry at that seq'); END;
-- END audit_anchor (0004)
