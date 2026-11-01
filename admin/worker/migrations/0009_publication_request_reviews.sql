-- 0009: the post-execution review of an emergency publication request (review F4 of #53). Its own append-only record, one per request, so it can be
-- written after the request closed (a closed request row is final). A NEW migration, not an edit of 0008: a database that already applied 0008 gets it here.
CREATE TABLE IF NOT EXISTS publication_request_reviews (
  request_id TEXT PRIMARY KEY,
  at TEXT NOT NULL,
  by_login TEXT NOT NULL,
  by_id INTEGER NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('APPROPRIATE','INAPPROPRIATE')),
  reason TEXT NOT NULL CHECK (length(trim(reason)) >= 5)
);
CREATE TRIGGER IF NOT EXISTS publication_request_reviews_no_update BEFORE UPDATE ON publication_request_reviews BEGIN SELECT RAISE(ABORT, 'publication request reviews are append-only'); END;
CREATE TRIGGER IF NOT EXISTS publication_request_reviews_no_delete BEFORE DELETE ON publication_request_reviews BEGIN SELECT RAISE(ABORT, 'publication request reviews are append-only'); END;
