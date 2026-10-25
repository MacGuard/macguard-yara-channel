-- Additive migration for a gateway database created before the column existed (apply once; a column cannot be added twice, so use `wrangler d1 migrations apply`, which records it):
ALTER TABLE gh_sync ADD COLUMN authenticated INTEGER NOT NULL DEFAULT 0;
