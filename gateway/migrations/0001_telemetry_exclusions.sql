-- Additive migration for a gateway database created before this table existed (apply once, remote only with the owner's authorisation):
--   wrangler d1 execute macguard-gateway --remote --file migrations/0001_telemetry_exclusions.sql
CREATE TABLE IF NOT EXISTS telemetry_exclusions (source TEXT NOT NULL CHECK (source IN ('community_requests_daily')), row_key TEXT NOT NULL, row_digest TEXT NOT NULL, reason TEXT NOT NULL, marked_by TEXT NOT NULL, marked_at TEXT NOT NULL, PRIMARY KEY (source, row_key));
