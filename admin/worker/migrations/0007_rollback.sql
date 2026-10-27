-- Rollback of 0007 (export the rows first: this drops the requests).
DROP TRIGGER IF EXISTS source_requests_identity_frozen; DROP TRIGGER IF EXISTS source_requests_final; DROP TRIGGER IF EXISTS source_requests_no_delete; DROP TABLE IF EXISTS source_requests;
