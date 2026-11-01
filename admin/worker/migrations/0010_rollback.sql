-- Rollback of 0010 (export the rows first: this drops the dispatch, claim and pin records). 0008 and 0009 are untouched.
DROP TRIGGER IF EXISTS publication_release_pins_no_delete; DROP TRIGGER IF EXISTS publication_release_pins_no_update; DROP TABLE IF EXISTS publication_release_pins;
DROP TRIGGER IF EXISTS publication_request_claims_no_delete; DROP TRIGGER IF EXISTS publication_request_claims_no_update; DROP TABLE IF EXISTS publication_request_claims;
DROP TRIGGER IF EXISTS publication_request_dispatches_no_delete; DROP TRIGGER IF EXISTS publication_request_dispatches_no_update; DROP INDEX IF EXISTS publication_request_dispatches_request; DROP TABLE IF EXISTS publication_request_dispatches;
