-- Rollback of 0008 (export the rows first: this drops the requests and their events).
DROP TRIGGER IF EXISTS publication_request_events_no_delete; DROP TRIGGER IF EXISTS publication_request_events_no_update; DROP TRIGGER IF EXISTS publication_requests_final; DROP TRIGGER IF EXISTS publication_requests_version_step; DROP TRIGGER IF EXISTS publication_requests_identity_frozen; DROP TRIGGER IF EXISTS publication_requests_no_delete;
DROP TRIGGER IF EXISTS publication_request_reviews_no_delete; DROP TRIGGER IF EXISTS publication_request_reviews_no_update; DROP TABLE IF EXISTS publication_request_reviews;
DROP TABLE IF EXISTS publication_request_events; DROP TABLE IF EXISTS publication_requests;
