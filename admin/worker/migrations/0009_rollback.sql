-- Rollback of 0009 (export the reviews first: this drops them). 0008 and its requests are untouched.
DROP TRIGGER IF EXISTS publication_request_reviews_no_delete; DROP TRIGGER IF EXISTS publication_request_reviews_no_update; DROP TABLE IF EXISTS publication_request_reviews;
