-- Rollback of 0007. Leaves the 0005 schema byte-identical (test/intel_assurance.test.js compares sqlite_master). It DROPS the creation records, reviewer events,
-- reviews, lifecycle markers and source-approval events (export them first: intel backup) and the evidence column original_source_id (evidence rows are kept).
-- No 0001-0005 row is deleted or altered. Relationships created after 0007 stay (relationships are never deleted) and fall back to the 0004/0005 rules.
DROP VIEW IF EXISTS intel_relationship_public;
DROP VIEW IF EXISTS intel_relationship_lifecycle;
DROP VIEW IF EXISTS intel_relationship_conflicts;
DROP VIEW IF EXISTS intel_source_approvals;
DROP VIEW IF EXISTS intel_reviewers_active;
DROP VIEW IF EXISTS intel_reviewers;
DROP TRIGGER IF EXISTS intel_entity_types_frozen_insert; DROP TRIGGER IF EXISTS intel_entity_types_frozen_update; DROP TRIGGER IF EXISTS intel_entity_types_frozen_delete;
DROP TRIGGER IF EXISTS intel_relationship_types_frozen_insert; DROP TRIGGER IF EXISTS intel_relationship_types_frozen_update; DROP TRIGGER IF EXISTS intel_relationship_types_frozen_delete;
DROP TRIGGER IF EXISTS intel_entities_key_cve; DROP TRIGGER IF EXISTS intel_entities_key_cwe; DROP TRIGGER IF EXISTS intel_entities_key_hash; DROP TRIGGER IF EXISTS intel_entities_key_yara;
DROP TRIGGER IF EXISTS intel_rel_hash_method;
DROP TRIGGER IF EXISTS intel_rel_evidence_provenance; DROP TRIGGER IF EXISTS intel_rel_evidence_human_review; DROP TRIGGER IF EXISTS intel_rel_evidence_ai_weak;
DROP TRIGGER IF EXISTS intel_rel_assess_needs_creation; DROP TRIGGER IF EXISTS intel_rel_assess_no_ai; DROP TRIGGER IF EXISTS intel_rel_assess_method; DROP TRIGGER IF EXISTS intel_rel_assess_verified_review;
DROP TRIGGER IF EXISTS intel_rel_assess_detection_test; DROP TRIGGER IF EXISTS intel_rel_assess_identity_statement; DROP TRIGGER IF EXISTS intel_rel_assess_retracted;
DROP TRIGGER IF EXISTS intel_epss_history_vuln_only; DROP TRIGGER IF EXISTS intel_epss_history_no_delete; DROP TRIGGER IF EXISTS intel_epss_latest_no_delete; DROP TRIGGER IF EXISTS intel_version_ranges_no_delete;
DROP TRIGGER IF EXISTS intel_entity_types_no_overwrite; DROP TRIGGER IF EXISTS intel_relationship_types_no_overwrite; DROP TRIGGER IF EXISTS intel_entities_no_overwrite; DROP TRIGGER IF EXISTS intel_rel_no_overwrite; DROP TRIGGER IF EXISTS intel_rel_evidence_no_overwrite; DROP TRIGGER IF EXISTS intel_rel_assess_no_overwrite; DROP TRIGGER IF EXISTS intel_rel_state_no_overwrite; DROP TRIGGER IF EXISTS intel_source_snapshots_no_overwrite; DROP TRIGGER IF EXISTS intel_severity_no_overwrite; DROP TRIGGER IF EXISTS intel_epss_latest_no_overwrite; DROP TRIGGER IF EXISTS intel_epss_history_no_overwrite; DROP TRIGGER IF EXISTS intel_exploitation_no_overwrite; DROP TRIGGER IF EXISTS intel_version_ranges_no_overwrite; DROP TRIGGER IF EXISTS intel_packages_no_overwrite; DROP TRIGGER IF EXISTS intel_rel_creation_no_overwrite; DROP TRIGGER IF EXISTS intel_reviewer_events_no_overwrite; DROP TRIGGER IF EXISTS intel_rel_reviews_no_overwrite; DROP TRIGGER IF EXISTS intel_rel_lifecycle_no_overwrite; DROP TRIGGER IF EXISTS intel_source_approval_no_overwrite; DROP TRIGGER IF EXISTS intel_rel_creation_chain_unique; DROP TRIGGER IF EXISTS intel_reviewer_events_chain_unique; DROP TRIGGER IF EXISTS intel_rel_reviews_chain_unique; DROP TRIGGER IF EXISTS intel_rel_lifecycle_chain_unique; DROP TRIGGER IF EXISTS intel_source_approval_chain_unique; DROP TRIGGER IF EXISTS intel_rel_creation_no_legacy; DROP TRIGGER IF EXISTS intel_source_approval_monotonic;
DROP TABLE IF EXISTS intel_source_approval_events;
DROP TABLE IF EXISTS intel_relationship_lifecycle_events;
DROP TABLE IF EXISTS intel_relationship_reviews;
DROP TABLE IF EXISTS intel_reviewer_events;
DROP TABLE IF EXISTS intel_relationship_creation;
DROP INDEX IF EXISTS intel_rel_evidence_unique;
ALTER TABLE intel_relationship_evidence DROP COLUMN original_source_id;
