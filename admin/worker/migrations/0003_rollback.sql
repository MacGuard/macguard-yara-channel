-- Rollback of 0003. Roll the Worker and the pipeline files back first, and read the precondition below. NOT RUN by the task that wrote it.
-- Precondition (run before, expect 0 rows; otherwise export them with SELECT * FROM policies / policy_lifts / policy_events and decide): SELECT id FROM policies WHERE status = 'ACTIVE';
-- Dropping with ACTIVE policies silently re-allows the prohibited rules at the next daily run of a pipeline that does not know policies. The audit chain keeps a full copy of every policy event in audit.detail.
-- Only objects created by 0003 are dropped; no existing table is read or written.
DROP TRIGGER IF EXISTS policy_lifts_breakglass_review_overdue;
DROP TRIGGER IF EXISTS policy_lifts_breakglass_needs_critical;
DROP TRIGGER IF EXISTS policy_lifts_direct_standard_only;
DROP TRIGGER IF EXISTS policy_lifts_two_step_born_open;
DROP TRIGGER IF EXISTS policy_lifts_closed_is_final;
DROP TRIGGER IF EXISTS policy_lifts_version_step;
DROP TRIGGER IF EXISTS policy_lifts_identity_frozen;
DROP TRIGGER IF EXISTS policy_lifts_no_delete;
DROP TRIGGER IF EXISTS policies_lift_needs_recorded_authorization;
DROP TRIGGER IF EXISTS policies_withdrawal_forward;
DROP TRIGGER IF EXISTS policies_lifted_is_final;
DROP TRIGGER IF EXISTS policies_version_step;
DROP TRIGGER IF EXISTS policies_identity_frozen;
DROP TRIGGER IF EXISTS policies_no_delete;
DROP TRIGGER IF EXISTS policy_events_no_delete;
DROP TRIGGER IF EXISTS policy_events_no_update;
DROP INDEX IF EXISTS policy_events_policy;
DROP TABLE IF EXISTS policy_events;
DROP INDEX IF EXISTS policy_lifts_review;
DROP INDEX IF EXISTS policy_lifts_policy;
DROP INDEX IF EXISTS policy_lifts_open;
DROP TABLE IF EXISTS policy_lifts;
DROP INDEX IF EXISTS policies_status;
DROP INDEX IF EXISTS policies_candidate;
DROP INDEX IF EXISTS policies_active_key;
DROP TABLE IF EXISTS policies;
