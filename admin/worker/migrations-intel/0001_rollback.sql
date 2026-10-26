-- Rollback of 0001: drops only what 0001 created in the INTEL database. Export first if the promoted data is needed (it can also be promoted again from the local channel directories).
DROP TRIGGER IF EXISTS intel_events_no_update;
DROP TRIGGER IF EXISTS intel_events_no_delete;
DROP INDEX IF EXISTS intel_events_ts;
DROP INDEX IF EXISTS intel_events_run;
DROP TABLE IF EXISTS intel_events;
DROP INDEX IF EXISTS intel_records_family;
DROP INDEX IF EXISTS intel_records_key;
DROP INDEX IF EXISTS intel_records_state;
DROP TABLE IF EXISTS intel_records;
DROP INDEX IF EXISTS intel_runs_source;
DROP TABLE IF EXISTS intel_runs;
DROP TABLE IF EXISTS intel_sources;
