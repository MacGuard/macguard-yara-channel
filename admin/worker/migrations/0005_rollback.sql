-- Rollback of 0005. Roll the Worker back first (wrangler rollback), then run this.
-- Drops only objects created by 0005. The hash-chained `audit` table is NOT touched: the audit rows written for source proposals stay in the chain
-- (they are generic rows and verifyChain still passes). The proposal history held in source_proposal_events is lost: export it first if it is needed.
DROP TRIGGER IF EXISTS spe_no_update;
DROP TRIGGER IF EXISTS spe_no_delete;
DROP INDEX IF EXISTS source_proposal_events_req;
DROP INDEX IF EXISTS source_proposal_events_p;
DROP TABLE IF EXISTS source_proposal_events;
DROP INDEX IF EXISTS source_proposals_open_id;
DROP INDEX IF EXISTS source_proposals_open_repo;
DROP INDEX IF EXISTS source_proposals_repo;
DROP INDEX IF EXISTS source_proposals_state;
DROP TABLE IF EXISTS source_proposals;
