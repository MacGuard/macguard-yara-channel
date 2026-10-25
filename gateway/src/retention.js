// Analytics retention: one year. Prunes ONLY the telemetry aggregates; the billing ledger (usage_events), audit chain, cost entries, leads and policy are never touched.
// An actor's first-seen row is removed only when the actor has no activity left inside the window (otherwise it would look "new" again and corrupt cohorts).
import { addDays } from './kpi.js';

export const RETENTION_DAYS = 365;
export async function pruneAnalytics(db, clock, days = RETENTION_DAYS) {
  const cutoff = addDays(clock().toISOString().slice(0, 10), -days), cutIso = cutoff + 'T00:00:00Z', n = {};
  const run = async (key, sql, ...a) => { n[key] = (await db.prepare(sql).bind(...a).run()).meta.changes; };
  await run('analytics_daily', 'DELETE FROM analytics_daily WHERE day < ?', cutoff);
  await run('activity_daily', 'DELETE FROM activity_daily WHERE day < ?', cutoff);
  await run('community_requests_daily', 'DELETE FROM community_requests_daily WHERE day < ?', cutoff);
  await run('gh_observations', 'DELETE FROM gh_observations WHERE observed_at < ?', cutIso);
  await run('gh_sync_log', 'DELETE FROM gh_sync_log WHERE observed_at < ?', cutIso);
  await run('actor_first_seen', 'DELETE FROM actor_first_seen WHERE first_day < ? AND NOT EXISTS (SELECT 1 FROM activity_daily a WHERE a.tenant_id = actor_first_seen.tenant_id AND a.actor_kind = actor_first_seen.actor_kind AND a.actor_hash = actor_first_seen.actor_hash)', cutoff);
  return { cutoff, deleted: n };
}
