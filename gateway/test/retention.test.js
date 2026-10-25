import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { pruneAnalytics, RETENTION_DAYS } from '../src/retention.js';
import { addDays } from '../src/kpi.js';
import { openDb } from '../tools/sqlite_d1.mjs';
import { world } from './helpers.js';
import { audit } from '../src/audit.js';
import { importCsv } from '../src/cost.js';
import { createLead } from '../src/crm.js';

const digest = (raw, tables) => createHash('sha256').update(tables.map((t) => JSON.stringify(raw.prepare(`SELECT * FROM ${t} ORDER BY 1,2`).all())).join('|')).digest('hex');
const PROTECTED = ['audit', 'usage_events', 'cost_entries', 'cost_rates', 'leads', 'lead_events', 'policy_versions', 'policy_pointer', 'tenants', 'api_keys', 'admins', 'gh_assets', 'gh_releases', 'downloads', 'tenant_first_seen', 'telemetry_exclusions'];

test('the 365-day boundary is exact: day -365 stays, day -366 goes, across month ends and a leap day', async () => {
  for (const now of ['2026-10-23T03:17:00Z', '2028-03-01T03:17:00Z', '2027-01-01T00:05:00Z', '2029-02-28T23:59:00Z']) {
    const w = await world({ now }); const today = now.slice(0, 10), keep = addDays(today, -RETENTION_DAYS), drop = addDays(today, -RETENTION_DAYS - 1);
    for (const d of [drop, keep, today]) await w.db.prepare("INSERT INTO analytics_daily(day,tenant_id,channel,product,operation,status_class,commercial_mode,requests) VALUES (?,'t','rest','x','op','2xx','FREE_LAUNCH',1)").bind(d).run();
    const r = await pruneAnalytics(w.db, w.clock); assert.equal(r.cutoff, keep, now); assert.deepEqual((await w.db.prepare('SELECT day FROM analytics_daily ORDER BY day').all()).results.map((x) => x.day), [keep, today], now);
  }
  assert.equal(addDays('2028-03-01', -365), '2027-03-02', 'a leap year is counted in calendar days, not 365 x 24 h of months');
});
test('a controlled run on an ISOLATED in-memory database prunes only analytics, is idempotent, and leaves every protected table byte-identical', async () => {
  const w = await world({ now: '2027-10-23T03:17:00Z' }); await w.tenant('t1'); await audit(w.db, w.clock, 't1', 'x.y', { a: 1 }); await importCsv(w.db, w.clock, 'period,service,amount,currency\n2025-01,workers,1.00,USD\n', { provider: 'cloudflare' }); await createLead(w.db, w.clock, { id: 'a' }, { org_name: 'Acme' });
  await w.db.prepare("INSERT INTO gh_releases(release_id,repo,tag,first_observed_at,last_observed_at) VALUES (1,'o/r','rules-20250101-1','2025-01-02T00:00:00Z','2027-10-23T00:00:00Z')").run();
  await w.db.prepare("INSERT INTO gh_assets(asset_id,release_id,name,kind,size,first_observed_at,last_observed_at,last_count) VALUES (10,1,'rules-release.tar.gz','bundle',1,'2025-01-02T00:00:00Z','2027-10-23T00:00:00Z',50)").run();
  await w.db.prepare("INSERT INTO gh_observations(asset_id,observed_at,download_count,kind) VALUES (10,'2025-01-02T00:00:00Z',10,'baseline'),(10,'2027-10-01T00:00:00Z',50,'baseline')").run();
  const iso = openDb(':memory:');   // a separate database with the same schema and a large synthetic history
  for (const d of Array.from({ length: 800 }, (_, i) => addDays('2027-10-23', -i))) { await iso.prepare("INSERT INTO analytics_daily(day,tenant_id,channel,product,operation,status_class,commercial_mode,requests) VALUES (?,'t','rest','x','op','2xx','FREE_LAUNCH',5)").bind(d).run(); await iso.prepare("INSERT INTO activity_daily(day,tenant_id,actor_kind,actor_hash,premium) VALUES (?,'t','api_key_client','a',0)").bind(d).run(); }
  const before = digest(w.db.raw, PROTECTED); const r = await pruneAnalytics(iso, w.clock); assert.equal(r.deleted.analytics_daily, 800 - 366); assert.equal(r.deleted.activity_daily, 800 - 366);
  assert.equal((await iso.prepare('SELECT COUNT(*) n FROM analytics_daily').first()).n, 366, 'today plus 365 days back');
  assert.equal((await iso.prepare('SELECT MIN(day) d FROM analytics_daily').first()).d, addDays('2027-10-23', -365));
  assert.deepEqual((await pruneAnalytics(iso, w.clock)).deleted.analytics_daily, 0, 'a second run deletes nothing');
  const r2 = await pruneAnalytics(w.db, w.clock); assert.equal(r2.deleted.gh_observations, 1, 'only the observation older than a year'); assert.equal(digest(w.db.raw, PROTECTED), before, 'protected tables unchanged, byte for byte');
  assert.equal((await w.db.prepare('SELECT COUNT(*) n FROM gh_observations').first()).n, 1); assert.equal((await w.db.prepare('SELECT last_count FROM gh_assets').first()).last_count, 50, 'the current counter is kept');
});
test('the retention code names no protected table: audit, ledger, costs, policy and evidence cannot be pruned by it', async () => {
  const { readFileSync } = await import('node:fs'); const src = readFileSync(new URL('../src/retention.js', import.meta.url), 'utf8');
  for (const t of ['audit', 'usage_events', 'cost_entries', 'leads', 'policy_versions', 'admins', 'api_keys', 'downloads', 'gh_assets', 'gh_releases']) assert.ok(!new RegExp(`(DELETE FROM|UPDATE)\\s+${t}\\b`).test(src), t);
});
