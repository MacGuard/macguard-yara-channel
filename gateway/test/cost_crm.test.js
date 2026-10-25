import test from 'node:test';
import assert from 'node:assert/strict';
import { toMicros, parseCsv, importCsv, setRate, estimate, costSummary, unitCosts } from '../src/cost.js';
import { createLead, moveLead, listLeads, crmSummary } from '../src/crm.js';
import { world } from './helpers.js';

test('amounts parse exactly: no float error, no silent rounding, no ambiguous formats', () => {
  assert.equal(toMicros('0.1'), 100000); assert.equal(toMicros('12.345678'), 12345678); assert.equal(toMicros('-3.5'), -3500000); assert.equal(toMicros('0.000001'), 1);
  for (const bad of ['1,234.50', '1.1234567', '$5', '1e3', '', '--1', '1.', '.5', '1234567890']) assert.throws(() => toMicros(bad), /Not a plain decimal/, bad);
});
test('CSV parsing handles quotes, doubled quotes and CRLF', () => { assert.deepEqual(parseCsv('a,b\r\n"x, y","say ""hi"""\r\n'), [['a', 'b'], ['x, y', 'say "hi"']]); });

const INV = 'period,service,amount,currency,invoice_ref,tenant_id\n2026-09,workers,5.00,USD,INV-1,\n2026-09,workers,5.00,USD,INV-1,\n2026-09,r2,0.123456,USD,INV-1,t1\n2026-09,b2,7.5,EUR,INV-9,\n';
test('invoice import is idempotent, keeps two identical lines distinct, and is all-or-nothing', async () => {
  const w = await world(); await w.tenant('t1');
  const a = await importCsv(w.db, w.clock, INV, { provider: 'cloudflare' }); assert.deepEqual([a.imported, a.ignored, a.rejected], [4, 0, 0]);
  const b = await importCsv(w.db, w.clock, INV, { provider: 'cloudflare' }); assert.deepEqual([b.imported, b.ignored], [0, 4], 're-importing the same file adds nothing');
  const bad = await importCsv(w.db, w.clock, 'period,service,amount,currency\n2026-09,x,1.00,USD\n2026-13,y,2.00,USD\n2026-09,z,abc,USD\n', { provider: 'backblaze' });
  assert.equal(bad.imported, 0); assert.equal(bad.rejected, 2); assert.deepEqual(bad.errors.map((e) => e.line), [3, 4]); assert.equal((await w.db.prepare("SELECT COUNT(*) n FROM cost_entries WHERE provider='backblaze'").first()).n, 0);
  await assert.rejects(importCsv(w.db, w.clock, 'period,service,amount\n2026-09,x,1\n', { provider: 'cloudflare' }), /Missing column/); await assert.rejects(importCsv(w.db, w.clock, INV, { provider: 'nope' }), /Unknown provider/);
});
test('estimates exist only with an owner-supplied rate and a measured quantity; allocated, unallocated and currencies stay apart', async () => {
  const w = await world({ now: '2026-09-30T10:00:00Z' }); await w.tenant('t1'); await importCsv(w.db, w.clock, INV, { provider: 'cloudflare' });
  assert.deepEqual((await estimate(w.db, w.clock, '2026-09')).estimated, []); const none = await estimate(w.db, w.clock, '2026-09'); assert.ok(none.missing_rates.includes('cloudflare/workers/request'));
  await w.db.prepare("INSERT INTO analytics_daily(day,tenant_id,channel,product,operation,status_class,commercial_mode,requests) VALUES ('2026-09-05','t1','rest','intel','intel.hash','2xx','FREE_LAUNCH',2000)").run();
  await assert.rejects(setRate(w.db, w.clock, { provider: 'cloudflare', service: 'workers', usage_unit: 'request', micros_per_unit: 1, currency: 'USD', source_url: 'http://not-https' }), /https/);
  await assert.rejects(setRate(w.db, w.clock, { provider: 'cloudflare', service: 'd1', usage_unit: 'row', micros_per_unit: 1, currency: 'USD', source_url: 'https://x.test' }), /No measured quantity/);
  await setRate(w.db, w.clock, { provider: 'cloudflare', service: 'workers', usage_unit: 'request', micros_per_unit: 3000, currency: 'USD', source_url: 'https://example.test/pricing', as_of: '2026-09-01' });
  const e1 = await estimate(w.db, w.clock, '2026-09'), e2 = await estimate(w.db, w.clock, '2026-09'); assert.equal(e1.estimated[0].quantity, 2000); assert.equal(e2.estimated.length, 1);
  assert.equal((await w.db.prepare("SELECT COUNT(*) n FROM cost_entries WHERE kind='estimated'").first()).n, 1, 'recomputing replaces, never duplicates');
  const s = await costSummary(w.db, { period: '2026-09' }), wk = s.lines.find((l) => l.service === 'workers');
  assert.equal(wk.estimated_micros, 6000000); assert.equal(wk.confirmed_micros, 10000000); assert.equal(wk.unallocated_micros, 10000000); assert.equal(wk.reconciliation.status, 'MISMATCH'); assert.equal(wk.reconciliation.delta_micros, 4000000);
  assert.equal(s.lines.find((l) => l.service === 'r2').allocated_micros, 123456); assert.equal(s.lines.find((l) => l.service === 'r2').reconciliation.status, 'UNKNOWN');
  assert.deepEqual(Object.keys(s.totals_by_currency).sort(), ['EUR', 'USD']);
  assert.equal((await costSummary(w.db, { period: '2026-09', tenantId: 't1' })).lines.length, 1, 'a tenant sees only its allocated rows');
  assert.equal((await costSummary(w.db, { period: '2026-08' })).state, 'NO_DATA');
  const u = await unitCosts(w.db, '2026-09'); assert.equal(u.unit_costs[0].value, 5000000, '10 USD confirmed per 2000 requests = 5 USD per 1000'); assert.equal(u.unit_costs[0].accuracy, 'EXACT');
  assert.equal((await unitCosts(w.db, '2026-01')).unit_costs[0].value, null);
});

const admin = { id: 'adm1' };
test('CRM: leads move only along allowed transitions, WON is final, history is kept, and bulk listing hides contacts', async () => {
  const w = await world(); const l = await createLead(w.db, w.clock, admin, { org_name: 'Acme', contact: 'someone@acme.test', notes: 'asked for a demo' });
  await assert.rejects(createLead(w.db, w.clock, admin, { org_name: '' }), /org_name/); await assert.rejects(createLead(w.db, w.clock, admin, { org_name: 'X Corp', tenant_id: 'ghost' }), /Unknown tenant/);
  await assert.rejects(moveLead(w.db, w.clock, admin, l.lead_id, 'WON'), (e) => e.status === 409 && e.extra.allowed.includes('CONTACTED'));
  for (const s of ['CONTACTED', 'QUALIFIED', 'PILOT', 'PROPOSAL', 'WON']) await moveLead(w.db, w.clock, admin, l.lead_id, s);
  await assert.rejects(moveLead(w.db, w.clock, admin, l.lead_id, 'LOST'), /cannot move/);
  const l2 = await createLead(w.db, w.clock, admin, { org_name: 'Beta' }); await moveLead(w.db, w.clock, admin, l2.lead_id, 'LOST');
  const sum = await crmSummary(w.db); assert.equal(sum.total, 2); assert.equal(sum.current.WON, 1); assert.equal(sum.ever_reached.PILOT, 1); assert.equal(sum.win_rate, 0.5);
  const list = await listLeads(w.db, { limit: 1 }); assert.equal(list.leads.length, 1); assert.ok(list.next_cursor); assert.ok(!JSON.stringify(list).includes('acme.test'));
  assert.equal((await crmSummary((await world()).db)).state, 'NO_DATA');
});

import { pruneAnalytics } from '../src/retention.js';
test('retention removes telemetry older than a year, keeps the ledger/costs/leads, and keeps first-seen rows of actors still active', async () => {
  const w = await world({ now: '2027-10-23T10:00:00Z' }); await w.tenant('t1');
  const act = (d, a) => w.db.batch([w.db.prepare("INSERT INTO activity_daily(day,tenant_id,actor_kind,actor_hash,premium) VALUES (?, 't1','api_key_client',?,0)").bind(d, a), w.db.prepare("INSERT OR IGNORE INTO actor_first_seen(tenant_id,actor_kind,actor_hash,first_day) VALUES ('t1','api_key_client',?,?)").bind(a, d)]);
  await act('2026-09-01', 'old'); await act('2026-09-01', 'still'); await act('2027-10-01', 'still');
  await w.db.prepare("INSERT INTO analytics_daily(day,tenant_id,channel,product,operation,status_class,commercial_mode,requests) VALUES ('2026-09-01','t1','rest','x','op','2xx','FREE_LAUNCH',1),('2027-10-22','t1','rest','x','op','2xx','FREE_LAUNCH',1)").run();
  await importCsv(w.db, w.clock, 'period,service,amount,currency\n2026-01,workers,1.00,USD\n', { provider: 'cloudflare' }); await createLead(w.db, w.clock, { id: 'a' }, { org_name: 'Acme' });
  const r = await pruneAnalytics(w.db, w.clock); assert.equal(r.cutoff, '2026-10-23'); assert.equal(r.deleted.analytics_daily, 1);
  const q = async (s) => (await w.db.prepare(s).first()).n;
  assert.equal(await q('SELECT COUNT(*) n FROM analytics_daily'), 1); assert.equal(await q("SELECT COUNT(*) n FROM activity_daily WHERE actor_hash='old'"), 0);
  assert.equal(await q("SELECT COUNT(*) n FROM actor_first_seen WHERE actor_hash='old'"), 0, 'inactive for a year: its first-seen row goes'); assert.equal(await q("SELECT COUNT(*) n FROM actor_first_seen WHERE actor_hash='still'"), 1, 'still active: kept');
  assert.equal(await q('SELECT COUNT(*) n FROM cost_entries'), 1); assert.equal(await q('SELECT COUNT(*) n FROM leads'), 1);
});
