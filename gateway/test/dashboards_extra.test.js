// The four dashboards added in the second closing round: retention, pipeline, signatures, cas_backups. Local; synthetic worlds only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { world } from './helpers.js';
import { apiWorld } from './apiworld.js';
import { dashboard, DASHBOARDS } from '../src/dashboards.js';

const byId = (d) => Object.fromEntries(d.panels.map((p) => [p.id, p]));

test('the new dashboards exist and a brand-new world shows explicit states, never zeros', async () => {
  const w = await world({ now: '2026-10-24T05:00:00Z' });
  for (const id of ['retention', 'pipeline', 'signatures', 'cas_backups']) assert.ok(DASHBOARDS.includes(id), id);
  const p = byId(await dashboard(w.db, w.clock, 'pipeline'));
  assert.equal(p.premium_published.state, 'NO_DATA'); assert.match(p.premium_published.empty_reason, /not operational/); assert.equal(p.sources.data, null);
  const s = byId(await dashboard(w.db, w.clock, 'signatures'));
  assert.equal(s.integrity.state, 'NO_DATA'); assert.equal(s.signature.state, 'NOT_INSTRUMENTED'); assert.equal(s.transparency.state, 'NOT_INSTRUMENTED'); assert.equal(s.signature.data, null);
  const c = byId(await dashboard(w.db, w.clock, 'cas_backups'));
  assert.equal(c.cas.state, 'NOT_INSTRUMENTED'); assert.equal(c.backups.state, 'NOT_INSTRUMENTED');
  const r = byId(await dashboard(w.db, w.clock, 'retention')); assert.equal(r.policy.data.analytics_days, 365); assert.ok(r.d30.state !== 'REAL_VERIFIED' || r.d30.data !== null);
});

test('pipeline and signatures show the real rows of the database and do not call a seeded bundle "published Premium" unless a Premium release row says so', async () => {
  const w = await apiWorld({ envExtra: { KEY_PEPPER: 'k'.repeat(40) } });
  const p = byId(await dashboard(w.db, w.clock, 'pipeline'));
  assert.equal(p.sources.state, 'REAL_VERIFIED'); assert.ok(p.sources.data.some((x) => x.status === 'PREMIUM_APPROVED')); assert.equal(p.records.state, 'REAL_VERIFIED');
  assert.equal(p.releases.state, 'REAL_VERIFIED'); assert.equal(p.premium_published.state, 'REAL_VERIFIED'); assert.equal(p.premium_published.data, 2, 'two published premium rows exist in this synthetic world');
  const s = byId(await dashboard(w.db, w.clock, 'signatures')); assert.equal(s.integrity.data.total, 2); assert.ok(s.integrity.data.complete <= 2);
  assert.equal(s.signature.state, 'NOT_INSTRUMENTED', 'integrity hashes are not signatures');
});

test('the platform-level pipeline is not shown inside a tenant scope', async () => {
  const w = await apiWorld({ envExtra: { KEY_PEPPER: 'k'.repeat(40) } }); await w.tenant('t1');
  const p = byId(await dashboard(w.db, w.clock, 'pipeline', { tenantId: 't1' })); assert.equal(p.pipeline.state, 'NOT_APPLICABLE'); assert.equal(p.pipeline.data, null);
});

test('the offline renderer adds real backup state to cas_backups and says NO_DATA / FIRING honestly', async () => {
  const w = await world({ now: '2026-10-24T05:00:00Z' }), root = mkdtempSync(join(homedir(), '.mg-dash-')), out = mkdtempSync(join(homedir(), '.mg-dash-out-')); mkdirSync(join(root, 'x'), { recursive: true });
  try {
    writeFileSync(join(root, 'status.json'), JSON.stringify({ last_success_at: '2026-10-24T03:40:00Z', last_status: 'ok', encrypted: true, last_dir: 'x' }));
    const dbFile = join(out, 'gw.sqlite'); const { DatabaseSync } = await import('node:sqlite'); const d = new DatabaseSync(dbFile); const { dumpSql } = await import('../tools/backup_lib.mjs'); d.exec('PRAGMA foreign_keys = OFF'); d.exec(dumpSql(w.db.raw)); d.close();
    execFileSync('node', [new URL('../tools/render_dashboards.mjs', import.meta.url).pathname, '--db', dbFile, '--out', join(out, 'r'), '--now', '2026-10-24T06:00:00Z', '--backup-root', root], { stdio: 'pipe' });
    const j = JSON.parse((await import('node:fs')).readFileSync(join(out, 'r', 'dashboard-cas_backups.json'), 'utf8')), p = byId(j);
    assert.equal(p.backup_status.state, 'REAL_VERIFIED'); assert.equal(p.backup_status.data.last_status, 'ok'); assert.equal(p.restore_drills.state, 'NO_DATA');
    const al = Object.fromEntries(p.backup_alarms.data.map((a) => [a.rule_id, a.state])); assert.equal(al['backup.offsite_stale'], 'FIRING'); assert.equal(al['backup.drill_stale'], 'FIRING');
    assert.equal(p.backup_providers.state, 'NO_DATA'); assert.equal(p.backup_three_copies.state, 'NO_DATA'); assert.equal(al['backup.three_copies'], 'FIRING', 'no recorded copy: three copies is not claimed');
    writeFileSync(join(root, 'objstore.json'), JSON.stringify({ destinations: { b2: { last_verified_at: '2026-10-24T05:30:00Z', verified: '20261024T050235Z', last_drill_ok_at: '2026-10-24T05:40:00Z' } } }));
    execFileSync('node', [new URL('../tools/render_dashboards.mjs', import.meta.url).pathname, '--db', dbFile, '--out', join(out, 'r2'), '--now', '2026-10-24T06:00:00Z', '--backup-root', root], { stdio: 'pipe' });
    const q = byId(JSON.parse((await import('node:fs')).readFileSync(join(out, 'r2', 'dashboard-cas_backups.json'), 'utf8'))), rows = Object.fromEntries(q.backup_providers.data.map((r) => [r.provider, r]));
    assert.equal(q.backup_providers.state, 'REAL_VERIFIED'); assert.equal(rows.b2.copy_alarm, 'OK'); assert.equal(rows.b2.restore_alarm, 'OK'); assert.equal(rows.scaleway.copy_alarm, 'FIRING'); assert.equal(rows.r2.last_verified_copy_at, null);
    assert.deepEqual(q.backup_three_copies.data, { destinations_ok: 1, required: 3, alarm: 'FIRING' });
  } finally { rmSync(root, { recursive: true, force: true }); rmSync(out, { recursive: true, force: true }); }
});

test('DASHBOARDS.md is current, and on an empty gateway only static/definition panels claim REAL_VERIFIED: absence is never shown as data', async () => {
  execFileSync('node', [new URL('../tools/gen_dashboard_sources.mjs', import.meta.url).pathname, '--check'], { stdio: 'pipe' });
  const w = await world({ now: '2026-10-24T05:00:00Z' }), claims = [];
  for (const id of DASHBOARDS) for (const p of (await dashboard(w.db, w.clock, id)).panels) if (p.state === 'REAL_VERIFIED') claims.push(`${id}/${p.id}`);
  assert.deepEqual(claims.sort(), ['comparison/definitions', 'overview/alerts', 'retention/policy'], 'any other panel claiming real data on an empty database is a bug');
});
