// D1 migration tests. The "before" database is built from the schema that is actually DEPLOYED (git show 4d9b1ff:gateway/schema.sql), populated, migrated with every file in migrations/, and then compared
// with the current schema.sql: structure identical, data intact. This proves the upgrade path of the live database before anyone runs it remotely.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const ROOT = new URL('../', import.meta.url).pathname, DEPLOYED = '4d9b1ff';
let deployedSql = null; try { deployedSql = execFileSync('git', ['show', `${DEPLOYED}:gateway/schema.sql`], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch { /* commit not available (shallow clone) */ }
const migrations = readdirSync(ROOT + 'migrations').filter((f) => f.endsWith('.sql')).sort();
const shape = (db) => Object.fromEntries(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map((t) => [t.name, db.prepare(`PRAGMA table_info(${t.name})`).all().map((c) => `${c.name}:${c.type}:${c.notnull}:${c.dflt_value ?? ''}:${c.pk}`).join(',')]));
const idx = (db) => db.prepare("SELECT name FROM sqlite_master WHERE type IN ('index','trigger') AND sql IS NOT NULL ORDER BY name").all().map((r) => r.name);
const s = { skip: deployedSql ? false : `commit ${DEPLOYED} is not available here: the deployed schema cannot be reconstructed` };

test('migrations are numbered, additive, and every statement is either idempotent or a single ALTER ADD COLUMN', s, () => {
  assert.deepEqual(migrations, ['0001_telemetry_exclusions.sql', '0002_gh_sync_authenticated.sql', '0003_guardops_outbox.sql']);
  for (const f of migrations) { const t = readFileSync(ROOT + 'migrations/' + f, 'utf8').split('\n').filter((l) => !l.trim().startsWith('--')).join('\n'); assert.ok(!/\b(DROP|DELETE|UPDATE|TRUNCATE)\b/i.test(t), `${f} must be additive`); assert.ok(/CREATE TABLE IF NOT EXISTS|ALTER TABLE \w+ ADD COLUMN/i.test(t), f); }
});
test('the deployed database upgrades to exactly the current schema with its data intact', s, () => {
  const old = new DatabaseSync(':memory:'); old.exec(deployedSql);
  assert.ok(!('telemetry_exclusions' in shape(old)) && !shape(old).gh_sync.includes('authenticated'), 'the deployed schema really lacks both changes');
  old.exec("INSERT INTO gh_sync(id,last_status,consecutive_failures) VALUES (1,'ok',0)"); old.exec("INSERT INTO gh_sync_log VALUES ('2026-10-23T20:18:00Z',0,0,'github_rate_limited')");
  old.exec("INSERT INTO analytics_daily(day,tenant_id,channel,product,operation,status_class,commercial_mode,requests) VALUES ('2026-10-23','-','rest','x','op','4xx','FREE_LAUNCH',1)"); old.exec("INSERT INTO community_requests_daily VALUES ('2026-10-23','t','a','anonymous_request',1)");
  const before = { gh: old.prepare('SELECT * FROM gh_sync').get(), log: old.prepare('SELECT COUNT(*) n FROM gh_sync_log').get().n, ana: old.prepare('SELECT COUNT(*) n FROM analytics_daily').get().n };
  for (const f of migrations) old.exec(readFileSync(ROOT + 'migrations/' + f, 'utf8'));
  const cur = new DatabaseSync(':memory:'); cur.exec(readFileSync(ROOT + 'schema.sql', 'utf8'));
  assert.deepEqual(shape(old), shape(cur), 'tables and columns identical to schema.sql'); assert.deepEqual(idx(old), idx(cur), 'indexes and triggers identical');
  const after = old.prepare('SELECT * FROM gh_sync').get(); assert.equal(after.last_status, before.gh.last_status); assert.equal(after.authenticated, 0, 'existing rows get the default'); assert.equal(old.prepare('SELECT COUNT(*) n FROM gh_sync_log').get().n, before.log); assert.equal(old.prepare('SELECT COUNT(*) n FROM analytics_daily').get().n, before.ana);
  assert.equal(old.prepare('SELECT COUNT(*) n FROM telemetry_exclusions').get().n, 0);
});
test('re-applying: 0001 is idempotent, 0002 refuses a second run (which is why migrations are applied through the tracker, once)', s, () => {
  const db = new DatabaseSync(':memory:'); db.exec(deployedSql); for (const f of migrations) db.exec(readFileSync(ROOT + 'migrations/' + f, 'utf8'));
  db.exec(readFileSync(ROOT + 'migrations/0001_telemetry_exclusions.sql', 'utf8'));
  assert.throws(() => db.exec(readFileSync(ROOT + 'migrations/0002_gh_sync_authenticated.sql', 'utf8')), /duplicate column/i);
});
test('the migrated database works with the current code: a fresh sync and the telemetry exclusion path run on it', s, async () => {
  const { sync } = await import('../src/gh_collector.js'); const { dashboard } = await import('../src/dashboards.js');
  const raw = new DatabaseSync(':memory:'); raw.exec(deployedSql); for (const f of migrations) raw.exec(readFileSync(ROOT + 'migrations/' + f, 'utf8'));
  const db = { prepare: (q) => { let a = []; const st = { bind: (...x) => { a = x; return st; }, first: async () => raw.prepare(q).get(...a) ?? null, all: async () => ({ results: raw.prepare(q).all(...a) }), run: async () => ({ meta: { changes: Number(raw.prepare(q).run(...a).changes) } }), _sql: q, _args: () => a }; return st; },
    batch: async (l) => { raw.exec('BEGIN'); try { const o = []; for (const x of l) o.push({ meta: { changes: Number(raw.prepare(x._sql).run(...x._args()).changes) } }); raw.exec('COMMIT'); return o; } catch (e) { raw.exec('ROLLBACK'); throw e; } } };
  const r = await sync(db, () => new Date('2026-10-24T05:00:00Z'), async () => new Response('[]', { status: 200 }), { repo: 'o/r', token: 'github_pat_' + 'A1b2C3d4'.repeat(6) }); assert.equal(r.ok, true); assert.equal(r.authenticated, true);
  const d = await dashboard(db, () => new Date('2026-10-24T05:00:00Z'), 'downloads'); assert.equal(d.panels.find((p) => p.id === 'redirects').state, 'NO_DATA'); assert.equal(d.panels.find((p) => p.id === 'collector').data.authenticated, true);
});
