// The INTEL read API: roles, closed vocabularies, keyset pagination that never skips or repeats, bounded limits, escaped search, detail with its run and source, append-only events.
import test from 'node:test';
import assert from 'node:assert/strict';
import { world } from './helpers.js';
import { newDb } from './d1shim.js';

const SHA = (c) => c.repeat(64).slice(0, 64), NOW = '2026-10-25T10:00:00Z';
async function seed(db) {
  await db.prepare("INSERT INTO intel_sources (id,name,organization,url,family,grp,data_type,adapter,adapter_version,license_id,redistribution,auth,configured,updated_at) VALUES ('cisa-kev','CISA KEV','CISA','https://www.cisa.gov/kev','kev','vulnerabilities','vulnerability catalogue','intel.vulns.kev','1','US-GOV','allowed-with-conditions','none',1,?)").bind(NOW).run();
  await db.prepare("INSERT INTO intel_sources (id,name,family,grp,configured,updated_at) VALUES ('sigmahq','SigmaHQ','sigma','detections',1,?)").bind(NOW).run();
  await db.prepare("INSERT INTO intel_runs (id,source_id,retrieved_at,http_status,bytes,etag,content_sha256,declared,accepted,rejected,state,publishable,blocking,promoted_at,promoted_by,promotion_sha256) VALUES ('run-kev-1','cisa-kev','2026-10-25T03:46:29Z',200,1807090,'\"abc\"',?,250,250,0,'COMPLETE',0,?,?,'ada',?)").bind(SHA('a'), JSON.stringify(['owner has not confirmed redistribution']), NOW, SHA('b')).run();
  await db.prepare("INSERT INTO intel_runs (id,source_id,retrieved_at,state,promoted_at,promoted_by,promotion_sha256) VALUES ('run-sigma-1','sigmahq','2026-10-25T09:00:00Z','COMPLETE',?,'ada',?)").bind(NOW, SHA('c')).run();
  const SQL = 'INSERT INTO intel_records (id,family,source_id,run_id,key,title,severity,score,state,held_back,updated_at,body,doc,doc_sha256) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', ins = { bind: (...a) => db.prepare(SQL).bind(...a) };   // the shim reuses a statement object per prepare
  const batch = []; for (let i = 0; i < 250; i++) { const key = `CVE-2024-${String(1000 + i)}`; batch.push(ins.bind(`kev:${key}`, 'kev', 'cisa-kev', 'run-kev-1', key, `Vulnerability ${i}${i === 7 ? ' 100%_wild' : ''}`, i % 3 ? 'HIGH' : 'CRITICAL', (i % 10) / 10, 'RETENIDA', 1, `2026-10-${String(1 + (i % 20)).padStart(2, '0')}`, null, JSON.stringify({ cve: key, n: i }), SHA('d'))); }
  for (let i = 0; i < 5; i++) batch.push(ins.bind(`sigma:r${i}`, 'sigma', 'sigmahq', 'run-sigma-1', `r${i}`, `Rule ${i}`, null, null, 'QUARANTINED', 1, null, `title: r${i}\ndetection: {}`, JSON.stringify({ id: `r${i}` }), SHA('e')));
  await db.batch(batch);
  for (const [lvl, comp, msg, fam, run] of [['INFO', 'intel.fetch', 'download complete', 'kev', 'run-kev-1'], ['WARN', 'intel.fetch', 'partial download', 'sigma', 'run-sigma-1'], ['ERROR', 'intel.normalize', 'record rejected', 'kev', 'run-kev-1']])
    await db.prepare('INSERT INTO intel_events (ts,level,component,module,message,run_id,family) VALUES (?,?,?,?,?,?,?)').bind(NOW, lvl, comp, 'x', msg, run, fam).run();
}
async function setup(bound = true) {
  const w = await world(); const admin = await w.login('ada', { admin: true }, { id: 13 }), rev = await w.login('rita', { push: true }, { id: 12 }), viewer = await w.login('vera', { pull: true }, { id: 11 });
  for (const u of [admin, rev, viewer]) await w.call('GET', '/api/me', { user: u }); await w.grant(admin, 'vera', 'VIEWER');
  if (bound) { w.env.INTEL = newDb(['../migrations-intel/0001_intel.sql', '../migrations-intel/0002_decisions.sql']); await seed(w.env.INTEL); }
  return { w, admin, rev, viewer };
}
const get = (w, user, p) => w.call('GET', `/api/intel/${p}`, { user });

test('roles and binding: a viewer is refused, a reviewer reads, writes are refused, an unbound database says so', async () => {
  const { w, rev, viewer, admin } = await setup();
  assert.equal((await get(w, viewer, 'sources')).status, 403); assert.equal((await w.call('GET', '/api/intel/sources')).status, 401); assert.equal((await get(w, rev, 'sources')).status, 200); assert.equal((await get(w, admin, 'stats')).status, 200);
  assert.equal((await w.call('POST', '/api/intel/records', { user: admin, body: {} })).status, 405); assert.equal((await get(w, rev, 'nope')).status, 404);
  const none = await setup(false); const r = await get(none.w, none.rev, 'records'); assert.deepEqual([r.status, r.data.code], [503, 'intel_store_unavailable']);
});

test('sources carry their latest real run and their record count; nothing is invented for a source without a run', async () => {
  const { w, rev } = await setup(); const r = await get(w, rev, 'sources'); const kev = r.data.sources.find((s) => s.id === 'cisa-kev'), sg = r.data.sources.find((s) => s.id === 'sigmahq');
  assert.deepEqual([kev.records, kev.latest_run.http_status, kev.latest_run.accepted, kev.latest_run.publishable, kev.latest_run.blocking], [250, 200, 250, false, ['owner has not confirmed redistribution']]);
  assert.equal(sg.records, 5); assert.equal(sg.latest_run.bytes, null, 'an unknown size stays null, never zero');
});

test('keyset pagination visits every record exactly once, in id order and in score order with ties; the total is stable', async () => {
  const { w, rev } = await setup(); const seen = [], seenScore = [];
  for (let c = null, pages = 0; pages < 20; pages++) { const r = await get(w, rev, `records?family=kev&limit=40${c ? `&cursor=${c}` : ''}`); assert.equal(r.status, 200); assert.equal(r.data.total, 250); seen.push(...r.data.items.map((x) => x.id)); c = r.data.next_cursor; if (!c) break; }
  assert.equal(seen.length, 250); assert.equal(new Set(seen).size, 250); assert.deepEqual(seen, [...seen].sort());
  for (let c = null, pages = 0; pages < 20; pages++) { const r = await get(w, rev, `records?family=kev&sort=score_desc&limit=33${c ? `&cursor=${c}` : ''}`); seenScore.push(...r.data.items); c = r.data.next_cursor; if (!c) break; }
  assert.equal(seenScore.length, 250); assert.equal(new Set(seenScore.map((x) => x.id)).size, 250, 'ties on the score neither skip nor repeat'); for (let i = 1; i < seenScore.length; i++) assert.ok((seenScore[i - 1].score ?? 0) >= (seenScore[i].score ?? 0), 'non-increasing score');
});

test('filters, escaped search and limits: a wildcard is literal, an injection attempt is inert, the list never carries the document', async () => {
  const { w, rev } = await setup(); const q = async (s) => get(w, rev, `records?${s}`);
  assert.equal((await q('family=sigma')).data.total, 5); assert.equal((await q('family=sigma,kev')).data.total, 255, 'a list of families is one query'); assert.equal((await q('family=sigma,weapon')).status, 400); assert.equal((await q(`family=${'kev,'.repeat(7)}kev`)).status, 400); assert.equal((await q('family=kev&state=RETENIDA&limit=1')).data.items.length, 1); assert.equal((await q('family=kev&held_back=0')).data.total, 0);
  assert.equal((await q('q=CVE-2024-1007')).data.items[0].key, 'CVE-2024-1007'); assert.equal((await q('q=%25')).data.total, 1, '"%" is literal: it finds only the one title that contains a percent sign, not everything'); assert.equal((await q('q=100%25_wild')).data.total, 1, 'a literal wildcard text is found');
  const inj = await q(`q=${encodeURIComponent("' OR 1=1 --")}`); assert.equal(inj.status, 200); assert.equal(inj.data.total, 0);
  assert.equal((await q('limit=100000')).data.items.length, 200, 'the limit is capped, not trusted'); const one = (await q('limit=1')).data.items[0]; assert.ok(!('doc' in one) && !('body' in one));
  for (const bad of ['family=weapon', 'source=A%20B', 'limit=0', 'limit=abc', 'sort=password', 'state=1;drop', 'held_back=2', 'cursor=@@', `q=${'x'.repeat(81)}`]) assert.equal((await q(bad)).status, 400, bad);
  assert.equal((await q(`cursor=${btoa(JSON.stringify({ id: '../x' }))}`)).status, 400);
});

test('record detail joins its run and source; hostile ids are refused; events filter by level, component and run and cannot be edited', async () => {
  const { w, rev } = await setup(); const d = await get(w, rev, `records/${encodeURIComponent('kev:CVE-2024-1007')}`);
  assert.equal(d.status, 200); assert.deepEqual([d.data.record.doc.cve, d.data.run.id, d.data.source.id], ['CVE-2024-1007', 'run-kev-1', 'cisa-kev']); assert.equal((await get(w, rev, 'records/kev%3Anope')).status, 404);
  const sg = await get(w, rev, `records/${encodeURIComponent('sigma:r2')}`); assert.match(sg.data.record.body, /title: r2/);
  for (const id of ['..%2F..%2Fetc', '%00', 'a%20b', '%E0%A4%A']) assert.ok([400, 404].includes((await get(w, rev, `records/${id}`)).status), id);
  assert.equal((await get(w, rev, 'events?level=ERROR')).data.items.length, 1); assert.equal((await get(w, rev, 'events?component=intel.fetch&run_id=run-kev-1')).data.items.length, 1); assert.equal((await get(w, rev, 'events?level=LOUD')).status, 400);
  await assert.rejects(() => w.env.INTEL.prepare("UPDATE intel_events SET message = 'edited'").run(), /append-only/); await assert.rejects(() => w.env.INTEL.prepare('DELETE FROM intel_events').run(), /append-only/);
});

test('events: incremental reading with after, the head cursor, secrets masked on the way out, and stats carry per-run and per-event counts', async () => {
  const { w, rev } = await setup(); const all = (await get(w, rev, 'events')).data; assert.equal(all.items.length, 3); const head = all.head;
  assert.equal((await get(w, rev, `events?after=${head}`)).data.items.length, 0, 'nothing newer than the head'); await w.env.INTEL.prepare("INSERT INTO intel_events (ts,level,component,module,message) VALUES (?,?,?,?,?)").bind(NOW, 'INFO', 'intel.fetch', 'x', 'url https://x.test/f?sig=ABCDEF&jwt=GHIJKL and ghp_' + 'A'.repeat(30)).run();
  const inc = (await get(w, rev, `events?after=${head}`)).data; assert.equal(inc.items.length, 1); assert.ok(!/ABCDEF|GHIJKL|ghp_A/.test(inc.items[0].message), inc.items[0].message); assert.match(inc.items[0].message, /\[redacted\]/);
  assert.equal((await get(w, rev, `events?after=1&before=9`)).status, 400); assert.equal((await get(w, rev, 'events?after=-1')).status, 400);
  const st = (await get(w, rev, 'stats')).data; assert.deepEqual(st.events.by_level.map((x) => x.level).sort(), ['ERROR', 'INFO', 'INFO', 'WARN', 'WARN'].filter((v, i, a) => a.indexOf(v) === i).sort()); assert.equal(st.runs.items.length, 2); assert.equal(st.runs.items[0].accepted, 250);
});

test('events: text search and source filter are bounded, wildcards in the text are literal, and the filters combine', async () => {
  const { w, rev } = await setup(); const ins = (lvl, msg, src) => w.env.INTEL.prepare('INSERT INTO intel_events (ts,level,component,module,message,source_id,family) VALUES (?,?,?,?,?,?,?)').bind(NOW, lvl, 'intel.fetch', 'Fetcher', msg, src, 'kev').run();
  await ins('INFO', 'downloaded 100% of the file', 'cisa-kev'); await ins('INFO', 'downloaded 1000 of the file', 'cisa-kev'); await ins('ERROR', 'timeout while downloading', 'sigmahq');
  const n = async (q) => (await get(w, rev, `events?${q}`)); const count = async (q) => (await n(q)).data.items.length;
  assert.equal(await count('q=100%25'), 1, 'a percent sign in the text is literal, not a wildcard'); assert.equal(await count('q=download'), 5, 'message match is case-insensitive substring'); assert.equal(await count('q=fetcher'), 3, 'module matches too');
  assert.equal(await count('source_id=cisa-kev'), 2); assert.equal(await count('source_id=sigmahq&level=ERROR&q=timeout'), 1, 'filters combine');
  for (const bad of ['q=a', `q=${'x'.repeat(65)}`, 'source_id=a%20b', 'source_id=%27%3B--']) assert.equal((await n(bad)).status, 400, bad);
});
