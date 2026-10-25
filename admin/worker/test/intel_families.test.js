// Intelligence families: the catalogue is validated strictly (mutations are dropped, never trusted), every family that is not published says WHY, the YARA row is a live reading of the signed release,
// and only a reviewer or an admin may read it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { world, hashOf } from './helpers.js';
import { validateCatalogue, GROUPS } from '../src/intel_families.js';

const REAL = JSON.parse(readFileSync(new URL('../../../config/intel-families.json', import.meta.url), 'utf8'));
const clone = () => JSON.parse(JSON.stringify(REAL));

test('the real catalogue validates completely and every family that is not published gives a concrete cause', () => {
  const v = validateCatalogue(REAL); assert.equal(v.ok, true); assert.equal(v.dropped.length, 0); assert.equal(v.families.length, REAL.families.length);
  assert.deepEqual([...new Set(v.families.map((f) => f.group))].sort(), [...GROUPS].sort(), 'every group has at least one family');
  for (const f of v.families) if (['RETENIDA', 'NO_DATA', 'BLOCKED', 'NOT_RUN'].includes(f.publication)) assert.ok(f.causes.length >= 1, `${f.id} says ${f.publication} without a cause`);
  assert.equal(v.families.find((f) => f.id === 'ioc_feodo').publication, 'NO_DATA'); assert.equal(v.families.find((f) => f.id === 'hashes_malicious').integration, 'NOT_INTEGRATED');
  assert.equal(v.evidence.in_main, false, 'the catalogue says its evidence document is not on main'); assert.ok(v.families.every((f) => f.publication !== 'PUBLISHED'), 'the declared catalogue never claims PUBLISHED: only the live YARA reading can');
});

test('mutations are dropped: wrong vocabulary, hostile text, duplicates, bad counts, bad evidence head, wrong schema', () => {
  const c = clone(), base = c.families[0];
  c.families.push({ ...base, id: 'bad_group', group: 'weapons' }, { ...base, id: 'bad_pub', publication: 'PUBLISHED_OK' }, { ...base, id: 'html', name: '<img src=x onerror=1>' }, { ...base, id: 'dup' }, { ...base, id: 'dup' }, { ...base, id: 'neg', counts: { rules: -1 } },
    { ...base, id: 'float', counts: { rules: 1.5 } }, { ...base, id: 'cause', causes: ['Not A Cause!'] }, { ...base, id: 'head', evidence_head: 'zz' }, { ...base, id: 'BadId' }, null);
  const v = validateCatalogue(c); assert.equal(v.ok, true); for (const id of ['BadId', 'bad_group', 'bad_pub', 'cause', 'float', 'head', 'html', 'neg', 'dup', '?']) assert.ok(v.dropped.includes(id), `${id} is reported as dropped`);
  assert.ok(!v.families.some((f) => ['bad_group', 'bad_pub', 'html', 'neg', 'float', 'cause', 'head', 'BadId'].includes(f.id))); assert.equal(v.families.filter((f) => f.id === 'dup').length, 1, 'a duplicate id keeps the first');
  assert.equal(validateCatalogue({ ...c, schema: 'other/1' }).ok, false); assert.equal(validateCatalogue(null).ok, false); assert.equal(validateCatalogue({ schema: 'macguard.intel-families/1', families: 'x' }).ok, false);
});

async function setup({ catalogue = JSON.stringify(REAL), catalogueStatus = 200, release = true } = {}) {
  const w = await world(); const admin = await w.login('ada', { admin: true }, { id: 13 }), rev = await w.login('rita', { push: true }, { id: 12 }), viewer = await w.login('vera', { pull: true }, { id: 11 });
  for (const u of [admin, rev, viewer]) await w.call('GET', '/api/me', { user: u }); await w.grant(admin, 'vera', 'VIEWER');
  if (release) await w.release('rules-20261021-1', [{ path: 'rules/community/a.yar', sha256: hashOf('a'), bytes: 1, source: 'community' }, { path: 'rules/nextron/b.yar', sha256: hashOf('b'), bytes: 1, source: 'nextron' }], { meta: { stats: { yara_rules: 17, files: 2 } } });
  w.route(/config\/intel-families\.json$/, () => new Response(catalogue, { status: catalogueStatus }));
  return { w, admin, rev, viewer };
}
test('the endpoint merges the live YARA reading with the declared catalogue; a viewer is refused; a missing or hostile catalogue degrades to YARA only and says so', async () => {
  const { w, rev, viewer } = await setup(); const r = await w.call('GET', '/api/intel/families', { user: rev }); assert.equal(r.status, 200);
  const yara = r.data.families.find((f) => f.id === 'yara'); assert.deepEqual([yara.live, yara.publication, yara.counts.files, yara.counts.rules, yara.counts.files_community], [true, 'PUBLISHED', 2, 17, 1]); assert.equal(r.data.families.length, REAL.families.length + 1);
  assert.equal(r.data.declared.as_of, '2026-10-25'); assert.equal(r.data.catalogue_error, null);
  assert.equal((await w.call('GET', '/api/intel/families', { user: viewer })).status, 403); assert.equal((await w.call('GET', '/api/intel/families')).status, 401);
  const gone = await setup({ catalogueStatus: 404 }); const g = await gone.w.call('GET', '/api/intel/families', { user: gone.rev }); assert.deepEqual([g.data.families.map((f) => f.id), g.data.catalogue_error], [['yara'], 'http_404']);
  const junk = await setup({ catalogue: '{"schema":"x"}' }); assert.equal((await junk.w.call('GET', '/api/intel/families', { user: junk.rev })).data.catalogue_error, 'malformed');
  const none = await setup({ release: false }); const n = await none.w.call('GET', '/api/intel/families', { user: none.rev }); assert.equal(n.data.live_error, 'release_unreadable'); assert.equal(n.data.families.some((f) => f.id === 'yara'), false, 'no release read, no YARA claim');
});
