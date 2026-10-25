// One published rule: content read from the signed release package and checked against the manifest, provenance and licence from the manifest, role rules, and the registration that lets the
// withdrawal engine manage a rule the panel never saw.
import test from 'node:test';
import assert from 'node:assert/strict';
import { world, hashOf, makeTarGz } from './helpers.js';
import { tarEntry } from '../src/published_rules.js';

const A = 'rule A { condition: true }', B = 'rule B { condition: false }';
const PA = 'rules/community/a.yar', PB = 'rules/nextron/yara/b.yar', LONG = 'rules/nextron/' + 'deep/'.repeat(25) + 'long_name.yar';
const META = { created_at: '2026-10-21T03:50:09Z', sources: [{ id: 'community', repository: 'Yara-Rules/rules', commit: 'c'.repeat(40), kind: 'rules', license_check: { ok: true, detail: 'GPL-2.0: allowed-with-license-notice', redistribution: 'allowed-with-license-notice', spdx_reported: 'GPL-2.0' } }], validation: { checked: 3, engine: 'yara' }, evidence: { dynamic: { verdict: 'ok', canaries_detected: 5, canaries_expected: 5, engine: '4.5.0' }, publish_run_url: 'https://github.com/x/y/actions/runs/1' } };
const entries = () => [{ path: PA, sha256: hashOf(A), bytes: A.length, source: 'community' }, { path: PB, sha256: hashOf(B), bytes: B.length, source: 'nextron' }, { path: LONG, sha256: hashOf(A + B), bytes: A.length + B.length, source: 'nextron' }];
async function setup({ tar = { [PA]: A, [PB]: B, [LONG]: A + B }, pax = true } = {}) {
  const w = await world(); const admin = await w.login('ada', { admin: true }, { id: 13 }), rev = await w.login('rita', { push: true }, { id: 12 }), viewer = await w.login('vera', { pull: true }, { id: 11 });
  for (const u of [admin, rev, viewer]) await w.call('GET', '/api/me', { user: u });
  await w.grant(admin, 'vera', 'VIEWER');
  await w.release('rules-20261021-1', entries(), { tarball: tar ? makeTarGz(tar, { pax }) : null, meta: META });
  return { w, admin, rev, viewer };
}
const get = (w, user, path) => w.call('GET', `/api/published/file?path=${encodeURIComponent(path)}`, { user });

test('tarEntry reads ustar and pax long names and returns null for a missing entry', async () => {
  const files = { [PA]: A, [LONG]: B }; assert.equal(new TextDecoder().decode(await tarEntry(makeTarGz(files), PA)), A);
  assert.equal(new TextDecoder().decode(await tarEntry(makeTarGz(files, { pax: true }), LONG)), B); assert.equal(await tarEntry(makeTarGz(files), 'rules/nope.yar'), null);
});

test('detail of an unrecorded rule: identity and signed content verified, provenance and licence from the manifest, release evidence links, no record; any role may read it', async () => {
  const { w, viewer } = await setup();
  const r = await get(w, viewer, PA); assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.deepEqual([r.data.content.status, r.data.content.content], ['VERIFIED', A]); assert.equal(r.data.file.sha256, hashOf(A)); assert.equal(r.data.record, null);
  assert.equal(r.data.provenance.repository, 'Yara-Rules/rules'); assert.equal(r.data.provenance.license.redistribution, 'allowed-with-license-notice');
  assert.match(r.data.release.signatures.manifest, /manifest\.sigstore\.json$/); assert.equal(r.data.release.tag, 'rules-20261021-1'); assert.equal(r.data.set_validation.scope, 'the whole release, not this rule alone'); assert.equal(r.data.publication.publication, 'published');
  assert.equal((await get(w, viewer, LONG)).data.content.status, 'VERIFIED');
});

test('a package that disagrees with the signed manifest is never shown; a missing package, an unknown path and a hostile path fail closed', async () => {
  const bad = await setup({ tar: { [PA]: A + ' // tampered', [PB]: B, [LONG]: A + B } }); const r = await get(bad.w, bad.viewer, PA);
  assert.equal(r.status, 200); assert.equal(r.data.content.status, 'MISMATCH'); assert.equal(r.data.content.content, undefined, 'no content for a mismatching file'); assert.equal((await get(bad.w, bad.viewer, PB)).data.content.status, 'VERIFIED', 'the other files are unaffected');
  const none = await setup({ tar: null }); assert.equal((await get(none.w, none.viewer, PA)).data.content.status, 'UNAVAILABLE');
  for (const p of ['rules/unknown.yar', '../etc/passwd', '', 'rules/community/../../x']) assert.equal((await get(none.w, none.viewer, p)).status, 404, JSON.stringify(p));
  assert.equal((await none.w.call('GET', '/api/published/file?path=' + PA)).status, 401, 'signed-in only');
});

test('registering a published rule: ADMIN only, same-origin with CSRF, verified content, idempotent, audited; it then flows through the existing withdrawal engine', async () => {
  const { w, admin, rev, viewer } = await setup();
  assert.equal((await w.call('POST', '/api/published/adopt', { user: rev, body: { path: PA } })).status, 403); assert.equal((await w.call('POST', '/api/published/adopt', { user: viewer, body: { path: PA } })).status, 403);
  assert.equal((await w.call('POST', '/api/published/adopt', { user: admin, body: { path: PA }, csrf: false })).status, 403); assert.equal((await w.call('POST', '/api/published/adopt', { user: admin, body: { path: 'rules/unknown.yar' } })).status, 404);
  const a = await w.call('POST', '/api/published/adopt', { user: admin, body: { path: PA, request_id: 'req_1' } }); assert.equal(a.status, 200); assert.equal(a.data.existing, false);
  const again = await w.call('POST', '/api/published/adopt', { user: admin, body: { path: PA } }); assert.deepEqual([again.data.id, again.data.existing], [a.data.id, true]);
  const d = await get(w, rev, PA); assert.equal(d.data.record.id, a.data.id); assert.equal(d.data.record.state, 'RELEASED');
  const entry = (await w.db.prepare("SELECT actor, target FROM audit WHERE action = 'published.adopt'").all()).results; assert.equal(entry.length, 1); assert.equal(entry[0].actor, 'ada'); assert.equal(entry[0].target, a.data.id);
  const wd = await w.call('POST', '/api/policies/withdrawals', { user: admin, body: { candidate_id: a.data.id, scope: 'path', criticality: 'STANDARD', reason: 'withdrawn after review', request_id: 'req_withdraw_0000001', expect_version: 1, confirm_collateral: 0 } });
  assert.equal(wd.status, 200, JSON.stringify(wd.data)); const after = await get(w, viewer, PA); assert.equal(after.data.publication.publication, 'withdrawal_pending');
});

test('nothing is registered when the content cannot be verified', async () => {
  const { w, admin } = await setup({ tar: { [PA]: A + 'x', [PB]: B, [LONG]: A + B } });
  const r = await w.call('POST', '/api/published/adopt', { user: admin, body: { path: PA } }); assert.equal(r.status, 502); assert.equal((await w.db.prepare('SELECT COUNT(*) AS n FROM candidates').first()).n, 0);
});
