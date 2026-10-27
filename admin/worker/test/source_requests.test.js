// Requests for a new source of any family: roles, strict URL and vocabulary validation (a URL is data, never requested), idempotency, duplicates, ADMIN-only decisions, finality and the audit chain.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { world } from './helpers.js';
import { cleanUrl } from '../src/source_requests.js';
import { verifyChain } from '../src/core.js';
import { auditRows } from '../src/store.js';

const body = (over = {}) => ({ family: 'ioc', name: 'URLhaus recent', url: 'https://urlhaus.abuse.ch/downloads/csv_recent/', format: 'csv', auth: 'none', license_note: 'CC0', reason: 'we need malicious URLs for the IOC family', request_id: 'req-source-request-0001', ...over });
async function setup() {
  const w = await world(); const ada = await w.login('ada', { admin: true }, { id: 13 }), rita = await w.login('rita', { push: true }, { id: 12 }), vera = await w.login('vera', { pull: true }, { id: 11 });
  for (const u of [ada, rita, vera]) await w.call('GET', '/api/me', { user: u }); await w.grant(ada, 'vera', 'VIEWER');
  return { w, ada, rita, vera, post: (user, b, p = '/api/source-requests') => w.call('POST', p, { user, body: b }) };
}
test('URL cleaning: https and a plain host only; credentials, ports, fragments, IPs, odd schemes and control characters are refused', () => {
  assert.equal(cleanUrl('https://feeds.example.org/a.csv?x=1'), 'https://feeds.example.org/a.csv?x=1');
  for (const bad of ['http://a.example.org/x', 'https://u:p@a.example.org/x', 'https://a.example.org:8443/x', 'https://a.example.org/x#f', 'https://127.0.0.1/x', 'https://localhost/x', 'javascript:alert(1)', 'https://a.example.org/x y', 'https://a..example.org/x', 'ftp://a.example.org', '', null, 5]) assert.equal(cleanUrl(bad), null, String(bad));
});
test('roles and validation: viewers cannot ask, reviewers can; unknown family, format, auth, short reason and bad request id are refused', async () => {
  const { post, vera, rita } = await setup();
  assert.equal((await post(vera, body())).status, 403); assert.equal((await post(undefined, body())).status, 401);
  for (const bad of [body({ family: 'weapon' }), body({ format: 'exe' }), body({ auth: 'password' }), body({ name: 'x' }), body({ reason: 'no' }), body({ request_id: 'short' }), body({ url: 'http://x.example.org/a' }), body({ license_note: 'x'.repeat(501) }), null]) assert.equal((await post(rita, bad)).status, 400, JSON.stringify(bad)?.slice(0, 60));
  assert.equal((await post(rita, body())).status, 200);
});
test('a retirement request names the source to retire; an ADD cannot carry one by accident', async () => {
  const { post, rita } = await setup(); assert.equal((await post(rita, body({ kind: 'RETIRE', request_id: 'req-source-request-0010' }))).status, 400, 'target_source required');
  const ok = await post(rita, body({ kind: 'RETIRE', target_source: 'abusech-feodo', request_id: 'req-source-request-0011', reason: 'upstream stopped publishing' })); assert.equal(ok.status, 200, JSON.stringify(ok.data)); assert.equal(ok.data.request.kind, 'RETIRE'); assert.equal(ok.data.request.target_source, 'abusech-feodo');
  assert.equal((await post(rita, body({ request_id: 'req-source-request-0012' }))).status, 200, 'an ADD for the same address is a different kind'); assert.equal((await post(rita, body({ kind: 'PAUSE' }))).status, 400);
});
test('idempotency and duplicates: the same request id replays, another id for the same open address is refused, a reused id for another address is refused', async () => {
  const { post, rita } = await setup(); const a = await post(rita, body()); assert.equal(a.status, 200);
  const again = await post(rita, body()); assert.equal(again.status, 200); assert.equal(again.data.replay, true);
  assert.equal((await post(rita, body({ request_id: 'req-source-request-0002' }))).status, 409, 'an open request for this address exists');
  assert.equal((await post(rita, body({ url: 'https://other.example.org/feed.csv' }))).status, 409, 'same request id, other address');
});
test('only an ADMIN accepts or rejects; the requester or an admin may cancel; a decision needs a reason and the version seen; a decided request is final', async () => {
  const { w, post, rita, ada } = await setup(); const r = (await post(rita, body())).data.request; const act = (user, op, over = {}) => post(user, { reason: 'checked licence and format', expect_version: r.version, ...over }, `/api/source-requests/${r.id}/${op}`);
  assert.equal((await act(rita, 'accept')).status, 403, 'a reviewer cannot accept'); assert.equal((await act(ada, 'accept', { reason: 'ok' })).status, 400); assert.equal((await act(ada, 'accept', { expect_version: 9 })).status, 409);
  const ok = await act(ada, 'accept'); assert.equal(ok.status, 200); assert.equal(ok.data.request.state, 'ACCEPTED'); assert.equal((await act(ada, 'reject')).status, 409, 'final');
  await assert.rejects(() => w.db.prepare("UPDATE source_requests SET url = 'https://evil.example.org/x'").run(), /cannot be edited|final/); await assert.rejects(() => w.db.prepare('DELETE FROM source_requests').run(), /never deleted/);
  const r2 = (await post(rita, body({ url: 'https://second.example.org/feed.csv', request_id: 'req-source-request-0003' }))).data.request; assert.equal((await post(rita, { reason: 'changed my mind', expect_version: r2.version }, `/api/source-requests/${r2.id}/cancel`)).data.request.state, 'CANCELLED');
  assert.equal((await post(rita, { reason: 'not mine to cancel', expect_version: 1 }, `/api/source-requests/00000000-0000-4000-8000-000000000999/cancel`)).status, 404);
});
test('each step is one entry in the hash chain; the list shows every request; the schema mirrors the migration verbatim', async () => {
  const { w, post, rita, ada } = await setup(); const r = (await post(rita, body())).data.request; await post(ada, { reason: 'checked licence and format', expect_version: r.version }, `/api/source-requests/${r.id}/accept`);
  const rows = (await auditRows(w.db, 500)).filter((e) => e.action.startsWith('source.')); assert.deepEqual(rows.map((e) => e.action), ['source.requested', 'source.accepted']); assert.equal(JSON.parse(rows[0].detail).actor_id, 12);
  assert.equal((await verifyChain(await auditRows(w.db, 5000))).ok, true); assert.equal((await w.call('GET', '/api/source-requests', { user: rita })).data.items.length, 1);
  const up = readFileSync(new URL('../migrations/0007_source_requests.sql', import.meta.url), 'utf8'), schema = readFileSync(new URL('../schema.sql', import.meta.url), 'utf8'); const m = schema.match(/-- >>> 0007[^\n]*\n([\s\S]*?)-- <<< 0007/); assert.equal(m[1], up);
});

test('five roles and separation of duties: PUBLISHER and SECURITY_ADMIN read the requests but cannot ask or decide; an ADMIN cannot decide a request they made, another identity must', async () => {
  const { w, ada, rita } = await setup(); const post = (user, b, p = '/api/source-requests') => w.call('POST', p, { user, body: b });
  for (const [login, role, id] of [['pat', 'PUBLISHER', 21], ['sam', 'SECURITY_ADMIN', 22]]) { w.account(login, id); await w.grant(ada, login, role); const u = await w.login(login, { pull: true }, { id }); await w.call('GET', '/api/me', { user: u });
    assert.equal((await w.call('GET', '/api/source-requests', { user: u })).status, 200, `${role} reads`); assert.equal((await post(u, body({ request_id: `req-source-request-9${id}` }))).status, 403, `${role} cannot ask`); }
  const boss = await w.login('boss', { admin: true }, { id: 14 }); await w.call('GET', '/api/me', { user: boss });
  const mine = (await post(ada, body({ request_id: 'req-source-request-0050' }))).data.request, act = (user, op, r) => post(user, { reason: 'checked licence and format', expect_version: r.version }, `/api/source-requests/${r.id}/${op}`);
  const own = await act(ada, 'accept', mine); assert.equal(own.status, 403); assert.equal(own.data.code, 'same_identity'); assert.equal((await act(ada, 'reject', mine)).status, 403, 'nor reject');
  assert.ok(w.db.raw.prepare("SELECT COUNT(*) AS n FROM audit WHERE action = 'authz.denied'").get().n >= 1, 'the refusal is audited'); assert.equal((await act(boss, 'accept', mine)).data.request.state, 'ACCEPTED'); assert.equal((await act(ada, 'cancel', { id: (await post(ada, body({ url: 'https://x.example.org/f', request_id: 'req-source-request-0051' }))).data.request.id, version: 1 })).data.request.state, 'CANCELLED', 'the requester may still withdraw their own');
});
