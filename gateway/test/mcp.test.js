import test from 'node:test';
import assert from 'node:assert/strict';
import { apiWorld, SEED, clone, paid } from './apiworld.js';
import { tools, MODERN } from '../src/mcp.js';
import { OPS } from '../src/plans.js';
import { acceptTerms } from '../src/policy.js';
import { totp, fromBase32, stepOf } from '../src/totp.js';

const NS = 'io.github.macguard/';
const meta = (extra = {}) => ({ 'io.modelcontextprotocol/protocolVersion': MODERN, 'io.modelcontextprotocol/clientCapabilities': {}, 'io.modelcontextprotocol/clientInfo': { name: 'test', version: '1' }, ...extra });
let id = 0;
const rpc = (w, key, method, params = {}, { headers = {}, m = meta(), noMeta = false } = {}) => {
  const body = { jsonrpc: '2.0', id: ++id, method, params: { ...params, ...(noMeta ? {} : { _meta: { ...m, ...(params._meta || {}) } }) } };
  return w.call('/mcp', { method: 'POST', key, json: body, headers: { 'mcp-protocol-version': MODERN, 'mcp-method': method, ...(params.name ? { 'mcp-name': params.name } : {}), accept: 'application/json, text/event-stream', ...headers } });
};
const call = (w, key, name, args = {}, extra = {}) => rpc(w, key, 'tools/call', { name, arguments: args, ...(extra.meta ? { _meta: extra.meta } : {}) }, { headers: extra.headers });
const K = async (w, t = 't1', scopes, o = {}) => { await w.tenant(t, o); return (await w.key(t, scopes)).key; };

test('protocol: every request carries version and capabilities, headers must agree with the body, unsupported versions say what is supported', async () => {
  const w = await apiWorld(); const key = await K(w);
  assert.equal((await rpc(w, key, 'tools/list')).status, 200);
  const noMeta = await rpc(w, key, 'tools/list', {}, { noMeta: true, headers: {} }); assert.equal(noMeta.status, 400); assert.equal(noMeta.json.error.code, -32602);
  const v = await rpc(w, key, 'tools/list', {}, { m: meta({ 'io.modelcontextprotocol/protocolVersion': '2099-01-01' }) }); assert.equal(v.status, 400); assert.equal(v.json.error.code, -32022); assert.deepEqual(v.json.error.data.supported, [MODERN]);
  const h = await rpc(w, key, 'tools/list', {}, { headers: { 'mcp-protocol-version': '2025-11-25' } }); assert.equal(h.json.error.code, -32020);
  const hm = await rpc(w, key, 'tools/list', {}, { headers: { 'mcp-method': 'tools/call' } }); assert.equal(hm.json.error.code, -32020);
  const hn = await rpc(w, key, 'tools/call', { name: 'macguard_lookup_hash', arguments: { hash: w.H } }, { headers: { 'mcp-name': 'something_else' } }); assert.equal(hn.json.error.code, -32020);
  const caps = await rpc(w, key, 'tools/list', {}, { m: { 'io.modelcontextprotocol/protocolVersion': MODERN } }); assert.equal(caps.status, 400);
  assert.equal((await w.call('/mcp', { key })).status, 405); assert.equal((await w.call('/mcp', { key, method: 'DELETE' })).status, 405);
  assert.equal((await w.call('/mcp', { key, method: 'POST', body: '{bad' })).json.error.code, -32700);
  assert.equal((await w.call('/mcp', { key, method: 'POST', json: [{ jsonrpc: '2.0', id: 1, method: 'ping' }] })).status, 400, 'batches do not exist in this revision');
  assert.equal((await rpc(w, key, 'resources/list')).status, 404);
  assert.equal((await w.call('/mcp', { key, method: 'POST', json: { jsonrpc: '2.0', method: 'notifications/x', params: {} } })).status, 202);
});
test('security: origin allow-list, authentication on every method, and no session state is minted', async () => {
  const w = await apiWorld(); const key = await K(w);
  const bad = await rpc(w, key, 'tools/list', {}, { headers: { origin: 'https://evil.example' } }); assert.equal(bad.status, 403);
  assert.equal((await rpc(w, key, 'tools/list', {}, { headers: { origin: 'https://agent.example' } })).status, 200);
  assert.equal((await rpc(w, null, 'tools/list')).status, 401); assert.equal((await rpc(w, 'mgk_bad', 'tools/call', { name: 'macguard_lookup_hash', arguments: { hash: w.H } })).status, 401);
  const ok = await rpc(w, key, 'tools/list', {}, { headers: { 'mcp-session-id': 'attacker-chosen' } }); assert.equal(ok.res.headers.get('mcp-session-id'), null, 'sessions are neither minted nor echoed');
});
test('discovery: each tool says what it does, which scope it needs, whether it can cost money and how to get its result; the list follows the key', async () => {
  const w = await apiWorld(); const key = await K(w); const list = (await rpc(w, key, 'tools/list')).json.result;
  assert.equal(list.resultType, 'complete'); assert.deepEqual(list.tools.map((t) => t.name), list.tools.map((t) => t.name).sort(), 'deterministic order'); assert.equal(list.cacheScope, 'private');
  const t = Object.fromEntries(list.tools.map((x) => [x.name, x]));
  for (const x of list.tools) { assert.ok(x.description.length > 20 && x.inputSchema.type === 'object' && x.annotations); assert.ok(x._meta[NS + 'scope'] !== undefined && x._meta[NS + 'billing'].class && x._meta[NS + 'result']); assert.match(x.name, /^[A-Za-z0-9_.-]{1,128}$/); }
  assert.equal(t.macguard_enrich_indicators._meta[NS + 'billing'].class, 'metered'); assert.equal(t.macguard_lookup_hash._meta[NS + 'billing'].class, 'included'); assert.match(t.macguard_authorize_download._meta[NS + 'result'], /authorisation/);
  const small = await K(w, 't2', ['intel.query', 'mcp']); const names = (await rpc(w, small, 'tools/list')).json.result.tools.map((x) => x.name);
  assert.ok(names.includes('macguard_lookup_hash') && !names.includes('macguard_enrich_indicators') && !names.includes('macguard_authorize_download'), 'a tool the key could not call is not offered');
  const w2 = await apiWorld({ policy: paid() }); const c = await K(w2, 'c1'); assert.deepEqual((await rpc(w2, c, 'tools/list')).json.result.tools.map((x) => x.name).filter((n) => n.includes('lookup')), [], 'no entitlement, no tools');
  for (const [op, o] of Object.entries(OPS)) if (o.tool) assert.ok(tools().some((x) => x.name === o.tool && x._meta[NS + 'operation'] === op), op);
});
test('MCP and REST are the same path: identical results, identical permissions, identical accounting', async () => {
  const w = await apiWorld(); const key = await K(w);
  const rest = await w.call('/v1/intelligence/hash/' + w.H, { key }); const mcp = await call(w, key, 'macguard_lookup_hash', { hash: w.H });
  assert.deepEqual(mcp.json.result.structuredContent, rest.json); assert.equal(mcp.json.result.isError, false); assert.equal(JSON.parse(mcp.json.result.content[0].text).found, true);
  const narrow = await K(w, 't2', ['intel.query', 'mcp']); const e = await call(w, narrow, 'macguard_enrich_indicators', { indicators: ['203.0.113.7'] }, { meta: { [NS + 'idempotencyKey']: 'mcp-enrich-1' } });
  assert.equal(e.json.result.isError, true); assert.equal(e.json.result.structuredContent.error.code, 'insufficient_scope');
  const unknown = await call(w, key, 'macguard_delete_everything'); assert.equal(unknown.json.error.code, -32602);
  const badArgs = await call(w, key, 'macguard_lookup_hash', { hash: 'zzz' }); assert.equal(badArgs.json.result.isError, true); assert.equal(badArgs.json.result.structuredContent.error.code, 'invalid_input');
  const extra = await call(w, key, 'macguard_lookup_hash', { hash: w.H, tenant_id: 't9' }); assert.equal(extra.json.result.isError, true, 'extra arguments (a tenant id, say) are rejected, never honoured');
  const { revokeKey } = await import('../src/auth.js'); const k3 = await w.key('t1'); await revokeKey(w.db, w.clock, 't1', k3.id); assert.equal((await call(w, k3.key, 'macguard_lookup_hash', { hash: w.H })).status, 401);
  const rows = (await w.db.prepare("SELECT billing_status s, billable_micros b, commercial_mode m FROM usage_events WHERE operation = 'intel.hash'").all()).results;
  assert.equal(rows.length, 2, 'one recorded use for the REST call and one for the MCP call'); assert.ok(rows.every((r) => r.s === 'included' && r.b === 0 && r.m === 'FREE_LAUNCH'), 'identical accounting through both doors');
});
test('an agent without credit is told so in a form it can act on; with a budget it works; retries are not charged twice', async () => {
  const w = await apiWorld({ policy: paid() }); await w.tenant('t1', { plan: 'intelligence', budgetMicros: 0 }); const key = (await w.key('t1')).key; let ctx = await w.ctx(key);
  await acceptTerms(w.db, w.clock, ctx, ctx.policy.doc, { pricing_version: SEED.billing.pricing.version, terms_version: SEED.billing.terms_version }); w.clock.advance(1000);
  const args = { indicators: ['203.0.113.7', 'CVE-2026-0001'] }, m = { [NS + 'idempotencyKey']: 'agent-run-0001' };
  const noKey = await call(w, key, 'macguard_enrich_indicators', args); assert.equal(noKey.json.result.structuredContent.error.code, 'idempotency_key_required');
  const none = await call(w, key, 'macguard_enrich_indicators', args, { meta: m }); assert.equal(none.json.result.isError, true); assert.equal(none.json.result.structuredContent.error.code, 'budget_required'); assert.equal(none.json.result.structuredContent.error.estimated_micros, 10000);
  await w.db.prepare("UPDATE tenants SET monthly_budget_micros = 15000 WHERE id = 't1'").run();
  const a = await call(w, key, 'macguard_enrich_indicators', args, { meta: m }); assert.equal(a.json.result.isError, false); assert.equal(a.json.result._meta[NS + 'replayed'], false);
  const b = await call(w, key, 'macguard_enrich_indicators', args, { meta: m }); assert.equal(b.json.result._meta[NS + 'replayed'], true); assert.deepEqual(b.json.result.structuredContent, a.json.result.structuredContent);
  assert.equal((await w.db.prepare("SELECT SUM(billable_micros) s FROM usage_events WHERE billing_status = 'billed'").first()).s, 10000);
  const over = await call(w, key, 'macguard_enrich_indicators', args, { meta: { [NS + 'idempotencyKey']: 'agent-run-0002' } }); assert.equal(over.json.result.structuredContent.error.code, 'budget_exceeded');
  const est = await call(w, key, 'macguard_estimate_cost', { operations: [{ operation: 'intel.enrich', count: 100 }] }); assert.equal(est.json.result.structuredContent.total_would_be_charged_micros, 500000);
  assert.equal((await w.db.prepare("SELECT COUNT(*) n FROM usage_events WHERE idem_key LIKE 'agent-run-%'").first()).n, 1, 'pricing is separate from execution: estimating and refused calls leave no charge');
});
test('legacy clients (initialize handshake, no _meta) are served without any session', async () => {
  const w = await apiWorld(); const key = await K(w);
  const init = await w.call('/mcp', { method: 'POST', key, json: { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'old', version: '1' } } } });
  assert.equal(init.json.result.protocolVersion, '2025-06-18'); assert.ok(init.json.result.capabilities.tools); assert.equal(init.res.headers.get('mcp-session-id'), null);
  assert.equal((await w.call('/mcp', { method: 'POST', key, json: { jsonrpc: '2.0', method: 'notifications/initialized' } })).status, 202);
  const list = await w.call('/mcp', { method: 'POST', key, headers: { 'mcp-protocol-version': '2025-06-18' }, json: { jsonrpc: '2.0', id: 2, method: 'tools/list' } }); assert.ok(list.json.result.tools.length > 3); assert.equal(list.json.result.resultType, undefined);
  const c = await w.call('/mcp', { method: 'POST', key, headers: { 'mcp-protocol-version': '2025-06-18' }, json: { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'macguard_lookup_hash', arguments: { hash: w.H } } } }); assert.equal(c.json.result.structuredContent.found, true);
  const unauth = await w.call('/mcp', { method: 'POST', json: { jsonrpc: '2.0', id: 4, method: 'tools/list' } }); assert.equal(unauth.status, 401);
});

// ---- x402 (experimental, separate, off by default) ----
const REQ = { scheme: 'opaque-from-config', price: 'example' };
const b64 = (o) => btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(o))));
test('x402: off by default; when on, 402 with the requirements, then data only after a verified AND settled payment; nothing is stored about the payer', async () => {
  const calls = []; const fac = { verify: async (p) => { calls.push('verify'); return { isValid: p.ok === true }; }, settle: async (p) => { calls.push('settle'); return p.pending ? { success: false, error: 'settlement_pending' } : { success: true, transaction: '0xabc', network: 'test-net' }; } };
  const off = await apiWorld({ facilitator: fac }); assert.equal((await off.call('/x402/v1/intelligence/hash/' + off.H)).status, 404);
  const w = await apiWorld({ facilitator: fac, envExtra: { X402_ENABLED: 'true', X402_REQUIREMENTS: JSON.stringify(REQ) } });
  const first = await w.call('/x402/v1/intelligence/hash/' + w.H); assert.equal(first.status, 402); assert.deepEqual(JSON.parse(atob(first.res.headers.get('payment-required'))), REQ); assert.ok(!first.text.includes('SynMalware'));
  const pay = (o) => ({ headers: { 'payment-signature': b64(o) } });
  const bad = await w.call('/x402/v1/intelligence/hash/' + w.H, pay({ ok: false })); assert.equal(bad.status, 402); assert.ok(!bad.text.includes('SynMalware'));
  const pending = await w.call('/x402/v1/intelligence/hash/' + w.H, pay({ ok: true, pending: true })); assert.equal(pending.status, 402); assert.ok(!pending.text.includes('SynMalware'), 'data is delivered only after settlement succeeds');
  const ok = await w.call('/x402/v1/intelligence/hash/' + w.H, pay({ ok: true, payer: 'wallet-address-should-not-be-stored' })); assert.equal(ok.status, 200); assert.equal(ok.json.found, true); assert.deepEqual(JSON.parse(atob(ok.res.headers.get('payment-response'))), { transaction: '0xabc', network: 'test-net', success: true });
  const audit = JSON.stringify((await w.db.prepare('SELECT detail FROM audit').all()).results); assert.ok(audit.includes('0xabc') && !audit.includes('wallet-address'));
  assert.equal((await w.call('/x402/v1/intelligence/hash/' + w.H, { headers: { 'payment-signature': '!!notbase64' } })).status, 400); assert.equal((await w.call('/x402/v1/intelligence/hash/xyz')).status, 404);
  const noCfg = await apiWorld({ facilitator: fac, envExtra: { X402_ENABLED: 'true' } }); assert.equal((await noCfg.call('/x402/v1/intelligence/hash/' + noCfg.H)).status, 503);
  assert.equal((await w.call('/v1/intelligence/hash/' + w.H)).status, 401, 'x402 does not open the keyed API to anonymous callers');
});

// ---- administration over HTTP ----
test('administration over HTTP: customer keys cannot reach it, every call needs key + a fresh code, changes need approvals, rollback is immediate', async () => {
  const w = await apiWorld(); const [a, b] = [await w.admin('ana'), await w.admin('ben')]; await w.tenant('t1'); const cust = (await w.key('t1')).key;
  assert.equal((await w.call('/admin/v1/policy', { key: cust })).status, 401, 'a customer API key is not an administrator');
  const adm = async (who, path, method = 'GET', json) => w.call(path, { method, headers: await who.headers(), json });
  const get = await adm(a, '/admin/v1/policy'); assert.equal(get.status, 200); assert.equal(get.json.version, 1); assert.equal(get.json.policy.mode, 'FREE_LAUNCH'); assert.ok(!JSON.stringify(get.json).match(/mgk_|mga_|sk_/));
  const hs = await a.headers(); assert.equal((await w.call('/admin/v1/policy', { headers: hs })).status, 200); assert.equal((await w.call('/admin/v1/policy', { headers: hs })).status, 401, 'the same code cannot be used twice');
  const d = clone(SEED); d.mode = 'PAID'; assert.equal((await adm(a, '/admin/v1/policy/proposals', 'POST', { policy: d, reason: 'go' })).status, 422);
  const s = clone(SEED); s.scheduled = { mode: 'PAID', effective_from: '2027-03-01T00:00:00Z' }; s.billing.live = true; s.billing.pricing.approved = true;
  const p = await adm(a, '/admin/v1/policy/proposals', 'POST', { policy: s, reason: 'announce' }); assert.equal(p.status, 201); assert.equal(p.json.approvals_required, 2);
  assert.equal((await adm(a, `/admin/v1/policy/proposals/${p.json.id}/apply`, 'POST', {})).json.error.code, 'approvals_missing');
  assert.equal((await adm(b, `/admin/v1/policy/proposals/${p.json.id}/approve`, 'POST', {})).json.approvals, 2); assert.equal((await adm(b, `/admin/v1/policy/proposals/${p.json.id}/apply`, 'POST', {})).json.version, 2);
  assert.equal((await adm(a, '/admin/v1/policy')).json.policy.scheduled.mode, 'PAID');
  const rb = await adm(b, '/admin/v1/policy/rollback', 'POST', { reason: 'incident' }); assert.equal(rb.status, 200); assert.equal(rb.json.version, 3); const after = await adm(a, '/admin/v1/policy'); assert.deepEqual([after.json.policy.mode, after.json.policy.scheduled, after.json.policy.billing.live], ['FREE_LAUNCH', null, false]);
  assert.deepEqual(after.json.history.versions.map((v) => v.kind), ['seed', 'change', 'rollback']); assert.equal((await adm(a, '/admin/v1/nothing')).status, 404);
});
