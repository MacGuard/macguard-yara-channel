import test from 'node:test';
import assert from 'node:assert/strict';
import { EVENT_TYPES, emit, makeEvent, memorySink } from '../src/events.js';
import { apiWorld } from './apiworld.js';

const clock = () => new Date('2026-10-23T10:00:00Z');
test('the event contract: the twelve GuardOps events exist, need their fields, and carry no secret', () => {
  const wanted = ['download.authorized', 'download.rejected', 'usage.near_limit', 'tenant.suspended', 'billing.error', 'stripe.failure', 'api.saturated', 'abuse.detected', 'release.premium_published', 'signature.invalid', 'replication.failed', 'gateway.incident'];
  assert.deepEqual(Object.keys(EVENT_TYPES).sort(), wanted.sort());
  assert.throws(() => makeEvent('made.up', {}, clock), /unknown event type/); assert.throws(() => makeEvent('download.rejected', { tenant_id: 't' }, clock), /lacks reason/);
  const e = makeEvent('download.rejected', { tenant_id: 't1', reason: 'shared_link', api_key: 'mgk_0000000000000000_' + 'A'.repeat(43), authorization: 'Bearer x', stripe_secret: 's' }, clock);
  assert.equal(e.schema, 'macguard.gateway-event/1'); assert.equal(e.at, '2026-10-23T10:00:00Z'); assert.ok(!JSON.stringify(e).includes('mgk_') && !JSON.stringify(e).includes('Bearer')); assert.equal(e.data.api_key, '[redacted]');
});
test('an observer can never break a request: a failing sink is swallowed, and events leave no trace of the work done', async () => {
  const bad = { EVENTS: { emit: () => { throw new Error('sink down'); } } }; await emit(bad, clock, 'gateway.incident', { component: 'x', code: 'y' });
  const sink = memorySink(); await emit({ EVENTS: sink }, clock, 'gateway.incident', { component: 'origin', code: 'r2_error' }); assert.equal(sink.events.length, 1);
  await emit({}, clock, 'gateway.incident', { component: 'origin', code: 'r2_error' });                                       // no sink configured at all
  const w = await apiWorld(); w.env.EVENTS = bad.EVENTS; await w.tenant('t1'); const key = (await w.key('t1')).key; w.r2.fail = true;
  const a = await w.call('/v1/premium/releases/prem-1/download', { key }); const r = await w.call(a.json.url.replace('https://gw.test', ''), { key }); assert.equal(r.status, 503, 'the request still answers properly');
});
test('the events that matter are emitted where they happen', async () => {
  const w = await apiWorld(); await w.tenant('t1'); const key = (await w.key('t1')).key; const key2 = (await w.key('t1')).key;
  const a = await w.call('/v1/premium/releases/prem-1/download', { key }); await w.call(a.json.url.replace('https://gw.test', ''), { key: key2 });
  assert.ok(w.env.EVENTS.events.some((e) => e.type === 'download.authorized' && e.data.release_id === 'prem-1' && e.data.tenant_id === 't1'));
  assert.ok(w.env.EVENTS.events.some((e) => e.type === 'download.rejected' && e.data.reason === 'shared_link'));
});
