// The detail of each finding (contract findings_schema 1): validated and bounded on arrival, tied to the run of the verified token, never trusted from the request body.
import test from 'node:test';
import assert from 'node:assert/strict';
import { world, cand } from './helpers.js';
import { sanitizeFindings } from '../src/core.js';

const good = { code: 'costly-regex', severity: 'review', detail: 'regex /(a+)+b/ risk 7', observed: 7, threshold: 6, unit: 'risk score' };

test('a well formed report is kept as sent, and only the allowed fields of each finding', () => {
  const r = sanitizeFindings({ findings_schema: 1, findings: [{ ...good, secret: 'no' }, { code: 'filesize-loop', severity: 'review', detail: 'rule R iterates over the whole file' }], engine: 'YARA 4.5.0' });
  assert.deepEqual(r.findings, [good, { code: 'filesize-loop', severity: 'review', detail: 'rule R iterates over the whole file' }]);
  assert.deepEqual([r.findings_schema, r.findings_dropped, r.engine], [1, 0, 'YARA 4.5.0']);
});

test('nothing is repaired or guessed: what does not fit is dropped and counted', () => {
  const bad = [null, 'x', { severity: 'review' }, { code: 'Bad Code', severity: 'review' }, { code: 'ok-code', severity: 'catastrophic' }, { code: 'x'.repeat(41), severity: 'review' }];
  const r = sanitizeFindings({ findings_schema: 1, findings: [good, ...bad] });
  assert.deepEqual(r.findings, [good]); assert.equal(r.findings_dropped, bad.length);
  const odd = sanitizeFindings({ findings_schema: 1, findings: [{ code: 'a', severity: 'review', observed: Infinity, threshold: NaN, unit: 'u'.repeat(41) }, { code: 'b', severity: 'review', observed: { x: 1 }, threshold: 's'.repeat(81) }] });
  assert.deepEqual(odd.findings, [{ code: 'a', severity: 'review' }, { code: 'b', severity: 'review' }], 'a non-finite number, an object or an oversized value is not stored as a measurement');
});

test('sizes are bounded; control characters are removed; the count of findings is capped', () => {
  const r = sanitizeFindings({ findings_schema: 1, findings: [{ code: 'a', severity: 'review', detail: `x\u0000y\n${'z'.repeat(1000)}` }], engine: `YARA\u0007${'e'.repeat(300)}` });
  assert.equal(r.findings[0].detail.length, 400); assert.ok(r.findings[0].detail.endsWith('…')); assert.equal(/[\u0000-\u001f]/.test(r.findings[0].detail + r.engine), false); assert.equal(r.engine.length, 80);
  const many = sanitizeFindings({ findings_schema: 1, findings: Array.from({ length: 45 }, () => good) }); assert.deepEqual([many.findings.length, many.findings_dropped], [30, 15]);
});

test('an old pipeline sends no report, and an unknown version or shape is recorded as unsupported, not interpreted', () => {
  assert.equal(sanitizeFindings({}), null); assert.equal(sanitizeFindings(null), null);
  const v2 = sanitizeFindings({ findings_schema: 2, findings: [good] }); assert.deepEqual([v2.findings, v2.findings_dropped, v2.findings_unsupported], [[], 1, true]);
  const notArray = sanitizeFindings({ findings_schema: 1, findings: { code: 'a' } }); assert.deepEqual([notArray.findings, notArray.findings_unsupported], [[], true]);
});

const submit = (w, items) => w.call('POST', '/api/pipeline/submit', { bearer: w.__tok, body: { run_id: 'body-says-1', candidates: items } });
async function world2(claims = { run_id: '7777', run_attempt: '2' }) { const w = await world(); w.reviewer = await w.login('rita', { push: true }); w.__tok = await w.pipelineToken('daily.yml', claims); return w; }
const metricsOf = async (w, id) => (await w.call('GET', `/api/candidates/${id}`, { user: w.reviewer })).data.metrics;

test('the report is stored with the candidate and tied to the run of the verified token, whatever the request body says', async () => {
  const w = await world2();
  const r = await submit(w, [cand('a', 'rules/x/a.yar', { findings_schema: 1, findings: [good], engine: 'YARA 4.5.0', metrics: { cpu_s: 1.2, findings_run: { run_id: 'forged', run_attempt: 99 }, findings: [{ code: 'forged', severity: 'review' }], engine: 'forged' } })]);
  assert.equal(r.status, 200); const m = await metricsOf(w, r.data.results[0].id);
  assert.deepEqual(m.findings, [good]); assert.deepEqual([m.findings_schema, m.findings_dropped, m.engine, m.cpu_s], [1, 0, 'YARA 4.5.0', 1.2]);
  assert.deepEqual(m.findings_run, { run_id: '7777', run_attempt: 2 }, 'the run is the one the signed token names, not what the request claims');
});

test('a malformed report never rejects the submission and nothing forged survives; a pipeline without the field stores none', async () => {
  const w = await world2();
  const r = await submit(w, [cand('a', 'rules/x/a.yar', { findings_schema: 1, findings: [{ code: 'BAD', severity: 'x' }, good] }), cand('b', 'rules/x/b.yar', { metrics: { findings: [{ code: 'forged', severity: 'review' }], findings_run: { run_id: 'forged' }, engine: 'forged', cpu_s: 2 } })]);
  assert.equal(r.status, 200); const [a, b] = r.data.results;
  const ma = await metricsOf(w, a.id); assert.deepEqual([ma.findings, ma.findings_dropped], [[good], 1]);
  const mb = await metricsOf(w, b.id); assert.deepEqual(Object.keys(mb).sort(), ['cpu_s'], 'metrics sent without the contract cannot carry findings, a run or an engine');
});

test('the next run refreshes the report of a candidate it already knows and keeps its state', async () => {
  const w = await world2(); const item = cand('a', 'rules/x/a.yar');
  const first = await submit(w, [item]); const id = first.data.results[0].id; assert.equal((await metricsOf(w, id)).findings, undefined, 'received before the contract: no report');
  w.__tok = await w.pipelineToken('daily.yml', { run_id: '8888', run_attempt: '1' });
  const second = await submit(w, [{ ...item, findings_schema: 1, findings: [good] }]); assert.equal(second.data.results[0].status, 'known'); assert.equal(second.data.results[0].id, id);
  const m = await metricsOf(w, id); assert.deepEqual([m.findings, m.findings_run], [[good], { run_id: '8888', run_attempt: 1 }]);
  assert.equal((await w.call('GET', `/api/candidates/${id}`, { user: w.reviewer })).data.state, 'PENDING');
});
