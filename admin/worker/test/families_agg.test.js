// The multi-family day state and matrix: the worst observed state wins, an unobserved family is never green or zero, YARA-only data still works, and the matrix sums only what was observed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeDays, matrix } from '../public/views/families_agg.js';

const ops = [{ date: '2026-10-24', state: 'OK', runs: 1, stats: { accepted: 5, quarantined: 2, rejected: 1 } }, { date: '2026-10-25', state: 'OK', runs: 1, stats: { accepted: 6, quarantined: 0, rejected: 0 } }, { date: '2026-10-26', state: 'NO_RUN', runs: 0, stats: null }];
const run = (family, day, state, over = {}) => ({ family, retrieved_at: `${day}T04:00:00Z`, state, accepted: 10, rejected: 1, retained: 9, approved: 0, published: 0, ...over });

test('a failing family turns an otherwise green day red, a partial one amber, and the cell says which family', () => {
  const d = mergeDays(ops, [run('suricata', '2026-10-24', 'FAILED'), run('sigma', '2026-10-25', 'PARTIAL')]);
  assert.equal(d[0].state, 'FAIL'); assert.deepEqual(d[0].attention, [{ family: 'suricata', state: 'FAIL' }]);
  assert.equal(d[1].state, 'WARNING'); assert.deepEqual(d[1].attention, [{ family: 'sigma', state: 'WARNING' }]);
});
test('every family fine is green; no observation anywhere keeps the pipeline state (grey), never green', () => {
  const d = mergeDays(ops, [run('suricata', '2026-10-24', 'COMPLETE'), run('kev', '2026-10-24', 'COMPLETE')]);
  assert.equal(d[0].state, 'OK'); assert.equal(d[0].families_observed, 3); assert.equal(d[2].state, 'NO_RUN'); assert.equal(d[2].families_observed, 0);
});
test('a day with no YARA run but an intelligence run is judged by what was observed', () => {
  const d = mergeDays(ops, [run('cve', '2026-10-26', 'COMPLETE')]); assert.equal(d[2].state, 'OK'); assert.equal(d[2].ops_state, 'NO_RUN');
});
test('without intelligence data (a viewer) the result is the YARA pipeline alone and says so', () => {
  const d = mergeDays(ops, [], 14, false); assert.equal(d[0].state, 'OK'); assert.equal(d[0].intel_known, false); assert.equal(d.length, 3);
});
test('the matrix keeps unobserved cells null, sums only observed ones, and puts YARA first', () => {
  const d = mergeDays(ops, [run('suricata', '2026-10-24', 'COMPLETE', { retained: 7 }), run('suricata', '2026-10-24', 'COMPLETE', { retained: 3 }), run('sigma', '2026-10-25', 'COMPLETE', { retained: 4 })]);
  const m = matrix(d, 'retained'); assert.deepEqual(m.rows.map((r) => r.family), ['yara', 'sigma', 'suricata']);
  assert.deepEqual(m.rows.find((r) => r.family === 'suricata').values, [10, null, null]); assert.deepEqual(m.totals, [12, 4, null], 'YARA 2 + Suricata 10; YARA 0 + Sigma 4; nothing observed on the last day');
});
