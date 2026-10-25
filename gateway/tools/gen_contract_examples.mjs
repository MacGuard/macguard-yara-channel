// Writes contracts/v1/examples/*.json: one valid sample per operational event type MacGuard can send, produced by the SAME adapter code (not hand-written), so a receiver (GuardOps) can build its consumer
// tests against real payloads. `--check` fails if the committed examples differ from what the code produces now.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { toEnvelope, envelopeFromAlert, metricsSnapshot } from '../src/guardops.js';
import { newDb } from '../test/d1shim.js';

const clock = () => new Date('2026-10-24T06:00:00Z'), at = '2026-10-24T06:00:00Z', env = { GUARDOPS_TENANT: 'macguard' }, dir = new URL('../../contracts/v1/examples/', import.meta.url);
const samples = {
  'cron.run.failed': await toEnvelope({ type: 'gateway.incident', at, data: { component: 'github-collector', code: 'github_rate_limited' } }, env, clock),
  'download.failed': await toEnvelope({ type: 'gateway.incident', at, data: { component: 'origin', code: 'r2_error' } }, env, clock),
  'gateway.error': await toEnvelope({ type: 'stripe.failure', at, data: { stage: 'meter', status: 500 } }, env, clock),
  'saturation.detected': await toEnvelope({ type: 'api.saturated', at, data: { tenant_id: 'tenant-ref', scope: 'minute' } }, env, clock),
  'security.incident': await toEnvelope({ type: 'abuse.detected', at, data: { tenant_id: 'tenant-ref', signal: 'shared_link' } }, env, clock),
  'integrity.error': await toEnvelope({ type: 'signature.invalid', at, data: { release_id: 'prem-1', stage: 'verify' } }, env, clock),
  'backup.failed': await envelopeFromAlert({ rule_id: 'backup.stale', severity: 'high', state: 'FIRING', message: 'Last successful backup 40.0 h ago.', value: 40, evaluated_at: at, source: { kind: 'agent', id: 'backup-check' } }, env, clock),
  'metrics.snapshot': await metricsSnapshot(newDb(), clock),
};
samples['metrics.snapshot'].tenant_id = 'macguard';
const batch = { schema: 'macguard.event-batch/1', events: Object.values(samples) };
const files = { ...Object.fromEntries(Object.entries(samples).map(([k, v]) => [`event-${k}.json`, v])), 'batch.json': batch };
if (process.argv.includes('--check')) { let bad = 0; for (const [f, v] of Object.entries(files)) { let cur = ''; try { cur = readFileSync(new URL(f, dir), 'utf8'); } catch { /* missing */ } if (cur !== JSON.stringify(v, null, 2) + '\n') { console.error('out of date: ' + f); bad++; } } if (bad) process.exit(1); console.log('contract examples are current'); }
else { mkdirSync(dir, { recursive: true }); for (const [f, v] of Object.entries(files)) writeFileSync(new URL(f, dir), JSON.stringify(v, null, 2) + '\n'); console.log('written ' + Object.keys(files).length + ' examples'); }
