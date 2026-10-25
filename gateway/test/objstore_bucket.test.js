// A 404 on an object does not prove the bucket exists: the destination check asks the bucket itself, and a missing or forbidden bucket stops the destination before anything is attempted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { s3Client, syncAll, FILES } from '../tools/backup_objstore.mjs';

const client = (status) => s3Client({ endpoint: 'https://s3.example.invalid', region: 'r', bucket: 'b', accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'secretexample', fetchImpl: async (url, init) => { client.seen.push([init.method, new URL(url).pathname]); return new Response(null, { status: typeof status === 'function' ? status(init.method, new URL(url).pathname) : status }); } });
client.seen = [];

test('bucket(): EXISTS, MISSING, DENIED and anything else is reported as such, with a HEAD on the bucket path only', async () => {
  assert.equal(await client(200).bucket(), 'EXISTS'); assert.deepEqual(client.seen.at(-1), ['HEAD', '/b']);
  assert.equal(await client(404).bucket(), 'MISSING'); assert.equal(await client(403).bucket(), 'DENIED'); assert.equal(await client(401).bucket(), 'DENIED'); assert.equal(await client(500).bucket(), 'HTTP_500');
});

test('a destination whose bucket is missing or forbidden is stopped before any object is read or written, and the report says why', async () => {
  const root = mkdtempSync(join(tmpdir(), 'mg-ob-')), dir = join(root, '20261024T050235Z'); mkdirSync(dir); for (const f of FILES) writeFileSync(join(dir, f), 'x');
  const seen = []; const mk = (status) => ({ bucket: async () => status, get: async (k) => { seen.push(['get', k]); return null; }, put: async (k) => { seen.push(['put', k]); } });
  const r = await syncAll({ root, apply: true, clientOverride: { b2: mk('EXISTS'), scaleway: mk('MISSING'), r2: mk('DENIED') } });
  assert.equal(r.destinations.b2.state, 'READY'); assert.equal(r.destinations.scaleway.state, 'BUCKET_MISSING'); assert.equal(r.destinations.r2.state, 'BUCKET_DENIED');
  assert.ok(r.destinations.scaleway.errors[0].includes('nothing is attempted')); assert.equal(r.destinations.scaleway.ok, false);
  assert.ok(seen.every(([, k]) => k.startsWith('gateway-d1/')) && seen.length > 0, 'only the existing destination was touched');
});
