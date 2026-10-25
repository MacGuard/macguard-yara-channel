// The failure classification that travels as a job annotation: fixed vocabulary only, round-trips through the parser the panel uses, and never carries free text or credentials.
import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyFailure, annotation, parseAnnotation, ANNOTATION_PREFIX } from '../tools/backup_diagnose.mjs';

const WR = 'wrangler d1 export failed: ✘ [ERROR] A request to the Cloudflare API (/accounts/xxxx/d1/database/yyyy/export) failed. | Authentication error [code: 10000] | If you think this is a bug';
test('the real D1 export failure (HTTP 401, code 10000) is a Cloudflare authentication problem', () => {
  const c = classifyFailure('export', WR); assert.deepEqual([c.phase, c.kind, c.code], ['export', 'cloudflare_auth', '10000']);
  assert.deepEqual(parseAnnotation(annotation('panel', c).split('::error title=macguard-backup::')[1]), { resource: 'panel', phase: 'export', kind: 'cloudflare_auth', code: '10000', http: null });
});
test('other causes are told apart; an unknown one stays unknown instead of being guessed', () => {
  const k = (t, p = 'export') => classifyFailure(p, t).kind;
  assert.equal(k('Forbidden: not authorized to access this resource'), 'cloudflare_permission'); assert.equal(k('could not find database'), 'cloudflare_not_found'); assert.equal(k('429 Too Many Requests'), 'rate_limited');
  assert.equal(k('spawnSync npx ETIMEDOUT'), 'timeout'); assert.equal(k('getaddrinfo ENOTFOUND api.cloudflare.com'), 'network'); assert.equal(k('something odd happened'), 'unknown'); assert.equal(k('row counts differ', 'verify'), 'verify_failed');
});
test('the annotation never carries free text, a token or SQL, whatever the tool printed', () => {
  const token = ['cf', 'k', 'x'.repeat(40)].join('_'), line = annotation('gateway', classifyFailure('export', `Authentication error [code: 10000] token=${token} SELECT * FROM users WHERE secret='s3cr3t'`));
  assert.ok(!line.includes(token) && !/SELECT|s3cr3t/.test(line)); assert.match(line, /^::error title=macguard-backup::macguard-backup: resource=gateway phase=export kind=cloudflare_auth code=10000$/);
  assert.equal(line.split('\n').length, 1, 'one line: nothing a log line could inject');
});
test('the parser rejects anything that is not exactly the fixed shape', () => {
  for (const bad of ['', 'macguard-backup: kind=cloudflare_auth', `${ANNOTATION_PREFIX} resource=x phase=export kind=evil`, `${ANNOTATION_PREFIX} resource=gateway phase=export kind=cloudflare_auth <script>`, 'hello', `${ANNOTATION_PREFIX} phase=nope kind=unknown`]) assert.equal(parseAnnotation(bad), null, bad);
  assert.equal(parseAnnotation(`${ANNOTATION_PREFIX} phase=export kind=cloudflare_auth code=99999999`).code, null, 'a code of the wrong shape is dropped');
});
