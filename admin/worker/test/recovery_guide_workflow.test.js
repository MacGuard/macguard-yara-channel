// The workflow that signs the offline package: pinned actions, one signing job, no secrets, and the identity that the package README tells people to verify is exactly this workflow on main.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..'), wf = readFileSync(join(ROOT, '.github/workflows/recovery-guide.yml'), 'utf8'), gen = readFileSync(join(ROOT, 'admin/worker/tools/build_recovery_guide.mjs'), 'utf8');
test('recovery-guide.yml: main only, no secrets, id-token only for signing, actions pinned by SHA, and the README verifies the very identity it signs with', () => {
  assert.match(wf, /^permissions: \{\}$/m); assert.equal((wf.match(/id-token: write/g) ?? []).length, 1); assert.ok(!/secrets\.|environment:|contents: write|pull_request/.test(wf)); assert.match(wf, /if: github\.ref == 'refs\/heads\/main'/);
  for (const m of wf.matchAll(/uses: ([^\s@]+)@(\S+)/g)) assert.match(m[2], /^[0-9a-f]{40}$/, `${m[1]} pinned by SHA`);
  assert.match(wf, /certificate-identity "\$\{GITHUB_SERVER_URL\}\/\$\{GITHUB_REPOSITORY\}\/\.github\/workflows\/recovery-guide\.yml@refs\/heads\/main"/);
  assert.match(gen, /workflows\/recovery-guide\.yml@refs\/heads\/main/); assert.match(wf, /cosign sign-blob --yes --bundle SHA256SUMS\.sigstore\.json SHA256SUMS/); assert.match(wf, /retention-days: 90/);
  assert.ok(!/AGE-SECRET|PRIVATE KEY|MACGUARD_BACKUP_SIGNING_KEY/.test(wf));
});
