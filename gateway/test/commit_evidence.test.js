// commit_evidence.sh against a local bare repository: it stages ONLY evidence/backups.jsonl, does nothing when nothing changed, and survives a concurrent push by rebasing.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, appendFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SH = new URL('../tools/commit_evidence.sh', import.meta.url).pathname, git = (cwd, ...a) => execFileSync('git', a, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
test('only the evidence file is committed; no change = no commit; a concurrent push is rebased over', () => {
  const root = mkdtempSync(join(tmpdir(), 'mg-ev-')); try {
    const bare = join(root, 'bare.git'), a = join(root, 'a'), b = join(root, 'b'); git(root, 'init', '-q', '--bare', '-b', 'main', bare); git(root, 'clone', '-q', bare, a); git(a, 'config', 'user.email', 't@t'); git(a, 'config', 'user.name', 't');
    writeFileSync(join(a, 'README'), 'x'); git(a, 'add', '.'); git(a, 'commit', '-q', '-m', 'init'); git(a, 'push', '-q', 'origin', 'HEAD:main'); git(root, 'clone', '-q', bare, b);
    mkdirSync(join(a, 'evidence')); writeFileSync(join(a, 'evidence', 'backups.jsonl'), '{"kind":"backup","run_id":1}\n'); writeFileSync(join(a, 'logs.txt'), 'must not be committed');
    execFileSync('sh', [SH, 'backup run 1'], { cwd: a, stdio: 'pipe' }); assert.equal(git(a, 'show', '--stat', '--format=%an|%s', 'HEAD').trim().split('\n')[0], 'macguard-evidence[bot]|evidence: backup run 1'); assert.deepEqual(git(a, 'show', '--name-only', '--format=', 'HEAD').trim().split('\n'), ['evidence/backups.jsonl']);
    const n = git(a, 'rev-list', '--count', 'HEAD'); execFileSync('sh', [SH, 'again'], { cwd: a, stdio: 'pipe' }); assert.equal(git(a, 'rev-list', '--count', 'HEAD'), n, 'no change, no commit');
    git(b, 'config', 'user.email', 't@t'); git(b, 'config', 'user.name', 't'); git(b, 'pull', '-q', 'origin', 'main'); writeFileSync(join(b, 'other'), 'concurrent'); git(b, 'add', '.'); git(b, 'commit', '-q', '-m', 'someone else'); git(b, 'push', '-q', 'origin', 'HEAD:main');
    appendFileSync(join(a, 'evidence', 'backups.jsonl'), '{"kind":"backup","run_id":2}\n'); execFileSync('sh', [SH, 'backup run 2'], { cwd: a, stdio: 'pipe' }); git(root, 'clone', '-q', bare, join(root, 'c')); assert.equal(readFileSync(join(root, 'c', 'evidence', 'backups.jsonl'), 'utf8').trim().split('\n').length, 2); assert.equal(readFileSync(join(root, 'c', 'other'), 'utf8'), 'concurrent', 'nothing of the other writer was lost');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
