import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { REPO_ROOT, have, pathEntries, resolveTool } from './tools_available.js';

const mk = (dir, name, mode = 0o755) => { mkdirSync(dir, { recursive: true }); const f = join(dir, name); writeFileSync(f, '#!/bin/sh\nexit 0\n'); chmodSync(f, mode); return f; };

test('the PATH this suite runs with is trustworthy: every entry is absolute and none lies inside the repository (the tests spawn tools by bare name)', () => {
  const bad = pathEntries().filter((e) => !e.ok && e.why !== 'does not exist');
  assert.deepEqual(bad.map((e) => `${e.raw || '(empty)'}: ${e.why}`), [], 'a relative, empty or in-repo PATH entry would let a committed file stand in for a system tool');
});

test('resolveTool ignores relative and empty PATH entries and entries inside the repository, even when they hold an executable of that name', () => {
  const d = mkdtempSync(join(tmpdir(), 'mg-tools-')), prevCwd = process.cwd();
  try {
    mk(join(d, 'trusted'), 'faketool'); mk(join(REPO_ROOT, 'gateway', 'test', 'fixtures', '.untrusted-bin-test'), 'repotool');
    process.chdir(d); mk(d, 'cwdtool');   // 'cwdtool' lives in the current directory, which a relative or empty entry would resolve to
    const withRel = ['', '.', 'trusted', join(d, 'trusted')].join(delimiter);
    assert.equal(resolveTool('cwdtool', ['', '.', d.replace(/^\//, '')].join(delimiter)), null, 'empty / relative entries never resolve');
    assert.equal(resolveTool('faketool', withRel), join(realOf(d), 'trusted', 'faketool'), 'the absolute entry wins; the relative ones are skipped');
    assert.equal(resolveTool('repotool', join(REPO_ROOT, 'gateway', 'test', 'fixtures', '.untrusted-bin-test')), null, 'an entry inside the repository is refused');
    assert.deepEqual(pathEntries(join(REPO_ROOT, 'gateway')).map((e) => e.why), ['inside the repository']);
  } finally { process.chdir(prevCwd); rmSync(d, { recursive: true, force: true }); rmSync(join(REPO_ROOT, 'gateway', 'test', 'fixtures', '.untrusted-bin-test'), { recursive: true, force: true }); }
});

test('resolveTool refuses non-executable files, directories, names with a slash, and a symlink into the repository does not make an in-repo entry trusted', () => {
  const d = mkdtempSync(join(tmpdir(), 'mg-tools-'));
  try {
    mk(join(d, 'bin'), 'noexec', 0o644); mkdirSync(join(d, 'bin', 'adir')); const p = join(d, 'bin');
    assert.equal(resolveTool('noexec', p), null); assert.equal(resolveTool('adir', p), null); assert.equal(resolveTool('../bin/noexec', p), null); assert.equal(resolveTool('', p), null);
    const link = join(d, 'linkdir'); symlinkSync(join(REPO_ROOT, 'gateway'), link);
    assert.deepEqual(pathEntries(link).map((e) => e.why), ['inside the repository'], 'the real path is what is judged, not the link name');
    assert.equal(have('definitely-not-a-real-tool-xyz'), false);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

import { realpathSync } from 'node:fs';
const realOf = (p) => realpathSync(p);
