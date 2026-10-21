"""Moving the transparency log to its own branch loses nothing, duplicates nothing and rewrites nothing (owner decision B2).

A local simulation: the repository itself is cloned into a bare "origin", the migration scripts run against it exactly as the owner will run them against GitHub,
and the log keeps growing afterwards the way the three workflows grow it. No network, no GitHub. The Sigstore signatures are not re-verified here: the checkpoints and
their bundles are proven byte-identical (same git blobs), so they verify exactly as before; tests/test_verify_public_release.py re-verifies them against the real release."""
import io, os, pathlib, shutil, subprocess, sys, tarfile, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import tlog, verify_public_release as V

ENV = {**os.environ, 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_SYSTEM': os.devnull, 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@x', 'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@x', 'GIT_TERMINAL_PROMPT': '0'}


def git(cwd, *a, check=True):
    r = subprocess.run(['git', *a], cwd=cwd, env=ENV, capture_output=True, text=True)
    if check and r.returncode: raise AssertionError(f"git {' '.join(a)}: {r.stderr}")
    return r.stdout.strip()


def sh(cwd, script, *a, extra_env=None):
    return subprocess.run(['bash', str(script), *a], cwd=cwd, env={**ENV, **(extra_env or {})}, capture_output=True, text=True)


class Migration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp()); cls.base = cls.tmp / 'base.git'
        subprocess.run(['git', 'clone', '-q', '--bare', '--depth=1', f'file://{ROOT}', str(cls.base)], env=ENV, check=True)
        head = git(ROOT, 'rev-parse', 'HEAD'); git(cls.base, 'update-ref', 'refs/heads/main', head); git(cls.base, 'symbolic-ref', 'HEAD', 'refs/heads/main')
        cls.n = 0

    @classmethod
    def tearDownClass(cls): shutil.rmtree(cls.tmp, ignore_errors=True)

    def fresh(self):
        type(self).n += 1; origin = self.tmp / f'o{self.n}.git'; work = self.tmp / f'w{self.n}'
        subprocess.run(['git', 'clone', '-q', '--bare', str(self.base), str(origin)], env=ENV, check=True)
        subprocess.run(['git', 'clone', '-q', str(origin), str(work)], env=ENV, check=True)
        return origin, work

    def script(self, work, name, *a, **kw): return sh(work, ROOT / 'scripts' / name, *a, **kw)

    def migrate(self):
        origin, work = self.fresh(); main_before = git(origin, 'rev-parse', 'main')
        r = self.script(work, 'migrate_logs_branch.sh', 'check'); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(git(origin, 'for-each-ref', '--format=%(refname)'), '\n'.join(sorted(git(origin, 'for-each-ref', '--format=%(refname)').split('\n'))), 'check wrote no ref')
        self.assertEqual(git(origin, 'rev-parse', '--verify', '-q', 'refs/heads/logs', check=False), '')
        r = self.script(work, 'migrate_logs_branch.sh', 'create'); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return origin, work, main_before

    # ---- the migration itself ----
    def test_the_migrated_tree_is_byte_identical_and_no_history_is_rewritten(self):
        origin, work, main_before = self.migrate()
        self.assertEqual(git(origin, 'rev-parse', 'main'), main_before, 'main was not touched')
        logs = git(origin, 'rev-parse', 'logs')
        self.assertEqual(git(origin, 'rev-parse', 'logs:logs'), git(origin, 'rev-parse', f'{main_before}:logs'), 'the logs/ subtree is the SAME git object: every byte identical')
        self.assertEqual(git(origin, 'ls-tree', '--name-only', logs), 'logs', 'the branch holds only logs/')
        self.assertEqual(git(origin, 'rev-parse', f'{logs}^'), main_before, 'one new commit on top of main: every old commit is still there, unchanged')
        self.assertEqual(int(git(origin, 'rev-list', '--count', 'logs')), int(git(origin, 'rev-list', '--count', 'main')) + 1)
        self.assertEqual(git(origin, 'rev-list', '--count', f'{main_before}..logs'), '1')
        self.assertEqual(git(origin, 'log', '-1', '--format=%an', 'logs'), 'macguard-log[bot]')
        for name in ('00000020', '00000075', '00000180'):
            for ext in ('.txt', '.sigstore.json'):
                p = f'logs/checkpoints/{name}{ext}'; self.assertEqual(git(origin, 'rev-parse', f'logs:{p}'), git(origin, 'rev-parse', f'main:{p}'), p)
        self.assertEqual(git(origin, 'ls-tree', '-r', 'logs', 'logs'), git(origin, 'ls-tree', '-r', 'main', 'logs'))
        r = self.script(work, 'migrate_logs_branch.sh', 'verify'); self.assertEqual(r.returncode, 0, r.stdout + r.stderr); self.assertIn('VERIFIED', r.stdout)

    def test_a_second_create_is_refused_and_changes_nothing(self):
        origin, work, _ = self.migrate(); before = git(origin, 'rev-parse', 'logs')
        r = self.script(work, 'migrate_logs_branch.sh', 'create'); self.assertNotEqual(r.returncode, 0); self.assertIn('already exists', r.stderr + r.stdout)
        self.assertEqual(git(origin, 'rev-parse', 'logs'), before)

    def test_a_log_that_is_not_sound_is_never_migrated(self):
        origin, work = self.fresh(); p = work / 'logs' / 'log.jsonl'; lines = p.read_bytes().split(b'\n'); lines[3] = lines[3].replace(b'"level"', b'"levex"', 1) if b'"level"' in lines[3] else lines[3] + b' '
        p.write_bytes(b'\n'.join(lines)); git(work, 'add', 'logs'); git(work, 'commit', '-q', '-m', 'tamper'); git(work, 'push', '-q', 'origin', 'HEAD:main')
        for cmd in ('check', 'create'):
            r = self.script(work, 'migrate_logs_branch.sh', cmd); self.assertNotEqual(r.returncode, 0, cmd); self.assertIn('not sound', r.stderr)
        self.assertEqual(git(origin, 'rev-parse', '--verify', '-q', 'refs/heads/logs', check=False), '')

    def test_verify_catches_a_branch_that_lost_or_rewrote_something(self):
        origin, work, _ = self.migrate()
        tree = git(origin, 'rev-parse', 'logs:logs'); work_logs = work / 'x'; subprocess.run(['git', 'clone', '-q', '-b', 'logs', str(origin), str(work_logs)], env=ENV, check=True)
        lines = (work_logs / 'logs' / 'log.jsonl').read_bytes().split(b'\n'); lines[0] = lines[0] + b' '; (work_logs / 'logs' / 'log.jsonl').write_bytes(b'\n'.join(lines))   # rewrite entry 0
        git(work_logs, 'commit', '-qam', 'rewrite'); git(work_logs, 'push', '-q', 'origin', 'HEAD:logs'); self.assertNotEqual(tree, git(origin, 'rev-parse', 'logs:logs'))
        r = self.script(work, 'migrate_logs_branch.sh', 'verify'); self.assertNotEqual(r.returncode, 0); self.assertIn('FAIL', r.stderr)
        (work_logs / 'logs' / 'checkpoints' / '00000075.txt').write_bytes(b'x'); git(work_logs, 'commit', '-qam', 'checkpoint'); git(work_logs, 'push', '-q', 'origin', 'HEAD:logs')
        self.assertIn('00000075.txt', self.script(work, 'migrate_logs_branch.sh', 'verify').stderr)

    # ---- continuity: the log keeps growing on the branch exactly as the workflows grow it ----
    def job(self, origin, i):
        """What a workflow job does: check main out, materialize logs/, append, render, commit_logs."""
        w = self.tmp / f'job{self.n}_{i}'; subprocess.run(['git', 'clone', '-q', '--depth=1', f'file://{origin}', str(w)], env=ENV, check=True)
        r = sh(w, ROOT / 'scripts' / 'logs_branch.sh', 'materialize'); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return w

    def append(self, w, code, message='probe'):
        for args in (['event', '--level', 'INFO', '--code', code, '--message', message], ['render']):
            r = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'tlog.py'), '--logs', 'logs', *args], cwd=w, env=ENV, capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_log_continues_without_loss_duplication_or_rewriting_and_main_is_never_written(self):
        origin, work, main_before = self.migrate()
        frozen = git(origin, 'show', f'{main_before}:logs/log.jsonl').encode(); frozen_n = frozen.count(b'\n')
        w = self.job(origin, 1); self.append(w, 'a.first'); r = sh(w, ROOT / 'scripts' / 'commit_logs.sh', 'run 1'); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        w2 = self.job(origin, 2); self.append(w2, 'a.second'); self.append(w2, 'a.third'); r = sh(w2, ROOT / 'scripts' / 'commit_logs.sh', 'run 2'); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(git(origin, 'rev-parse', 'main'), main_before, 'no job wrote main')
        new = git(origin, 'show', 'logs:logs/log.jsonl').encode()
        self.assertTrue(new.startswith(frozen), 'every old entry is byte-identical and in place'); self.assertEqual(new.count(b'\n'), frozen_n + 3)
        entries = [tlog.json.loads(l) for l in new.split(b'\n') if l]; self.assertEqual([e['seq'] for e in entries], list(range(len(entries))), 'seq is contiguous: no gap, no duplicate')
        self.assertEqual(len({l for l in new.split(b'\n') if l}), len(entries), 'no line appears twice')
        self.assertEqual([e['event'] for e in entries[-3:]], ['a.first', 'a.second', 'a.third'])
        d = pathlib.Path(tempfile.mkdtemp(dir=self.tmp)); tarfile.open(fileobj=io.BytesIO(subprocess.run(['git', f'--git-dir={origin}', 'archive', 'logs', 'logs'], env=ENV, check=True, capture_output=True).stdout)).extractall(d, filter='data')
        self.assertEqual(tlog.Log(d / 'logs').verify(), [], 'structure, every checkpoint root (20, 75, 180) and the consistency between them still hold')
        for n, size in (('00000020', 20), ('00000075', 75), ('00000180', 180)):
            size_, root = tlog.Log.parse_checkpoint((d / 'logs' / 'checkpoints' / f'{n}.txt').read_bytes()); self.assertEqual(size_, size)
            self.assertEqual(tlog.mth(tlog.Log(d / 'logs').leaves()[:size]), root, f'checkpoint {size} still commits to the same first {size} entries')
        self.assertEqual(git(origin, 'ls-tree', '-r', 'logs', 'logs/checkpoints'), git(origin, 'ls-tree', '-r', f'{main_before}', 'logs/checkpoints'), 'no checkpoint file changed')
        self.assertEqual(self.script(work, 'migrate_logs_branch.sh', 'verify').returncode, 0)
        self.assertEqual(int(git(origin, 'rev-list', '--count', f'{main_before}..logs')), 3, 'the cut-over commit and the two log commits')

    def test_no_change_makes_no_commit(self):
        origin, _, _ = self.migrate(); w = self.job(origin, 1); before = git(origin, 'rev-parse', 'logs')
        r = sh(w, ROOT / 'scripts' / 'commit_logs.sh', 'nothing'); self.assertEqual(r.returncode, 0); self.assertIn('No log changes', r.stdout); self.assertEqual(git(origin, 'rev-parse', 'logs'), before)

    def test_a_writer_that_lost_the_race_refuses_instead_of_overwriting(self):
        origin, _, _ = self.migrate(); a = self.job(origin, 1); b = self.job(origin, 2)
        self.append(a, 'a.mine'); self.append(b, 'b.theirs')
        self.assertEqual(sh(a, ROOT / 'scripts' / 'commit_logs.sh', 'a').returncode, 0); head = git(origin, 'rev-parse', 'logs')
        r = sh(b, ROOT / 'scripts' / 'commit_logs.sh', 'b'); self.assertNotEqual(r.returncode, 0); self.assertIn('moved', r.stderr)
        self.assertEqual(git(origin, 'rev-parse', 'logs'), head, 'the other writer\'s entry is intact'); self.assertIn('a.mine', git(origin, 'show', 'logs:logs/log.jsonl'))

    def test_commit_logs_needs_a_materialized_log_and_never_pushes_to_main(self):
        origin, _, main_before = self.migrate(); w = self.tmp / f'bare{self.n}'; subprocess.run(['git', 'clone', '-q', '--depth=1', f'file://{origin}', str(w)], env=ENV, check=True)
        r = sh(w, ROOT / 'scripts' / 'commit_logs.sh', 'x'); self.assertNotEqual(r.returncode, 0); self.assertIn('materialize', r.stderr)
        text = (ROOT / 'scripts' / 'commit_logs.sh').read_text(); self.assertNotIn('git push\n', text); self.assertNotIn('pull', text); self.assertNotRegex(text, r'push[^\n]*--force'); self.assertIn('refs/heads/$branch', text)
        self.assertEqual(git(origin, 'rev-parse', 'main'), main_before)

    def test_materialize_fails_loudly_before_the_branch_exists(self):
        origin, work = self.fresh(); r = self.script(work, 'logs_branch.sh', 'materialize'); self.assertNotEqual(r.returncode, 0); self.assertIn('not been moved yet', r.stderr)


class Readers(unittest.TestCase):
    class Net:
        def __init__(self, have): self.have = have; self.asked = []
        def download(self, url, dest, size=None):
            self.asked.append(url)
            if url not in self.have: raise V.Fail(4, f'404 {url}')
            pathlib.Path(dest).write_bytes(self.have[url])

    A = type('A', (), {'raw_url': 'https://raw.example', 'repo': 'o/r'})

    def test_the_verifier_reads_a_checkpoint_from_the_logs_branch_and_falls_back_to_main_as_a_pair(self):
        b = V.checkpoint_bases(self.A, 75); self.assertEqual(b, ['https://raw.example/o/r/logs/logs/checkpoints/00000075', 'https://raw.example/o/r/main/logs/checkpoints/00000075'])
        d = pathlib.Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, d)
        net = self.Net({b[1] + '.txt': b'old', b[1] + '.sigstore.json': b'oldsig'}); V.fetch_checkpoint(net, self.A, 75, d)
        self.assertEqual((d / 'checkpoint.txt').read_bytes(), b'old'); self.assertEqual(net.asked[0], b[0] + '.txt', 'the logs branch is tried first')
        net = self.Net({b[0] + '.txt': b'new', b[0] + '.sigstore.json': b'newsig', b[1] + '.txt': b'old', b[1] + '.sigstore.json': b'oldsig'}); V.fetch_checkpoint(net, self.A, 75, d)
        self.assertEqual((d / 'checkpoint.sigstore.json').read_bytes(), b'newsig')
        net = self.Net({b[0] + '.txt': b'new', b[1] + '.txt': b'old', b[1] + '.sigstore.json': b'oldsig'}); V.fetch_checkpoint(net, self.A, 75, d)
        self.assertEqual((d / 'checkpoint.txt').read_bytes(), b'old'); self.assertEqual((d / 'checkpoint.sigstore.json').read_bytes(), b'oldsig', 'never a .txt from one place and a bundle from the other')
        with self.assertRaises(V.Fail): V.fetch_checkpoint(self.Net({}), self.A, 75, d)
        self.assertFalse((d / 'checkpoint.txt').exists())

    def test_every_job_that_commits_the_log_materializes_it_from_the_branch_first_and_no_workflow_pushes_main(self):
        import re
        for name in ('daily', 'publish', 'site'):
            text = (ROOT / '.github' / 'workflows' / f'{name}.yml').read_text()
            self.assertIn('commit_logs.sh', text)
            for job in re.split(r'\n  (?=[a-z][a-z0-9-]*:\n)', text.split('\njobs:\n', 1)[1]):
                if 'commit_logs.sh' in job: self.assertLess(job.index('logs_branch.sh materialize'), job.index('commit_logs.sh'), name)
                if 'tlog.py' in job or 'build_site.py' in job: self.assertIn('logs_branch.sh materialize', job, f'{name}: a job reads logs/ without materializing it')
            self.assertNotRegex(text, r'git push(?! origin HEAD:refs/heads/proposal/)')


if __name__ == '__main__':
    unittest.main()
