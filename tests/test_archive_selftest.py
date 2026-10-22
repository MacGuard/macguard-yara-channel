import contextlib, io, json, os, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
from archive import selftest  # noqa: E402

FAKE = str(ROOT / 'tests' / 'fixtures' / 'archive' / 'fake_aws.py')


def run(role, leak='', readonly=False, state=None, existing=None):
    with tempfile.TemporaryDirectory() as d:
        st = state or os.path.join(d, 'state.json')
        env = {'FAKE_AWS_STATE': st, 'FAKE_AWS_LEAK': leak, 'FAKE_AWS_READONLY': '1' if readonly else ''}
        if existing: env['SELFTEST_EXISTING_KEY'] = existing
        old = {k: os.environ.get(k) for k in env}; os.environ.update(env)
        try: return selftest.run_checks(selftest.Aws('https://e.example', 'r', 'b', cli=(sys.executable, FAKE)), role, 'selftest/t/')
        finally:
            for k, v in old.items():
                if v is None: os.environ.pop(k, None)
                else: os.environ[k] = v


def verdicts(res): return {r['check']: r['result'] for r in res}


class SelfTest(unittest.TestCase):
    def test_a_protected_bucket_passes_every_write_check(self):
        res = run('write'); self.assertTrue(all(r['result'] == 'PASS' for r in res), res); self.assertEqual(len(res), 5)

    def test_a_deletable_version_is_a_fail(self):
        self.assertEqual(verdicts(run('write', leak='delete'))['delete of the locked version is refused'], 'FAIL')

    def test_a_changeable_retention_is_a_fail(self):
        self.assertEqual(verdicts(run('write', leak='retention'))['shortening the retention is refused'], 'FAIL')

    def test_an_overwrite_that_destroys_the_original_is_a_fail(self):
        self.assertEqual(verdicts(run('write', leak='overwrite'))['overwrite does not alter the original version'], 'FAIL')

    def test_a_read_key_that_can_write_or_delete_fails_and_one_that_cannot_passes(self):
        with tempfile.TemporaryDirectory() as d:
            st = os.path.join(d, 's.json')
            self.assertTrue(all(r['result'] == 'PASS' for r in run('write', state=st)))
            ok = run('read', readonly=True, state=st, existing='selftest/t/object-1'); self.assertTrue(all(r['result'] == 'PASS' for r in ok), ok)
            bad = verdicts(run('read', readonly=False, state=st, existing='selftest/t/object-1')); self.assertEqual(bad['upload is refused for the read role'], 'FAIL')

    def test_nothing_runs_without_the_explicit_synthetic_confirmation_or_credentials(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err): self.assertEqual(selftest.main(['--role', 'write', '--provider', 'x']), 2)
        self.assertIn('--confirm-synthetic-only', err.getvalue())
        for v in ('ARCHIVE_BUCKET', 'AWS_SECRET_ACCESS_KEY'): os.environ.pop(v, None)
        with contextlib.redirect_stderr(err): self.assertEqual(selftest.main(['--role', 'write', '--provider', 'x', '--confirm-synthetic-only']), 2)
        self.assertIn('missing environment:', err.getvalue())
        self.assertNotIn('SECRET', err.getvalue().replace('AWS_SECRET_ACCESS_KEY', ''))   # names only, never values

    def test_the_report_never_contains_credentials(self):
        os.environ.update({'ARCHIVE_BUCKET': 'b', 'ARCHIVE_ENDPOINT': 'https://e.example', 'ARCHIVE_REGION': 'r', 'AWS_ACCESS_KEY_ID': 'AKIDSENTINEL', 'AWS_SECRET_ACCESS_KEY': 'SECRETSENTINEL'})
        try:
            self.assertNotIn('SENTINEL', json.dumps(run('write')))
        finally:
            for v in ('ARCHIVE_BUCKET', 'ARCHIVE_ENDPOINT', 'ARCHIVE_REGION', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'): os.environ.pop(v, None)


if __name__ == '__main__': unittest.main()
