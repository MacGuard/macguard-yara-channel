"""Archive P1: providers (local + S3-compatible CLI adapter with a fake binary) and the age wrapper (test double + optional real binary)."""
import json, os, pathlib, shutil, subprocess, sys, threading, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from archive_support import FAKE_AGE, FAKE_S3, RECIPIENT_A, RECIPIENT_B, canon, identity_file, tmpdir
from archive.crypto import AgeCli, CryptoError
from archive.providers import LocalDirectory, MissingObject, ObjectConflict, Provider, ProviderError, S3Cli


class ProviderContract:
    """Run against every provider implementation."""
    def make(self): raise NotImplementedError

    def test_write_once_roundtrip(self):
        p = self.make()
        self.assertEqual(p.put_if_absent('objects/a/b', b'one'), 'created')
        self.assertEqual(p.put_if_absent('objects/a/b', b'one'), 'exists-identical')
        with self.assertRaises(ObjectConflict): p.put_if_absent('objects/a/b', b'two')
        self.assertEqual(p.get('objects/a/b'), b'one', 'the original is untouched by the refused write')
        self.assertTrue(p.exists('objects/a/b')); self.assertFalse(p.exists('objects/a/c'))
        p.put_if_absent('index/x.json', b'{}'); self.assertEqual(p.list('objects/'), ['objects/a/b']); self.assertEqual(p.list(), ['index/x.json', 'objects/a/b'])

    def test_missing_object(self):
        with self.assertRaises(MissingObject): self.make().get('objects/nope')

    def test_unsafe_keys_refused(self):
        p = self.make()
        for k in ('', '/abs', '../x', 'a/../b', 'a//b', 'a\\b'):
            with self.assertRaises(ProviderError, msg=k): p.put_if_absent(k, b'x')

    def test_no_delete_or_overwrite_api(self):
        for name in ('delete', 'remove', 'put', 'overwrite', 'unlink'): self.assertFalse(hasattr(Provider, name), name)
        self.assertFalse(hasattr(self.make(), 'delete'))


class LocalTests(ProviderContract, unittest.TestCase):
    def make(self): return LocalDirectory(tmpdir(self) / 'bucket', 'local')

    def test_concurrent_writers_exactly_one_creates(self):
        p, res = self.make(), []
        def w(i):
            try: res.append(p.put_if_absent('objects/k', b'same'))
            except ProviderError as e: res.append(repr(e))
        ts = [threading.Thread(target=w, args=(i,)) for i in range(12)]; [t.start() for t in ts]; [t.join(10) for t in ts]
        self.assertEqual(res.count('created'), 1); self.assertEqual(set(res) - {'created', 'exists-identical'}, set())
        res.clear()
        def w2(i):
            try: res.append(p.put_if_absent('objects/k3', f'v{i}'.encode()))
            except ObjectConflict: res.append('conflict')
        ts = [threading.Thread(target=w2, args=(i,)) for i in range(8)]; [t.start() for t in ts]; [t.join(10) for t in ts]
        self.assertEqual(res.count('created'), 1); self.assertEqual(res.count('conflict'), 7)
        self.assertEqual([k for k in p.list() if '.part-' in k], [])


class S3Base(ProviderContract):
    kind = None
    def make(self):
        d = tmpdir(self); (d / 'bkt').mkdir()
        self.root = d; os.environ['FAKE_S3_ROOT'] = str(d); self.addCleanup(os.environ.pop, 'FAKE_S3_ROOT', None)
        return S3Cli('fake', self.kind, FAKE_S3 + (['--endpoint-url', 'https://example.invalid'] if self.kind == 'aws' else []), 'bkt', remote='rem' if self.kind == 'rclone' else None, timeout=20)

    def test_secret_in_environment_never_reaches_a_command_line(self):
        p = self.make(); os.environ['AWS_SECRET_ACCESS_KEY'] = 'TOP-SECRET-VALUE-123'; self.addCleanup(os.environ.pop, 'AWS_SECRET_ACCESS_KEY', None)
        p.put_if_absent('objects/a', b'x'); p.get('objects/a'); p.list()
        log = (self.root / 'argv.log').read_text(); self.assertNotIn('TOP-SECRET', log); self.assertGreater(len(log.splitlines()), 3)

    def test_timeout_is_bounded(self):
        p = self.make(); p.timeout = 1; os.environ['FAKE_S3_HANG'] = '1'; self.addCleanup(os.environ.pop, 'FAKE_S3_HANG', None)
        with self.assertRaisesRegex(ProviderError, 'timed out'): p.exists('objects/a')

    def test_missing_cli_is_a_clear_error(self):
        with self.assertRaisesRegex(ProviderError, 'cannot run'): S3Cli('x', self.kind, ['/nonexistent/tool'], 'b', remote='r').exists('k')


class RcloneTests(S3Base, unittest.TestCase): kind = 'rclone'
class AwsTests(S3Base, unittest.TestCase): kind = 'aws'


class S3Config(unittest.TestCase):
    def test_bad_kind_or_missing_remote(self):
        with self.assertRaises(ProviderError): S3Cli('x', 'gsutil', ['g'], 'b')
        with self.assertRaises(ProviderError): S3Cli('x', 'rclone', ['rclone'], 'b')


class AgeDouble(unittest.TestCase):
    def setUp(self): self.age = AgeCli([RECIPIENT_A, RECIPIENT_B], FAKE_AGE); self.d = tmpdir(self)

    def test_roundtrip_with_either_recipient_and_ciphertext_hides_plaintext(self):
        data = b'{"actor":"vera-private-login"}\n' * 5; ct = self.age.encrypt(data)
        self.assertNotIn(b'vera-private-login', ct); self.assertNotEqual(ct, self.age.encrypt(data), 'fresh randomness per encryption')
        for r in (RECIPIENT_A, RECIPIENT_B): self.assertEqual(self.age.decrypt(ct, identity_file(self.d, r)), data)

    def test_tampered_ciphertext_fails(self):
        ct = bytearray(self.age.encrypt(b'secret audit')); ct[-1] ^= 1
        with self.assertRaisesRegex(CryptoError, 'modified'): self.age.decrypt(bytes(ct), identity_file(self.d))

    def test_wrong_identity_fails(self):
        ct = self.age.encrypt(b'x'); other = 'age1' + 'r' * 58
        with self.assertRaisesRegex(CryptoError, 'no identity matched'): self.age.decrypt(ct, identity_file(self.d, other))

    def test_only_public_recipients_are_accepted(self):
        for bad in ('AGE-SECRET-KEY-1' + 'Q' * 50, 'ssh-ed25519 AAAA', '', 'age1short'):
            with self.assertRaises(CryptoError): AgeCli([bad], FAKE_AGE)
        with self.assertRaises(CryptoError): AgeCli([], FAKE_AGE)

    def test_missing_binary_and_failure_are_clear(self):
        with self.assertRaisesRegex(CryptoError, 'cannot run age'): AgeCli([RECIPIENT_A], ['/nonexistent/age']).encrypt(b'x')
        with self.assertRaises(CryptoError): self.age.decrypt(b'not age', identity_file(self.d))


class RealAge(unittest.TestCase):
    """Runs the REAL `age` / `age-keygen` binaries. Enabled with ARCHIVE_REAL_AGE=1. When enabled and the binaries are missing this test FAILS (it never skips
    silently); when not enabled it is reported as skipped with the reason below, so a run that did not exercise the real binary says so by name."""
    @unittest.skipUnless(os.environ.get('ARCHIVE_REAL_AGE') == '1', 'NOT RUN: real age binary test; set ARCHIVE_REAL_AGE=1 to run it')
    def test_real_age_roundtrip_two_recipients_and_tamper(self):
        age, keygen = shutil.which('age'), shutil.which('age-keygen')
        if not (age and keygen): self.fail('ARCHIVE_REAL_AGE=1 but `age` and/or `age-keygen` are not installed: install https://github.com/FiloSottile/age and rerun')
        d = tmpdir(self); ids = []
        for n in ('custodian', 'archive'):
            f = d / f'{n}.key'; r = subprocess.run([keygen, '-o', str(f)], capture_output=True, text=True, check=True)
            ids.append((str(f), r.stderr.strip().split()[-1]))
        a = AgeCli([r for _, r in ids], [age]); data = b'{"actor":"vera"}\n' * 100; ct = a.encrypt(data)
        self.assertNotIn(b'vera', ct)
        for f, _ in ids: self.assertEqual(a.decrypt(ct, f), data)
        bad = bytearray(ct); bad[len(bad) // 2] ^= 1
        with self.assertRaises(CryptoError): a.decrypt(bytes(bad), ids[0][0])
        with self.assertRaises(CryptoError): a.decrypt(ct, str(d / 'missing.key'))


if __name__ == '__main__': unittest.main()
