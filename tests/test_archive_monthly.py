"""Archive P2: the steps the monthly workflow runs (prepare / publish / verify), against fakes. No network, no credentials."""
import json, os, pathlib, sys, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from archive_support import FAKE_AGE, FIX, RECIPIENT_A, RECIPIENT_B, canon, identity_file, make_rows, months, tmpdir
from archive import monthly, restore
from archive.crypto import AgeCli
from archive.providers import LocalDirectory
from archive.store import ArchiveError, read_unit

FAKE_WRANGLER = [sys.executable, str(FIX / 'fake_wrangler.py')]


class Monthly(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self); self.age = AgeCli([RECIPIENT_A, RECIPIENT_B], FAKE_AGE); self.ident = identity_file(self.d)
        self.rows = make_rows(months({'2026-07': 4, '2026-08': 3, '2026-09': 5, '2026-10': 2}))
        self.provs = [LocalDirectory(self.d / n, n) for n in ('r2', 'b2', 'scaleway')]
        self.fetch_env(self.rows, [])

    def fetch_env(self, rows, anchors):
        f = self.d / 'd1.json'; f.write_text(json.dumps({'audit': rows, 'anchors': anchors})); os.environ['FAKE_D1'] = str(f); self.addCleanup(os.environ.pop, 'FAKE_D1', None)

    def prep(self, out='prep', anchors=None, rows=None):
        rows_, anch = monthly.fetch_audit('DB', FAKE_WRANGLER, page=3)
        return monthly.prepare(rows if rows is not None else rows_, anchors if anchors is not None else anch, self.age, self.d / out, '2026-10')

    def test_fetch_pages_and_tolerates_missing_anchor_table(self):
        rows, anchors = monthly.fetch_audit('DB', FAKE_WRANGLER, page=3); self.assertEqual(rows, self.rows); self.assertEqual(anchors, [])
        self.fetch_env(self.rows, None); self.assertEqual(monthly.fetch_audit('DB', FAKE_WRANGLER, page=4)[1], [])

    def test_wrangler_failure_is_an_error(self):
        os.environ['FAKE_D1'] = str(self.d / 'missing.json')
        with self.assertRaisesRegex(ArchiveError, 'wrangler'): monthly.fetch_audit('DB', FAKE_WRANGLER)

    def test_open_month_is_not_sealed_and_nothing_private_is_in_clear(self):
        r = self.prep(); self.assertEqual(r['periods'], ['2026-07', '2026-08', '2026-09'])
        for f in (self.d / 'prep').rglob('segment.jsonl.age'): self.assertNotIn(b'test.event', f.read_bytes())
        self.assertFalse(list((self.d / 'prep').rglob('*.jsonl')))

    def test_full_cycle_is_idempotent_and_verifies_from_every_provider(self):
        self.prep()
        for p in self.provs:
            r = monthly.publish(p, self.d / 'prep'); self.assertTrue(r['ok'], r); self.assertEqual({x['status'] for x in r['results']}, {'created'})
        for p in self.provs:
            v = monthly.verify(p, self.d / 'prep'); self.assertTrue(v['ok'], v); self.assertEqual(v['chain']['last_seq'], 12)
        shas = [monthly.verify(p, self.d / 'prep')['ciphertext_sha256'] for p in self.provs]; self.assertEqual(shas[0], shas[1]); self.assertEqual(shas[1], shas[2])
        self.prep('prep2')   # a later run: same seals, fresh ciphertext
        again = monthly.publish(self.provs[0], self.d / 'prep2')
        self.assertEqual({x['status'] for x in again['results']}, {'already-archived'}); self.assertFalse(again['ok'], 'different ciphertext is reported, not silently accepted')
        self.assertTrue(all(x['ciphertext_matches_prepared'] is False for x in again['results']))
        self.assertEqual(monthly.verify(self.provs[0], self.d / 'prep')['ok'], True, 'the archived copy was not touched')
        self.assertTrue(restore.restore_audit(self.provs[2], self.age, self.ident)['ok'])

    def test_provider_missing_a_period_fails_verification(self):
        self.prep(); monthly.publish(self.provs[0], self.d / 'prep')
        v = monthly.verify(self.provs[1], self.d / 'prep'); self.assertFalse(v['ok']); self.assertIn('missing', v['error'])

    def test_different_seal_already_archived_is_a_conflict(self):
        self.prep(); monthly.publish(self.provs[0], self.d / 'prep')
        other = make_rows(months({'2026-07': 3, '2026-09': 1}))
        self.prep('prep3', anchors=[], rows=other)
        r = monthly.publish(self.provs[0], self.d / 'prep3'); self.assertFalse(r['ok']); self.assertIn('conflict', {x['status'] for x in r['results']})

    def test_tampered_prepared_directory_is_refused(self):
        self.prep(); f = next((self.d / 'prep').rglob('segment.jsonl.age')); f.write_bytes(f.read_bytes() + b'x')
        with self.assertRaisesRegex(ArchiveError, 'do not match'): monthly.publish(self.provs[0], self.d / 'prep')

    def test_after_a_prune_the_next_month_continues_from_the_anchor(self):
        first = canon.__dict__  # noqa: F841
        from archive.segment import build_segments
        segs = build_segments(self.rows); anchor_seal = segs[0]['seal']   # July is pruned: only its anchor remains
        kept = [r for r in self.rows if r['seq'] > anchor_seal['last_seq']]
        anchors = [{'seq': anchor_seal['last_seq'], 'hash': anchor_seal['head_hash'], 'seal_sha256': canon.seal_sha256(anchor_seal)}]
        r = self.prep('p4', anchors=anchors, rows=kept); self.assertEqual(r['periods'], ['2026-08', '2026-09'])
        seal = json.loads((self.d / 'p4' / '2026-08' / 'seal.json').read_text()); self.assertEqual(seal, segs[1]['seal'], 'identical to sealing everything at once')
        with self.assertRaisesRegex(ArchiveError, 'not GENESIS and not an anchor'): self.prep('p5', anchors=[], rows=kept)
        with self.assertRaisesRegex(ArchiveError, 'not GENESIS and not an anchor'): self.prep('p6', anchors=[{**anchors[0], 'hash': '5' * 64}], rows=kept)

    def test_empty_audit(self):
        self.assertEqual(monthly.prepare([], [], self.age, self.d / 'e', '2026-10')['periods'], [])

    def test_manifest_chains_to_the_newest_earlier_manifest_and_env_providers_need_a_bucket(self):
        import io
        from contextlib import redirect_stdout
        from archive import cli
        self.prep(); monthly.publish(self.provs[0], self.d / 'prep')
        cfg = self.d / 'one.json'; cfg.write_text(json.dumps({'providers': [{'name': 'r2', 'type': 'local', 'root': str(self.d / 'r2')}]}))
        def run(*a):
            buf = io.StringIO()
            with redirect_stdout(buf): code = cli.main(list(a))
            return code, json.loads(buf.getvalue())
        self.assertEqual(run('manifest', '--providers', str(cfg), '--date', '2026-11-02', '--out', str(self.d / 'm1.json'), '--store', '--prev-latest')[0], 0)
        c, r = run('manifest', '--providers', str(cfg), '--date', '2026-12-02', '--out', str(self.d / 'm2.json'), '--prev-latest'); self.assertEqual(c, 0, r)
        self.assertEqual(json.loads((self.d / 'm2.json').read_bytes())['prev_manifest_sha256'], canon.sha256_hex((self.d / 'm1.json').read_bytes()))
        os.environ.pop('ARCHIVE_BUCKET', None)
        c, r = run('publish-prepared', '--from-env', 'r2', '--dir', str(self.d / 'prep')); self.assertEqual(c, 2); self.assertIn('ARCHIVE_BUCKET', r['error'])

    def test_bundle_is_deterministic_and_unpacks_only_what_it_should(self):
        import io, tarfile, gzip
        self.prep(); a = monthly.pack(self.d / 'prep', self.d / 'b1.tar.gz'); b = monthly.pack(self.d / 'prep', self.d / 'b2.tar.gz'); self.assertEqual(a, b)
        monthly.unpack(self.d / 'b1.tar.gz', self.d / 'un'); self.assertTrue(monthly.verify(self._pub(), self.d / 'un')['ok'] is False)   # nothing published yet, but the bundle itself loads
        self.assertTrue(monthly.publish(self.provs[0], self.d / 'un')['ok'])
        with self.assertRaisesRegex(ArchiveError, 'not empty'): monthly.unpack(self.d / 'b1.tar.gz', self.d / 'un')
        def bundle(name, data=b'x', typ=tarfile.REGTYPE, link=''):
            f = self.d / f'{abs(hash(name))}.tar.gz'
            with tarfile.open(f, 'w:gz') as tf:
                ti = tarfile.TarInfo(name); ti.type = typ; ti.linkname = link; ti.size = len(data) if typ == tarfile.REGTYPE else 0
                tf.addfile(ti, io.BytesIO(data) if typ == tarfile.REGTYPE else None)
            return f
        for i, (name, kw) in enumerate([('../escape', {}), ('/abs', {}), ('2026-07/../../x', {}), ('extra.txt', {}), ('2026-07/seal.json', {'typ': tarfile.SYMTYPE, 'link': '/etc/passwd'})]):
            with self.assertRaisesRegex(ArchiveError, 'unexpected entry'): monthly.unpack(bundle(name, **kw), self.d / f'bad{i}')
        self.assertFalse((self.d / 'escape').exists())
        tampered = self.d / 'tamp'; import shutil; shutil.copytree(self.d / 'prep', tampered); next(tampered.rglob('seal.json')).write_bytes(b'{}')
        monthly.pack(tampered, self.d / 'bt.tar.gz')
        with self.assertRaisesRegex(ArchiveError, 'do not match'): monthly.unpack(self.d / 'bt.tar.gz', self.d / 'bt')
        (self.d / 'prep' / 'prepared.json').write_text(json.dumps({'periods': [{'period': '../x', 'seal_sha256': '0', 'ciphertext_sha256': '0'}]}))
        with self.assertRaisesRegex(ArchiveError, 'bad period'): monthly.publish(self.provs[0], self.d / 'prep')

    def _pub(self): return self.provs[1]


if __name__ == '__main__': unittest.main()
