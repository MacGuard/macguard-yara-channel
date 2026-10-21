"""Archive P1: write-once archiving of audit periods and releases, restore-and-verify per provider, manifest of manifests, prune dry run, CLI, and the
hand-off to the Worker's anchor guard."""
import io, json, os, pathlib, stat, subprocess, sys, unittest
from contextlib import redirect_stdout
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from archive_support import FAKE_AGE, FIX, RECIPIENT_A, RECIPIENT_B, ROOT, canon, identity_file, make_rows, months, tmpdir
from archive import cli, manifest as man, prune, restore, store
from archive.crypto import AgeCli
from archive.providers import LocalDirectory, MissingObject, ProviderError
from archive.segment import build_segments
from archive.store import ArchiveError, archive_audit_period, archive_release, make_receipt, read_unit

NAMES = ('r2', 'b2', 'scaleway')


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self); self.provs = [LocalDirectory(self.d / n, n) for n in NAMES]
        self.age = AgeCli([RECIPIENT_A, RECIPIENT_B], FAKE_AGE); self.ident = identity_file(self.d)
        self.rows = make_rows(months({'2026-07': 4, '2026-08': 3, '2026-09': 5})); self.segs = build_segments(self.rows)

    def archive(self, i=0, provs=None): return archive_audit_period(provs or self.provs, self.segs[i]['seal'], self.segs[i]['segment'], self.age)
    def all_periods(self):
        for i in range(3): self.assertTrue(self.archive(i)['complete'])


class AuditArchive(Base):
    def test_three_verified_copies_are_byte_identical_and_hold_no_plaintext(self):
        rep = self.archive(); self.assertTrue(rep['complete']); self.assertEqual([c['provider'] for c in rep['copies']], list(NAMES))
        self.assertEqual(len({c['ciphertext_sha256'] for c in rep['copies']}), 1)
        ct_objs = [p.get(k) for p in self.provs for k in p.list('objects/') if p.get(k).startswith(b'FAKE-AGE')]
        self.assertEqual(len(ct_objs), 3); self.assertTrue(all(b'ada' not in c for c in ct_objs), 'private audit detail is encrypted before it leaves the process')
        for p in self.provs: self.assertTrue(all(oct(stat.S_IMODE((p.root / k).stat().st_mode)) == '0o444' for k in p.list()), 'objects are read-only on disk')

    def test_rerun_is_idempotent_and_changes_nothing(self):
        a = self.archive(); before = [{k: p.get(k) for k in p.list()} for p in self.provs]
        b = self.archive(); self.assertEqual([c['ciphertext_sha256'] for c in a['copies']], [c['ciphertext_sha256'] for c in b['copies']])
        self.assertEqual(before, [{k: p.get(k) for k in p.list()} for p in self.provs]); self.assertEqual({c['status'] for c in b['copies']}, {'exists-identical'})

    def test_a_partial_earlier_run_is_completed_with_the_same_ciphertext(self):
        first = self.archive(provs=self.provs[:1]); self.assertFalse(first['complete'], 'one provider is not three')
        full = self.archive(); self.assertTrue(full['complete'])
        self.assertEqual({c['ciphertext_sha256'] for c in full['copies']}, {first['copies'][0]['ciphertext_sha256']})

    def test_a_failing_provider_means_incomplete_and_no_receipt(self):
        class Down(LocalDirectory):
            def _put_new(self, key, data): raise ProviderError('boom: provider is down')
        rep = self.archive(provs=[self.provs[0], self.provs[1], Down(self.d / 'down', 'scaleway')]); self.assertFalse(rep['complete'])
        self.assertIn('down', [c for c in rep['copies'] if not c['readback_verified']][0]['error'])
        with self.assertRaisesRegex(ArchiveError, 'all three'): make_receipt(rep, {'ok': True})

    def test_readback_mismatch_is_detected(self):
        class Liar(LocalDirectory):
            def get(self, key): return super().get(key)[:-1] + b'X' if key.startswith('objects/') else super().get(key)
        rep = self.archive(provs=[self.provs[0], self.provs[1], Liar(self.d / 'liar', 'scaleway')]); self.assertFalse(rep['complete'])
        self.assertIn('read-back', rep['copies'][2]['error'])

    def test_same_period_with_a_different_seal_is_refused(self):
        self.archive(); other = build_segments(make_rows(months({'2026-07': 3})))
        self.assertEqual(other[0]['period'], '2026-07')
        with self.assertRaisesRegex(ArchiveError, 'different seal'): archive_audit_period(self.provs, other[0]['seal'], other[0]['segment'], self.age)

    def test_unsealed_or_inconsistent_input_is_refused_before_anything_is_written(self):
        bad = {**self.segs[0]['seal'], 'count': 9}
        with self.assertRaises(Exception): archive_audit_period(self.provs, bad, self.segs[0]['segment'], self.age)
        self.assertEqual([p.list() for p in self.provs], [[], [], []])

    def test_unit_rejects_unsafe_names(self):
        with self.assertRaises(ArchiveError): store.archive_unit(self.provs[0], 'audit', '../x', {'a': b'1'})
        with self.assertRaises(ArchiveError): store.archive_unit(self.provs[0], 'audit', '2026-07', {'a/b': b'1'})
        with self.assertRaises(ArchiveError): store.archive_unit(self.provs[0], 'secrets', 'x', {'a': b'1'})


class Restore(Base):
    def setUp(self): super().setUp(); self.all_periods()

    def test_full_restore_from_each_provider_alone(self):
        for p in self.provs:
            r = restore.restore_audit(p, self.age, self.ident, expected_head=self.rows[-1]['hash'])
            self.assertTrue(r['ok'], r); self.assertEqual((r['level'], r['periods'], r['last_seq']), ('full', ['2026-07', '2026-08', '2026-09'], 12))

    def test_seals_only_needs_no_key(self):
        r = restore.restore_audit(self.provs[1]); self.assertTrue(r['ok']); self.assertEqual(r['level'], 'seals-only')

    def test_provider_lacking_an_object_fails_clearly_and_others_still_pass(self):
        victim = self.provs[2]; sha = json.loads(victim.get('index/audit/2026-08.json'))['files']['segment.jsonl.age']['sha256']
        (victim.root / store.object_key(sha)).chmod(0o644); (victim.root / store.object_key(sha)).unlink()
        r = restore.restore_audit(victim, self.age, self.ident); self.assertFalse(r['ok']); self.assertIn('MissingObject', r['error'])
        self.assertTrue(restore.restore_audit(self.provs[0], self.age, self.ident)['ok'])
        gone = (victim.root / 'index/audit/2026-09.json'); gone.chmod(0o644); gone.unlink()
        r2 = restore.restore_audit(victim); self.assertFalse(r2['ok'])

    def test_provider_lacking_an_index_has_no_such_period(self):
        r = restore.rehearse_period(self.provs[0], '2030-01', self.age, self.ident); self.assertFalse(r['ok']); self.assertIn('MissingObject', r['error'])

    def test_tampered_ciphertext_is_detected_by_digest_and_by_authentication(self):
        p = self.provs[0]; ent = json.loads(p.get('index/audit/2026-07.json'))['files']['segment.jsonl.age']
        f = p.root / store.object_key(ent['sha256']); f.chmod(0o644); b = bytearray(f.read_bytes()); b[-1] ^= 1; f.write_bytes(bytes(b))
        r = restore.restore_audit(p, self.age, self.ident); self.assertFalse(r['ok']); self.assertIn('corrupted', r['error'])
        # an attacker who also fixes the digest chain (re-addresses the object and index) is still stopped by age authentication
        sha2 = canon.sha256_hex(bytes(b)); (p.root / store.object_key(sha2)).parent.mkdir(parents=True, exist_ok=True); (p.root / store.object_key(sha2)).write_bytes(bytes(b))
        idxf = p.root / 'index/audit/2026-07.json'; idx = json.loads(idxf.read_bytes()); idx['files']['segment.jsonl.age']['sha256'] = sha2
        idxf.chmod(0o644); idxf.write_bytes((canon.canonical(idx) + '\n').encode())
        r2 = restore.restore_audit(p, self.age, self.ident); self.assertFalse(r2['ok']); self.assertIn('CryptoError', r2['error'])

    def test_missing_period_in_a_provider_breaks_the_seal_chain(self):
        p = self.provs[0]; f = p.root / 'index/audit/2026-08.json'; f.chmod(0o644); f.unlink()
        r = restore.restore_audit(p); self.assertFalse(r['ok']); self.assertIn('does not chain', r['error'])

    def test_wrong_expected_head_and_wrong_start_are_refused(self):
        self.assertFalse(restore.restore_audit(self.provs[0], expected_head='1' * 64)['ok'])
        self.assertFalse(restore.restore_audit(self.provs[0], start_hash='1' * 64)['ok'])

    def test_rehearsal_and_receipt_feed_the_worker_guard(self):
        rep = self.archive(1); self.assertTrue(rep['complete'])
        rh = restore.rehearse_period(self.provs[1], '2026-07', self.age, self.ident); self.assertTrue(rh['ok'])
        seal = self.segs[0]['seal']; arch = {'seal': seal, 'complete': True, 'copies': self.archive(0)['copies']}
        rec = make_receipt(arch, rh); self.assertEqual(rec['schema'], store.RECEIPT_SCHEMA)
        with self.assertRaisesRegex(ArchiveError, 'rehearsal'): make_receipt(arch, {**rh, 'seal_sha256': '0' * 64})
        inp = self.d / 'cross.json'; inp.write_text(json.dumps({'rows': self.rows, 'seal': seal, 'receipt': rec}))
        out = json.loads(subprocess.run(['node', str(FIX / 'anchor_crosscheck.mjs'), str(inp)], capture_output=True, text=True, check=True).stdout)
        self.assertTrue(out['before']['ok'], out); self.assertEqual(out['anchor'], {'status': 'created', 'seq': 4}, out)
        self.assertTrue(out['after']['ok'], out); self.assertEqual(out['after']['entries'], 8); self.assertEqual(out['after']['anchor']['hash'], seal['head_hash'])
        bad = {**rec, 'copies': rec['copies'][:2]}; inp.write_text(json.dumps({'rows': self.rows, 'seal': seal, 'receipt': bad}))
        out2 = json.loads(subprocess.run(['node', str(FIX / 'anchor_crosscheck.mjs'), str(inp)], capture_output=True, text=True, check=True).stdout)
        self.assertEqual(out2['anchor_error']['code'], 'not_archived')

    def test_restores_never_go_to_downloads_or_into_a_used_directory(self):
        with self.assertRaisesRegex(ArchiveError, 'Downloads'): restore.fresh_dir(pathlib.Path.home() / 'Downloads' / 'x')
        used = self.d / 'used'; used.mkdir(); (used / 'f').write_text('x')
        with self.assertRaisesRegex(ArchiveError, 'not an empty'): restore.fresh_dir(used)


class Releases(Base):
    def bundle(self, extra=b''):
        b = self.d / 'rel'; b.mkdir(exist_ok=True)
        for n, c in {'rules-release.tar.gz': b'tarbytes' + extra, 'manifest.json': b'{"m":1}', 'manifest.sigstore.json': b'{"sig":1}', 'checkpoint.txt': b'cp'}.items(): (b / n).write_bytes(c)
        return b

    def verifier(self, code):
        script = self.d / f'v{code}.py'; script.write_text(f'import sys; print("verifier saw", sys.argv[1:]); sys.exit({code})')
        return lambda d, tag, prev=None: [sys.executable, str(script), str(d), tag]

    def test_archive_restore_roundtrip_with_verifier(self):
        res = archive_release(self.provs, self.bundle(), 'rules-20261021-1'); self.assertTrue(all('error' not in r for r in res))
        for p in self.provs:
            r = restore.restore_release(p, 'rules-20261021-1', self.d / f'out-{p.name}', self.verifier(0)); self.assertTrue(r['ok'], r); self.assertEqual(r['files'], 4)
            self.assertEqual((self.d / f'out-{p.name}' / 'manifest.json').read_bytes(), b'{"m":1}')

    def test_failing_verifier_fails_the_restore(self):
        archive_release(self.provs, self.bundle(), 't1'); r = restore.restore_release(self.provs[0], 't1', self.d / 'o', self.verifier(1)); self.assertFalse(r['ok']); self.assertEqual(r['verifier_exit'], 1)

    def test_default_verifier_is_the_public_verifier_in_isolated_mode(self):
        cmd = restore.default_verifier('/x', 'tag', '/cp.txt'); self.assertEqual(cmd[1], '-I'); self.assertTrue(cmd[2].endswith('scripts/verify_public_release.py'))
        self.assertIn('--directory', cmd); self.assertIn('--previous-checkpoint', cmd); self.assertTrue(pathlib.Path(cmd[2]).is_file())

    def test_idempotent_and_conflicting_rearchive(self):
        archive_release(self.provs, self.bundle(), 't1'); again = archive_release(self.provs, self.bundle(), 't1'); self.assertEqual({r['status'] for r in again}, {'exists-identical'})
        changed = archive_release(self.provs, self.bundle(b'-changed'), 't1'); self.assertTrue(all('write-once' in r['error'] for r in changed), changed)
        self.assertEqual(read_unit(self.provs[0], 'releases', 't1')[1]['rules-release.tar.gz'], b'tarbytes', 'the first copy is untouched')

    def test_precheck_failure_writes_nothing_and_symlinks_are_refused(self):
        def no(_): raise ArchiveError('private rule name found')
        with self.assertRaises(ArchiveError): archive_release(self.provs, self.bundle(), 't2', no)
        self.assertEqual([p.list() for p in self.provs], [[], [], []])
        b = self.bundle(); (b / 'link').symlink_to(b / 'manifest.json')
        with self.assertRaisesRegex(ArchiveError, 'regular files'): archive_release(self.provs, b, 't3')

    def test_variable_asset_sets_are_recorded_as_they_are(self):
        b = self.bundle(); (b / 'checkpoint.txt').unlink(); archive_release(self.provs[:1], b, 'old'); self.assertEqual(sorted(read_unit(self.provs[0], 'releases', 'old')[0]['files']), ['manifest.json', 'manifest.sigstore.json', 'rules-release.tar.gz'])

    def test_missing_release_in_a_provider(self):
        archive_release(self.provs[:2], self.bundle(), 't1'); r = restore.restore_release(self.provs[2], 't1', self.d / 'o', self.verifier(0)); self.assertFalse(r['ok']); self.assertIn('not there', r['error'])


class Manifest(Base):
    def setUp(self):
        super().setUp(); self.all_periods(); archive_release(self.provs, Releases.bundle(self), 'rel-1')

    def test_build_verify_store_and_chain(self):
        m1 = man.build(self.provs, '2026-10-21'); r = man.verify(m1, self.provs[0]); self.assertTrue(r['ok']); self.assertEqual(r['entries'], len(json.loads(m1)['entries']))
        self.assertEqual(m1, man.build(self.provs, '2026-10-21'), 'deterministic')
        self.assertEqual({s['status'] for s in man.store(self.provs, '2026-10-21', m1)}, {'created'}); self.assertEqual({s['status'] for s in man.store(self.provs, '2026-10-21', m1)}, {'exists-identical'})
        with self.assertRaises(ProviderError): man.store(self.provs, '2026-10-21', m1 + b' ')
        archive_release(self.provs, Releases.bundle(self), 'rel-2')
        m2 = man.build(self.provs, '2026-10-22', m1); self.assertEqual(json.loads(m2)['prev_manifest_sha256'], canon.sha256_hex(m1)); man.verify(m2, self.provs[2], m1)
        with self.assertRaisesRegex(ArchiveError, 'chain'): man.verify(m2, None, None)

    def test_tampered_manifest_and_divergent_providers(self):
        m = man.build(self.provs, '2026-10-21'); doc = json.loads(m); doc['entries'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ArchiveError, 'root'): man.verify((canon.canonical(doc) + '\n').encode())
        doc = json.loads(m); doc['entries'].reverse()
        with self.assertRaises(ArchiveError): man.verify((canon.canonical(doc) + '\n').encode())
        archive_release(self.provs[:2], Releases.bundle(self, b'zz'), 'rel-3')
        with self.assertRaisesRegex(ArchiveError, 'disagree'): man.build(self.provs, '2026-10-23')
        with self.assertRaisesRegex(ArchiveError, 'lacks or differs'): man.verify(man.build(self.provs[:2], '2026-10-23'), self.provs[2])

    def test_a_corrupted_object_stops_the_inventory(self):
        p = self.provs[0]; k = [k for k in p.list('objects/')][0]; f = p.root / k; f.chmod(0o644); f.write_bytes(b'rot')
        with self.assertRaisesRegex(ArchiveError, 'does not match'): man.inventory(p)


class PruneDryRun(Base):
    def setUp(self):
        super().setUp(); self.all_periods()
        s = self.segs[0]['seal']; self.sha = canon.seal_sha256(s)
        self.rh = {'ok': True, 'seal_sha256': self.sha, 'segment_sha256': s['segment_sha256']}
        self.anchors = [{'seq': s['last_seq'], 'hash': s['head_hash'], 'seal_sha256': self.sha}]
        self.auth = {'approved': True, 'approver': 'owner', 'seal_sha256': self.sha}
    def run_check(self, **kw):
        a = dict(rehearsal=self.rh, d1_anchors=self.anchors, authorization=self.auth); a.update(kw)
        return prune.check_period(self.provs, '2026-07', a['rehearsal'], a['d1_anchors'], a['authorization'], ['2026-07', '2026-08', '2026-09'])

    def test_ready_only_when_every_condition_holds_and_nothing_is_ever_executed(self):
        r = self.run_check(); self.assertTrue(r['ready'], r); self.assertFalse(r['executed']); self.assertEqual(r['would_prune'], {'first_seq': 1, 'last_seq': 4, 'rows': 4})

    def test_each_missing_condition_blocks(self):
        for name, kw in {'c_restore_rehearsed': dict(rehearsal=None), 'e_anchor_in_database': dict(d1_anchors=[]), 'f_owner_authorization': dict(authorization=None)}.items():
            r = self.run_check(**kw); self.assertFalse(r['ready'], name); self.assertFalse(r['checks'][name]['pass'], name)
        self.assertFalse(self.run_check(authorization={**self.auth, 'seal_sha256': '1' * 64})['ready'])
        self.assertFalse(self.run_check(rehearsal={**self.rh, 'ok': False})['ready'])
        self.assertFalse(self.run_check(d1_anchors=[{**self.anchors[0], 'hash': '2' * 64}])['ready'])

    def test_two_copies_are_not_enough_and_the_newest_period_is_never_ready(self):
        f = self.provs[2].root / 'index/audit/2026-07.json'; f.chmod(0o644); f.unlink()
        r = self.run_check(); self.assertFalse(r['ready']); self.assertFalse(r['checks']['a_b_three_verified_copies']['pass'])
        newest = prune.check_period(self.provs[:2] + [self.provs[0]], '2026-09', self.rh, self.anchors, self.auth, ['2026-07', '2026-08', '2026-09'])
        self.assertFalse(newest['ready']); self.assertFalse(newest['checks']['not_newest_period']['pass'])

    def test_no_deletion_code_exists_in_the_archive_toolset(self):
        import re
        src = {p.name: p.read_text() for p in (ROOT / 'scripts' / 'archive').glob('*.py')}
        for name, text in src.items():
            code = '\n'.join(l for l in text.splitlines() if not l.strip().startswith('#'))
            if name == 'providers.py': code = code.replace('os.unlink(tmp)', '')   # the only unlink: our own temp file in the local provider
            self.assertIsNone(re.search(r'\.(unlink|rmdir|rmtree|remove)\(|DELETE\s+FROM|\b(rclone|aws)\b.*\b(delete|rm|purge|sync)\b|os\.remove', code), name)


class Cli(Base):
    def run_cli(self, *a):
        buf = io.StringIO()
        with redirect_stdout(buf): code = cli.main(list(a))
        return code, json.loads(buf.getvalue())

    def test_end_to_end(self):
        cfg = self.d / 'p.json'; cfg.write_text(json.dumps({'providers': [{'name': n, 'type': 'local', 'root': str(self.d / n)} for n in NAMES]}))
        exp = self.d / 'export.jsonl'; exp.write_text('\n'.join(json.dumps(r) for r in self.rows) + '\n')
        c, r = self.run_cli('segment', '--export', str(exp), '--out-dir', str(self.d / 'seg')); self.assertEqual((c, r['sealed']), (0, ['2026-07', '2026-08']), 'the open (newest) month is not sealed')
        c, r = self.run_cli('verify-local', '--dir', str(self.d / 'seg')); self.assertEqual(c, 0)
        c, r = self.run_cli('archive-audit', '--providers', str(cfg), '--seal', str(self.d / 'seg/seal-2026-07.json'), '--segment', str(self.d / 'seg/segment-2026-07.jsonl'), '--recipient', RECIPIENT_A, '--age', ' '.join(FAKE_AGE)); self.assertEqual(c, 0, r)
        rep = self.d / 'rep.json'; rep.write_text(json.dumps(r))
        c, rh = self.run_cli('rehearse', '--providers', str(cfg), '--provider', 'scaleway', '--period', '2026-07', '--identity', self.ident, '--recipient', RECIPIENT_A, '--age', ' '.join(FAKE_AGE)); self.assertEqual(c, 0, rh)
        (self.d / 'rh.json').write_text(json.dumps(rh))
        c, r = self.run_cli('receipt', '--archive-report', str(rep), '--rehearsal', str(self.d / 'rh.json'), '--out', str(self.d / 'receipt.json')); self.assertEqual(c, 0, r)
        c, r = self.run_cli('restore', '--providers', str(cfg), '--provider', 'r2', '--identity', self.ident, '--recipient', RECIPIENT_A, '--age', ' '.join(FAKE_AGE)); self.assertEqual((c, r['ok']), (0, True))
        c, r = self.run_cli('manifest', '--providers', str(cfg), '--date', '2026-10-21', '--out', str(self.d / 'm.json'), '--store'); self.assertEqual(c, 0, r)
        c, r = self.run_cli('prune-check', '--providers', str(cfg), '--period', '2026-07'); self.assertEqual(c, 1); self.assertFalse(r['executed'])
        c, r = self.run_cli('restore', '--providers', str(cfg), '--provider', 'r2', '--tag', 'missing', '--out-dir', str(self.d / 'x')); self.assertEqual(c, 1)
        c, r = self.run_cli('segment', '--export', str(self.d / 'nope.jsonl'), '--out-dir', str(self.d / 's2')); self.assertEqual(c, 2)


if __name__ == '__main__': unittest.main()
