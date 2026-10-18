"""seal.py and verify_release.py end to end on a synthetic release. cosign is replaced by a stub that accepts any bundle:
these tests are about everything around the signature (inventory, rules root, evidence, log head, inclusion proof), not about Sigstore itself.
The real signature path is exercised by scripts/chain_test.py and by verify_live.py against the published release."""
import hashlib, json, os, pathlib, shutil, subprocess, sys, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import tlog


class SealAndVerifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / 'scripts').mkdir()
        for n in ('seal.py', 'catalog.py', 'tlog.py', 'verify_release.py'): shutil.copy(ROOT / 'scripts' / n, self.tmp / 'scripts' / n)
        self.dist = self.tmp / 'dist'; (self.dist / 'rules/s').mkdir(parents=True)
        text = 'rule A { condition: true }\n'; (self.dist / 'rules/s/a.yar').write_text(text)
        self.files = [{'path': 'rules/s/a.yar', 'sha256': hashlib.sha256(text.encode()).hexdigest(), 'bytes': len(text), 'source': 'nextron'}]
        self.root = tlog.rules_root(self.files)
        (self.dist / 'candidate.json').write_text(json.dumps({'files': self.files, 'sources': [], 'rejected': []}))
        (self.dist / 'validation.json').write_text(json.dumps({'checked': 1, 'engine': 'yara', 'failures': []}))
        self.write_dynamic()
        log = tlog.Log(self.tmp / 'logs'); log.append(tlog.event('INFO', 'candidate.accepted', 'ok', '77', rules_root=self.root)); log.write_checkpoint()
        self.bin = self.tmp / 'bin'; self.bin.mkdir(); (self.bin / 'cosign').write_text('#!/bin/sh\nexit 0\n'); (self.bin / 'cosign').chmod(0o755)
        self.env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'RUN_ID': '77', 'CANDIDATE_SHA': 'c' * 40, 'RUN_URL': 'https://example.test/run/1'}

    def write_dynamic(self, **kw):
        d = {'set_root': self.root, 'verdict': 'ok', 'engine': 'YARA 4.5.0', 'platform': 'linux', 'canaries_detected': 3, 'canaries_expected': 3, 'corpus': {'clean_files': 5, 'canaries': 3}}
        d.update(kw); (self.dist / 'dynamic.json').write_text(json.dumps(d))

    def seal(self): return subprocess.run([sys.executable, str(self.tmp / 'scripts/seal.py')], capture_output=True, text=True, env=self.env, cwd=self.tmp)

    def release(self):
        rel = self.tmp / 'release'; shutil.rmtree(rel, ignore_errors=True); (rel / 'logs').mkdir(parents=True)
        shutil.copytree(self.dist / 'rules', rel / 'rules'); shutil.copy(self.dist / 'manifest.json', rel / 'manifest.json'); (rel / 'manifest.sigstore.json').write_text('{}')
        for n in ('checkpoint.txt',): shutil.copy(self.tmp / 'logs' / n, rel / 'logs' / n)
        (rel / 'logs/checkpoint.sigstore.json').write_text('{}')
        manifest = json.loads((rel / 'manifest.json').read_text())
        doc = tlog.Log(self.tmp / 'logs').release_proof('77', manifest['rules_root'], manifest['log']['size']); (rel / 'inclusion-proof.json').write_text(json.dumps(doc))
        return rel

    def verify(self, rel): return subprocess.run([sys.executable, str(self.tmp / 'scripts/verify_release.py'), str(rel), '--identity', 'id', '--repo', 'o/r'], capture_output=True, text=True, env=self.env)

    def test_a_sealed_release_carries_signed_evidence_and_verifies(self):
        r = self.seal(); self.assertEqual(r.returncode, 0, r.stderr)
        m = json.loads((self.dist / 'manifest.json').read_text()); ev = m['evidence']
        self.assertEqual((ev['candidate_run_id'], ev['candidate_workflow_sha'], ev['dynamic']['set_root']), ('77', 'c' * 40, self.root))
        v = self.verify(self.release()); self.assertEqual(v.returncode, 0, v.stdout + v.stderr)

    def test_evidence_for_another_rule_set_cannot_be_sealed(self):
        self.write_dynamic(set_root='0' * 64); r = self.seal(); self.assertNotEqual(r.returncode, 0); self.assertIn('different rule set', r.stderr + r.stdout)
        self.assertFalse((self.dist / 'manifest.json').exists())

    def test_missing_failing_or_incomplete_evidence_cannot_be_sealed(self):
        (self.dist / 'dynamic.json').unlink(); self.assertNotEqual(self.seal().returncode, 0)
        self.write_dynamic(verdict='regression'); self.assertNotEqual(self.seal().returncode, 0)
        self.write_dynamic(canaries_detected=2); self.assertNotEqual(self.seal().returncode, 0)
        self.assertFalse((self.dist / 'manifest.json').exists())

    def test_an_unsafe_inventory_cannot_be_sealed(self):
        bad = self.files + [dict(self.files[0])]   # duplicate path
        (self.dist / 'candidate.json').write_text(json.dumps({'files': bad, 'sources': [], 'rejected': []})); r = self.seal()
        self.assertNotEqual(r.returncode, 0); self.assertIn('cannot be sealed', r.stderr + r.stdout)

    def test_the_verifier_rejects_tampering_after_sealing(self):
        self.assertEqual(self.seal().returncode, 0)
        def tampered(edit):
            rel = self.release(); m = json.loads((rel / 'manifest.json').read_text()); edit(rel, m); (rel / 'manifest.json').write_text(json.dumps(m)); return self.verify(rel)
        def other_set(rel, m): m['evidence']['dynamic']['set_root'] = '1' * 64
        def failing(rel, m): m['evidence']['dynamic']['verdict'] = 'regression'
        def dup(rel, m): m['files'].append(dict(m['files'][0]))
        def traversal(rel, m): m['files'][0]['path'] = '../x'
        def stats(rel, m): m['stats']['files'] = 99
        def size(rel, m): m['files'][0]['bytes'] = 1
        def content(rel, m): (rel / 'rules/s/a.yar').write_text('rule B { condition: true }\n')
        def extra_file(rel, m): (rel / 'rules/s/unlisted.yar').write_text('rule X { condition: true }\n')
        def root(rel, m): m['rules_root'] = '2' * 64
        def head(rel, m): m['log']['size'] = 9
        for name, edit in (('evidence set', other_set), ('evidence verdict', failing), ('duplicate', dup), ('traversal', traversal), ('stats', stats), ('size', size), ('content', content), ('unlisted file', extra_file), ('root', root), ('log head', head)):
            r = tampered(edit); self.assertNotEqual(r.returncode, 0, name); self.assertIn('VERIFY FAILED', r.stderr + r.stdout, name)

    def test_a_release_without_evidence_still_verifies_but_with_a_wrong_checkpoint_it_does_not(self):
        self.assertEqual(self.seal().returncode, 0); rel = self.release(); m = json.loads((rel / 'manifest.json').read_text()); del m['evidence']; (rel / 'manifest.json').write_text(json.dumps(m))
        self.assertEqual(self.verify(rel).returncode, 0)   # releases made before the evidence field existed
        (rel / 'logs/checkpoint.txt').write_bytes(tlog.Log(self.tmp / 'logs').checkpoint_bytes(1, b'\x05' * 32)); self.assertNotEqual(self.verify(rel).returncode, 0)


if __name__ == '__main__': unittest.main()
