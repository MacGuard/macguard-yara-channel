import base64, copy, json, pathlib, sys, tempfile, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import tlog

def leaves(n): return [tlog.leaf_hash(f'entry-{i}'.encode()) for i in range(n)]

def iterative_root(ls):
    """Independent MTH: pair up levels, promoting an unpaired node unchanged (equivalent for RFC 6962 trees)."""
    if not ls: return tlog.EMPTY_ROOT
    level = list(ls)
    while len(level) > 1:
        nxt = [tlog.node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2: nxt.append(level[-1])
        level = nxt
    return level[0]

class MerkleTests(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(tlog.EMPTY_ROOT.hex(), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        self.assertEqual(tlog.leaf_hash(b'').hex(), '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d')
    def test_root_matches_independent_implementation(self):
        for n in range(0, 70): self.assertEqual(tlog.mth(leaves(n)), iterative_root(leaves(n)), n)
    def test_inclusion_all_sizes_and_indexes(self):
        for n in range(1, 41):
            ls = leaves(n); root = tlog.mth(ls)
            for i in range(n):
                proof = tlog.inclusion_proof(i, ls)
                self.assertTrue(tlog.verify_inclusion(i, n, ls[i], proof, root), (n, i))
                self.assertFalse(tlog.verify_inclusion(i, n, tlog.leaf_hash(b'forged'), proof, root))
                self.assertFalse(tlog.verify_inclusion((i + 1) % n, n, ls[i], proof, root) and n > 1 and (i + 1) % n != i)
    def test_inclusion_rejects_tampered_proof(self):
        ls = leaves(13); root = tlog.mth(ls); proof = tlog.inclusion_proof(5, ls)
        bad = list(proof); bad[0] = bytes(32)
        self.assertFalse(tlog.verify_inclusion(5, 13, ls[5], bad, root))
        self.assertFalse(tlog.verify_inclusion(5, 13, ls[5], proof[:-1], root))
        self.assertFalse(tlog.verify_inclusion(5, 13, ls[5], proof + [bytes(32)], root))
    def test_consistency_all_pairs(self):
        for second in range(1, 34):
            ls = leaves(second); r2 = tlog.mth(ls)
            for first in range(1, second + 1):
                r1 = tlog.mth(ls[:first]); proof = tlog.consistency_proof(first, ls)
                self.assertTrue(tlog.verify_consistency(first, second, r1, r2, proof), (first, second))
    def test_consistency_detects_rewritten_history(self):
        ls = leaves(20); r2 = tlog.mth(ls)
        forged = leaves(20); forged[3] = tlog.leaf_hash(b'rewritten')
        r1_forged = tlog.mth(forged[:9]); proof = tlog.consistency_proof(9, ls)
        self.assertFalse(tlog.verify_consistency(9, 20, r1_forged, r2, proof))
        self.assertFalse(tlog.verify_consistency(9, 20, tlog.mth(ls[:9]), tlog.mth(forged), proof))
    def test_rules_root_is_order_independent_and_content_sensitive(self):
        files = [{'path': 'b', 'sha256': '22'}, {'path': 'a', 'sha256': '11'}]
        self.assertEqual(tlog.rules_root(files), tlog.rules_root(list(reversed(files))))
        changed = copy.deepcopy(files); changed[0]['sha256'] = '23'
        self.assertNotEqual(tlog.rules_root(files), tlog.rules_root(changed))

class LogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.log = tlog.Log(pathlib.Path(self.tmp.name) / 'logs')
    def sign(self):
        """Stand-in for cosign: a bundle that records the exact bytes it signed."""
        for txt in self.log.checkpoint_files():
            if not self.log.bundle_for(txt).exists(): self.log.bundle_for(txt).write_bytes(txt.read_bytes())
        newest = self.log.checkpoint_files()[-1:]   # what publish.yml does: the copies clients read are the newest signed checkpoint
        if newest and (self.log.folder / 'checkpoint.txt').exists(): (self.log.folder / 'checkpoint.sigstore.json').write_bytes(self.log.bundle_for(newest[0]).read_bytes())
    @staticmethod
    def verifier(txt, bundle): return None if bundle.read_bytes() == txt.read_bytes() else 'signature does not match'
    def check(self): self.sign(); return self.log.verify(self.verifier)
    def add(self, n):
        for i in range(n): self.log.append({'type': 'candidate-accepted', 'run_id': str(i)})
    def test_clean_log_verifies(self):
        self.add(3); self.log.write_checkpoint(); self.add(4); self.log.write_checkpoint(); self.sign()
        self.assertEqual(self.check(), [])
    def test_checkpoint_requires_new_entries(self):
        self.add(2); self.log.write_checkpoint()
        with self.assertRaises(ValueError): self.log.write_checkpoint()
    def test_edited_entry_is_detected(self):
        self.add(5); self.log.write_checkpoint()
        f = self.log.entries_file; f.write_bytes(f.read_bytes().replace(b'"run_id":"2"', b'"run_id":"X"'))
        self.assertTrue(any('root does not match' in p for p in self.check()))
    def test_dropped_entries_are_detected(self):
        self.add(5); self.log.write_checkpoint()
        f = self.log.entries_file; f.write_bytes(b''.join(f.read_bytes().splitlines(True)[:3]))
        self.assertTrue(self.check())
    def test_history_rewrite_after_checkpoint_is_detected(self):
        self.add(4); self.log.write_checkpoint(); self.add(3); self.log.write_checkpoint()
        f = self.log.entries_file; lines = f.read_bytes().splitlines(True)
        lines[1] = lines[1].replace(b'"run_id":"1"', b'"run_id":"evil"'); f.write_bytes(b''.join(lines))
        self.assertTrue(self.check())
    def test_unsigned_or_tampered_checkpoint_is_detected(self):
        self.add(3); self.log.write_checkpoint()
        self.assertTrue(any('missing' in p for p in self.log.verify(self.verifier)))
        self.sign(); self.assertEqual(self.check(), [])
        cp = self.log.checkpoint_files()[-1]; cp.write_bytes(cp.read_bytes().replace(b'\n3\n', b'\n2\n'))
        self.assertTrue(self.check())
    def test_release_proof_binds_manifest_rules_root_to_the_signed_tree(self):
        self.log.append(tlog.event('INFO', 'sources.fetched', 'x', '9'))
        self.log.append(tlog.event('INFO', 'candidate.accepted', 'ok', '9', rules_root='ab' * 32))
        self.log.append(tlog.event('INFO', 'release.approved', 'ok', '9'))
        self.log.write_checkpoint(); body = self.log.checkpoint_files()[-1].read_bytes()
        doc = self.log.release_proof('9', 'ab' * 32, 3)
        self.assertIsNone(tlog.check_inclusion_proof(doc, body, 'ab' * 32))
        self.assertIsNotNone(tlog.check_inclusion_proof(doc, body, 'cd' * 32))
        forged = dict(doc, entry=doc['entry'].replace('ab' * 32, 'cd' * 32)); self.assertIsNotNone(tlog.check_inclusion_proof(forged, body, 'cd' * 32))
        self.assertIsNotNone(tlog.check_inclusion_proof(dict(doc, proof=doc['proof'][:-1]), body, 'ab' * 32))
        with self.assertRaises(ValueError): self.log.release_proof('8', 'ab' * 32, 3)
        with self.assertRaises(ValueError): self.log.release_proof('9', 'cd' * 32, 3)
    def test_events_are_readable_and_levelled(self):
        cand = {'sources': [{'repository': 'o/r', 'commit': 'abc'}], 'files': [{'path': 'rules/a.yar', 'sha256': '11'}],
                'rejected': [{'source': 'o', 'path': 'big.yar', 'reason': 'size-or-binary'}]}
        val = {'checked': 1, 'failures': [{'file': 'rules/a.yar', 'error': 'error: rule "X" in /home/runner/work/r/r/dist/rules/a.yar(5): undefined identifier "foo"'}]}
        evs = tlog.events_for_candidate(cand, val, '42', '2026-10-18T03:00:00Z')
        self.assertEqual([e['level'] for e in evs], ['INFO', 'WARNING', 'ERROR', 'ERROR'])
        rejected = next(e for e in evs if e['event'] == 'rule.rejected')
        self.assertIn('rules/a.yar was rejected', rejected['message']); self.assertIn('undefined identifier "foo"', rejected['message'])
        self.assertNotIn('/home/runner', rejected['message']); self.assertIn('external variable', rejected['message'])
        self.assertEqual(evs[-1]['event'], 'candidate.rejected'); self.assertEqual(evs[0]['time'], '2026-10-18T03:00:00Z')
        ok = tlog.events_for_candidate(cand, {'checked': 1, 'failures': []}, '42', 't')
        self.assertEqual(ok[-1]['event'], 'candidate.accepted'); self.assertEqual(ok[-1]['level'], 'INFO')
    def test_event_validation_and_render(self):
        with self.assertRaises(ValueError): tlog.event('FATAL', 'x', 'y')
        self.log.append(tlog.event('ERROR', 'publish.pages_failed', 'Deploying to Cloudflare Pages failed: HTTP 403 | token', '7', '2026-10-18T04:05:06Z'))
        self.log.append(tlog.event('INFO', 'candidate.accepted', 'ok', '7', '2026-10-18T04:06:00Z'))
        self.log.write_checkpoint()
        md = tlog.render(self.log)
        self.assertIn('2026-10-18T04:05:06Z | ERROR | `publish.pages_failed`', md); self.assertIn('INFO 1, WARNING 0, ERROR 1', md)
        self.assertIn('\\|', md); self.assertLess(md.index('candidate.accepted'), md.index('publish.pages_failed'))  # newest first
        self.assertIn('Latest signed checkpoint: 2 entries', md)

if __name__ == '__main__': unittest.main()
