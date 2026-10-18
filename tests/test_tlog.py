import base64, copy, json, pathlib, sys, tempfile, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import tlog

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # signing tests need the same dependency the publish job installs
    Ed25519PrivateKey = None

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

@unittest.skipIf(Ed25519PrivateKey is None, 'cryptography not installed')
class LogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.log = tlog.Log(pathlib.Path(self.tmp.name) / 'logs')
        key = Ed25519PrivateKey.generate()
        self.priv = base64.b64encode(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode()
        self.pub = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    def add(self, n):
        for i in range(n): self.log.append({'type': 'candidate-accepted', 'run_id': str(i)})
    def test_clean_log_verifies(self):
        self.add(3); self.log.write_checkpoint(self.priv); self.add(4); self.log.write_checkpoint(self.priv)
        self.assertEqual(self.log.verify(self.pub), [])
    def test_checkpoint_requires_new_entries(self):
        self.add(2); self.log.write_checkpoint(self.priv)
        with self.assertRaises(ValueError): self.log.write_checkpoint(self.priv)
    def test_edited_entry_is_detected(self):
        self.add(5); self.log.write_checkpoint(self.priv)
        f = self.log.entries_file; f.write_bytes(f.read_bytes().replace(b'"run_id":"2"', b'"run_id":"X"'))
        self.assertTrue(any('root does not match' in p for p in self.log.verify(self.pub)))
    def test_dropped_entries_are_detected(self):
        self.add(5); self.log.write_checkpoint(self.priv)
        f = self.log.entries_file; f.write_bytes(b''.join(f.read_bytes().splitlines(True)[:3]))
        self.assertTrue(self.log.verify(self.pub))
    def test_history_rewrite_after_checkpoint_is_detected(self):
        self.add(4); self.log.write_checkpoint(self.priv); self.add(3); self.log.write_checkpoint(self.priv)
        f = self.log.entries_file; lines = f.read_bytes().splitlines(True)
        lines[1] = lines[1].replace(b'"run_id":"1"', b'"run_id":"evil"'); f.write_bytes(b''.join(lines))
        self.assertTrue(self.log.verify(self.pub))
    def test_wrong_key_and_tampered_checkpoint_are_detected(self):
        self.add(3); self.log.write_checkpoint(self.priv)
        other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.assertTrue(self.log.verify(base64.b64encode(other).decode()))
        cp = self.log.checkpoint_files()[-1]; cp.write_bytes(cp.read_bytes().replace(b'\n3\n', b'\n2\n'))
        self.assertTrue(self.log.verify(self.pub))
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
        self.log.write_checkpoint(self.priv)
        md = tlog.render(self.log)
        self.assertIn('2026-10-18T04:05:06Z | ERROR | `publish.pages_failed`', md); self.assertIn('INFO 1, WARNING 0, ERROR 1', md)
        self.assertIn('\\|', md); self.assertLess(md.index('candidate.accepted'), md.index('publish.pages_failed'))  # newest first
        self.assertIn('Latest signed checkpoint: 2 entries', md)

if __name__ == '__main__': unittest.main()
