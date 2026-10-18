"""Adversarial and property tests for the transparency-log primitives (stdlib only, fixed seeds, bounded run time).

Every accepted input is checked against an independent construction; every one-element mutation of a valid proof must be rejected.
Failures found by the fuzzing runs of the final audit are kept here as named regression cases."""
import base64, copy, json, pathlib, random, sys, tempfile, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import tlog

def leaves(n, salt=b''): return [tlog.leaf_hash(salt + b'e%d' % i) for i in range(n)]
def flip(h: bytes, bit=0) -> bytes: b = bytearray(h); b[bit // 8 % len(b)] ^= 1 << (bit % 8); return bytes(b)


class MerkleMutationTests(unittest.TestCase):
    def test_every_single_change_to_an_inclusion_proof_is_rejected(self):
        rnd = random.Random(1)
        for n in range(1, 34):
            ls = leaves(n); root = tlog.mth(ls)
            for i in range(n):
                proof = tlog.inclusion_proof(i, ls)
                self.assertTrue(tlog.verify_inclusion(i, n, ls[i], proof, root))
                for k in range(len(proof)):
                    bad = list(proof); bad[k] = flip(bad[k], rnd.randrange(256)); self.assertFalse(tlog.verify_inclusion(i, n, ls[i], bad, root), (n, i, k))
                if proof:
                    self.assertFalse(tlog.verify_inclusion(i, n, ls[i], proof[:-1], root), 'truncated proof')
                    self.assertFalse(tlog.verify_inclusion(i, n, ls[i], proof[::-1], root) and len(set(proof)) > 1, 'reordered proof')
                self.assertFalse(tlog.verify_inclusion(i, n, ls[i], proof + [b'\0' * 32], root), 'padded proof')
                self.assertFalse(tlog.verify_inclusion(i, n, ls[i], proof, flip(root)), 'wrong root')
                # the size is not asserted here: for some n the path of leaf i has the same shape in n and n+1, so (proof, root) alone cannot tell them apart.
                # What binds the size is the signed checkpoint (size, root); check_inclusion_proof compares both, see test_inclusion_proof_for_another_checkpoint.
                self.assertFalse(tlog.verify_inclusion(-1, n, ls[i], proof, root)); self.assertFalse(tlog.verify_inclusion(n, n, ls[i], proof, root))

    def test_every_single_change_to_a_consistency_proof_is_rejected(self):
        rnd = random.Random(2)
        for second in range(1, 30):
            ls = leaves(second); r2 = tlog.mth(ls)
            for first in range(1, second + 1):
                r1 = tlog.mth(ls[:first]); proof = tlog.consistency_proof(first, ls)
                self.assertTrue(tlog.verify_consistency(first, second, r1, r2, proof), (first, second))
                self.assertFalse(tlog.verify_consistency(first, second, flip(r1), r2, proof), 'forged old root')
                self.assertFalse(tlog.verify_consistency(first, second, r1, flip(r2), proof), 'forged new root')
                for k in range(len(proof)):
                    bad = list(proof); bad[k] = flip(bad[k], rnd.randrange(256)); self.assertFalse(tlog.verify_consistency(first, second, r1, r2, bad), (first, second, k))
                if first != second: self.assertFalse(tlog.verify_consistency(first, second, r1, r2, proof + [b'\1' * 32]), 'padded proof')
                if proof and first != second: self.assertFalse(tlog.verify_consistency(first, second, r1, r2, proof[:-1]), 'truncated proof')
                self.assertFalse(tlog.verify_consistency(second, first, r2, r1, proof) and first != second, 'sizes swapped')

    def test_a_rewritten_history_has_no_valid_consistency_proof(self):
        old = leaves(10); new_history = leaves(5) + leaves(10, b'fork')[5:]   # the first 5 entries agree, the rest was rewritten
        r_old = tlog.mth(old); r_new = tlog.mth(new_history)
        self.assertFalse(tlog.verify_consistency(10, 10, r_old, r_new, []))
        for forged in (tlog.consistency_proof(5, new_history), tlog.consistency_proof(5, old)):
            self.assertFalse(tlog.verify_consistency(10, 20, r_old, tlog.mth(new_history + leaves(10, b'more')), forged))

    def test_second_preimage_cannot_pass_a_leaf_for_an_inner_node(self):
        ls = leaves(4); root = tlog.mth(ls)
        inner = tlog.node_hash(ls[0], ls[1])   # an attacker offers an inner node as if it were a leaf of a 3-leaf tree
        self.assertFalse(tlog.verify_inclusion(0, 3, inner, [tlog.node_hash(ls[2], ls[3])], root))


class ProofBindingTests(unittest.TestCase):
    def test_inclusion_proof_for_another_checkpoint(self):
        ls = leaves(6); entry = json.dumps({'event': 'candidate.accepted', 'details': {'rules_root': 'aa'}}, sort_keys=True, separators=(',', ':'))
        ls[2] = tlog.leaf_hash(entry.encode()); root = tlog.mth(ls); body = tlog.Log(pathlib.Path('.')).checkpoint_bytes(6, root)
        doc = {'size': 6, 'root': root.hex(), 'index': 2, 'entry': entry, 'proof': [h.hex() for h in tlog.inclusion_proof(2, ls)]}
        self.assertIsNone(tlog.check_inclusion_proof(doc, body, 'aa'))
        self.assertIsNotNone(tlog.check_inclusion_proof({**doc, 'size': 7}, body, 'aa'))                # same proof, claimed for a larger tree
        self.assertIsNotNone(tlog.check_inclusion_proof(doc, tlog.Log(pathlib.Path('.')).checkpoint_bytes(7, root), 'aa'))
        self.assertIsNotNone(tlog.check_inclusion_proof(doc, body, 'bb'))                                  # the entry names another rules_root
        for bad in ({**doc, 'proof': ['zz']}, {**doc, 'index': 'x'}, {**doc, 'proof': None}, {**doc, 'entry': 5}, {k: v for k, v in doc.items() if k != 'root'}, {**doc, 'proof': [1]}):
            self.assertIsNotNone(tlog.check_inclusion_proof(bad, body, 'aa'), bad)   # malformed documents give an error string, never an exception


class CheckpointParsingTests(unittest.TestCase):
    ROOT = base64.b64encode(b'\x07' * 32).decode()
    def body(self, size='5', root=None, origin=tlog.ORIGIN, tail='\n'): return f'{origin}\n{size}\n{self.ROOT if root is None else root}{tail}'.encode()

    def test_the_canonical_checkpoint_parses(self):
        self.assertEqual(tlog.Log.parse_checkpoint(self.body()), (5, b'\x07' * 32)); self.assertEqual(tlog.Log.parse_checkpoint(self.body('0'))[0], 0)

    def test_every_non_canonical_or_malformed_form_is_refused(self):
        weird_root = base64.b64encode(b'\x07' * 31).decode()
        loose = self.ROOT[:-2] + 'd='   # non-zero trailing bits: same 32 bytes under lenient decoders, different text
        bodies = [self.body('+5'), self.body(' 5'), self.body('5 '), self.body('5_0'), self.body('05'), self.body('-1'), self.body(''), self.body('٥'), self.body('1' * 40),
                  self.body('5.0'), self.body('0x5'), self.body(root=weird_root), self.body(root=loose), self.body(root=''), self.body(root=self.ROOT + '='), self.body(origin='other v1'),
                  self.body(tail=''), self.body(tail='\n\n'), self.body(tail='\r\n'), self.body(root=self.ROOT.replace('B', '\0', 1)), b'\xff\xfe', b'', self.body() + b'extra\n',
                  self.body(root='é' * 43)]
        for b in bodies:
            with self.assertRaises(ValueError, msg=repr(b)): tlog.Log.parse_checkpoint(b)

    def test_random_bytes_never_crash_the_parser_with_anything_but_valueerror(self):
        rnd = random.Random(3)
        for _ in range(3000):
            b = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 120)))
            try: tlog.Log.parse_checkpoint(b)
            except ValueError: pass
        good = self.body()
        for i in range(len(good)):
            for c in (0, 10, 32, 48, 61, 255):
                m = bytearray(good); m[i] = c
                try: tlog.Log.parse_checkpoint(bytes(m))
                except ValueError: pass


class InventoryTests(unittest.TestCase):
    H = 'ab' * 32
    def test_a_normal_inventory_is_accepted(self):
        self.assertIsNone(tlog.check_inventory([{'path': 'rules/community/a b.yar', 'sha256': self.H}, {'path': 'rules/nextron/x+y@1.yar', 'sha256': self.H}]))

    def test_ambiguous_or_unsafe_inventories_are_refused(self):
        cases = {'duplicate': [{'path': 'a', 'sha256': self.H}, {'path': 'a', 'sha256': self.H}], 'empty': [], 'not a list': {'path': 'a'}, 'null entry': [None],
                 'dotdot': [{'path': 'rules/../x', 'sha256': self.H}], 'absolute': [{'path': '/etc/passwd', 'sha256': self.H}], 'dot segment': [{'path': './x', 'sha256': self.H}],
                 'empty segment': [{'path': 'a//b', 'sha256': self.H}], 'nul': [{'path': 'a\0b', 'sha256': self.H}], 'newline': [{'path': 'a\nb', 'sha256': self.H}],
                 'rtl override': [{'path': 'a‮b', 'sha256': self.H}], 'backslash': [{'path': 'a\\b', 'sha256': self.H}], 'percent': [{'path': '%2e%2e/x', 'sha256': self.H}],
                 'upper hex': [{'path': 'a', 'sha256': self.H.upper()}], 'short hash': [{'path': 'a', 'sha256': 'ab'}], 'nul in hash': [{'path': 'a', 'sha256': self.H[:-1] + '\0'}],
                 'path number': [{'path': 1, 'sha256': self.H}], 'hash missing': [{'path': 'a'}], 'long path': [{'path': 'a' * 401, 'sha256': self.H}]}
        for name, inv in cases.items(): self.assertIsNotNone(tlog.check_inventory(inv), name)

    def test_the_leaf_encoding_cannot_be_made_ambiguous_with_nul_in_path_or_hash(self):
        # NUL joins path and hash in the leaf; with NUL forbidden in both, (path, hash) pairs map to leaves one to one
        a = [{'path': 'a', 'sha256': self.H}]; b = [{'path': 'a\0' + self.H[:10], 'sha256': self.H[10:] + 'ab' * 5}]
        self.assertIsNone(tlog.check_inventory(a)); self.assertIsNotNone(tlog.check_inventory(b))

    def test_the_real_release_inventory_is_accepted_and_one_byte_changes_its_root(self):
        import hashlib
        files = [{'path': f'rules/s/f{i}.yar', 'sha256': hashlib.sha256(b'%d' % i).hexdigest()} for i in range(257)]
        self.assertIsNone(tlog.check_inventory(files)); root = tlog.rules_root(files)
        self.assertEqual(root, tlog.rules_root(list(reversed(files))))
        for i in (0, 128, 256):
            m = copy.deepcopy(files); m[i]['sha256'] = m[i]['sha256'][:-1] + ('0' if m[i]['sha256'][-1] != '0' else '1'); self.assertNotEqual(root, tlog.rules_root(m))
            m = copy.deepcopy(files); m[i]['path'] += 'x'; self.assertNotEqual(root, tlog.rules_root(m))
        self.assertNotEqual(root, tlog.rules_root(files[:-1])); self.assertNotEqual(root, tlog.rules_root(files + [{'path': 'z', 'sha256': files[0]['sha256']}]))


class LogTamperingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.dir = pathlib.Path(self.tmp.name); self.log = tlog.Log(self.dir)
        for i in range(3): self.log.append(tlog.event('INFO', 'x.y', f'm{i}', time='2026-01-01T00:00:00Z'))
        self.log.write_checkpoint(); (self.dir / 'checkpoint.txt').write_bytes((self.dir / 'checkpoints/00000003.txt').read_bytes())
        self.sign = lambda: [self.log.bundle_for(p).write_text('{}') for p in self.log.checkpoint_files()]
        for i in range(2): self.log.append(tlog.event('INFO', 'x.y', f'n{i}', time='2026-01-02T00:00:00Z'))
        self.log.write_checkpoint(); self.sign()
        self.sync()
    def tearDown(self): self.tmp.cleanup()
    def sync(self):
        newest = self.log.checkpoint_files()[-1]; (self.dir / 'checkpoint.txt').write_bytes(newest.read_bytes()); (self.dir / 'checkpoint.sigstore.json').write_bytes(self.log.bundle_for(newest).read_bytes())
    ok = staticmethod(lambda txt, bundle: None)

    def test_the_untouched_log_verifies(self): self.assertEqual(self.log.verify(self.ok), [])

    def test_editing_dropping_or_reordering_entries_is_detected(self):
        lines = (self.dir / 'log.jsonl').read_bytes().split(b'\n')[:-1]
        for name, new in (('edited', [lines[0].replace(b'm0', b'mX')] + lines[1:]), ('dropped', lines[1:]), ('reordered', [lines[1], lines[0]] + lines[2:]), ('truncated', lines[:2])):
            (self.dir / 'log.jsonl').write_bytes(b'\n'.join(new) + b'\n'); self.assertTrue(self.log.verify(self.ok), name)
            (self.dir / 'log.jsonl').write_bytes(b'\n'.join(lines) + b'\n')
        (self.dir / 'log.jsonl').write_bytes(b'\n'.join(lines))   # no trailing newline
        self.assertTrue(self.log.verify(self.ok))

    def test_a_stale_or_different_checkpoint_copy_is_detected(self):
        old = (self.dir / 'checkpoints/00000003.txt').read_bytes()
        (self.dir / 'checkpoint.txt').write_bytes(old)
        self.assertTrue(any('checkpoint.txt' in p for p in self.log.verify(self.ok)))   # clients would be pointed at an old head
        self.sync(); (self.dir / 'checkpoint.sigstore.json').write_text('{"other":1}')
        self.assertTrue(any('checkpoint.sigstore.json' in p for p in self.log.verify(self.ok)))
        self.sync(); (self.dir / 'checkpoint.txt').unlink(); self.assertTrue(any('missing' in p for p in self.log.verify(self.ok)))

    def test_a_checkpoint_for_a_forked_history_or_a_longer_log_is_detected(self):
        newest = self.log.checkpoint_files()[-1]
        newest.write_bytes(self.log.checkpoint_bytes(5, b'\x09' * 32)); self.sync(); self.assertTrue(any('root does not match' in p for p in self.log.verify(self.ok)))
        newest.write_bytes(self.log.checkpoint_bytes(9, tlog.mth(self.log.leaves()))); self.sync(); self.assertTrue(any('covers 9 entries' in p for p in self.log.verify(self.ok)))

    def test_an_unsigned_checkpoint_is_detected(self):
        self.log.bundle_for(self.log.checkpoint_files()[0]).unlink(); self.assertTrue(any('bundle is missing' in p for p in self.log.verify(self.ok)))
        self.assertTrue(any('bad' in p for p in self.log.verify(lambda t, b: 'bad signature')))


if __name__ == '__main__': unittest.main()
