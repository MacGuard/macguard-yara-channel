import json, pathlib, sys, tempfile, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import catalog, changes, release_meta, tlog

def man(files, **kw):
    m = {'files': [{'path': p, 'sha256': h, 'bytes': 10, 'source': 'nextron'} for p, h in files.items()], 'rules_root': 'rr', 'sources': [], 'stats': {'files': len(files), 'yara_rules': 7, 'expanded_bytes': 10 * len(files)}}
    m.update(kw); return m

class RuleCountTests(unittest.TestCase):
    def test_counts_declarations_not_files(self):
        t = 'import "pe"\nrule A { condition: true }\nprivate rule B { condition: true }\nglobal private rule C { condition: true }\n// rule D\n  rule E{condition:true}'
        self.assertEqual(catalog.count_rules(t), 4)
    def test_file_without_rules(self): self.assertEqual(catalog.count_rules('include "x.yar"'), 0)

class ChangesTests(unittest.TestCase):
    def test_first_release_always_changes(self):
        self.assertTrue(changes.compute(man({'rules/a.yar': '1'}))['changed'])
    def test_identical_content_is_not_a_change_even_if_upstream_commit_moved(self):
        prev = man({'rules/a.yar': '1'}, sources=[{'id': 'nextron', 'commit': 'old'}]); cand = man({'rules/a.yar': '1'}, sources=[{'id': 'nextron', 'commit': 'new'}])
        d = changes.compute(cand, prev); self.assertFalse(d['changed']); self.assertEqual(d['counts']['unchanged'], 1)
    def test_each_kind_of_change_triggers(self):
        base = man({'rules/a.yar': '1', 'rules/b.yar': '2'})
        for cand in (man({'rules/a.yar': '1', 'rules/b.yar': '2', 'rules/c.yar': '3'}), man({'rules/a.yar': '1', 'rules/b.yar': 'X'}), man({'rules/a.yar': '1'})):
            self.assertTrue(changes.compute(cand, base)['changed'])

class ReleaseMetaTests(unittest.TestCase):
    def test_metadata_changelog_and_consistency(self):
        lines = [f'line-{i}'.encode() for i in range(6)]
        leaves = [tlog.leaf_hash(l) for l in lines]
        prev = man({'rules/a.yar': '1'}, log={'size': 3, 'root': tlog.mth(leaves[:3]).hex()}, rules_root='old')
        cur = man({'rules/a.yar': '2', 'rules/b.yar': '3'}, log={'size': 6, 'root': tlog.mth(leaves).hex()}, rules_root='new')
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td); (td / 'manifest.json').write_text(json.dumps(cur)); (td / 'pkg.tgz').write_bytes(b'x' * 123)
            r = release_meta.build(td, td / 'pkg.tgz', 'rules-1', 'https://run', td / 'out', prev, lines, now='2026-10-18T00:00:00Z')
            self.assertEqual((r['files'], r['yara_rules'], r['package_bytes']), (2, 7, 123))
            self.assertEqual(r['changes'], {'added': 1, 'modified': 1, 'removed': 0, 'unchanged': 0, 'total': 2})
            self.assertTrue(r['complete_release'])
            self.assertIn('complete current rule set', (td / 'out/CHANGELOG.md').read_text())
            self.assertIn('rules/b.yar', (td / 'out/CHANGELOG.md').read_text())
            c = json.loads((td / 'out/consistency.json').read_text())
            self.assertTrue(tlog.verify_consistency(3, 6, bytes.fromhex(c['first_root']), bytes.fromhex(c['second_root']), [bytes.fromhex(p) for p in c['proof']]))
    def test_no_consistency_file_for_the_first_release(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td); (td / 'manifest.json').write_text(json.dumps(man({'rules/a.yar': '1'}))); (td / 'p').write_bytes(b'1')
            release_meta.build(td, td / 'p', 't', 'u', td / 'out', None, [])
            self.assertFalse((td / 'out/consistency.json').exists())
if __name__ == '__main__': unittest.main()
