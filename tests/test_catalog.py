import pathlib, sys, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import catalog, tlog

def man(files, root='r', log=None):
    return {'files': [{'path': p, 'sha256': h, 'bytes': 1, 'source': p.split('/')[1]} for p, h in files.items()], 'rules_root': root, 'log': log,
            'sources': [{'id': 'nextron', 'repository': 'Neo23x0/signature-base', 'commit': 'aaa'}, {'id': 'community', 'repository': 'Yara-Rules/rules', 'commit': 'bbb'}],
            'validation': {'engine': 'yara', 'checked': len(files)}}

class CatalogTests(unittest.TestCase):
    def test_diff_uses_paths_and_hashes_not_totals(self):
        old = man({'rules/nextron/a.yar': '1', 'rules/nextron/b.yar': '2', 'rules/nextron/c.yar': '3'})
        new = man({'rules/nextron/a.yar': '1', 'rules/nextron/b.yar': 'X', 'rules/nextron/d.yar': '4'})   # same total, different content
        d = catalog.diff(old, new)
        self.assertEqual((d['added'], d['modified'], d['removed']), (['rules/nextron/d.yar'], ['rules/nextron/b.yar'], ['rules/nextron/c.yar']))
    def test_history_counts_and_order(self):
        r1 = {'tag': 't1', 'published_at': '2026-10-01T00:00:00Z', 'url': 'https://x/releases/tag/t1', 'manifest': man({'rules/nextron/a.yar': '1'})}
        r2 = {'tag': 't2', 'published_at': '2026-10-02T00:00:00Z', 'url': 'https://x/releases/tag/t2', 'manifest': man({'rules/nextron/a.yar': '2', 'rules/nextron/b.yar': '3'}), 'verification': {'checked': True}}
        rows = catalog.history([r2, r1])
        self.assertEqual([r['tag'] for r in rows], ['t1', 't2'])
        self.assertEqual((rows[0]['added'], rows[0]['modified'], rows[0]['removed']), (1, 0, 0))
        self.assertEqual((rows[1]['added'], rows[1]['modified'], rows[1]['removed']), (1, 1, 0))
        self.assertEqual(rows[0]['verification'], {'checked': False})
        self.assertIn('/releases/download/t1/manifest.json', rows[0]['assets']['manifest.json'])
        self.assertNotIn('_diff', catalog.public_rows(rows)[0])
    def test_first_seen_and_changed(self):
        s = catalog.first_seen([('t1', man({'rules/nextron/a.yar': '1'})), ('t2', man({'rules/nextron/a.yar': '2', 'rules/nextron/b.yar': '3'}))])
        self.assertEqual(s['rules/nextron/a.yar'], ('t1', 't2')); self.assertEqual(s['rules/nextron/b.yar'], ('t2', 't2'))
    def test_catalog_rows_come_from_the_manifest(self):
        m = man({'rules/nextron/yara/apt_x.yar': '1', 'rules/community/packers/p.yar': '2'})
        c = catalog.build_catalog(m, {}, 't1')
        self.assertEqual(c['count'], 2)
        by = {f['name']: f for f in c['files']}
        self.assertEqual(by['apt_x.yar']['category'], 'apt'); self.assertEqual(by['p.yar']['category'], 'packers')
        self.assertEqual(by['p.yar']['repository'], 'Yara-Rules/rules'); self.assertEqual(by['p.yar']['commit'], 'bbb')
        self.assertEqual(by['p.yar']['validation'], 'compiled')
    def test_unchecked_when_validation_does_not_cover_every_file(self):
        m = man({'rules/nextron/a.yar': '1'}); m['validation'] = {'engine': 'yara', 'checked': 0}
        self.assertEqual(catalog.build_catalog(m, {}, 't')['files'][0]['validation'], 'unchecked')
    def test_consistency_document_verifies_and_refuses_wrong_heads(self):
        lines = [f'line-{i}'.encode() for i in range(9)]
        leaves = [tlog.leaf_hash(l) for l in lines]
        old = {'size': 4, 'root': tlog.mth(leaves[:4]).hex()}; new = {'size': 9, 'root': tlog.mth(leaves).hex()}
        doc = catalog.consistency_doc(lines, old, new)
        self.assertTrue(tlog.verify_consistency(4, 9, bytes.fromhex(doc['first_root']), bytes.fromhex(doc['second_root']), [bytes.fromhex(p) for p in doc['proof']]))
        self.assertIsNone(catalog.consistency_doc(lines, {'size': 4, 'root': '00' * 32}, new))
        self.assertIsNone(catalog.consistency_doc(lines, new, new))
        self.assertIsNone(catalog.consistency_doc(lines, old, {'size': 99, 'root': new['root']}))
if __name__ == '__main__': unittest.main()
