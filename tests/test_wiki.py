"""The wiki tooling: parity ES/EN, links, evidence, diagrams, secrets, absolute claims, and the flat output for GitHub Wiki."""
import json, pathlib, shutil, sys, tempfile, unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
import wiki_build, wiki_check  # noqa: E402

PROV = {'entries': [{'id': 'EV-1', 'claim': {'es': 'Existe', 'en': 'It exists'}, 'source': 'README.md', 'date': '2026-10-22', 'ref': '', 'confidence': 'high', 'validation': 'read', 'state': 'published', 'class': 'PUBLICABLE'}]}
PAGES = {'pages': [{'id': 'Home', 'section': {'es': 'Inicio', 'en': 'Start'}, 'title': {'es': 'Inicio', 'en': 'Home'}, 'summary': {'es': 'x', 'en': 'x'}}]}
ES = '# Inicio\n\n## En 30 segundos\n\nTexto {{ev:EV-1}}.\n\n{{diagram:d1}}\n\n| a | b |\n|---|---|\n| 1 | 2 |\n'
EN = '# Home\n\n## In 30 seconds\n\nText {{ev:EV-1}}.\n\n{{diagram:d1}}\n\n| a | b |\n|---|---|\n| 1 | 2 |\n'
DJ = {'title': {'es': 'D', 'en': 'D'}, 'alt': {'es': 'alt es', 'en': 'alt en'}}


class Wiki(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp(prefix='wikitest-')); self.addCleanup(shutil.rmtree, self.d, True)
        (self.d / 'es').mkdir(); (self.d / 'en').mkdir(); (self.d / 'diagrams').mkdir()
        self.put('pages.json', PAGES); self.put('provenance.json', PROV)
        (self.d / 'es' / 'Home.md').write_text(ES); (self.d / 'en' / 'Home.md').write_text(EN)
        (self.d / 'diagrams' / 'd1.mmd').write_text('flowchart LR\n  A --> B\n'); self.put('diagrams/d1.json', DJ)
        for m in (wiki_build, wiki_check): p = mock.patch.object(m, 'WIKI', self.d); p.start(); self.addCleanup(p.stop)

    def put(self, name, obj): (self.d / name).write_text(json.dumps(obj))
    def problems(self): return wiki_check.check(self.d)
    def edit(self, lang, fn): p = self.d / lang / 'Home.md'; p.write_text(fn(p.read_text()))

    def test_a_consistent_pair_passes_and_builds(self):
        self.assertEqual(self.problems(), [])
        out = self.d / 'out'; self.assertEqual(wiki_build.main(['--out', str(out)]), 0)
        names = sorted(p.name for p in out.iterdir())
        self.assertEqual(names, ['EN-Evidence.md', 'EN-Home.md', 'ES-Evidence.md', 'ES-Home.md', '_Footer.md', '_Sidebar.md'])
        es = (out / 'ES-Home.md').read_text()
        self.assertTrue(es.startswith('**ES** | [EN](EN-Home)'))
        self.assertIn('```mermaid\nflowchart LR', es); self.assertIn('alt es', es); self.assertIn('(ES-Evidence#ev-1)', es)
        self.assertIn('[ES](ES-Home)', (out / 'EN-Home.md').read_text())
        self.assertIn('](ES-Home)', (out / '_Sidebar.md').read_text()); self.assertIn('](EN-Home)', (out / '_Sidebar.md').read_text())

    def test_a_page_missing_in_one_language_is_reported(self):
        (self.d / 'en' / 'Home.md').unlink(); self.assertTrue(any('missing' in p for p in self.problems()))

    def test_different_structure_between_languages_is_reported(self):
        self.edit('en', lambda t: t + '\n## Extra\n'); self.assertTrue(any('heading structure' in p for p in self.problems()))
        self.edit('en', lambda t: t.replace('## Extra\n', '')); self.edit('es', lambda t: t.replace('{{diagram:d1}}', '')); self.assertTrue(any('different diagrams' in p for p in self.problems()))

    def test_unknown_evidence_or_diagram_and_raw_mermaid_are_reported(self):
        self.edit('es', lambda t: t.replace('EV-1', 'EV-9')); self.edit('en', lambda t: t.replace('EV-1', 'EV-9')); self.assertTrue(any('EV-9' in p for p in self.problems()))
        self.edit('es', lambda t: t.replace('EV-9', 'EV-1') + '\n```mermaid\nflowchart LR\n```\n'); self.edit('en', lambda t: t.replace('EV-9', 'EV-1')); self.assertTrue(any('raw mermaid' in p for p in self.problems()))

    def test_links_must_resolve_inside_the_wiki_and_stay_in_the_language(self):
        self.edit('es', lambda t: t + '\n[roto](ES-Nada)\n'); self.edit('en', lambda t: t + '\n[broken](EN-Nothing)\n'); self.assertEqual(sum('does not resolve' in p for p in self.problems()), 2)
        self.edit('es', lambda t: t.replace('[roto](ES-Nada)', '[x](EN-Home)')); self.edit('en', lambda t: t.replace('[broken](EN-Nothing)', '[x](EN-Home)')); self.assertTrue(any('other language' in p for p in self.problems()))
        self.edit('es', lambda t: t.replace('[x](EN-Home)', '[aquí](ES-Home)')); self.assertTrue(any('says nothing' in p for p in self.problems()))

    def test_secret_like_strings_private_paths_and_absolute_claims_are_reported(self):
        self.edit('es', lambda t: t + '\nclave AGE-SECRET-KEY-1' + 'A' * 30 + '\n'); self.assertTrue(any('secret-like' in p for p in self.problems()))
        self.edit('es', lambda t: t.split('\nclave')[0] + '\nver /Users/alguien/proyecto/x\n'); self.assertTrue(any('private-path' in p or 'secret-like' in p for p in self.problems()))
        self.edit('es', lambda t: t.split('\nver')[0] + '\nEs 100% seguro.\n'); self.assertTrue(any('absolute security claim' in p for p in self.problems()))

    def test_provenance_rules(self):
        bad = json.loads(json.dumps(PROV)); bad['entries'][0]['class'] = 'CONFIDENCIAL'; self.put('provenance.json', bad); self.assertTrue(any('CONFIDENCIAL' in p for p in self.problems()))
        bad['entries'][0].update({'class': 'PUBLICABLE', 'state': 'finished'}); self.put('provenance.json', bad); self.assertTrue(any('allowed states' in p for p in self.problems()))
        bad['entries'][0].update({'state': 'published', 'repo': 'self', 'path': 'no/such/file.md'}); self.put('provenance.json', bad); self.assertTrue(any('obsolete' in p for p in self.problems()))
        bad['entries'][0].update({'path': 'README.md', 'ref': 'deadbeefdeadbeef'}); self.put('provenance.json', bad); self.assertTrue(any('does not exist' in p for p in self.problems()))

    def test_a_diagram_needs_both_languages_and_a_known_type(self):
        self.put('diagrams/d1.json', {'title': {'es': 'D'}, 'alt': {'es': 'a', 'en': 'a'}}); self.assertTrue(any('needs es and en' in p for p in self.problems()))
        self.put('diagrams/d1.json', DJ); (self.d / 'diagrams' / 'd1.mmd').write_text('banana\n'); self.assertTrue(any('unknown Mermaid type' in p for p in self.problems()))

    def test_heading_levels_and_single_h1(self):
        for l in ('es', 'en'): self.edit(l, lambda t: t + '\n#### Salto\n')
        self.assertTrue(any('jumps' in p for p in self.problems()))
        for l in ('es', 'en'): self.edit(l, lambda t: t.replace('#### Salto', '# Otro h1'))
        self.assertTrue(any('exactly one H1' in p for p in self.problems()))

    def test_the_real_sources_pass(self):
        # the repository's own docs/wiki (when present) must satisfy every rule; this is the check CI runs
        real = ROOT / 'docs' / 'wiki'
        if not (real / 'pages.json').exists(): self.skipTest('docs/wiki not present')
        with mock.patch.object(wiki_build, 'WIKI', real), mock.patch.object(wiki_check, 'WIKI', real):
            self.assertEqual(wiki_check.check(real), [])
            out = pathlib.Path(tempfile.mkdtemp(prefix='wikiout-')); self.addCleanup(shutil.rmtree, out, True); self.assertEqual(wiki_build.main(['--out', str(out)]), 0)


if __name__ == '__main__': unittest.main()
