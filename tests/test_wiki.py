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
        (self.d / 'diagrams' / 'd1.mmd').write_text('flowchart LR\n  A --> B\n'); (self.d / 'diagrams' / 'd1.es.mmd').write_text('flowchart LR\n  A --> B\n'); self.put('diagrams/d1.json', DJ)
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

    def test_the_roadmap_table_comes_from_measured_data_and_is_required_to_exist(self):
        import wiki_roadmap
        calls = {'milestones': [{'number': 2, 'title': 'B', 'html_url': 'https://x/2', 'open_issues': 1, 'closed_issues': 2}, {'number': 1, 'title': 'A', 'html_url': 'https://x/1', 'open_issues': 0, 'closed_issues': 0}],
                 'releases': [{'tag_name': 'r1', 'html_url': 'https://x/r1', 'published_at': '2026-10-21T00:00:00Z', 'draft': False}, {'tag_name': 'd', 'html_url': 'https://x/d', 'published_at': None, 'draft': True}]}
        def fake(args):
            a = args[0]
            if 'milestones' in a: return calls['milestones']
            if 'releases' in a: return calls['releases']
            return {'total_count': 7 if 'is:merged' in a else 3}
        data = wiki_roadmap.collect('o/r', '2026-10-22', call=fake)
        self.assertEqual([m['title'] for m in data['milestones']], ['A', 'B']); self.assertEqual([r['tag'] for r in data['releases']], ['r1'], 'a draft release is not listed')
        self.assertEqual((data['open_prs'], data['merged_last_30_days'], data['measured_on']), (3, 7, '2026-10-22'))
        self.assertNotIn('percent', json.dumps(data).lower())
        for l in ('es', 'en'): self.edit(l, lambda t: t + '\n## Datos\n\n{{roadmap:table}}\n')
        self.assertTrue(any('roadmap-data.json does not exist' in p for p in self.problems()))
        self.put('roadmap-data.json', data); self.assertEqual(self.problems(), [])
        out = self.d / 'out'; wiki_build.main(['--out', str(out)]); built = (out / 'EN-Home.md').read_text()
        self.assertIn('| [A](https://x/1) | 0 | 0 |', built); self.assertIn('2026-10-22', built); self.assertIn('[r1](https://x/r1)', built)

    EN_D = 'flowchart TB\n  A["Start"]:::a --> B["Two<br/>lines"]:::b\n  classDef a fill:#111111,stroke:#eeeeee,color:#ffffff\n  classDef b fill:#eeeeee,stroke:#111111,color:#000000\n'
    ES_D = EN_D.replace('Start', 'Inicio').replace('Two<br/>lines', 'Dos<br/>líneas')

    def diagram(self, en, es=None, meta=None):
        (self.d / 'diagrams' / 'd1.mmd').write_text(en); self.put('diagrams/d1.json', meta or dict(DJ, legend={'es': 'a, b', 'en': 'a, b'}))
        (self.d / 'diagrams' / 'd1.es.mmd').write_text(en if es is None else es)

    def test_a_spanish_variant_is_used_by_the_es_page_and_drops_the_english_labels_note(self):
        self.diagram(self.EN_D, self.ES_D); self.assertEqual(self.problems(), [])
        self.assertIn('Dos<br/>líneas', wiki_build.diagram_block('d1', 'es')); self.assertNotIn('Start', wiki_build.diagram_block('d1', 'es'))
        self.assertNotIn('inglés', wiki_build.diagram_block('d1', 'es')); self.assertIn('Start', wiki_build.diagram_block('d1', 'en'))
        self.assertIn('*Leyenda: a, b*', wiki_build.diagram_block('d1', 'es')); self.assertIn('*Legend: a, b*', wiki_build.diagram_block('d1', 'en'))
        (self.d / 'diagrams' / 'd1.es.mmd').unlink(); self.assertIn('inglés', wiki_build.diagram_block('d1', 'es'), 'without a Spanish variant the note stays')
        self.assertTrue(any('no Spanish variant' in p for p in self.problems()), 'and the check fails: every diagram a page uses needs Spanish labels')

    SEQ_EN = 'sequenceDiagram\n  participant U as User\n  participant S as Server (Pages)\n  U->>S: ask for the file\n  S-->>U: the file\n'
    SEQ_ES = 'sequenceDiagram\n  participant U as Usuario\n  participant S as Servidor (Pages)\n  U->>S: pedir el archivo\n  S-->>U: el archivo\n'

    def reuse_from_docs_src(self, en, es):
        # d1 lives in a docs-src tree (not owned by the wiki); only the Spanish variant is in docs/wiki/diagrams
        src = self.d / 'src' / 'docs-src' / 'diagrams'; src.mkdir(parents=True)
        (src / 'd1.mmd').write_text(en); (src / 'd1.json').write_text(json.dumps(DJ)); (self.d / 'diagrams' / 'd1.mmd').unlink(); (self.d / 'diagrams' / 'd1.json').unlink()
        (self.d / 'diagrams' / 'd1.es.mmd').write_text(es)
        for m in (wiki_build, wiki_check): p = mock.patch.object(m, 'ROOT', self.d / 'src'); p.start(); self.addCleanup(p.stop)

    def test_a_docs_src_diagram_uses_the_wiki_spanish_variant_and_is_compared_with_its_english_source(self):
        self.reuse_from_docs_src(self.SEQ_EN, self.SEQ_ES); self.assertEqual(self.problems(), [])
        es = wiki_build.diagram_block('d1', 'es'); self.assertIn('pedir el archivo', es); self.assertNotIn('inglés', es)
        en = wiki_build.diagram_block('d1', 'en'); self.assertIn('ask for the file', en); self.assertNotIn('pedir', en)
        (self.d / 'diagrams' / 'd1.es.mmd').write_text(self.SEQ_ES.replace('  S-->>U: el archivo\n', '')); self.assertTrue(any('differs from d1.mmd' in p or 'structure' in p for p in self.problems()))
        (self.d / 'diagrams' / 'd1.es.mmd').write_text(self.SEQ_ES.replace('U->>S', 'S->>U')); self.assertTrue(any('structure' in p for p in self.problems()))
        (self.d / 'diagrams' / 'd1.es.mmd').unlink(); self.assertTrue(any('no Spanish variant' in p for p in self.problems())); self.assertIn('inglés', wiki_build.diagram_block('d1', 'es'))
        (self.d / 'diagrams' / 'd1.es.mmd').write_text(self.SEQ_ES); (self.d / 'diagrams' / 'orphan.es.mmd').write_text(self.SEQ_ES); self.assertTrue(any('no English twin' in p for p in self.problems()))

    def test_a_spanish_variant_without_its_english_twin_or_with_another_structure_is_reported(self):
        self.diagram(self.EN_D, self.ES_D); (self.d / 'diagrams' / 'orphan.es.mmd').write_text(self.ES_D); self.assertTrue(any('no English twin' in p for p in self.problems()))
        (self.d / 'diagrams' / 'orphan.es.mmd').unlink()
        self.diagram(self.EN_D, self.ES_D.replace('A["Inicio"]:::a --> B', 'A["Inicio"]:::a --> C["Extra"]:::b\n  A --> B')); self.assertTrue(any('differs from d1.mmd' in p for p in self.problems()))
        self.diagram(self.EN_D, self.ES_D.replace(':::b', ':::a')); self.assertTrue(any('structure' in p for p in self.problems()))
        self.diagram(self.EN_D, self.ES_D.replace('  classDef b fill:#eeeeee,stroke:#111111,color:#000000\n', '')); self.assertTrue(any('classDef' in p for p in self.problems()))

    def test_dark_mode_every_classdef_sets_fill_stroke_and_color_and_every_node_has_a_class(self):
        for missing in ('fill:#111111,', 'stroke:#eeeeee,', ',color:#ffffff'):
            self.diagram(self.EN_D.replace(missing, '', 1)); self.assertTrue(any('lacks' in p for p in self.problems()), missing)
        self.diagram(self.EN_D.replace('B["Two<br/>lines"]:::b', 'B["Two<br/>lines"]')); self.assertTrue(any('nodes without a class: B' in p for p in self.problems()))
        self.diagram(self.EN_D.replace('B["Two<br/>lines"]:::b', 'B["Two<br/>lines"]') + '  class B b\n'); self.assertEqual(self.problems(), [])

    def test_long_label_lines_and_a_missing_legend_are_reported(self):
        self.diagram(self.EN_D.replace('Start', 'x' * 20 + ' ' + 'y' * 20)); self.assertTrue(any('characters (max' in p for p in self.problems()))
        self.diagram(self.EN_D.replace('Start', 'x' * 20 + '<br/>' + 'y' * 20)); self.assertEqual(self.problems(), [])
        self.diagram(self.EN_D, meta=DJ); self.assertTrue(any('needs a legend' in p for p in self.problems()))

    def test_the_real_diagrams_have_a_spanish_variant(self):
        real = ROOT / 'docs' / 'wiki' / 'diagrams'
        if not real.exists(): self.skipTest('docs/wiki/diagrams not present')
        missing = [p.stem for p in real.glob('*.mmd') if not p.name.endswith('.es.mmd') and not p.with_name(p.stem + '.es.mmd').exists()]
        self.assertEqual(missing, [], 'every wiki-owned diagram has Spanish labels')
        for p in sorted((ROOT / 'docs-src' / 'diagrams').glob('*.mmd')):   # the ones reused from docs-src (the pages use 13 of them) also have Spanish labels
            if (real / (p.stem + '.es.mmd')).exists(): self.assertEqual(wiki_check.parity_problems(p, real / (p.stem + '.es.mmd')), [], p.stem)
        self.assertGreaterEqual(len([p for p in real.glob('*.es.mmd') if (ROOT / 'docs-src' / 'diagrams' / p.name.replace('.es.mmd', '.mmd')).exists()]), 13)

    def test_the_real_sources_pass(self):
        # the repository's own docs/wiki (when present) must satisfy every rule; this is the check CI runs
        real = ROOT / 'docs' / 'wiki'
        if not (real / 'pages.json').exists(): self.skipTest('docs/wiki not present')
        with mock.patch.object(wiki_build, 'WIKI', real), mock.patch.object(wiki_check, 'WIKI', real):
            self.assertEqual(wiki_check.check(real), [])
            self.assertEqual(wiki_check.private_report(real), [], 'no internal path, branch or private commit may appear in the public pages')
            out = pathlib.Path(tempfile.mkdtemp(prefix='wikiout-')); self.addCleanup(shutil.rmtree, out, True); self.assertEqual(wiki_build.main(['--out', str(out)]), 0)


if __name__ == '__main__': unittest.main()
