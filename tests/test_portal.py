"""Multi-family portal pages (catalog, packages, plans, vulnerabilities): data derived only from real sources, no invented numbers or downloads,
ES/EN texts, safe DOM writes, valid links, and the Freemium capability split (PoC metadata never in a plan)."""
import json, pathlib, re, shutil, subprocess, sys, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import portal

WEB = ROOT / 'web'
PRICE = r'€|\$\s?\d|\d+[.,]\d{2}\s?(eur|usd)\b|/mes\b|per month|checkout|stripe|buy now|comprar ahora'   # an amount, a currency or a payment flow (saying "no prices" is fine)
NEW_PAGES = {'catalog.html': 'catalog.js', 'packages.html': 'packages.js', 'plans.html': 'plans.js', 'vulnerabilities.html': 'vulns.js'}
CONFIG = json.loads((ROOT / 'config' / 'intel-families.json').read_text())
LATEST = {'stats': {'files': 12, 'yara_rules': 340, 'expanded_bytes': 9000, 'package_bytes': 4000, 'source': 'counted by the site build'}, 'schema': 1, 'manifest': 'manifest.json',
          'signature': 'manifest.sigstore.json', 'inclusion_proof': 'inclusion-proof.json', 'checkpoint': 'logs/checkpoint.txt', 'checkpoint_signature': 'logs/checkpoint.sigstore.json',
          'manifest_sha256': 'a' * 64, 'package': 'rules-release.tar.gz', 'package_sha256': 'b' * 64, 'package_bytes': 4000}
ROWS = [{'tag': 'rules-20261030-1', 'published_at': '2026-10-30T03:40:00Z', 'url': 'https://github.com/MacGuard/macguard-yara-channel/releases/tag/rules-20261030-1', 'total': 10, 'added': 10,
         'modified': 0, 'removed': 0, 'rules_root': 'c' * 64, 'log': None, 'stats': {'yara_rules': 300}, 'package_bytes': 3900, 'verification': {'checked': True, 'manifest_signature': 'valid'},
         'assets': {'manifest.json': 'https://example.invalid/m'}},
        {'tag': 'rules-20261031-2', 'published_at': '2026-10-31T03:40:00Z', 'url': 'https://github.com/MacGuard/macguard-yara-channel/releases/tag/rules-20261031-2', 'total': 12, 'added': 2,
         'modified': 1, 'removed': 0, 'rules_root': 'd' * 64, 'log': None, 'stats': {'yara_rules': 340}, 'package_bytes': 4000, 'verification': {'checked': False}, 'assets': {}}]


def numbers_without_source(doc, path='$', holder=None):
    """Every number (not bool) must live in an object that names its `source` (or be a schema/identity field). Returns the offending paths."""
    bad = []
    if isinstance(doc, dict):
        for k, v in doc.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool) and 'source' not in doc and k not in ('schema',): bad.append(f'{path}.{k}')
            else: bad += numbers_without_source(v, f'{path}.{k}', doc)
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            if isinstance(v, (int, float)) and not isinstance(v, bool): bad.append(f'{path}[{i}]')
            else: bad += numbers_without_source(v, f'{path}[{i}]', holder)
    return bad


class DataTests(unittest.TestCase):
    def test_families_take_real_states_and_only_the_published_family_has_numbers_or_a_package(self):
        d = portal.families(CONFIG, LATEST); by = {f['id']: f for f in d['families']}
        self.assertEqual(by['yara_community']['state'], 'PUBLISHED'); self.assertEqual(by['yara_community']['tier'], 'FREE')
        self.assertEqual(by['yara_community']['package']['yara_rules'], LATEST['stats']['yara_rules']); self.assertEqual(by['yara_community']['package']['manifest_sha256'], LATEST['manifest_sha256'])
        for f in CONFIG['families']:
            g = by[f['id']]; self.assertIsNone(g['package'], f['id']); self.assertNotIn('counts', g, 'local counts of an unpublished family are never shown')
            self.assertNotEqual(g['state'], 'PUBLISHED', f['id']); self.assertNotEqual(g['state'], 'NOT_PUBLISHED', f'{f["id"]}: every configured publication value has a known state')
        self.assertEqual(by['hashes_malicious']['state'], 'NOT_INTEGRATED'); self.assertEqual(by['yara_x']['state'], 'ENGINE_ONLY'); self.assertEqual(by['cisa_kev']['state'], 'RETAINED')
        for fid in ('clamav', 'gcve', 'cwe', 'ghsa', 'cvss'): self.assertEqual(by[fid]['state'], 'NOT_CONFIGURED', fid)
        self.assertEqual(by['cisa_kev']['tier'], 'FREE', 'public vulnerability data is FREE'); self.assertEqual(by['sigma_sigmahq']['tier'], 'PREMIUM')
        self.assertEqual(d['as_of'], CONFIG['as_of']); self.assertEqual(numbers_without_source(d), [])

    def test_no_release_means_nothing_published_and_unknown_publication_is_not_optimistic(self):
        d = portal.families({'families': [{'id': 'x', 'group': 'detections', 'name': 'X', 'integration': 'INTEGRATED_LOCAL', 'publication': 'SOMETHING_NEW'}]}, None)
        by = {f['id']: f for f in d['families']}; self.assertEqual(by['yara_community']['state'], 'NOT_PUBLISHED'); self.assertIsNone(by['yara_community']['package'])
        self.assertEqual(by['x']['state'], 'NOT_PUBLISHED')

    def test_packages_are_exactly_the_releases_newest_first_and_every_number_names_its_source(self):
        d = portal.packages(ROWS, LATEST)
        self.assertEqual([p['tag'] for p in d['packages']], ['rules-20261031-2', 'rules-20261030-1'])
        p = d['packages'][0]; r = ROWS[1]
        self.assertEqual((p['items']['files'], p['items']['yara_rules'], p['size']['package_bytes'], p['changes']['added'], p['rules_root'], p['url']), (r['total'], 340, r['package_bytes'], r['added'], r['rules_root'], r['url']))
        self.assertEqual(d['current']['package_sha256'], LATEST['package_sha256']); self.assertEqual(d['premium']['available'], [], 'no fake Premium package')
        self.assertEqual(numbers_without_source(d), []); self.assertEqual(portal.packages([], None)['packages'], []); self.assertIsNone(portal.packages([], None)['current'])

    def test_write_produces_the_two_files_from_the_site_build_inputs(self):
        with tempfile.TemporaryDirectory() as t:
            site = pathlib.Path(t) / 'site'; site.mkdir(); (site / 'latest.json').write_text(json.dumps(LATEST))
            portal.write(site, ROOT, ROWS)
            self.assertEqual(json.loads((site / 'families.json').read_text()), json.loads(json.dumps(portal.families(CONFIG, LATEST))))
            self.assertEqual(json.loads((site / 'packages.json').read_text()), json.loads(json.dumps(portal.packages(ROWS, LATEST))))

    def test_the_capability_split_follows_the_freemium_decision_and_poc_metadata_is_never_in_a_plan(self):
        c = json.loads((WEB / 'capabilities.json').read_text()); plans = {p['id']: set(p['capabilities']) for p in c['plans']}
        self.assertEqual(plans['free'], {'catalog.public.read', 'vulnerability.public.read', 'yara.community.download'})
        self.assertEqual(plans['premium'], {'rules.premium.read', 'rules.premium.download', 'ioc.premium.read', 'intel.correlation.read', 'intel.advanced.export'})
        self.assertFalse(plans['free'] & plans['premium']); self.assertNotIn('research.poc.metadata.read', plans['free'] | plans['premium'])
        self.assertEqual([s['capability'] for s in c['separate']], ['research.poc.metadata.read']); self.assertEqual(c['access_mode'], 'OPEN_PREMIUM_PREVIEW')
        self.assertNotRegex(json.dumps(c).lower(), PRICE, 'no prices or checkout')


class PageTests(unittest.TestCase):
    NAV = ['./', 'catalog.html', 'indicators.html', 'vulnerabilities.html', 'packages.html', 'plans.html', 'transparency.html', 'docs/index.html']   # hub navigation (also test_portal_hub.py)

    def test_every_portal_page_has_the_same_navigation_with_one_current_page(self):
        for name in ['index.html', 'rules.html', 'releases.html', 'transparency.html', *NEW_PAGES]:
            s = (WEB / name).read_text(); nav = re.search(r'<nav aria-label="Principal">(.*?)</nav>', s, re.S).group(1)
            self.assertEqual(re.findall(r'href="([^"]+)"', nav), self.NAV, name); self.assertEqual(nav.count('aria-current="page"'), 1, name)

    def test_every_text_key_of_the_new_pages_has_an_english_translation(self):
        common = (WEB / 'common.js').read_text(); nav_en = set(re.findall(r"(\w+):'", re.search(r"\ben:\{(nav_home.*?)\}\};", common, re.S).group(1)))
        for page, js in NEW_PAGES.items():
            keys = set(re.findall(r'data-t="(\w+)"', (WEB / page).read_text())); src = (WEB / js).read_text()
            en = set(re.findall(r"(\w+):'", re.search(r"var D=\{es:\{\},en:\{(.*?)\}\};", src, re.S).group(1)))
            self.assertEqual(keys - en - nav_en, set(), f'{page}: keys without English text')

    def test_dynamic_data_is_never_written_as_html(self):
        for js in sorted(WEB.glob('*.js')):
            if js.name == 'docs.js': continue   # pre-existing: inserts the docs build's own pre-rendered HTML, no remote data (out of this change)
            self.assertIsNone(re.search(r'innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function', js.read_text()), js.name)

    def test_links_of_the_new_pages_resolve_to_site_files(self):
        generated = {'families.json', 'packages.json', 'manifest.json', 'manifest.sigstore.json', 'inclusion-proof.json', 'verify_public_release.py', 'releases.json', 'rules-list.html', 'kev/index.json', 'sources.json'}
        for page in NEW_PAGES:
            for h in re.findall(r'href="([^"#]+)"', (WEB / page).read_text()):
                if h == './' or h.startswith('docs/'): continue
                self.assertTrue((WEB / h).exists() or h in generated, f'{page}: {h}')

    def test_the_vulnerability_pages_make_no_request_without_a_configured_service_and_detect_identifier_kinds(self):
        # the explorer itself (requests, static KEV, API client) is exercised by test_portal_hub.py BrowserLogicTests; the identifier contract lives in common.js
        node = shutil.which('node')
        if not node: self.skipTest('node not installed')
        for page in ('vulnerabilities.html', 'vuln.html'): self.assertNotIn('mg-vuln-api', (WEB / page).read_text(), 'no lookup service is configured while none is published')
        harness = r'''const vm=require('vm'),fs=require('fs');const ctx={document:{querySelector:()=>null,querySelectorAll:()=>[],getElementById:()=>null},navigator:{language:'es'},localStorage:{getItem:()=>null,setItem(){}},TextEncoder,console};
ctx.window=ctx;vm.createContext(ctx);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),ctx);
const k=(v)=>{const r=ctx.MG.vulnKind(v);return r?r.kind+' '+r.id:null};
console.log(JSON.stringify({api:ctx.MG.apiBase(),cases:[k('cve-2024-3094'),k('EUVD-2025-12345'),k('GCVE-1-2025-0001'),k('GCVE-0-2024-3094'),k('ghsa-2345-6789-cfgh'),k('CWE-079'),k('CVE-24-1'),k('GHSA-aaaa-bbbb-cccc'),k('x'.repeat(80)),k(' CVE-2021-44228 ')]}))'''
        out = json.loads(subprocess.run([node, '-e', harness, str(WEB / 'common.js')], capture_output=True, text=True, check=True).stdout)
        self.assertEqual(out['api'], '', 'no API base without the meta tag')
        self.assertEqual(out['cases'], ['CVE CVE-2024-3094', 'EUVD EUVD-2025-12345', 'GCVE GCVE-1-2025-0001', 'GCVE GCVE-0-2024-3094', 'GHSA GHSA-2345-6789-cfgh', 'CWE CWE-79', None, None, None, 'CVE CVE-2021-44228'])

    def test_a_vulnerability_record_of_the_r1_contract_is_rendered_as_text_and_anything_off_contract_is_refused(self):
        node = shutil.which('node')
        if not node: self.skipTest('node not installed')
        contract = ROOT / 'contracts' / 'v1' / 'intel-vulnerability.schema.json'   # added by the R1 branch (feat/r1-canonical); until it is on this branch, read it from git if present
        tmp = None
        if not contract.exists():
            r = subprocess.run(['git', '-C', str(ROOT), 'show', '327d937:contracts/v1/intel-vulnerability.schema.json'], capture_output=True, text=True)
            if r.returncode == 0: tmp = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False); tmp.write(r.stdout); tmp.close(); contract = pathlib.Path(tmp.name)
        try:
            out = json.loads(subprocess.run([node, str(ROOT / 'tests/web/vulnrecord_check.mjs'), str(contract) if contract.exists() else '-'], capture_output=True, text=True, check=True).stdout)
        finally:
            if tmp: pathlib.Path(tmp.name).unlink()
        if out['contract'] is not None: self.assertEqual(out['contract'], [], 'the synthetic fixture follows macguard.intel-vulnerability/1')
        es, en, held = out['es'], out['en'], out['held']
        self.assertTrue(es['ok'] and en['ok']); self.assertEqual((es['links'], es['scripts']), (0, 0), 'PoC references and data are never links or markup')
        self.assertIn('<script>alert(1)</script>', es['text'], 'markup in data stays literal text')
        for s in ('Sin regla verificada disponible', 'No figura en KEV a fecha de 2099-01-03', 'No figurar en KEV no significa que no se esté explotando', 'no es una gravedad',
                  'Equivalencias en disputa (no se fusionan)', 'la fuente no proporciona puntuación', 'CVSS 3.1 · 9.8 CRITICAL', '2099-01-03 · fuente: synthetic-epss', 'solo metadatos'):
            self.assertIn(s, es['text'], s)
        self.assertIn('No verified rule available', en['text']); self.assertIn('does not mean it is not exploited', en['text'])
        self.assertNotIn('Sin regla verificada disponible', held['text'], 'a withheld (Premium) section is never shown as "no rule exists"'); self.assertIn('información Premium', held['text'])
        for k in ('badSchema', 'badId', 'exec', 'badEpss', 'missingList'): self.assertFalse(out[k]['ok'], k); self.assertNotIn('CVE-2099-0001', out[k]['text'], f'{k}: nothing of the record is shown')

    def test_plans_and_packages_pages_promise_nothing_that_does_not_exist(self):
        plans = (WEB / 'plans.html').read_text().lower(); self.assertNotRegex(plans, PRICE)
        pk = (WEB / 'packages.html').read_text(); self.assertIn('Aún no hay paquetes Premium publicados', pk); self.assertIn('Ningún paquete incluye código de PoC', pk)
        self.assertIn('aún no publicado', (WEB / 'vulns.js').read_text())


if __name__ == '__main__':
    unittest.main()
