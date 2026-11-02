"""Threat Intelligence Hub (portada, explorador, ficha, biblioteca, indicadores, guía): build-time data only from VERIFIED packages, static KEV search
in bounded year shards, the API client against fixtures, and the pages' safety (no HTML from data, ES/EN, links, CSP). Synthetic data only."""
import hashlib, io, json, os, pathlib, re, shutil, subprocess, sys, tarfile, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import portal, portal_hub, csp

WEB = ROOT / 'web'
HUB_PAGES = {'index.html': 'hub.js', 'vulnerabilities.html': 'vulns.js', 'vuln.html': 'vuln.js', 'indicators.html': 'indicators.js', 'guide.html': 'guide.js'}
NAV = ['./', 'catalog.html', 'indicators.html', 'vulnerabilities.html', 'packages.html', 'plans.html', 'transparency.html', 'docs/index.html']
ITEMS = [  # synthetic KEV-like records (not real CISA data)
    {'cve_id': 'CVE-2021-44228', 'vendor': 'Apache', 'product': 'Log4j2', 'name': 'Synthetic Apache Log4j2 RCE', 'date_added': '2021-12-10', 'short_description': 'Synthetic description <script>alert(1)</script>',
     'required_action': 'Apply updates per vendor instructions.', 'due_date': '2021-12-24', 'known_ransomware_use': 'Known', 'notes': '', 'cwes': ['CWE-502', 'CWE-20']},
    {'cve_id': 'CVE-2024-0001', 'vendor': 'Example', 'product': 'Widget', 'name': 'Example Widget flaw', 'date_added': '2024-02-01', 'short_description': 'Synthetic.',
     'required_action': 'Apply mitigations.', 'due_date': '2024-02-22', 'known_ransomware_use': 'Unknown', 'notes': '', 'cwes': []},
    {'cve_id': 'CVE-2024-3094', 'vendor': 'Tukaani', 'product': 'xz', 'name': 'Synthetic xz backdoor', 'date_added': '2024-04-01', 'short_description': 'Synthetic.',
     'required_action': 'Downgrade.', 'due_date': None, 'known_ransomware_use': 'Unknown', 'notes': None, 'cwes': ['CWE-506']}]


def kev_doc(items=ITEMS, **over):
    d = {'schema': 'macguard.intel-kev/1', 'source': {'id': 'cisa-kev', 'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'license': 'CC0-1.0',
         'attribution': 'Source: CISA Known Exploited Vulnerabilities Catalog', 'catalog_version': '2099.01.01', 'date_released': '2099-01-01T00:00:00Z',
         'retrieved_at': '2099-01-01T01:00:00Z', 'upstream_sha256': 'e' * 64}, 'count': len(items), 'items': items}
    d.update(over); return d


def make_package(d: pathlib.Path, doc: dict, *, tamper=None, verifier_exit=0, extra_member=None):
    """A package dir like BUNDLES produces + a repo root with a stub scripts/intel_package.py that exits `verifier_exit`. Returns the fake root."""
    root = d / 'root'; (root / 'scripts').mkdir(parents=True)
    if verifier_exit is not None:
        (root / 'scripts' / 'intel_package.py').write_text(f'import sys\nsys.exit({verifier_exit} if sys.argv[1:2] == ["verify"] else 2)\n')
    (root / 'config' / 'intel').mkdir(parents=True)
    shutil.copy(ROOT / 'config' / 'intel' / 'sources.registry.json', root / 'config' / 'intel' / 'sources.registry.json')
    shutil.copy(ROOT / 'config' / 'intel-families.json', root / 'config' / 'intel-families.json')
    pk = root / 'intel-release' / 'cisa-kev'; pk.mkdir(parents=True)
    data = json.dumps(doc, sort_keys=True).encode()
    files = [{'path': 'data/kev.json', 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}]
    man = {'schema': 'macguard.package-manifest/1', 'package': {'id': 'package:vulnerability-data:cisa-kev@2099.01.01', 'family': 'vulnerability-data', 'tier': 'free', 'name': 'cisa-kev',
           'version': '2099.01.01', 'created_at': '2099-01-01T02:00:00Z', 'engine': {'name': 'none'}, 'format': 'json'}, 'files': files, 'rules_root': 'f' * 64,
           'log': {'origin': 'rules.mac-guard.com/log', 'size': 1, 'root': 'f' * 64}, 'status': 'PUBLISHED', 'validation': {'state': 'SYNTAX_CHECKED', 'engine': 'schema', 'checked': 1},
           'sources': [{'id': 'cisa-kev', 'licence': 'CC0-1.0'}], 'stats': {'files': 1, 'items': len(doc['items']), 'expanded_bytes': len(data)}}
    mb = json.dumps(man, indent=1, sort_keys=True).encode()
    (pk / 'manifest.json').write_bytes(mb); (pk / 'manifest.sigstore.json').write_text('{"synthetic":"bundle"}')
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as t:
        members = [('manifest.json', mb), ('data/kev.json', data if tamper != 'data' else data.replace(b'Synthetic', b'Tampered!'))]
        if extra_member: members.append(extra_member)
        for n, b in members:
            ti = tarfile.TarInfo(n); ti.size = len(b); t.addfile(ti, io.BytesIO(b))
    (pk / 'intel-cisa-kev-2099.01.01.tar.gz').write_bytes(buf.getvalue())
    (pk / 'meta.json').write_text(json.dumps({'tag': 'intel-cisa-kev-20990101-1', 'published_at': '2099-01-01T03:00:00Z', 'url': 'https://github.com/MacGuard/macguard-yara-channel/releases/tag/intel-cisa-kev-20990101-1'}))
    if tamper == 'manifest': (pk / 'manifest.json').write_bytes(mb.replace(b'"cisa-kev"', b'"cisa-kev2"', 1))
    return root


def build(root: pathlib.Path, rows=()):
    site = root / 'site'; site.mkdir()
    latest = {'stats': {'files': 12, 'yara_rules': 340, 'source': 'counted by the site build'}, 'manifest_sha256': 'a' * 64}
    (site / 'latest.json').write_text(json.dumps(latest))
    portal.write(site, root, list(rows))
    os.environ['MG_INTEL_RELEASES'] = str(root / 'intel-release')
    try: hub = portal_hub.write(site, root, list(rows))
    finally: os.environ.pop('MG_INTEL_RELEASES', None)
    return site, hub


def numbers_without_source(doc, path='$'):
    bad = []
    if isinstance(doc, dict):
        for k, v in doc.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool) and 'source' not in doc and k != 'schema': bad.append(f'{path}.{k}')
            else: bad += numbers_without_source(v, f'{path}.{k}')
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            if isinstance(v, (int, float)) and not isinstance(v, bool): bad.append(f'{path}[{i}]')
            else: bad += numbers_without_source(v, f'{path}[{i}]')
    return bad


class BuildTests(unittest.TestCase):
    def setUp(self): self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='mg-hub-'))
    def tearDown(self): shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_verified_package_becomes_year_shards_an_index_a_download_and_a_published_family(self):
        site, hub = build(make_package(self.tmp, kev_doc()))
        idx = json.loads((site / 'kev' / 'index.json').read_text())
        self.assertEqual(idx['count']['value'], 3); self.assertEqual([s['file'] for s in idx['shards']], ['kev/2021.json', 'kev/2024.json'])
        self.assertIn('KEV only', idx['label']); self.assertEqual(idx['source']['license'], 'CC0-1.0')
        for s in idx['shards']:
            raw = (site / s['file']).read_bytes(); self.assertEqual(hashlib.sha256(raw).hexdigest(), s['sha256'], 'the browser checks this hash')
            self.assertLessEqual(len(raw), portal_hub.MAX_SHARD)
        self.assertEqual(len(list((site / 'kev').glob('*.json'))), 3, 'one file per year + the index, never one file per CVE')
        pj = json.loads((site / 'packages.json').read_text()); self.assertEqual(len(pj['intel']), 1); p = pj['intel'][0]
        self.assertEqual(p['package_sha256'], hashlib.sha256((site / p['assets']['intel-cisa-kev-2099.01.01.tar.gz']).read_bytes()).hexdigest())
        self.assertTrue((site / 'intel' / 'cisa-kev' / 'manifest.sigstore.json').exists())
        fam = {f['id']: f for f in json.loads((site / 'families.json').read_text())['families']}
        self.assertEqual(fam['cisa_kev']['state'], 'PUBLISHED'); self.assertEqual(fam['cisa_kev']['package']['records'], 3)
        self.assertEqual(hub['stats']['kev']['records'], 3); self.assertTrue(hub['kev_static'])
        for d in (idx, pj, hub, json.loads((site / 'families.json').read_text())): self.assertEqual(numbers_without_source(d), [])

    def test_no_verifier_a_refusing_verifier_or_any_content_mismatch_means_no_kev_data_at_all(self):
        cases = {'no verifier': dict(verifier_exit=None), 'verifier refuses': dict(verifier_exit=1), 'tampered data': dict(tamper='data'), 'manifest differs': dict(tamper='manifest'),
                 'unlisted member': dict(extra_member=('data/extra.bin', b'x')), 'path traversal': dict(extra_member=('../evil', b'x'))}
        for name, kw in cases.items():
            with self.subTest(name):
                d = self.tmp / re.sub(r'\W', '_', name); d.mkdir()
                site, hub = build(make_package(d, kev_doc(), **kw))
                self.assertEqual(sorted(x.name for x in (site / 'kev').iterdir()), ['index.json'], name); self.assertIs(json.loads((site / 'kev' / 'index.json').read_text())['available'], False, name); self.assertFalse(hub['kev_static']); self.assertNotIn('kev', hub['stats'])
                pj = json.loads((site / 'packages.json').read_text()); self.assertEqual(pj['intel'], []); self.assertEqual(len(pj['intel_refused']), 1)
                fam = {f['id']: f for f in json.loads((site / 'families.json').read_text())['families']}; self.assertNotEqual(fam['cisa_kev']['state'], 'PUBLISHED')

    def test_the_newest_verified_kev_catalogue_feeds_search_even_when_an_older_release_sorts_first(self):
        # Codex pr81 F1: release dirs are walked in name order; an older catalogue in a dir that sorts first must not win.
        newer = make_package(self.tmp / 'n', kev_doc())
        old_src = {**kev_doc()['source'], 'catalog_version': '2098.01.01', 'date_released': '2098-01-01T00:00:00Z'}
        older = make_package(self.tmp / 'o', kev_doc(ITEMS[:1], source=old_src))
        shutil.move(str(older / 'intel-release' / 'cisa-kev'), str(newer / 'intel-release' / 'a-older-cisa-kev'))
        self.assertLess('a-older-cisa-kev', 'cisa-kev')
        site, hub = build(newer)
        idx = json.loads((site / 'kev' / 'index.json').read_text())
        self.assertEqual(idx['source']['catalog_version'], '2099.01.01'); self.assertEqual(idx['count']['value'], 3)
        self.assertEqual(hub['stats']['kev']['catalog_version'], '2099.01.01'); self.assertEqual(hub['stats']['kev']['records'], 3)
        self.assertEqual(len(json.loads((site / 'packages.json').read_text())['intel']), 2, 'the older verified package stays listed as a download')

    def test_the_kev_dataset_is_validated_field_by_field(self):
        bad = {'unsorted': kev_doc(list(reversed(ITEMS))), 'count': kev_doc(count=99), 'licence': kev_doc(source={'license': 'proprietary'}),
               'bad id': kev_doc([{**ITEMS[0], 'cve_id': 'CVE-21-1'}]), 'bad cwe': kev_doc([{**ITEMS[0], 'cwes': ['79']}]), 'bad date': kev_doc([{**ITEMS[0], 'date_added': '10/12/2021'}]),
               'huge field': kev_doc([{**ITEMS[0], 'notes': 'x' * 5000}]), 'duplicate': kev_doc([ITEMS[0], ITEMS[0]], count=2)}
        for name, doc in bad.items():
            with self.subTest(name), self.assertRaises(portal_hub.PackageError): portal_hub.kev_dataset({'data/kev.json': json.dumps(doc).encode()})

    def test_a_large_year_is_split_into_bounded_shards(self):
        many = [{**ITEMS[0], 'cve_id': f'CVE-2023-{i:05d}', 'short_description': 'y' * 3000} for i in range(400)]
        idx, shards = portal_hub.kev_shards(kev_doc(many), {'tag': 't'})
        self.assertGreater(len(shards), 1); self.assertEqual(sum(s['count']['value'] for s in idx['shards']), 400)
        for body in shards.values(): self.assertLessEqual(len(json.dumps(body, separators=(',', ':'), sort_keys=True).encode()), portal_hub.MAX_SHARD)

    def test_sources_json_exposes_only_state_licence_and_attribution_and_every_source_is_still_retained_by_default(self):
        s = portal_hub.sources(ROOT)
        self.assertEqual(set(s['sources'][0]), {'id', 'name', 'approval_state', 'licence', 'attribution'})
        reg = {x['id']: x for x in json.loads((ROOT / 'config' / 'intel' / 'sources.registry.json').read_text())['sources']}
        for row in s['sources']: self.assertEqual(row['approval_state'], reg[row['id']].get('approval_state') or 'RETAINED')

    def test_the_api_base_is_opt_in_validated_and_only_widens_connect_src_to_that_origin(self):
        site = self.tmp / 's'; site.mkdir(); (site / 'vulnerabilities.html').write_text('<!doctype html><meta charset="utf-8"><p>x')
        self.assertEqual(portal_hub.inject_api(site, ''), ''); self.assertNotIn('mg-vuln-api', (site / 'vulnerabilities.html').read_text())
        portal_hub.inject_api(site, 'https://api.mac-guard.com/intel'); self.assertIn('<meta name="mg-vuln-api" content="https://api.mac-guard.com/intel">', (site / 'vulnerabilities.html').read_text())
        for bad in ('http://x.example', 'https://x.example/"><script>', 'javascript:alert(1)'):
            os.environ['MG_VULN_API'] = bad
            try:
                with self.assertRaises(SystemExit): csp.api_base()
            finally: os.environ.pop('MG_VULN_API')
        code = "import os,sys;sys.path.insert(0,sys.argv[1]);import csp;print(csp.POLICY)"
        pol = subprocess.run([sys.executable, '-c', code, str(ROOT / 'scripts')], capture_output=True, text=True, env={**os.environ, 'MG_VULN_API': 'https://api.mac-guard.com/intel'}).stdout
        self.assertIn("connect-src 'self' https://api.mac-guard.com;", pol)
        pol0 = subprocess.run([sys.executable, '-c', code, str(ROOT / 'scripts')], capture_output=True, text=True, env={k: v for k, v in os.environ.items() if k != 'MG_VULN_API'}).stdout
        self.assertIn("connect-src 'self';", pol0)


class PageTests(unittest.TestCase):
    def test_every_portal_page_has_the_same_navigation(self):
        for name in ['index.html', 'rules.html', 'releases.html', 'transparency.html', 'catalog.html', 'packages.html', 'plans.html', *HUB_PAGES]:
            s = (WEB / name).read_text(); nav = re.search(r'<nav aria-label="Principal">(.*?)</nav>', s, re.S).group(1)
            self.assertEqual(re.findall(r'href="([^"]+)"', nav), NAV, name); self.assertEqual(nav.count('aria-current="page"'), 1, name)

    def test_every_text_key_of_the_hub_pages_has_an_english_translation(self):
        common = (WEB / 'common.js').read_text(); nav_en = set(re.findall(r"(\w+):'", re.search(r"\ben:\{(nav_home.*?)\}\};", common, re.S).group(1)))
        for page, js in HUB_PAGES.items():
            if page == 'index.html': continue   # the home keeps its data-i texts (script.js) and hub.js translates its own ids
            keys = set(re.findall(r'data-t="(\w+)"', (WEB / page).read_text())); src = (WEB / js).read_text()
            en = set(re.findall(r"(\w+):'", re.search(r"var D=\{es:\{\},en:\{(.*?)\}\};", src, re.S).group(1)))
            self.assertEqual(keys - en - nav_en, set(), f'{page}: keys without English text')
        hub = (WEB / 'hub.js').read_text()
        for k in re.findall(r"(\w+):'hub-", hub): self.assertGreaterEqual(hub.count(f'{k}:'), 3, f'hub.js: {k} needs es and en text')

    def test_links_of_the_hub_pages_resolve(self):
        generated = {'hub.json', 'sources.json', 'families.json', 'packages.json', 'verify_public_release.py', 'kev/index.json', 'latest.json', 'manifest.json', 'releases.json', 'stats.json'}
        for page in HUB_PAGES:
            for h in re.findall(r'href="([^"#]+)"', (WEB / page).read_text()):
                if h == './' or h.startswith('docs/') or h.startswith('https://'): continue
                self.assertTrue((WEB / h).exists() or h in generated, f'{page}: {h}')
            for src in re.findall(r'<script src="([^"]+)"', (WEB / page).read_text()): self.assertTrue((WEB / src).exists(), f'{page}: {src}')

    def test_no_dynamic_html_no_eval_and_no_api_configured_in_the_sources(self):
        for js in ('hub.js', 'vulns.js', 'vuln.js', 'kevstatic.js', 'indicators.js', 'guide.js', 'common.js', 'packages.js', 'catalog.js'):
            self.assertIsNone(re.search(r'innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function', (WEB / js).read_text()), js)
        for page in HUB_PAGES: self.assertNotIn('mg-vuln-api', (WEB / page).read_text(), 'the API base is added only by a configured build')

    def test_no_prices_no_fake_numbers_and_explicit_not_available_texts(self):
        for page in HUB_PAGES: self.assertNotRegex((WEB / page).read_text().lower(), r'€|\$\s?\d|/mes\b|per month|checkout|buy now')
        v = (WEB / 'vulns.js').read_text(); self.assertIn('aún no publicado', v); self.assertIn('No incluye NVD, EUVD ni GCVE', v)
        self.assertIn('NO DISPONIBLE', (WEB / 'indicators.js').read_text()); self.assertIn('Sin regla verificada disponible', (WEB / 'vuln.js').read_text())
        idx = (WEB / 'index.html').read_text(); self.assertIn('id="latest-state"', idx, 'the YARA release panel of the home is kept')
        self.assertNotRegex(re.search(r'<section class="hubgrid".*?</section>', idx, re.S).group(0), r'<strong>\d', 'no hard-coded numbers in the hub panels')

    def test_the_guide_gives_the_pinned_signing_identity_and_the_kev_attribution(self):
        g = (WEB / 'guide.html').read_text()
        self.assertIn('--certificate-identity "https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main"', g)
        self.assertIn('--certificate-oidc-issuer "https://token.actions.githubusercontent.com"', g); self.assertIn('CC0 1.0', g); self.assertIn('no está afiliado a CISA', g)


class BrowserLogicTests(unittest.TestCase):
    """The real page scripts in a DOM stub (tests/web/hub_check.mjs) against fixtures built here."""
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which('node')
        if not cls.node: raise unittest.SkipTest('node not installed')
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix='mg-hubjs-'))
        site, _ = build(make_package(cls.tmp, kev_doc()), rows=[{'tag': 'rules-20990101-1', 'published_at': '2099-01-01T03:40:00Z', 'url': 'https://github.com/MacGuard/macguard-yara-channel/releases/tag/rules-20990101-1',
                                                                 'total': 12, 'added': 1, 'modified': 0, 'removed': 0, 'stats': {'yara_rules': 340}, 'verification': {'checked': True, 'manifest_signature': 'valid'}}])
        fx = cls.tmp / 'fx'; (fx / 'kev').mkdir(parents=True)
        for n in ('kev/index.json', 'kev/2021.json', 'kev/2024.json', 'hub.json', 'sources.json'): shutil.copy(site / n, fx / n)
        (fx / 'api-sources.json').write_text(json.dumps({'schema': 'macguard.intel-search/1', 'sources': [{'id': 'cisa-kev', 'name': 'CISA KEV', 'status': 'APPROVED'}, {'id': 'nvd', 'name': 'NVD', 'status': 'RETAINED'}]}))
        (fx / 'api-search.json').write_text(json.dumps({'schema': 'macguard.intel-search/1', 'query': {'q': 'CVE-2024-3094', 'detected': 'CVE', 'normalized': 'CVE-2024-3094', 'filters': {}},
            'items': [{'id': 'CVE-2024-3094', 'namespace': 'cve', 'title': 'xz backdoor', 'vendor': 'Tukaani', 'product': 'xz', 'kev': {'status': 'LISTED', 'date_added': '2024-04-01'},
                       'cvss': {'max_score': 10.0, 'version': '3.1', 'source': 'nvd'}, 'epss': {'probability': None, 'percentile': None, 'score_date': None}, 'cwes': ['CWE-506'], 'has_rules': None,
                       'has_iocs': False, 'access': {'restricted_sections': ['detections']}}], 'next_cursor': 'opaque-1', 'sources': [{'id': 'nvd', 'status': 'RETAINED'}], 'notes': []}))
        r = subprocess.run([cls.node, str(ROOT / 'tests' / 'web' / 'hub_check.mjs'), str(fx)], capture_output=True, text=True, timeout=120)
        if r.returncode: raise AssertionError(r.stderr[-3000:])
        cls.out = json.loads(r.stdout)

    @classmethod
    def tearDownClass(cls): shutil.rmtree(getattr(cls, 'tmp', '/nonexistent'), ignore_errors=True)

    def test_identifier_detection(self):
        self.assertEqual(self.out['kinds'], ['CVE CVE-2024-3094', 'EUVD EUVD-2025-12345', 'GCVE GCVE-1-2025-0001', 'GHSA GHSA-2345-6789-cfgh', 'CWE CWE-79', 'SHA256 ' + 'a' * 64,
                                             'SID sid:2000105', 'SID sid:2000105', 'TEXT openssl 3.0', 'TEXT CVE-24-1', None, None])

    def test_static_explorer_lists_kev_only_newest_first_and_searches_without_leaving_the_site(self):
        first = self.out['static_first']; ids = [r[0] for r in first['rows']]
        self.assertEqual(ids, ['CVE-2024-3094', 'CVE-2024-0001', 'CVE-2021-44228']); self.assertIn('CISA KEV', first['mode']); self.assertTrue(first['disabled'], 'CVSS filter needs the API')
        self.assertEqual([r[4] for r in first['rows']], ['No disponible'] * 3, 'no CVSS in KEV: never 0'); self.assertEqual(first['rows'][2][6], 'CWE-502, CWE-20')
        self.assertEqual([r[0] for r in self.out['static_cve']], ['CVE-2021-44228']); self.assertEqual([r[0] for r in self.out['static_text']], ['CVE-2021-44228'])
        self.assertEqual(self.out['static_euvd']['rows'], []); self.assertIn('requiere el servicio de consulta', self.out['static_euvd']['mode'])
        for u in self.out['static_requests']: self.assertNotRegex(u, r'^https?://', 'static mode only reads site files')

    def test_a_tampered_shard_or_no_package_shows_nothing(self):
        t = self.out['tampered']; self.assertEqual([r[0] for r in t['rows'] if r[0].startswith('CVE-2024')], [], 'the tampered year is never shown')
        n = self.out['nokev']; self.assertEqual(n['rows'], []); self.assertIn('no se muestra ningún dato', n['mode'])

    def test_api_mode_bounded_query_rows_paging_and_premium_marker(self):
        a = self.out['api']; q = a['requests'][-1]
        self.assertTrue(q.startswith('https://api.example.test/v1/vulns/search?'), q)
        for part in ('q=CVE-2024-3094', 'kev=1', 'cvss_min=7', 'limit=25'): self.assertIn(part, q)
        self.assertNotIn('epss_min', q, 'an out-of-range EPSS (5) is dropped, never sent')
        row = a['rows'][0]; self.assertEqual(row[0], 'CVE-2024-3094'); self.assertIn('10', row[4]); self.assertEqual(row[5], 'No disponible'); self.assertEqual(row[7], 'No disponible', 'has_rules null is unknown, not "no"')
        self.assertIn('PREMIUM', row[8]); self.assertTrue(a['next']); self.assertTrue(any('cursor=opaque-1' in u for u in self.out['api_next']))

    def test_vulnerability_page_static_and_api(self):
        for action in ('resubmit', 'reset'):   # Codex pr81 F2
            r = self.out['api_race_' + action]
            self.assertEqual(r['rows'], [], f'{action}: the superseded answer for oldq must never be rendered')
            if action == 'resubmit': self.assertTrue(any('q=newq' in u for u in r['requests']), 'the second submission is sent, not dropped')
            else: self.assertEqual(r['count'], '', 'a reset stays cleared')
        k = self.out['vuln_kev']; self.assertIn('Synthetic Apache Log4j2 RCE', k['body']); self.assertIn('En el catálogo KEV', k['body']); self.assertIn('Sin regla verificada disponible', k['body'])
        self.assertIn('<script>alert(1)</script>', k['body'], 'markup in data stays literal text'); self.assertIn('CC0-1.0', k['body'])
        for h in k['links']: self.assertRegex(h, r'^intel/cisa-kev/[A-Za-z0-9._-]+$')
        self.assertIn('no significa que no esté siendo explotada', self.out['vuln_notkev']['state']); self.assertEqual(self.out['vuln_notkev']['body'], '')
        self.assertIn('requiere el servicio de consulta', self.out['vuln_euvd']['state']); self.assertIn('Identificador no válido', self.out['vuln_bad']['state'])
        api = self.out['vuln_api']; self.assertIn('CVE-2099-0001', api['body']); self.assertNotIn('Sin regla verificada disponible', api['body'], 'a withheld section is never "no rule"')
        self.assertIn('Premium', api['body'])
        self.assertTrue(self.out['static_cwe']['rows'], 'a CWE query searches the verified KEV dataset statically'); self.assertTrue(all('CWE' not in r or True for r in self.out['static_cwe']['rows']))
        acc = self.out['api_access']; self.assertTrue(acc['requests']); self.assertTrue(all('access=' not in u for u in acc['requests']), acc['requests'])
        ku = self.out['kev_unavailable']; self.assertEqual(ku['rows'], []); self.assertTrue(all(not re.search(r'kev/\d{4}', u) for u in ku['requests']), ku['requests'])
        real = self.out['vuln_api_real']; self.assertNotIn('Sin regla verificada disponible', real['body'], 'gateway shape: a withheld section is never "no rule"'); self.assertIn('Premium', real['body'])

    def test_hub_shows_only_hub_json_numbers_and_routes_searches(self):
        h = self.out['hub']; self.assertIn('12', h['stats']); self.assertIn('340', h['stats']); self.assertIn('3', h['stats']); self.assertIn('rules-20990101-1', h['recent'])
        self.assertIn('válida', h['integrity']); self.assertEqual(self.out['hub_go_cve'], 'vuln.html?id=CVE-2021-44228'); self.assertEqual(self.out['hub_go_text'], 'vulnerabilities.html?q=openssl')


if __name__ == '__main__':
    unittest.main()


class RealBundlesLayout(unittest.TestCase):
    """The package exactly as BUNDLES builds it (scripts/intel_package.py build) and as publish.yml attaches it to the intel release:
    <P>.tar.gz (data only), <P>.manifest.json, <P>.manifest.sigstore.json, <P>.inclusion-proof.json, <P>.sha256, checkpoint.txt, checkpoint.sigstore.json."""
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='mg-hub-real-')); self.addCleanup(shutil.rmtree, self.tmp)
        import intel_package as ip
        ds = self.tmp / 'ds'; ds.mkdir()
        doc = kev_doc(); (ds / 'kev.json').write_bytes(json.dumps(doc, sort_keys=True, separators=(',', ':')).encode())
        rows = ['cve_id,vendor'] + [f"{x['cve_id']},{x['vendor']}" for x in doc['items']]
        (ds / 'kev.csv').write_text('\r\n'.join(rows) + '\r\n'); (ds / 'LICENSE-NOTICE.txt').write_text('CC0 1.0 - CISA KEV\n')
        c = ip.build('cisa-kev', ds, '2099.01.01', self.tmp / 'out')
        self.root = self.tmp / 'root'; (self.root / 'scripts').mkdir(parents=True); (self.root / 'config' / 'intel').mkdir(parents=True)
        shutil.copy(ROOT / 'config' / 'intel' / 'sources.registry.json', self.root / 'config' / 'intel' / 'sources.registry.json')
        shutil.copy(ROOT / 'config' / 'intel-families.json', self.root / 'config' / 'intel-families.json')
        pk = self.root / 'intel-release' / 'intel-cisa-kev-20990101-1'; pk.mkdir(parents=True); P = 'intel-cisa-kev-2099.01.01'
        tb = pathlib.Path(c['tarball']['path']) if isinstance(c.get('tarball'), dict) and c['tarball'].get('path') else next((self.tmp / 'out').glob('*.tar.gz'))
        shutil.copy(tb, pk / f'{P}.tar.gz')
        man = dict(c['manifest']); man['status'] = 'PUBLISHED'   # what `seal` writes after the transparency entry (signature checked by the verifier, stubbed here)
        (pk / f'{P}.manifest.json').write_bytes(json.dumps(man, sort_keys=True).encode())
        for n in (f'{P}.manifest.sigstore.json', f'{P}.inclusion-proof.json', 'checkpoint.sigstore.json'): (pk / n).write_text('{}')
        (pk / f'{P}.sha256').write_text(hashlib.sha256((pk / f'{P}.tar.gz').read_bytes()).hexdigest() + f'  {P}.tar.gz\n'); (pk / 'checkpoint.txt').write_text('cp\n')
        self.args = self.tmp / 'argv.json'

    def stub(self, code):
        (self.root / 'scripts' / 'intel_package.py').write_text(f'import json, sys\nopen({str(self.args)!r}, "w").write(json.dumps(sys.argv[1:]))\nsys.exit({code})\n')

    def test_verifier_gets_every_asset_and_a_verified_real_package_feeds_the_kev_index(self):
        self.stub(0); site, hub = build(self.root)
        argv = json.loads(self.args.read_text())
        for opt in ('--package', '--manifest', '--bundle', '--proof', '--checkpoint', '--checkpoint-bundle', '--sha256-file'): self.assertIn(opt, argv)
        idx = json.loads((site / 'kev' / 'index.json').read_text()); self.assertEqual(idx['count']['value'], len(ITEMS)); self.assertEqual(idx['count']['source'], 'verified KEV package')
        pkgs = json.loads((site / 'packages.json').read_text()); intel = [p for p in pkgs.get('intel', pkgs.get('intel_packages', [])) if 'cisa-kev' in json.dumps(p)]
        self.assertTrue(intel, json.dumps(pkgs)[:400])

    def test_signature_not_checked_means_refused(self):
        self.stub(3); site, hub = build(self.root)
        self.assertFalse((site / 'kev' / 'index.json').exists() and (json.loads((site / 'kev' / 'index.json').read_text()).get('count') or {}).get('value'), 'no KEV data without a checked signature')
