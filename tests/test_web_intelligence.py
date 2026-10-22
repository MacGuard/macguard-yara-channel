"""Checks of the Security Intelligence pages (web/intelligence/) and their data (web/api/v1/): the data equals what the generator produces from the
repository, no old public URL was lost, the pages obey the CSP, badges come from data, ES/EN are in parity, and no text claims more than the data supports.
No network. The optional browser test needs Chrome and is skipped (reported as skipped) without it."""
import copy, json, os, pathlib, re, shutil, signal, socket, subprocess, sys, tempfile, time, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / 'scripts'))
import csp, gen_intel_pages as pages, gen_intel_web as gen
from intel import status as chstatus

WEB = ROOT / 'web'; INTEL = WEB / 'intelligence'; API = WEB / 'api' / 'v1'
PAGE_FILES = sorted(INTEL.glob('*.html'))
STATUSES = {'operational', 'experimental', 'planned'}
ALL_JS = [INTEL / 'intel.js', INTEL / 'intel-i18n.js']

# every public path listed in docs/intelligence/WEB-PLAN.md section 1.1 that lives in web/ (the rest is produced by scripts/build_site.py, checked below)
OLD_WEB_FILES = ['index.html', 'rules.html', 'releases.html', 'transparency.html', 'docs.html', '404.html', 'robots.txt', 'style.css', 'common.js', 'img/yara-rules.png',
                 'vendor/mermaid-12.2.0.min.js', 'docs-redirect.js', 'docs.js', 'docs.css', 'channel.js', 'script.js', 'rules.js', 'releases.js', 'transparency.js']
# paths produced by the site build, not by web/: the build must still name them
BUILD_PRODUCED = ['latest.json', 'manifest.json', 'manifest.sigstore.json', 'inclusion-proof.json', 'rules-release.tar.gz', 'catalog.json', 'releases.json', 'stats.json',
                  'consistency.json', 'rules-list.html', 'verify_public_release.py', 'logs']
DOC_SLUGS = ['overview', 'architecture', 'sources', 'static-validation', 'dynamic-validation', 'quarantine', 'admin-panel', 'decision-gate', 'merkle', 'transparency-log', 'sigstore',
             'release', 'web-distribution', 'operations', 'client-update', 'client-failures', 'verification', 'threat-model', 'limits', 'glossary']
# links every old page had before the Security Intelligence section was added: all must still be there
OLD_LINKS = {
 'index': ['channel.js', 'common.js', 'docs/index.html', 'latest.json', 'manifest.json', 'releases.html', 'rules.html', 'script.js', 'stats.json', 'style.css', 'transparency.html'],
 'rules': ['./', 'catalog.json', 'common.js', 'docs/en/verification.html', 'docs/es/verification.html', 'docs/index.html', 'inclusion-proof.json', 'latest.json', 'logs/checkpoint.sigstore.json',
           'logs/checkpoint.txt', 'manifest.json', 'manifest.sigstore.json', 'releases.html', 'rules-list.html', 'rules-release.tar.gz', 'rules.html', 'rules.js', 'style.css', 'transparency.html', 'verify_public_release.py'],
 'releases': ['./', 'common.js', 'docs/index.html', 'releases.html', 'releases.js', 'releases.json', 'rules.html', 'style.css', 'transparency.html'],
 'transparency': ['./', 'common.js', 'docs/en/verification.html', 'docs/es/verification.html', 'docs/index.html', 'inclusion-proof.json', 'logs/LOG.md', 'logs/checkpoint.sigstore.json', 'logs/checkpoint.txt',
                  'logs/log.jsonl', 'manifest.json', 'releases.html', 'rules.html', 'style.css', 'transparency.html', 'transparency.js', 'verify_public_release.py', 'verify_public_release.py.sha256']}

def jload(p): return json.loads(pathlib.Path(p).read_text(encoding='utf-8'))
def i18n(): return json.loads((INTEL / 'intel-i18n.js').read_text(encoding='utf-8').split('=', 1)[1].strip().rstrip(';'))
def hrefs(s): return set(re.findall(r'(?:href|src)="([^"#][^"]*)"', s))
def all_strings(o):
    if isinstance(o, str): yield o
    elif isinstance(o, dict):
        for v in o.values(): yield from all_strings(v)
    elif isinstance(o, list):
        for v in o: yield from all_strings(v)


class DataIsFromTheRepository(unittest.TestCase):
    def test_committed_data_equals_regenerated_data(self):
        at = jload(API / 'index.json')['generated_at']
        files = gen.build(at)
        for p, d in files.items():
            self.assertTrue((API / p).exists(), p); self.assertEqual((API / p).read_text(encoding='utf-8'), gen.serialise(d), f'{p} is stale: run scripts/gen_intel_web.py')
        extra = {p.relative_to(API).as_posix() for p in API.rglob('*.json')} - set(files)
        self.assertEqual(extra, set(), 'data files nobody generates')

    def test_committed_pages_equal_regenerated_pages(self):
        for n, s in pages.outputs().items(): self.assertEqual((INTEL / n).read_text(encoding='utf-8'), s, f'{n} is stale: run scripts/gen_intel_pages.py')

    def test_every_file_declares_when_where_from_and_what_is_real(self):
        for p in API.rglob('*.json'):
            d = jload(p)
            for k in ('schema', 'generated_at', 'generated_by', 'data_origin', 'what_is_real'): self.assertTrue(d.get(k), f'{p.name}: {k}')
            self.assertRegex(d['generated_at'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')

    def test_numbers_trace_to_the_evidence_files(self):
        ev = ROOT / 'docs/intelligence/live-evidence/2026-10-22'
        for cid, d in (('vulns-1', 'vulns-1'), ('ioc-1', 'ioc-1')):
            card = jload(API / 'cards' / f'{cid}.json'); man = jload(ev / d / 'manifest.json'); rep = jload(ev / d / 'build-report.json')
            self.assertEqual(card['build']['report'], rep); self.assertEqual(rep, man['stats'])
            self.assertEqual(card['approval']['blocking_reasons'], man['approval']['blocking_reasons'])
            self.assertEqual({a['path']: (a['sha256'], a['bytes']) for a in card['artifacts']}, {a['path']: (a['sha256'], a['bytes']) for a in man['artifacts']})
        kev = jload(API / 'cards/vulns-1.json')['build']['key_numbers']; self.assertEqual((kev['accepted'], kev['input_items'], kev['rejected']), (1754, 1754, 0))
        fe = jload(API / 'cards/ioc-1.json')['build']['key_numbers']; self.assertEqual((fe['input_items'], fe['published'], fe['expired']), (5, 0, 5))
        yl = jload(API / 'cards/yara-legacy.json'); log = [json.loads(l) for l in (ROOT / 'logs/log.jsonl').read_text().splitlines() if l.strip()]
        acc = [e for e in log if e['event'] == 'candidate.accepted'][-1]['details']
        self.assertEqual(yl['latest_candidate']['file_count'], acc['file_count']); self.assertIn(yl['version'], [e['message'] for e in log if e['event'] == 'release.published'][-1])

    def test_no_third_party_data_and_no_local_paths_are_published(self):
        for p in API.rglob('*.json'):
            self.assertLess(p.stat().st_size, 40_000, f'{p.name} is too big to be metadata')
            s = p.read_text(encoding='utf-8')
            for bad in ('/Users/', '/private/', '/tmp/'): self.assertNotIn(bad, s, f'{p.name} leaks a local path')
        self.assertFalse(list(WEB.rglob('known_exploited*')) + list(WEB.rglob('*ipblocklist*')) + list(WEB.rglob('kev-index*')))
        for card in ('vulns-1', 'ioc-1'):
            c = jload(API / 'cards' / f'{card}.json'); self.assertFalse(c['download']['published']); self.assertFalse(c['download']['third_party_data_hosted'])
            self.assertTrue(all(a['hosted_on_this_site'] is False for a in c['artifacts']))


class OldUrlsStillExist(unittest.TestCase):
    def test_every_old_public_file_of_web_is_still_there(self):
        for f in OLD_WEB_FILES: self.assertTrue((WEB / f).is_file(), f)

    def test_old_pages_keep_every_link_they_had(self):
        for page, links in OLD_LINKS.items():
            now = hrefs((WEB / f'{page}.html').read_text(encoding='utf-8'))
            for l in links: self.assertIn(l, now, f'{page}.html lost {l}')
        for page in ('index', 'rules', 'releases', 'transparency'): self.assertIn('intelligence/index.html', (WEB / f'{page}.html').read_text(encoding='utf-8'))

    def test_the_site_build_still_produces_the_other_public_paths(self):
        src = (ROOT / 'scripts/build_site.py').read_text(encoding='utf-8')
        for n in BUILD_PRODUCED: self.assertIn(n, src, n)
        slugs = [p['slug'] for p in jload(ROOT / 'docs-src/pages.json')]
        self.assertEqual(slugs[:len(DOC_SLUGS)], DOC_SLUGS)   # new documentation slugs may only be appended
        self.assertIn('copytree(root / \'web\', site)', src)   # web/ (including intelligence/ and api/) is copied as is

    def test_old_pages_do_not_depend_on_the_new_files(self):
        for f in OLD_WEB_FILES:
            if f.endswith(('.html', '.js')):
                self.assertNotIn('intelligence/intel', (WEB / f).read_text(encoding='utf-8'))

    def test_every_local_link_of_the_new_pages_resolves(self):
        for p in PAGE_FILES:
            for l in hrefs(p.read_text(encoding='utf-8')):
                if re.match(r'(https?:|mailto:)', l): self.fail(f'{p.name}: external link {l}')
                target = os.path.normpath(str(INTEL / l.split('?')[0].split('#')[0]))
                rel = os.path.relpath(target, WEB)
                if rel in ('.', ''): continue
                built = rel.split('/')[0] in ('docs', 'logs') or rel in BUILD_PRODUCED
                self.assertTrue(pathlib.Path(target).exists() or built, f'{p.name}: {l} does not exist and the site build does not make it')


class CspRules(unittest.TestCase):
    def test_no_inline_script_handler_or_javascript_url(self):
        for p in PAGE_FILES:
            s = p.read_text(encoding='utf-8')
            for m in re.finditer(r'<script\b([^>]*)>(.*?)</script[^>]*>', s, re.S | re.I):
                self.assertIn('src=', m.group(1), f'{p.name}: inline script'); self.assertEqual(m.group(2).strip(), '')
            self.assertIsNone(re.search(r'\son[a-z]+\s*=', re.sub(r'content="[^"]*"', '', s)), f'{p.name}: inline handler')
            self.assertIsNone(re.search(r'(href|src|action)\s*=\s*"\s*javascript:', s, re.I)); self.assertNotIn('<form', s.lower())

    def test_no_external_host_in_pages_scripts_or_styles(self):
        for p in PAGE_FILES + ALL_JS + [INTEL / 'intel.css']:
            s = p.read_text(encoding='utf-8')
            self.assertIsNone(re.search(r'(https?:)?//[a-z0-9.-]+\.[a-z]{2,}', re.sub(r'<!--.*?-->', '', s)) if p.suffix == '.html' else re.search(r'https?://', s), f'{p.name}: external host')
            self.assertNotIn('@import', s)

    def test_scripts_only_read_static_files_of_the_site(self):
        js = (INTEL / 'intel.js').read_text(encoding='utf-8')
        self.assertEqual(set(re.findall(r"MG\.get\(([^,]+),", js)), {"'../api/v1/' + p"}); self.assertNotIn('fetch(', js)
        for bad in ('eval(', 'new Function', 'innerHTML', 'outerHTML', 'document.write', 'insertAdjacentHTML', 'XMLHttpRequest', 'sendBeacon', 'WebSocket', 'sessionStorage', 'document.cookie'):
            self.assertNotIn(bad, js, bad)
        self.assertEqual(sorted(set(re.findall(r'localStorage\.(\w+)\(\'(\w+)\'', js))), [('getItem', 'theme'), ('setItem', 'theme')])   # only the theme preference (language goes through common.js)

    def test_policy_is_injected_and_precedes_the_scripts(self):
        with tempfile.TemporaryDirectory() as t:
            site = pathlib.Path(t) / 'site'; shutil.copytree(WEB, site, ignore=shutil.ignore_patterns('vendor')); csp.inject(site)
            for p in (site / 'intelligence').glob('*.html'):
                s = p.read_text(encoding='utf-8'); self.assertEqual(s.count('Content-Security-Policy'), 1); self.assertLess(s.index('Content-Security-Policy'), s.index('<script'))


class BadgesComeFromData(unittest.TestCase):
    def test_pages_hard_code_no_badge(self):
        for p in PAGE_FILES:
            s = p.read_text(encoding='utf-8')
            self.assertNotRegex(s, r'class="[^"]*badge|st-(operational|experimental|planned)', p.name)
            self.assertNotRegex(s, r'(?i)>\s*(operational|experimental|planned|operativo|planificado)\s*<', f'{p.name}: an element whose whole text is a status word')
        js = (INTEL / 'intel.js').read_text(encoding='utf-8')
        self.assertEqual(len(re.findall(r"status\s*[:=]\s*'(operational|experimental|planned)'", js)), 0)

    def test_every_status_is_one_of_three_and_equals_intel_status(self):
        table = {c['id']: c['status'] for c in chstatus.CHANNELS}
        ch = jload(API / 'channels.json')
        self.assertEqual({c['id']: c['status'] for c in ch['channels']}, table); self.assertEqual([c['id'] for c in ch['channels']], [c['id'] for c in chstatus.CHANNELS])
        self.assertEqual(ch['counts_by_status'], {s: sum(1 for v in table.values() if v == s) for s in STATUSES})
        for p in (API / 'cards').glob('*.json'):
            c = jload(p); self.assertEqual(c['status'], table[c['channel']], p.name)
        for r in jload(API / 'roadmap.json')['rows']: self.assertIn(r['status'], STATUSES)
        self.assertEqual(jload(API / 'provenance.json')['status'], 'planned')
        self.assertEqual(jload(API / 'provenance.json')['engine_code_found'], [])

    def test_operational_or_experimental_without_evidence_is_a_build_error(self):
        fake = copy.deepcopy(chstatus.CHANNELS); fake[2] = {**fake[2], 'status': 'operational', 'evidence': 'no/such/file.py'}
        old = chstatus.CHANNELS
        try:
            chstatus.CHANNELS = fake
            with self.assertRaises(SystemExit): gen.build('2026-01-01T00:00:00Z')
        finally: chstatus.CHANNELS = old

    def test_roadmap_status_follows_the_evidence(self):
        rows = {r['phase']: r for r in jload(API / 'roadmap.json')['rows']}
        self.assertEqual(rows['P2']['status'], 'planned'); self.assertEqual(rows['Cloud']['status'], 'planned')
        self.assertEqual(rows['P1']['status'], 'experimental')
        text = jload(API / 'roadmap.json')
        self.assertNotRegex(json.dumps(text), r'\d+\s?%'); self.assertEqual([t['status'] for t in text['tracks'] if t['id'] == 'linux-intelligence-guard'], ['planned'])


class SpanishAndEnglish(unittest.TestCase):
    def test_both_languages_have_the_same_keys_and_no_empty_text(self):
        d = i18n(); self.assertEqual(set(d['es']), set(d['en']))
        for l in ('es', 'en'):
            for k, v in d[l].items(): self.assertTrue(v.strip(), f'{l}.{k}')
        same = [k for k in d['es'] if d['es'][k] == d['en'][k] and len(d['es'][k]) > 25 and k != 'h_overview']
        self.assertEqual(same, [], 'long texts identical in both languages')

    def test_every_key_used_by_pages_and_script_exists(self):
        d = i18n(); keys = set(d['es'])
        for p in PAGE_FILES:
            s = p.read_text(encoding='utf-8')
            for k in re.findall(r'data-t(?:-label|-ph)?="([^"]+)"', s): self.assertIn(k, keys, f'{p.name}: {k}')
            self.assertRegex(s, r'<option value="es">.*<option value="en">'); self.assertIn('<html lang="es">', s); self.assertIn('id="theme"', s)
        js = (INTEL / 'intel.js').read_text(encoding='utf-8')
        for k in re.findall(r"\bt\('([a-z0-9_]+)'\)", js): self.assertIn(k, keys, f'intel.js: {k}')
        for s in STATUSES: self.assertIn('st_' + s, keys); self.assertIn('def_' + s, keys)
        for o in ('original', 'derived'): self.assertIn('origin_' + o, keys)
        for c in jload(API / 'provenance.json')['coverage']['counts']: self.assertIn('cov_' + c.replace('-', '_'), keys)
        for p in PAGE_FILES: self.assertIn('title_' + re.search(r'data-page="(\w+)"', p.read_text()).group(1), keys)

    def test_the_spanish_text_of_the_html_is_the_dictionary_and_the_pages_share_one_navigation(self):
        d = i18n()['es']; navs = set()
        for p in PAGE_FILES:
            s = p.read_text(encoding='utf-8')
            for k, txt in re.findall(r'data-t="([^"]+)"[^>]*>([^<]*)<', s):
                import html as H
                self.assertEqual(H.unescape(txt), d[k], f'{p.name}: {k}')
            navs.add(tuple(re.findall(r'<nav[^>]*>(.*?)</nav>', re.sub(r' aria-current="page"', '', s), re.S)))
        self.assertEqual(len(navs), 1, 'the navigation differs between pages')
        self.assertEqual(len(PAGE_FILES), 9)


class NoClaimBeyondTheData(unittest.TestCase):
    CLAIM = re.compile(r'\b(signed|firmad[oa]s?|published|publicad[oa]s?|verified|verificad[oa]s?|operational|operativ[oa]s?)\b', re.I)
    QUALIFIED = re.compile(r'\b(not|no|nunca|never|without|sin|pending|pendiente|blocked|bloquead\w+|planned|planificad\w+|only|solo|until|hasta|if|si|cuando|when|ni|none|ninguno|ninguna|nothing|nada|nor)\b', re.I)
    # unqualified claims that are definitions or are tied to data checked below
    ALLOWED = {'st_operational', 'def_operational', 'sec_c1', 'k_published_at'}   # label of a data field

    def test_text_claims_need_a_qualifier_or_a_reviewed_reason(self):
        d = i18n(); flagged = set()
        for l in ('es', 'en'):
            for k, v in d[l].items():
                if self.CLAIM.search(re.sub(r'(?i)sistema operativo', '', v)) and not self.QUALIFIED.search(v): flagged.add(k)
        self.assertEqual(flagged - self.ALLOWED, set(), 'unqualified claims: review them or qualify them')

    def test_the_allowed_claims_hold_in_the_data(self):
        yl = jload(API / 'cards/yara-legacy.json'); ch = {c['id']: c for c in jload(API / 'channels.json')['channels']}
        self.assertEqual(yl['signature']['status'], 'signed_sigstore'); self.assertTrue((ROOT / 'logs/checkpoint.sigstore.json').exists())
        self.assertEqual(yl['status'], 'operational'); self.assertEqual([c for c in ch if ch[c]['status'] == 'operational'], ['yara'])

    def test_published_signed_and_attested_only_where_the_data_says(self):
        ch = jload(API / 'channels.json')['channels']
        for c in ch: self.assertEqual(c['publication']['published'], c['status'] == 'operational', c['id'])
        for p in (API / 'cards').glob('*.json'):
            c = jload(p)
            if c['status'] != 'operational':
                self.assertEqual(c['signature']['status'], 'not_signed'); self.assertEqual(c['signature']['text'], 'not signed: no signing workflow exists')
                self.assertEqual(c['attestation']['status'], 'none'); self.assertEqual(c['attestation']['text'], 'none: not produced')
                self.assertFalse(c['download']['published']); self.assertFalse(c['approval']['publishable']); self.assertTrue(c['approval']['blocking_reasons'])
                self.assertEqual(c['approval']['state'], 'draft')
                self.assertEqual(c['attestation']['validation_gates'], [])
            else:
                self.assertTrue(c['download']['published']); self.assertEqual(c['attestation']['status'], 'none')   # no attestation exists for the legacy channel either
        for p in API.rglob('*.json'):
            for s in all_strings(jload(p)):
                if re.search(r'\b(slsa|in-toto)\b', s, re.I): self.assertRegex(s, self.QUALIFIED, f'{p.name}: attestation claim: {s[:80]}')

    def test_pages_never_say_the_new_channels_are_published(self):
        d = i18n()
        for l in ('es', 'en'):
            for k, v in d[l].items():
                if k.startswith(('sec_n', 'p_dl', 'p_downloads')) or self.QUALIFIED.search(v): continue
                self.assertNotRegex(v, r'(?i)\b(is|are|está|están) (published|signed|publicad|firmad)', f'{l}.{k}')

    def test_licence_page_is_marked_as_evidence_not_legal_advice(self):
        d = i18n(); self.assertIn('not legal advice', d['en']['p_licenses']); self.assertIn('no asesoría legal', d['es']['p_licenses'])
        self.assertIn('not legal advice', jload(API / 'licenses.json')['what_is_real'])

    def test_roadmap_and_provenance_state_what_does_not_exist(self):
        pv = jload(API / 'provenance.json'); self.assertIn('DESIGN', pv['what_is_real']); self.assertEqual(len(pv['six_facts']), 6)
        self.assertIn('no provenance engine code found', pv['status_basis'])


@unittest.skipUnless(os.path.exists('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome') or shutil.which('google-chrome') or shutil.which('chromium'), 'no Chrome: the filter test is skipped')
class FiltersInARealBrowser(unittest.TestCase):
    """Loads the Explorer in headless Chrome (one process, own server, own temp copy), drives the filters and reads the DOM."""
    def test_filters_filter(self):
        chrome = next(c for c in ('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', shutil.which('google-chrome') or '', shutil.which('chromium') or '') if c and os.path.exists(c))
        tmp = pathlib.Path(tempfile.mkdtemp(prefix='intel-filters-')); srv = None
        try:
            site = tmp / 'site'; shutil.copytree(WEB, site, ignore=shutil.ignore_patterns('vendor')); csp.inject(site)
            (site / '__t.html').write_text('<!doctype html><meta charset=utf-8><pre id=r>RUN</pre><script src="__t.js"></script>')
            (site / '__t.js').write_text(r"""
var out={};function sleep(ms){return new Promise(function(r){setTimeout(r,ms)})}
(async function(){
 var f=document.createElement('iframe');f.style.cssText='width:1280px;height:900px';f.src='intelligence/explorer.html?lang=en';document.body.appendChild(f);
 await new Promise(function(r){f.onload=r});var d=f.contentDocument,w=f.contentWindow;
 for(var i=0;i<50&&!/of/.test(d.getElementById('count').textContent);i++)await sleep(100);
 function n(){return d.querySelectorAll('#results > li').length}
 function ids(){return Array.prototype.map.call(d.querySelectorAll('#results > li h3'),function(h){return h.firstChild.textContent.trim()}).join(',')}
 function set(id,v){var e=d.getElementById(id);e.value=v;e.dispatchEvent(new w.Event(e.tagName==='INPUT'?'input':'change',{bubbles:true}))}
 out.all=n();out.allCount=d.getElementById('count').textContent;
 set('f-st','operational');out.operational=ids();out.opCount=d.getElementById('count').textContent;set('f-st','');
 set('f-st','experimental');out.experimental=ids();set('f-st','');
 set('f-src','cisa-kev');out.src=ids();set('f-src','');
 set('f-fam','sigma');out.fam=ids();set('f-fam','');
 set('f-lic','GPL-2.0');out.lic=ids();set('f-lic','');
 set('f-os','linux');out.os=ids();set('f-os','');
 set('f-os','__none');out.osnone=n();set('f-os','');
 set('f-st','planned');set('f-src','cisa-kev');out.none=n();out.noneMsg=d.getElementById('count').textContent;
 d.getElementById('f-reset').click();out.reset=n();
 set('f-q','feodo');out.q=ids();set('f-q','');
 d.getElementById('lang').value='es';d.getElementById('lang').dispatchEvent(new w.Event('change',{bubbles:true}));await sleep(200);out.es=d.getElementById('count').textContent;
 out.live=d.getElementById('count').getAttribute('aria-live');out.labels=Array.prototype.every.call(d.querySelectorAll('select,input'),function(e){return e.closest('label')||e.getAttribute('aria-label')});
 d.getElementById('lang').value='en';
 document.getElementById('r').textContent='DONE'+JSON.stringify(out)})();""")
            s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
            srv = subprocess.Popen([sys.executable, '-m', 'http.server', str(port), '--bind', '127.0.0.1', '--directory', str(site)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(1)
            p = subprocess.Popen([chrome, '--headless=new', '--disable-gpu', '--no-sandbox', '--virtual-time-budget=30000', '--dump-dom', f'http://127.0.0.1:{port}/__t.html'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True)
            try: o, _ = p.communicate(timeout=90)
            finally:
                try: os.killpg(p.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError): pass
                p.wait()
            import html as H
            m = re.search(r'<pre id="r">DONE(.*?)</pre>', o, re.S); self.assertTrue(m, o[-300:])
            r = json.loads(H.unescape(m.group(1)))
        finally:
            if srv: srv.terminate()
            shutil.rmtree(tmp, ignore_errors=True)
        ch = jload(API / 'channels.json')['channels']
        self.assertEqual(r['all'], len(ch)); self.assertEqual(r['operational'], 'yara'); self.assertEqual(r['experimental'].split(','), [c['family'] for c in ch if c['status'] == 'experimental'])
        self.assertEqual(r['src'], 'vulns'); self.assertEqual(r['fam'], 'sigma'); self.assertEqual(r['lic'].split(','), [c['family'] for c in ch if 'GPL-2.0' in c['licenses']])
        self.assertEqual(r['os'].split(','), [c['family'] for c in ch if 'linux' in c['os']]); self.assertEqual(r['osnone'], len([c for c in ch if not c['os']]))
        self.assertEqual(r['none'], 0); self.assertIn('No channel matches', r['noneMsg']); self.assertEqual(r['reset'], len(ch)); self.assertEqual(r['q'], 'ioc')
        self.assertEqual(r['es'], f'{len(ch)} de {len(ch)} canales'); self.assertEqual(r['live'], 'polite'); self.assertTrue(r['labels'])
        self.assertTrue(r['opCount'].startswith('1 of'))


if __name__ == '__main__': unittest.main()
