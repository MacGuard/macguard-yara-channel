"""Coherence between the documentation, the code and the real release. Everything the docs state as a number, a name, a command or a path is
checked against its source. Release data comes from DOCS_SITE (an assembled site) or ./site; if neither has it, from the public site (real files)."""
import base64, hashlib, html, json, os, pathlib, re, subprocess, sys, tempfile, unittest, urllib.request
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import build_docs

SRC = ROOT / 'docs-src'; LANGS = ('es', 'en')
PAGES = json.loads((SRC / 'pages.json').read_text())
DIAGRAMS = ['architecture', 'sources-sequence', 'static-decision', 'dynamic-sequence', 'dynamic-decision', 'quarantine-states', 'rules-merkle', 'log-merkle', 'checkpoint-sequence', 'checkpoint-evolution',
            'sigstore-sequence', 'release-sequence', 'client-update', 'client-signature-failure', 'client-network-failure', 'client-altered-file', 'client-rollback', 'client-atomic-install', 'verifier-flow', 'trust-boundaries']
PUBLIC = 'https://macguard.github.io/macguard-yara-channel/'

def md(lang, slug): return (SRC / lang / f'{slug}.md').read_text(encoding='utf-8')
def code_blocks(text): return re.findall(r'```[^\n]*\n(.*?)\n```', text, re.S)

def site_dir():
    for c in (os.environ.get('DOCS_SITE'), str(ROOT / 'site')):
        if c and (pathlib.Path(c) / 'manifest.json').exists() and (pathlib.Path(c) / 'latest.json').exists() and (pathlib.Path(c) / 'releases.json').exists(): return pathlib.Path(c)
    d = pathlib.Path(tempfile.mkdtemp(prefix='docs-site-'))
    for n in ('manifest.json', 'latest.json', 'releases.json'): (d / n).write_bytes(urllib.request.urlopen(PUBLIC + n, timeout=60).read())
    return d

_CACHE = {}
class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # the 40 pages are built once per test run, not once per test class
        if not _CACHE:
            site = site_dir(); out = pathlib.Path(tempfile.mkdtemp(prefix='docs-out-')); report = build_docs.build(out, site)
            _CACHE.update(site=site, out=out, report=report, manifest=json.loads((site / 'manifest.json').read_text()), latest=json.loads((site / 'latest.json').read_text()),
                          html={(l, p['slug']): (out / l / f'{p["slug"]}.html').read_text(encoding='utf-8') for l in LANGS for p in PAGES})
        for k, v in _CACHE.items(): setattr(cls, k, v)

class Structure(Base):
    def test_twenty_pages_each_language(self):
        self.assertEqual(len(PAGES), 20); self.assertEqual(len({p['slug'] for p in PAGES}), 20)
        for l in LANGS:
            self.assertEqual(sorted(f.stem for f in (SRC / l).glob('*.md')), sorted(p['slug'] for p in PAGES))
            for p in PAGES: self.assertTrue(p['title'][l].strip())
    def test_front_matter(self):
        for l in LANGS:
            for p in PAGES:
                meta, _ = build_docs.parse_front(md(l, p['slug'])); self.assertEqual(meta['title'], p['title'][l], (l, p['slug'])); self.assertGreater(len(meta.get('summary', '')), 20)
    def test_es_en_parity(self):
        for p in PAGES:
            es, en = md('es', p['slug']), md('en', p['slug'])
            self.assertEqual(len(re.findall(r'^## ', es, re.M)), len(re.findall(r'^## ', en, re.M)), f'H2 count {p["slug"]}')
            self.assertEqual(len(re.findall(r'^### ', es, re.M)), len(re.findall(r'^### ', en, re.M)), f'H3 count {p["slug"]}')
            self.assertEqual(re.findall(r'\{\{diagram:([\w-]+)\}\}', es), re.findall(r'\{\{diagram:([\w-]+)\}\}', en), f'diagrams {p["slug"]}')
            self.assertEqual(code_blocks(es), code_blocks(en), f'code blocks {p["slug"]}')
            self.assertEqual(re.findall(r'\]\((page:[\w#-]+)\)', es), re.findall(r'\]\((page:[\w#-]+)\)', en), f'page links {p["slug"]}')
            self.assertEqual(len(re.findall(r'^\|', es, re.M)), len(re.findall(r'^\|', en, re.M)), f'table rows {p["slug"]}')
            self.assertEqual(sorted(re.findall(r'\{\{([a-z_.]+)\}\}', es)), sorted(re.findall(r'\{\{([a-z_.]+)\}\}', en)), f'placeholders {p["slug"]}')
            tag = {'ACTUAL': 'CURRENT', 'PROPUESTA': 'PROPOSED', 'LÍMITE': 'LIMIT', 'NOTA': 'NOTE'}
            self.assertEqual(sorted(tag[t] for t in re.findall(r'^> \*\*([^*]+)\*\*', es, re.M)), sorted(re.findall(r'^> \*\*([^*]+)\*\*', en, re.M)), f'callouts {p["slug"]}')
    def test_build_counts(self):
        self.assertEqual(self.report['pages'], 40); self.assertEqual({l: len(set(v)) for l, v in self.report['diagrams'].items()}, {'es': 20, 'en': 20})

class Diagrams(Base):
    def test_named_diagrams_exist_and_are_used(self):
        self.assertEqual(sorted(f.stem for f in (SRC / 'diagrams').glob('*.mmd')), sorted(DIAGRAMS))
        used = {d for v in self.report['diagrams'].values() for d in v}
        self.assertEqual(used, set(DIAGRAMS))
    def test_metadata_in_both_languages(self):
        for n in DIAGRAMS:
            m = json.loads((SRC / 'diagrams' / f'{n}.json').read_text())
            for k in ('title', 'alt'):
                for l in LANGS: self.assertGreater(len(m[k][l].strip()), 10, (n, k, l))
            self.assertGreater(len(m['alt']['en']), 80)
    def test_sources_are_plain_mermaid(self):
        for n in DIAGRAMS:
            s = (SRC / 'diagrams' / f'{n}.mmd').read_text()
            for bad in ('<script', 'javascript:', 'click ', 'href', '%%{'): self.assertNotIn(bad, s, (n, bad))
            self.assertRegex(s.split('\n')[0], r'^(flowchart|sequenceDiagram|stateDiagram-v2)')
    def test_each_diagram_is_in_the_right_pages_with_accessible_name(self):
        for l in LANGS:
            for (ll, slug), h in self.html.items():
                if ll != l: continue
                for fig in re.findall(r'<figure class="diagram".*?</figure>', h, re.S):
                    self.assertIn('aria-labelledby=', fig); self.assertIn('<details class="dg-desc">', fig); self.assertIn('<details class="dg-code">', fig)

class Links(Base):
    def test_internal_links_and_anchors(self):
        for (l, slug), h in self.html.items():
            ids = set(re.findall(r'\bid="([^"]+)"', h))
            for href in re.findall(r'<a [^>]*href="([^"]+)"', h):
                href = html.unescape(href)
                if href.startswith(('http://', 'https://', 'mailto:')): continue
                if href.startswith('#'): self.assertIn(href[1:], ids, f'{l}/{slug} {href}'); continue
                target, _, frag = href.partition('#'); f = (self.out / l / target).resolve()
                if target.startswith('../../'):
                    self.assertTrue((ROOT / 'web' / target[6:]).exists() or (self.out.parent / target[6:]).exists() or target[6:] in ('index.html', 'style.css', 'docs.css', 'docs.js', 'common.js'), f'{l}/{slug} {href}'); continue
                self.assertTrue(f.exists(), f'{l}/{slug}: {href}')
                if frag: self.assertIn(frag, set(re.findall(r'\bid="([^"]+)"', f.read_text(encoding='utf-8'))), f'{l}/{slug}: {href}')
    def test_external_links_are_https_and_expected_hosts(self):
        ok = ('github.com', 'macguard.github.io', 'macguard-rules.pages.dev', 'raw.githubusercontent.com', 'token.actions.githubusercontent.com')
        for (l, slug), h in self.html.items():
            for u in re.findall(r'(?:href|src)="(https?://[^"]+)"', h): self.assertIn(u.split('/')[2], ok, f'{l}/{slug} {u}'); self.assertTrue(u.startswith('https://'), u)
    def test_ui_links_into_docs_are_relative(self):
        for (l, slug), h in self.html.items(): self.assertNotIn('javascript:', h)

class RepoReferences(Base):
    PATH_RE = re.compile(r'`((?:scripts|config|docs|admin|tests|web|DMGTrustAuditor|logs|\.github)/[^`\s]*[\w/])`')
    def test_every_referenced_repo_path_exists(self):
        missing = []
        for l in LANGS:
            for p in PAGES:
                for ref in self.PATH_RE.findall(md(l, p['slug'])):
                    if '{' in ref or '<' in ref or '*' in ref: continue
                    if not (ROOT / ref).exists(): missing.append(f'{l}/{p["slug"]}: {ref}')
        self.assertEqual(missing, [])
    def test_scripts_and_workflows_named_exist(self):
        missing = []
        for l in LANGS:
            for p in PAGES:
                t = md(l, p['slug'])
                for n in set(re.findall(r'`([\w-]+\.py)`', t)): 
                    if not list(ROOT.glob(f'**/{n}')) : missing.append(f'{l}/{p["slug"]}: {n}')
                for n in set(re.findall(r'`([\w-]+\.yml)`', t)):
                    if not (ROOT / '.github/workflows' / n).exists(): missing.append(f'{l}/{p["slug"]}: {n}')
        self.assertEqual(missing, [])
    def test_repo_paths_in_manifest_exist(self):
        paths = {f['path'] for f in self.manifest['files']}
        for l in LANGS:
            for p in PAGES:
                for ref in re.findall(r'`(rules/[^`\s]+\.(?:yar|yara))`', md(l, p['slug'])): self.assertIn(ref, paths)

class Events(Base):
    def test_documented_events_exist_in_their_source(self):
        ev = json.loads((SRC / 'events.json').read_text()); self.assertEqual(len({e['code'] for e in ev}), len(ev))
        for e in ev:
            self.assertTrue(re.search(re.escape(e['code']), (ROOT / e['source']).read_text()), f'{e["code"]} not in {e["source"]}')
            self.assertIn(e['level'], ('INFO', 'WARNING', 'ERROR')); self.assertTrue(e['es'] and e['en'])
    def test_emitted_events_are_documented(self):
        documented = {e['code'] for e in json.loads((SRC / 'events.json').read_text())}
        emitted = set(re.findall(r"event\('(?:INFO|WARNING|ERROR)', '([a-z_.]+)'", (ROOT / 'scripts/tlog.py').read_text()))
        for wf in (ROOT / '.github/workflows').glob('*.yml'): emitted |= set(re.findall(r'--code ([a-z_]+\.[a-z_.]+)', wf.read_text()))
        self.assertEqual(sorted(emitted - documented), [], 'events emitted by the code but not documented')
    def test_levels_match_the_code(self):
        for e in json.loads((SRC / 'events.json').read_text()):
            src = (ROOT / e['source']).read_text()
            m = re.search(r"event\('(INFO|WARNING|ERROR)', '%s'" % re.escape(e['code']), src) or re.search(r'--level (INFO|WARNING|ERROR) --code %s' % re.escape(e['code']), src) or re.search(r'--level (INFO|WARNING|ERROR) --code\s+%s' % re.escape(e['code']), src) or re.search(r'ev --level (INFO|WARNING|ERROR) --code %s' % re.escape(e['code']), src)
            if m: self.assertEqual(m.group(1), e['level'], e['code'])
    def test_real_log_only_uses_documented_events_or_known_legacy(self):
        documented = {e['code'] for e in json.loads((SRC / 'events.json').read_text())} | {'site.skipped'}
        seen = {json.loads(l)['event'] for l in (ROOT / 'logs/log.jsonl').read_text().split('\n') if l}
        self.assertEqual(sorted(seen - documented), [])

class Commands(Base):
    def test_cosign_commands_are_complete(self):
        user_example = ('cosign verify-blob manifest.json \\\n  --bundle manifest.sigstore.json \\\n  --certificate-identity "https://github.com/MacGuard/macguard-yara-channel/.github/workflows/publish.yml@refs/heads/main" \\\n'
                        '  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"')
        for l in LANGS:
            h = html.unescape(self.html[(l, 'verification')]); self.assertIn(user_example, h)
            self.assertIn('--certificate-github-workflow-repository "MacGuard/macguard-yara-channel"', h)
        for l in LANGS:
            for blk in code_blocks(md(l, 'verification')):
                for cmd in [c for c in blk.replace('\\\n', ' ').split('\n') if c.startswith('cosign verify-blob')]:
                    for flag in ('--bundle', '--certificate-identity', '--certificate-oidc-issuer'): self.assertIn(flag, cmd)
    def test_identity_matches_the_workflow_and_the_verifier(self):
        import verify_public_release as v
        ctx = build_docs.build_context(self.site); self.assertEqual(ctx['identity'], v.DEFAULT_IDENTITY); self.assertEqual(ctx['issuer'], v.DEFAULT_ISSUER); self.assertEqual(ctx['repo'], v.DEFAULT_REPO)
        self.assertTrue(ctx['identity'].endswith('/.github/workflows/publish.yml@refs/heads/main')); self.assertTrue((ROOT / '.github/workflows/publish.yml').exists())
        self.assertIn('id-token: write', (ROOT / '.github/workflows/publish.yml').read_text())
    def test_verifier_options_and_exit_codes_in_docs_exist(self):
        helptext = subprocess.run([sys.executable, str(ROOT / 'scripts/verify_public_release.py'), '--help'], capture_output=True, text=True).stdout
        for l in LANGS:
            t = md(l, 'verification'); sect = t.split('## G.')[1].split('## H.')[0]
            for flag in set(re.findall(r'`(--[a-z-]+)', sect)): self.assertIn(flag, helptext, flag)
            rows = dict(re.findall(r'^\| (\d) \| (.*) \|$', sect, re.M))
            self.assertEqual(sorted(rows), ['0', '1', '2', '3', '4', '5', '6'])
        import verify_public_release as v
        for l in LANGS: self.assertIn(', '.join(map(str, v.PRECEDENCE)), md(l, 'verification'))
        doc = v.__doc__; self.assertIn('Exit codes   0 all mandatory checks done and passed   1 integrity   2 signature or identity   3 Merkle', doc)
    def test_merkle_snippet_in_docs_reproduces_the_real_root(self):
        code = code_blocks(md('en', 'merkle'))[0]
        with tempfile.TemporaryDirectory() as d:
            pathlib.Path(d, 'manifest.json').write_text((self.site / 'manifest.json').read_text())
            out = subprocess.run([sys.executable, '-I', '-c', code], cwd=d, capture_output=True, text=True); self.assertEqual(out.returncode, 0, out.stderr)
            self.assertTrue(out.stdout.strip().endswith('True'), out.stdout)
    def test_cli_commands_documented(self):
        t = md('en', 'verification'); self.assertIn('python3 verify_public_release.py --latest', t); self.assertNotRegex(t, r'curl[^\n]*\|\s*(ba)?sh'); self.assertNotRegex(t, r'curl[^\n]*\|\s*python')

class RealData(Base):
    def test_release_numbers_come_from_real_files(self):
        h = html.unescape(self.html[('en', 'overview')])
        for v in (self.latest['package_sha256'], self.manifest['rules_root'], str(len(self.manifest['files']))): self.assertIn(v, h)
        self.assertIn(self.latest['manifest_sha256'], html.unescape(self.html[('es', 'verification')]))
        ctx = build_docs.build_context(self.site); self.assertEqual(ctx['release.log_size'], str(self.manifest['log']['size'])); self.assertEqual(ctx['release.rules_root'], self.manifest['rules_root'])
        self.assertTrue(ctx['release.url'].startswith('https://github.com/MacGuard/macguard-yara-channel/releases/tag/'))
    def test_manifest_example_is_real(self):
        ex = json.loads(build_docs.build_context(self.site)['manifest_example'].replace('"... %d more entries ..."' % (len(self.manifest['files']) - 1), '"x"'))
        self.assertEqual(ex['files'][0], self.manifest['files'][0]); self.assertEqual(ex['rules_root'], self.manifest['rules_root']); self.assertEqual(ex['log'], self.manifest['log'])
    def test_fields_the_docs_name_exist(self):
        for k in ('files', 'rules_root', 'log', 'sources', 'schema', 'created_at'): self.assertIn(k, self.manifest)
        for k in ('origin', 'size', 'root'): self.assertIn(k, self.manifest['log'])
        for k in ('path', 'sha256', 'bytes', 'source'): self.assertIn(k, self.manifest['files'][0])
        import tlog; self.assertEqual(tlog.Log.ORIGIN if hasattr(tlog.Log, 'ORIGIN') else 'macguard-rules-log v1', self.manifest['log']['origin'])
        for l in LANGS: self.assertIn(self.manifest['log']['origin'], md(l, 'transparency-log'))
    def test_policy_numbers_in_docs_match_config(self):
        pol = json.loads((ROOT / 'config/policy.json').read_text()); dyn = pol['dynamic']
        t = {l: md(l, 'dynamic-validation') for l in LANGS}
        for l in LANGS:
            self.assertIn(f"{dyn['runs']} ", t[l]); self.assertIn(str(dyn['timeout_seconds_per_file']) + ' s', t[l]); self.assertIn(str(dyn['absolute']['max_scan_rss_mb']) + ' MB', t[l]); self.assertIn(str(dyn['absolute']['max_compile_rss_mb']) + ' MB', t[l]); self.assertIn(str(dyn['absolute']['max_compile_wall_s']) + ' s', t[l])
            self.assertIn(f"{int(dyn['regression']['min_relative_increase'] * 100)} %", t[l]); self.assertIn(f"{dyn['regression']['metric_noise_multiplier']:g}".replace('.', ',') if l == 'es' else f"{dyn['regression']['metric_noise_multiplier']:g}", t[l])
            g = md(l, 'decision-gate'); self.assertIn(f"{int(pol['anomaly']['max_removed_fraction'] * 100)} %", g); self.assertIn(f"{int(pol['anomaly']['max_changed_fraction'] * 100)} %", g)
            s = md(l, 'static-validation')
            for m in pol['allowed_modules'] + pol['blocked_modules']: self.assertIn(f'`{m}`', s)
            self.assertIn(f"{pol['limits']['max_file_bytes'] // 1_000_000} MB", s)
        for k in ('allowed_modules', 'blocked_modules'): self.assertTrue(pol[k])
    def test_sources_match_config(self):
        cfg = json.loads((ROOT / 'config/sources.json').read_text())
        for l in LANGS:
            t = md(l, 'sources')
            for s in cfg['sources']: self.assertIn(f"`{s['repo']}`", t)
            self.assertIn('Nextron Systems', t); self.assertIn('VirusTotal', t)
            for s in cfg['sources']:
                if s['kind'] == 'engine': self.assertRegex(t, r'(?i)engine|motor')
    def test_accounting_invariant_is_stated_and_enforced(self):
        import accounting
        self.assertTrue(hasattr(accounting, 'require'))
        for l in LANGS: self.assertRegex(md(l, 'decision-gate'), r'examin\w+ = \w+ \+ ')
    def test_quarantine_states_match_the_service_schema(self):
        schema = (ROOT / 'admin/worker/schema.sql').read_text() + (ROOT / 'admin/worker/src/core.js').read_text()
        for s in ('PENDING', 'UNDER_REVIEW', 'APPROVED_PENDING_VALIDATION', 'REJECTED', 'RELEASED'):
            self.assertIn(s, schema, s)
            for l in LANGS: self.assertIn(f'`{s}`' if False else s, md(l, 'quarantine'))
        for r in ('VIEWER', 'REVIEWER', 'ADMIN'):
            self.assertIn(r, (ROOT / 'admin/worker/src/auth.js').read_text() + schema)
            for l in LANGS: self.assertIn(r, md(l, 'admin-panel'))
    def test_release_assets_match_the_workflow(self):
        wf = (ROOT / '.github/workflows/publish.yml').read_text()
        for a in ('rules-release.tar.gz', 'manifest.json', 'manifest.sigstore.json', 'inclusion-proof.json', 'checkpoint.txt', 'checkpoint.sigstore.json', 'release.json', 'changes.json', 'CHANGELOG.md', 'consistency.json'):
            self.assertIn(a, wf, a)
            for l in LANGS: self.assertIn(f'`{a}`', md(l, 'release'))
        import verify_public_release as v
        for a in v.REQUIRED: self.assertIn(f'{{{{release.download}}}}/{a}', md('en', 'verification'))

class Honesty(Base):
    def test_no_slsa_or_intoto_claims(self):
        for l in LANGS:
            for slug in ('sigstore', 'overview', 'limits'):
                self.assertRegex(md(l, slug), r'(?i)(no hay atestaciones SLSA|There are no SLSA|\*\*No hay atestaciones|no SLSA|No existen|Do not exist)', f'{l}/{slug}')
        for l in LANGS:
            for p in PAGES:
                for line in md(l, p['slug']).split('\n'):
                    if re.search(r'SLSA|in-toto', line): self.assertRegex(line, r'(?i)no |not |sin |Do not|PROPUESTA|PROPOSED|propuesta|would|sería|\*\*Do|existen|exist', line)
    def test_status_labels_present(self):
        for l in LANGS:
            joined = ''.join(md(l, p['slug']) for p in PAGES)
            self.assertIn('**ACTUAL**' if l == 'es' else '**CURRENT**', joined); self.assertIn('**PROPUESTA**' if l == 'es' else '**PROPOSED**', joined)
    def test_cloudflare_claims_match_the_workflow_and_the_log(self):
        wf = (ROOT / '.github/workflows/site.yml').read_text(); log = (ROOT / 'logs/log.jsonl').read_text()
        self.assertIn('pages deploy site --project-name=macguard-rules', wf); self.assertIn("steps.creds.outputs.status == 'present'", wf)
        deployed = '"event":"site.cloudflare_deployed"' in log
        for l in LANGS:
            t = md(l, 'web-distribution')
            if deployed: self.assertRegex(t, r'(?i)automáticamente|automatically'); self.assertIn('site.cloudflare_deployed', t)
            else: self.assertRegex(t, r'(?i)no está automatizado|is not automated')
        self.assertTrue((ROOT / 'config/cloudflare_account_id.txt').read_text().strip())
    def test_no_secrets_or_private_names(self):
        pat = re.compile(r'ghp_[A-Za-z0-9]{20,}|github_pat_|AKIA[0-9A-Z]{12,}|BEGIN (RSA |EC )?PRIVATE KEY|-----BEGIN|eyJ[A-Za-z0-9_-]{30,}|[A-Za-z0-9_-]{40,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}')
        for (l, slug), h in self.html.items():
            self.assertIsNone(pat.search(html.unescape(h)), f'{l}/{slug}')
        for f in SRC.rglob('*'):
            if f.is_file(): self.assertIsNone(pat.search(f.read_text(encoding='utf-8')), str(f))
    def test_versions_come_from_the_code(self):
        tv = build_docs.tool_versions(); self.assertRegex(tv['yara'], r'^\d+\.\d+\.\d+$'); self.assertRegex(tv['cosign'], r'^v\d+\.\d+\.\d+$')
        lit = re.compile(r'\b(?:4\.5\.\d+|v3\.\d+\.\d+|10\.9\.\d+|3\.\d+\.\d+)\b')
        for l in LANGS:
            for p in PAGES:
                for m in lit.finditer(md(l, p['slug'])):
                    ctx = md(l, p['slug'])[max(0, m.start() - 40):m.end() + 10]
                    self.assertTrue(m.group(0) == '4.5.0' and 'Ubuntu' in ctx, f'hard-coded version {m.group(0)} in {l}/{p["slug"]}: {ctx!r}')
        self.assertIn(tv['yara'], html.unescape(self.html[('en', 'client-update')]))
    def test_ubuntu_yara_claim_matches_the_workflow(self):
        self.assertIn('apt-get install -y -qq yara', (ROOT / '.github/workflows/publish.yml').read_text())

class Safety(Base):
    def test_markdown_is_escaped(self):
        body = '## T\n\n<script>alert(1)</script> and `<b>` [x](javascript:alert(1))'
        with self.assertRaises(build_docs.BuildError): build_docs.render_md(body, 'en', {}, {}, [])
        out, _ = build_docs.render_md('<img src=x onerror=alert(1)> **b**', 'en', {}, {}, []); self.assertNotIn('<img', out); self.assertIn('&lt;img', out)
    def test_unresolved_placeholder_is_a_build_error(self):
        with self.assertRaises(build_docs.BuildError): build_docs.render_md('{{nope.nothing}}', 'en', {}, {}, [])
    def test_unknown_page_link_is_a_build_error(self):
        with self.assertRaises(build_docs.BuildError): build_docs.render_md('[a](page:does-not-exist)', 'en', {}, {'x': 'x.html'}, [])
    def test_mermaid_vendored_hash_sri_and_version_agree(self):
        f = ROOT / 'web' / build_docs.MERMAID_FILE; data = f.read_bytes(); readme = (ROOT / 'web/vendor/README.md').read_text()
        self.assertIn(hashlib.sha256(data).hexdigest(), readme); self.assertIn('sha256-' + base64.b64encode(hashlib.sha256(data).digest()).decode(), readme); self.assertIn(build_docs.MERMAID_VERSION, readme)
        self.assertIn(f'mermaid-{build_docs.MERMAID_VERSION}.min.js', readme)
        for h in self.html.values():
            if 'class="diagram"' in h: self.assertIn('integrity="sha256-' + base64.b64encode(hashlib.sha256(data).digest()).decode() + '"', h)
        self.assertNotRegex(''.join(self.html.values()), r'src="https?://(?!macguard)')
    def test_pages_have_no_inline_scripts(self):
        for (l, s), h in self.html.items(): self.assertEqual(re.findall(r'<script(?![^>]*\bsrc=)', h), [], f'{l}/{s}')

if __name__ == '__main__': unittest.main()
