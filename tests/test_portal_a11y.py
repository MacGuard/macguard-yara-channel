"""Accessibility regressions of the portal and the docs (WCAG 2.2 AA), one test per confirmed defect. Browser-level checks (axe-core, keyboard,
reflow) live in tests/web/cross_browser.mjs; these are the source-level and script-level guards that run without a browser."""
import json, pathlib, re, shutil, subprocess, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
WEB = ROOT / 'web'


def node():
    n = shutil.which('node')
    if not n: raise unittest.SkipTest('node not installed')
    return n


INDEX_STUB = r"""
const vm = require('vm'), fs = require('fs');
const [file, stored] = process.argv.slice(1);
const mk = (i) => ({ dataset: { i }, textContent: '' });
const items = ['title', 'skip'].map(mk), sel = { value: '', onchange: null }, html = { lang: 'es' };
const theme = { onclick: null, attrs: {}, setAttribute(k, v) { this.attrs[k] = String(v); } }, cls = new Set();
const store = { lang: stored === '-' ? null : stored };
const ctx = { document: { querySelector: (q) => (q === '#lang' ? sel : q === '#theme' ? theme : null), querySelectorAll: () => items, documentElement: html, body: { classList: { add: (c) => cls.add(c), toggle: (c) => (cls.has(c) ? cls.delete(c) : cls.add(c)), contains: (c) => cls.has(c) } } },
  localStorage: { getItem: (k) => store[k] ?? null, setItem: (k, v) => { store[k] = v; } }, navigator: { language: 'en-US' } };
vm.createContext(ctx); vm.runInContext(fs.readFileSync(file, 'utf8'), ctx);
const before = { ...theme.attrs }; theme.onclick(); const after = { ...theme.attrs };
console.log(JSON.stringify({ lang: html.lang, sel: sel.value, texts: Object.fromEntries(items.map((e) => [e.dataset.i, e.textContent])), theme: { before, after } }));
"""


class IndexLanguage(unittest.TestCase):
    """WCAG 3.1.1/3.1.2: the home offered fr/de, set <html lang> to them, but the hub, the nav and the activity panel fall back to English or
    Spanish: an untranslated mix under a wrong language. Only ES and EN exist on every page, so only they are offered; the skip link is translated."""
    def run_index(self, stored):
        r = subprocess.run([node(), '-e', INDEX_STUB, str(WEB / 'script.js'), stored], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr[-800:]); return json.loads(r.stdout)

    def test_the_home_offers_only_the_languages_every_page_has(self):
        sel = re.search(r'<select id="lang"[^>]*>(.*?)</select>', (WEB / 'index.html').read_text(), re.S).group(1)
        self.assertEqual(re.findall(r'<option value="(\w+)"', sel), ['es', 'en'])

    def test_a_stored_language_without_translation_becomes_english_never_a_mix(self):
        for stored, want in (('fr', 'en'), ('de', 'en'), ('en', 'en'), ('es', 'es'), ('-', 'es')):
            r = self.run_index(stored); self.assertEqual((r['lang'], r['sel']), (want, want), stored)
            self.assertTrue(r['texts']['title'], stored)

    def test_the_skip_link_of_the_home_is_translated(self):
        self.assertIn('<a class="skip" href="#main" data-i="skip">', (WEB / 'index.html').read_text())
        self.assertEqual(self.run_index('en')['texts']['skip'], 'Skip to content'); self.assertEqual(self.run_index('es')['texts']['skip'], 'Saltar al contenido')


class StatusMessages(unittest.TestCase):
    """WCAG 4.1.3: text that scripts change after load without moving focus is in a live region."""
    def test_the_channel_status_and_the_hub_numbers_of_the_home_are_announced(self):
        h = (WEB / 'index.html').read_text()
        self.assertEqual(h.count('<p class="status" role="status" data-i="pending">'), 1, 'one live region: the same text in two would be announced twice')
        self.assertEqual(h.count('<p class="status" aria-hidden="true" data-i="pending">'), 1, 'the sidebar copy is visual only')
        self.assertIn('<div class="tiles" id="hub-stats" aria-live="polite">', h, 'hub.js replaces "Loading…" by the numbers or an error')

    def test_docs_copy_feedback_goes_to_a_status_region(self):
        # the copy buttons keep a fixed aria-label, so "Copied" on the button is never heard; docs.js announces it (browser check: cross_browser.mjs)
        js = (WEB / 'docs.js').read_text()
        self.assertRegex(js, r"setAttribute\('role', 'status'\)"); self.assertRegex(js, r"announce\(ui\.copied \|\| 'Copied'\)")
        self.assertIn('.sr-status{', (WEB / 'docs.css').read_text())



class ThemeToggle(unittest.TestCase):
    """WCAG 4.1.2 / 3.1.2: the theme button was named "Claro / oscuro · Light / dark" (two languages in one name) and did not expose its state.
    It is now "Tema oscuro" / "Dark theme" in the page language with aria-pressed."""
    PAGES = ['index.html', 'catalog.html', 'guide.html', 'indicators.html', 'packages.html', 'plans.html', 'releases.html', 'rules.html', 'transparency.html', 'vulnerabilities.html', 'vuln.html']

    def test_every_page_has_a_one_language_toggle_with_a_state(self):
        for name in self.PAGES:
            h = (WEB / name).read_text(); self.assertNotIn('Light / dark', h, name)
            self.assertIn('<button id="theme" type="button" aria-label="Tema oscuro" data-t-label="theme" aria-pressed="false">', h, name)
        common = (WEB / 'common.js').read_text()
        self.assertIn("theme:'Tema oscuro'", common); self.assertIn("theme:'Dark theme'", common); self.assertIn("th.setAttribute('aria-pressed'", common)

    def test_the_home_names_the_toggle_in_its_language_and_reports_the_state(self):
        r = IndexLanguage.run_index(self, 'en')
        self.assertEqual(r['theme']['before'], {'aria-label': 'Dark theme', 'aria-pressed': 'false'})
        self.assertEqual(r['theme']['after']['aria-pressed'], 'true', 'a click turns the dark theme on and says so')
        self.assertEqual(IndexLanguage.run_index(self, 'es')['theme']['before']['aria-label'], 'Tema oscuro')


class LanguageOfParts(unittest.TestCase):
    """WCAG 3.1.2: deliberately bilingual links and the docs' language switch carry their own lang; docs texts follow the page language."""
    def test_bilingual_verifier_links_mark_each_language(self):
        for name in ('rules.html', 'transparency.html'):
            h = (WEB / name).read_text()
            self.assertIn('<span lang="es">Descargar verificador</span> · <span lang="en">Download verifier</span>', h, name)
            self.assertIn('lang="es" hreflang="es">Cómo verificar</a>', h, name); self.assertIn('lang="en" hreflang="en">How to verify</a>', h, name)

    def test_docs_language_switch_pager_and_diagram_error_follow_the_language(self):
        src = (ROOT / 'scripts' / 'build_docs.py').read_text()
        self.assertIn('<a id="lang-switch" class="btn" lang="{other}" hreflang="{other}"', src); self.assertNotIn('aria-label="pager"', src)
        self.assertIn("'draw_error': 'No se pudo dibujar el diagrama. Su código está debajo.'", src)
        js = (WEB / 'docs.js').read_text(); self.assertIn('ui.draw_error', js); self.assertNotIn("<p class=\"badmsg\">The diagram", js)

    def test_the_docs_entry_pages_mark_the_other_language_and_never_redirect_on_a_timer(self):
        """3.1.2: docs.html (Spanish) and docs/index.html (English) had the other language unmarked. 2.2.1 (F41): docs/index.html redirected
        after 3 s with a meta refresh, a time limit the reader cannot extend; the redirect is now immediate (0 s), like docs.html."""
        h = (WEB / 'docs.html').read_text()
        self.assertIn('<h1>Documentación · <span lang="en">Documentation</span></h1>', h)
        self.assertIn('<span lang="en">The documentation moved to <a href="docs/index.html">docs/</a>.</span>', h)
        src = (ROOT / 'scripts' / 'build_docs.py').read_text()
        self.assertIn('<h1><span lang="es">Documentación</span> · Documentation</h1>', src)
        self.assertIn('lang="es" hreflang="es">Leer en español</a>', src)
        for page, text in (('docs.html', h), ('build_docs.py', src)):
            for delay in re.findall(r'http-equiv="refresh" content="(\d+);', text):
                with self.subTest(page=page): self.assertEqual(delay, '0')

    def test_the_english_half_of_the_404_page_is_marked(self):
        h = (WEB / '404.html').read_text()
        self.assertIn('<html lang="es">', h); self.assertIn('<p lang="en">This address does not exist', h); self.assertIn('<main><h1>404</h1>', h)


def _lum(h):
    if len(h) == 4: h = '#' + ''.join(ch * 2 for ch in h[1:])
    c = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]; f = lambda v: v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2])


def _contrast(a, b):
    x, y = _lum(a), _lum(b); return (max(x, y) + 0.05) / (min(x, y) + 0.05)


def _tokens(css, block):
    """Custom properties declared in every `block{...}` rule of the stylesheet (later declarations win, like the cascade)."""
    out = {}
    for body in re.findall(r'(?:^|[}\s])' + re.escape(block) + r'\{([^}]*)\}', css):
        out.update(re.findall(r'--([\w-]+):(#[0-9a-fA-F]{6}|#[0-9a-fA-F]{3})\b', body))
    return out


class FieldBoundaries(unittest.TestCase):
    """WCAG 1.4.11: text fields and selects of the portal are identified only by their border (same fill as the panel). The border used
    --line, 1.25:1 against white and 1.43:1 in dark: invisible for low-vision users. Now a --field border with at least 3:1 against the panel and
    the page in both themes, applied with a selector that outranks .toolbar input / .herosearch input."""
    def test_field_border_has_3_to_1_against_panel_and_page_in_both_themes(self):
        css = (WEB / 'style.css').read_text()
        for block in (':root', 'body.dark'):
            tok = {**(_tokens(css, ':root') if block == 'body.dark' else {}), **_tokens(css, block)}
            for bg in ('panel', 'bg'):
                with self.subTest(theme=block, against=bg):
                    self.assertGreaterEqual(_contrast(tok['field'], tok[bg]), 3.0)

    def test_every_field_uses_the_field_border(self):
        css = (WEB / 'style.css').read_text()
        self.assertIn(':is(input,select,textarea):not([type=hidden]):not([type=checkbox]):not([type=radio]){border-color:var(--field)}', css)
        for page in WEB.glob('*.html'):
            with self.subTest(page=page.name):
                self.assertNotRegex(page.read_text(), r'<(input|select|textarea)[^>]*style="[^"]*border', 'inline border overrides the field border')


class ScrollRegionName(unittest.TestCase):
    """WCAG 4.1.2/3.1.2: common.js made every scrollable table a focusable region named with aria-label = caption text, copied once at load.
    The captions are translated afterwards (data-t), so in English the region kept the Spanish name ("Paquetes publicados"). The region is now
    named by reference to its caption, which always holds the current language."""
    STUB = r"""
const vm = require('vm'), fs = require('fs');
const mk = (txt, id) => ({ id: id || '', textContent: txt });
const caps = [mk('Paquetes publicados'), mk('Releases', 'given')], wraps = caps.map((c) => ({ attrs: {}, setAttribute(k, v) { this.attrs[k] = String(v); }, querySelector: (q) => (q === 'caption' ? c : null) }));
const ctx = { document: { querySelectorAll: (q) => (q === '.tablewrap' ? wraps : []) } }; vm.createContext(ctx);
const src = fs.readFileSync(process.argv[1], 'utf8').split('\n').filter((l) => l.startsWith("document.querySelectorAll('.tablewrap')"));
if (src.length !== 1) throw new Error('expected one .tablewrap statement in common.js, found ' + src.length);
vm.runInContext(src[0], ctx);
caps[0].textContent = 'Published packages';
console.log(JSON.stringify({ wraps: wraps.map((w) => w.attrs), ids: caps.map((c) => c.id) }));
"""

    def test_the_scroll_region_is_named_by_its_caption_not_a_copy(self):
        r = subprocess.run([node(), '-e', self.STUB, str(WEB / 'common.js')], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr[-800:]); out = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual(len(out['wraps']), 2, r.stderr[-400:])
        for w, cid in zip(out['wraps'], out['ids']):
            self.assertEqual(w.get('role'), 'region'); self.assertEqual(w.get('tabindex'), '0')
            self.assertNotIn('aria-label', w); self.assertTrue(cid); self.assertEqual(w.get('aria-labelledby'), cid)
        self.assertEqual(out['ids'][1], 'given')


class TargetSpacing(unittest.TestCase):
    """WCAG 2.5.8: the packages and releases tables list files as " · "-separated links (13 px, 15 px tall). Such a list is not a sentence, so
    the inline exception does not apply; when a cell wrapped, the rows were 15 px apart and the 24 px circles of the links overlapped. Cells with
    links and the packages link row now have a line height of at least 24 px. Browser check: tests/web/cross_browser.mjs check 7."""
    def test_link_lists_keep_24_px_between_rows(self):
        css = (WEB / 'style.css').read_text()
        self.assertIn('.linkrow,.tablewrap td:has(a){line-height:max(24px,1.6em)}', css)
        self.assertIn('<li class="linkrow"><a href="guide.html"><span lang="es">Guía del portal</span> · <span lang="en">Portal guide</span></a>', (WEB / 'packages.html').read_text())

if __name__ == '__main__':
    unittest.main()
