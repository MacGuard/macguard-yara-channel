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
  localStorage: { getItem: (k) => store[k] ?? null, setItem: (k, v) => { store[k] = v; } }, navigator: { language: 'es-ES' } };
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
        self.assertEqual(h.count('<p class="status" role="status" data-i="pending">'), 2, 'channel.js rewrites both channel-status lines')
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

if __name__ == '__main__':
    unittest.main()
