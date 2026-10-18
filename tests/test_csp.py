import pathlib, re, sys, tempfile, unittest, os, urllib.request
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import csp

PAGE = '<!doctype html><html lang="en"><meta charset="utf-8"><title>t</title><script src="a.js"></script></html>'

class PolicyTests(unittest.TestCase):
    def test_scripts_are_same_origin_only_with_no_inline_code_and_no_eval(self):
        d = {x.split(' ', 1)[0]: x.split(' ', 1)[1] for x in csp.POLICY.split('; ')}
        self.assertEqual(d['script-src'], "'self'"); self.assertEqual(d['default-src'], "'none'"); self.assertEqual(d['object-src'], "'none'"); self.assertEqual(d['base-uri'], "'none'")
        self.assertNotIn('unsafe-eval', csp.POLICY); self.assertNotIn('*', csp.POLICY); self.assertNotIn('http:', csp.POLICY)
        self.assertNotIn('unsafe-inline', d['script-src'])
        self.assertIn("frame-ancestors 'none'", csp.HEADER_POLICY); self.assertNotIn('frame-ancestors', csp.POLICY)   # ignored in a meta tag

    def test_inject_is_idempotent_and_precedes_scripts(self):
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t); (d / 'sub').mkdir(); (d / 'index.html').write_text(PAGE); (d / 'sub/x.html').write_text(PAGE)
            self.assertEqual(csp.inject(d), 2); once = (d / 'index.html').read_text(); self.assertEqual(csp.inject(d), 2); self.assertEqual(once, (d / 'index.html').read_text())
            self.assertEqual(once.count('Content-Security-Policy'), 1); self.assertLess(once.index('Content-Security-Policy'), once.index('<script'))
            (d / 'bad.html').write_text('<!doctype html><script src="x.js"></script><meta charset="utf-8">')
            with self.assertRaises(SystemExit): csp.inject(d)

    def test_the_headers_file_carries_the_same_policy_plus_frame_ancestors(self):
        h = csp.headers(); self.assertIn(csp.HEADER_POLICY, h); self.assertIn('X-Content-Type-Options: nosniff', h); self.assertIn('/latest.json', h)

class RealPagesTests(unittest.TestCase):
    """The pages that are really served must work under that policy: no inline script, no handlers, no javascript: URLs, no sub-resource from another origin."""
    @classmethod
    def setUpClass(cls):
        site = os.environ.get('DOCS_SITE') or ''
        cls.pages = sorted(pathlib.Path(site).rglob('*.html')) if site and pathlib.Path(site).is_dir() else sorted((ROOT / 'web').glob('*.html'))
        if not cls.pages: raise AssertionError('no pages to check')

    def test_no_inline_script_handler_or_javascript_url(self):
        for p in self.pages:
            s = p.read_text(encoding='utf-8')
            for m in re.finditer(r'<script\b([^>]*)>(.*?)</script>', s, re.S | re.I):
                self.assertIn('src=', m.group(1), f'{p.name}: inline script'); self.assertEqual(m.group(2).strip(), '', f'{p.name}: script with src has a body')
            self.assertIsNone(re.search(r'\son[a-z]+\s*=', re.sub(r'content="[^"]*"', '', s)), f'{p.name}: inline event handler')
            self.assertIsNone(re.search(r'(href|src|action)\s*=\s*"\s*javascript:', s, re.I), f'{p.name}: javascript: URL')

    def test_sub_resources_are_same_origin(self):
        for p in self.pages:
            s = p.read_text(encoding='utf-8')
            for m in re.finditer(r'<(?:script|link|img|iframe|source|video|audio|embed|object)\b[^>]*?\s(?:src|href|data)\s*=\s*"([^"]+)"', s, re.I):
                tag = m.group(0).lower(); url = m.group(1)
                if tag.startswith('<link') and 'stylesheet' not in tag and 'icon' not in tag: continue   # canonical/alternate links are navigation, not loads
                self.assertFalse(re.match(r'(?:https?:)?//', url), f'{p.name}: loads {url} from another origin')

    def test_the_browser_code_only_fetches_same_origin(self):
        for js in (ROOT / 'web').glob('*.js'):
            s = js.read_text(encoding='utf-8')
            for m in re.finditer(r"fetch\(\s*(['\"])(https?:[^'\"]+)\1", s): self.fail(f'{js.name} fetches {m.group(2)}')
            self.assertNotRegex(s, r'\beval\s*\(|new Function\s*\(', js.name)

if __name__ == '__main__': unittest.main()
