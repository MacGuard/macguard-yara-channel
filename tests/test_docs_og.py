import pathlib, re, subprocess, sys, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]

class OpenGraph(unittest.TestCase):
    def test_inject_per_host_and_idempotent(self):
        sys.path.insert(0, str(ROOT / 'scripts')); import og_inject
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d); (d / 'img').mkdir(); (d / 'img/yara-rules.png').write_bytes((ROOT / 'web/img/yara-rules.png').read_bytes())
            (d / 'index.html').write_text('<!doctype html><html lang="es"><title>A &amp; B</title><main>x</main></html>')
            for base in ('https://a.example/x/', 'https://b.example/'):
                og_inject.inject(d, base); s = (d / 'index.html').read_text()
                self.assertEqual(s.count('og:image"'), 1); self.assertIn(f'content="{base}img/yara-rules.png"', s); self.assertNotIn('a.example' if 'b.example' in base else 'b.example', s)
            self.assertIn('og:title" content="A &amp; B"', s)
    def test_image_is_png_1200x600_and_small(self):
        b = (ROOT / 'web/img/yara-rules.png').read_bytes(); self.assertEqual(b[:8], b'\x89PNG\r\n\x1a\n')
        self.assertEqual((int.from_bytes(b[16:20], 'big'), int.from_bytes(b[20:24], 'big')), (1200, 600)); self.assertLess(len(b), 600_000)
if __name__ == '__main__': unittest.main()
