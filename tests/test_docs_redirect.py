"""web/docs-redirect.js sends the reader to docs/<lang>/overview.html. CodeQL (js/xss-through-dom) flagged an earlier version that read the
page id from a DOM attribute; the id is now a constant, so no DOM text reaches the URL. This pins both the behaviour and that property."""
import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JS = ROOT / "web" / "docs-redirect.js"
HARNESS = """
const src = require('fs').readFileSync(process.argv[1], 'utf8');
const [lang, attr] = JSON.parse(process.argv[2]);
let target = null;
new Function('document', 'localStorage', 'navigator', 'location', src)(
  { currentScript: { getAttribute: () => attr } }, { getItem: () => lang }, { language: 'en' }, { replace: (u) => { target = u; } });
console.log(JSON.stringify(target));
"""


@unittest.skipUnless(shutil.which("node"), "node is needed")
class DocsRedirect(unittest.TestCase):
    def go(self, lang, attr="../../evil"):
        out = subprocess.run(["node", "-e", HARNESS, str(JS), json.dumps([lang, attr])], capture_output=True, text=True, check=True).stdout
        return json.loads(out)

    def test_language_picks_the_target(self):
        self.assertEqual(self.go("es-ES"), "es/overview.html")
        self.assertEqual(self.go("fr"), "en/overview.html")

    def test_nothing_from_the_page_reaches_the_url(self):
        self.assertEqual(self.go("en", "javascript:alert(1)"), "en/overview.html")
        self.assertIsNone(re.search(r"getAttribute|dataset|document\.|innerHTML|textContent", JS.read_text()))

    def test_the_build_emits_no_attribute_and_requires_overview_first(self):
        src = (ROOT / "scripts" / "build_docs.py").read_text()
        self.assertNotIn("data-first", src)
        self.assertIn("first != 'overview'", src)


if __name__ == "__main__":
    unittest.main()
