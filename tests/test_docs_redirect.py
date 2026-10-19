"""web/docs-redirect.js sends the reader to docs/<lang>/<first>.html. `first` comes from an attribute of the page; CodeQL (js/xss-through-dom)
flagged it as a DOM-text-to-URL flow. It is build-generated, but the script now accepts only [a-z0-9-] and this pins it."""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

JS = Path(__file__).resolve().parent.parent / "web" / "docs-redirect.js"
HARNESS = """
const src = require('fs').readFileSync(process.argv[1], 'utf8');
const [first, lang] = JSON.parse(process.argv[2]);
let target = null;
new Function('document', 'localStorage', 'navigator', 'location', src)(
  { currentScript: { getAttribute: () => first } }, { getItem: () => lang }, { language: 'en' }, { replace: (u) => { target = u; } });
console.log(JSON.stringify(target));
"""


@unittest.skipUnless(shutil.which("node"), "node is needed")
class DocsRedirect(unittest.TestCase):
    def go(self, first, lang=None):
        out = subprocess.run(["node", "-e", HARNESS, str(JS), json.dumps([first, lang])], capture_output=True, text=True, check=True).stdout
        return json.loads(out)

    def test_normal_targets(self):
        self.assertEqual(self.go("overview", "es-ES"), "es/overview.html")
        self.assertEqual(self.go("release-flow", "fr"), "en/release-flow.html")

    def test_hostile_first_page_falls_back(self):
        for bad in ["../../evil", "//evil.example/x", "javascript:alert(1)", "a/b", "x.html?y", "", "A B"]:
            self.assertEqual(self.go(bad, "en"), "en/overview.html", bad)


if __name__ == "__main__":
    unittest.main()
