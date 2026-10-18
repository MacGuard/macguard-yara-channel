import json, pathlib, sys, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import licensing
POL = json.loads((pathlib.Path(__file__).resolve().parents[1] / 'config/policy.json').read_text())['licenses']
class LicenseTests(unittest.TestCase):
    def test_expected_license_passes(self):
        self.assertTrue(licensing.verdict(POL['Neo23x0/signature-base'], 'NOASSERTION', 'Detection Rule License (DRL) 1.1 ...')['ok'])
        self.assertTrue(licensing.verdict(POL['Yara-Rules/rules'], 'GPL-2.0', 'GNU GENERAL PUBLIC LICENSE')['ok'])
    def test_a_changed_license_is_flagged(self):
        v = licensing.verdict(POL['Yara-Rules/rules'], 'MIT', 'MIT License'); self.assertFalse(v['ok']); self.assertIn('policy expects', v['detail'])
        v = licensing.verdict(POL['Neo23x0/signature-base'], 'NOASSERTION', 'All rights reserved'); self.assertFalse(v['ok'])
    def test_unknown_source_or_missing_text_is_not_ok(self):
        self.assertFalse(licensing.verdict(None, 'MIT', 'x')['ok']); self.assertFalse(licensing.verdict(POL['Yara-Rules/rules'], 'GPL-2.0', '')['ok'])
    def test_a_pinned_text_hash_detects_silent_edits(self):
        rule = dict(POL['Yara-Rules/rules']); rule['sha256'] = '0' * 64
        self.assertFalse(licensing.verdict(rule, 'GPL-2.0', 'GNU GENERAL PUBLIC LICENSE')['ok'])
if __name__ == '__main__': unittest.main()
