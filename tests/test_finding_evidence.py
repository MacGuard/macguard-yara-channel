"""What the pipeline sends the private quarantine service about each finding: only what a check really measured, bounded to a fixed set of fields.

A finding that is a yes/no test carries its detail and nothing else; a finding that measures something (a regex risk score, a loop count, the share of the clean
corpus a rule matches, a module name) carries the observed value, the threshold the policy applied and the unit. Nothing is estimated or defaulted."""
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import decide  # noqa: E402
import quarantine_client as qc  # noqa: E402
import rulecheck as rc  # noqa: E402

POLICY = json.loads((ROOT / 'config/policy.json').read_text())


def finding(text, code):
    return next((f for f in rc.analyse_text(text, POLICY)['findings'] if f['code'] == code), None)


class MeasuredFindings(unittest.TestCase):
    def test_a_costly_regex_reports_its_score_against_the_policy_threshold(self):
        f = finding('rule A { strings: $a = /(a+)+b/ condition: $a }', 'costly-regex')
        self.assertIsNotNone(f)
        self.assertEqual((f['unit'], f['threshold']), ('risk score', POLICY['regex']['max_risk_score']))
        self.assertIsInstance(f['observed'], int)
        self.assertGreaterEqual(f['observed'], f['threshold'])
        self.assertIn(f"risk {f['observed']}", f['detail'], 'the structured value is the one the text states')

    def test_too_many_loops_reports_the_count_and_the_limit(self):
        loops = ' and '.join(['for any i in (0..3) : (uint8(i) == 0x41)'] * (POLICY['condition']['max_for_loops'] + 2))
        f = finding(f'rule A {{ condition: {loops} }}', 'many-loops')
        self.assertIsNotNone(f)
        self.assertEqual((f['observed'], f['threshold'], f['unit']), (POLICY['condition']['max_for_loops'] + 2, POLICY['condition']['max_for_loops'], 'for loops'))
        self.assertIn(f"{f['observed']} loops", f['detail'])

    def test_a_module_finding_names_the_module(self):
        blocked = POLICY['blocked_modules'][0]
        f = finding(f'import "{blocked}"\nrule A {{ condition: true }}', 'blocked-module')
        self.assertEqual((f['observed'], f['unit']), (blocked, 'module')); self.assertNotIn('threshold', f)
        g = finding('import "not_a_real_module"\nrule A { condition: true }', 'unknown-module')
        self.assertEqual((g['observed'], g['unit']), ('not_a_real_module', 'module'))

    def test_a_yes_no_check_carries_no_invented_number(self):
        f = finding('rule A { condition: for any i in (0..filesize) : ( uint8(i) == 0x41 ) }', 'filesize-loop')
        self.assertIsNotNone(f)
        self.assertEqual(set(f), {'code', 'severity', 'detail'})


class SubmissionsCarryOnlyTheAllowedFields(unittest.TestCase):
    def test_matches_benign_corpus_reports_the_measured_share_and_the_limit(self):
        files = [{'path': 'rules/g.yar', 'sha256': 'a' * 64, 'bytes': 10, 'source': 'nextron', 'state': 'VALIDATED', 'reasons': [], 'depends_on': []}]
        res = decide.decide(files, dynamic_required=False, benign_hits={'rules/g.yar': 20}, corpus_size=58)
        sub = next(s for s in res['submissions'] if s['path'] == 'rules/g.yar')
        f = next(x for x in sub['findings'] if x['code'] == 'matches-benign-corpus')
        self.assertEqual((f['observed'], f['threshold'], f['unit']), (round(100 * 20 / 58, 1), 5.0, '% of the clean corpus'))
        self.assertIn('20 of 58', f['detail'])
        self.assertEqual(sub['reasons'], ['matches-benign-corpus'], 'the codes are unchanged')

    def test_nothing_but_the_allowed_fields_leaves_the_job(self):
        files = [{'path': 'rules/t.yar', 'sha256': 'b' * 64, 'bytes': 10, 'source': 'nextron', 'state': 'QUARANTINED', 'depends_on': [],
                  'reasons': [{'code': 'unclosed-rule', 'severity': 'truncated', 'detail': 'x', 'secret_internal_field': 'must not travel', 'observed': 3}]}]
        res = decide.decide(files, dynamic_required=False)
        sub = next(s for s in res['submissions'] if s['path'] == 'rules/t.yar')
        self.assertEqual(sub['findings'], [{'code': 'unclosed-rule', 'severity': 'truncated', 'detail': 'x', 'observed': 3}])

    def test_the_client_sends_the_findings_with_their_schema_and_the_engine_when_known(self):
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / 'rules').mkdir(); (pathlib.Path(d) / 'rules/a.yar').write_text('rule A { condition: true }')
            dec = {'submissions': [{'path': 'rules/a.yar', 'sha256': 'c' * 64, 'bytes': 25, 'source': 'nextron', 'reasons': ['costly-regex'],
                                    'findings': [{'code': 'costly-regex', 'severity': 'review', 'detail': 'd', 'observed': 7, 'threshold': 6, 'unit': 'risk score'}]}]}
            item = qc.build_submissions(dec, d, {'engine': 'YARA 4.5.0 ' + 'x' * 200})[0]
            self.assertEqual((item['findings_schema'], item['findings'][0]['observed']), (1, 7))
            self.assertEqual(len(item['engine']), 80)
            self.assertNotIn('engine', qc.build_submissions(dec, d)[0], 'no engine is claimed when the dynamic report has none')
            old = qc.build_submissions({'submissions': [{k: v for k, v in dec['submissions'][0].items() if k != 'findings'}]}, d)[0]
            self.assertEqual(old['findings'], [], 'a decision from before this contract still builds a valid submission')


if __name__ == '__main__':
    unittest.main()
