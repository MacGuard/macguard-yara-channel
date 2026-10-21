"""The new-source hold (scripts/admission.py + the hook in scripts/decide.py): offline, no network.

Negative tests N1-N9, N14, N17 of docs/audit/source-proposals-spec.md section 10.2 that can run without the private service."""
import json, pathlib, re, sys, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import admission, decide


def f(path, source, state='VALIDATED', reasons=None, sha=None):
    return {'path': path, 'sha256': sha or (path.encode().hex() + '0' * 64)[:64], 'bytes': 10, 'source': source, 'state': state, 'reasons': reasons or [], 'depends_on': []}


def dyn(files):
    return {'verdict': 'ok', 'set_root': decide.set_root(files), 'canaries_detected': 5, 'canaries_expected': 5}


def prev(*paths):
    return {'files': [{'path': p, 'sha256': str(i % 10) * 64} for i, p in enumerate(paths)]}


OLD = [f('rules/nextron/a.yar', 'nextron'), f('rules/community/b.yar', 'community')]
NEW = [f('rules/acme/x.yar', 'acme'), f('rules/acme/y.yar', 'acme')]
PREV = prev('rules/nextron/a.yar', 'rules/community/b.yar')
SOURCES = {'nextron': {'id': 'nextron'}, 'community': {'id': 'community'}, 'acme': {'id': 'acme', 'admission': 'probation'}}


def run(files, previous=PREV, decisions=None, sources=SOURCES, dynamic=None):
    kept = [x for x in files if x['source'] != 'acme']
    return decide.decide(files, previous, decisions, dynamic or dyn(kept), sources=sources)


class Hold(unittest.TestCase):
    def test_n1_a_probation_source_is_held_and_the_others_are_untouched(self):
        res = run(OLD + NEW)
        self.assertEqual(sorted(a['path'] for a in res['approved']), ['rules/community/b.yar', 'rules/nextron/a.yar'])
        held = [e for e in res['excluded'] if e['source'] == 'acme']
        self.assertEqual(len(held), 2)
        for e in held:
            self.assertEqual(e['state'], 'QUARANTINED'); self.assertIn('new-source', [r['code'] for r in e['reasons']])
        self.assertTrue(res['publishable']); self.assertEqual(res['public_stats']['examined'], 4)
        self.assertEqual((res['public_stats']['accepted'], res['public_stats']['quarantined']), (2, 2))
        self.assertEqual(sorted(s['path'] for s in res['submissions']), ['rules/acme/x.yar', 'rules/acme/y.yar'])

    def test_n2_without_any_decision_from_the_service_it_is_still_held(self):
        self.assertEqual(len(run(OLD + NEW, decisions={})['approved']), 2)

    def test_n4_an_admin_approval_of_the_exact_bytes_releases_it_and_n5_changed_bytes_are_held_again(self):
        d = {NEW[0]['sha256']: {'state': 'APPROVED_PENDING_VALIDATION', 'by': 'ada'}}
        files = OLD + NEW
        res = decide.decide(files, PREV, d, dyn(OLD + [NEW[0]]), sources=SOURCES)
        self.assertEqual(sorted(a['path'] for a in res['approved']), ['rules/acme/x.yar', 'rules/community/b.yar', 'rules/nextron/a.yar'])
        self.assertIn('waived-by-review', [r['code'] for r in [x for x in res['approved'] if x['source'] == 'acme'][0]['reasons']])
        changed = [f('rules/acme/x.yar', 'acme', sha='e' * 64), NEW[1]]
        res2 = decide.decide(OLD + changed, PREV, d, dyn(OLD), sources=SOURCES)
        self.assertEqual([a['source'] for a in res2['approved']].count('acme'), 0)

    def test_n6_a_changed_licence_cannot_be_waived_by_approving_the_hold(self):
        lic = f('rules/acme/x.yar', 'acme', state='QUARANTINED', reasons=[{'code': 'license-changed', 'severity': 'review', 'detail': 'x'}])
        d = {lic['sha256']: {'state': 'APPROVED_PENDING_VALIDATION', 'by': 'ada'}}
        res = decide.decide(OLD + [lic], PREV, d, dyn(OLD), sources=SOURCES)
        self.assertEqual([a['source'] for a in res['approved']].count('acme'), 0)
        self.assertEqual(sorted(r['code'] for r in res['excluded'][0]['reasons'] if r['severity'] != 'info'), ['license-changed', 'new-source'])

    def test_n7_a_source_added_by_hand_without_the_key_is_held_when_it_was_never_released(self):
        res = run(OLD + NEW, sources={'nextron': {}, 'community': {}, 'acme': {}})
        self.assertEqual([a['source'] for a in res['approved']].count('acme'), 0)

    def test_n8_probation_also_holds_files_added_later_and_the_unapproved_rest(self):
        released = prev('rules/nextron/a.yar', 'rules/community/b.yar', 'rules/acme/x.yar')   # x was approved and released before
        files = OLD + [NEW[0], NEW[1], f('rules/acme/z.yar', 'acme')]
        res = decide.decide(files, released, {NEW[0]['sha256']: {'state': 'APPROVED_PENDING_VALIDATION', 'by': 'ada'}}, dyn(OLD + [NEW[0]]), sources=SOURCES)
        self.assertEqual(sorted(a['path'] for a in res['approved'] if a['source'] == 'acme'), ['rules/acme/x.yar'])
        self.assertEqual(sorted(e['path'] for e in res['excluded'] if e['source'] == 'acme'), ['rules/acme/y.yar', 'rules/acme/z.yar'])

    def test_n9_an_empty_previous_release_holds_only_the_sources_with_the_key(self):
        res = decide.decide(OLD + NEW, None, None, dyn(OLD), sources={'nextron': {}, 'community': {}, 'acme': {'admission': 'probation'}})
        self.assertEqual(sorted({a['source'] for a in res['approved']}), ['community', 'nextron'])
        res2 = decide.decide(OLD + NEW, None, None, dyn(OLD + NEW), sources={'nextron': {}, 'community': {}, 'acme': {}})
        self.assertEqual(len(res2['approved']), 4)   # documented limit of condition 2

    def test_n14_a_source_removed_and_added_again_is_held_again(self):
        released_without_it = prev('rules/nextron/a.yar', 'rules/community/b.yar')
        res = decide.decide(OLD + NEW, released_without_it, None, dyn(OLD), sources={'nextron': {}, 'community': {}, 'acme': {}})
        self.assertEqual([a['source'] for a in res['approved']].count('acme'), 0)

    def test_the_hook_is_inert_when_the_caller_passes_no_sources(self):
        files = OLD + NEW
        self.assertEqual(len(decide.decide(files, PREV, None, dyn(files))['approved']), 4)
        self.assertEqual(admission.held_sources(files, ['rules/nextron/a.yar'], None), set())

    def test_the_three_current_sources_are_not_held_and_their_entries_are_byte_identical(self):
        text = (ROOT / 'config' / 'sources.json').read_text()
        self.assertNotIn('admission', text)   # open item: the spec asks for no explicit value on current sources; the fail-safe leaves a source that has released files alone
        srcs = admission.load_sources(ROOT / 'config' / 'sources.json')
        self.assertEqual(admission.held_sources(OLD, ['rules/nextron/a.yar', 'rules/community/b.yar'], srcs), set())

    def test_a_new_source_file_does_not_move_the_anomaly_gate(self):
        anomaly = {'max_removed_fraction': 0.15, 'max_changed_fraction': 0.40}
        big = [f(f'rules/acme/n{i}.yar', 'acme') for i in range(60)]
        base = [f(f'rules/nextron/p{i}.yar', 'nextron', sha=str(i % 10) * 64) for i in range(10)]
        res = decide.decide(base + big, prev(*[f'rules/nextron/p{i}.yar' for i in range(10)]), None, dyn(base), anomaly=anomaly, sources=SOURCES)
        self.assertEqual(res['change_fractions']['changed'], 0)


class Parity(unittest.TestCase):
    def test_new_source_is_waivable_in_the_panel_exactly_as_in_the_pipeline(self):
        core = (ROOT / 'admin/worker/src/core.js').read_text()
        js = set(re.findall(r"'([a-z-]+)'", re.search(r"WAIVABLE = new Set\(\[([^\]]*)\]", core).group(1)))
        self.assertIn('new-source', js); self.assertEqual(js, decide.WAIVABLE)

    def test_the_daily_gate_turns_the_hold_on_from_config_sources_json(self):
        text = (ROOT / 'scripts/dynamic_gate.py').read_text()
        self.assertIn("anomaly=policy.get('anomaly'), allow_large_change=allow_large_change, sources=sources)", text)
        self.assertIn("ap.add_argument('--sources', default='config/sources.json'", text); self.assertIn('sources=admission.load_sources(a.sources)', text)

    def test_the_hold_cli_option_reads_the_real_sources_file(self):
        self.assertEqual(sorted(admission.load_sources(ROOT / 'config' / 'sources.json')), ['community', 'nextron', 'yara-x'])


if __name__ == '__main__':
    unittest.main()
