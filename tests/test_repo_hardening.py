"""The repository guarantees that keep an unreviewed source out of config/sources.json, checked offline against the files we intend to apply.

Nothing here calls GitHub. scripts/ruleset_probe.sh is the real-repository proof (run by the owner on a sandbox); these tests pin what can be pinned without one."""
import copy, json, pathlib, subprocess, sys, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import ruleset_check as rc

HARD = ROOT / 'docs' / 'audit' / 'repo-hardening'
load = lambda name: json.loads((HARD / name).read_text())
CODEOWNERS = (ROOT / '.github' / 'CODEOWNERS').read_text()


class MainRuleset(unittest.TestCase):
    def test_the_proposed_main_ruleset_has_no_actions_bypass_and_forces_a_code_owner_review(self):
        rs = load('ruleset-main-v2.json'); self.assertEqual(rc.check_main_ruleset(rs), [])
        self.assertEqual([b['actor_type'] for b in rs['bypass_actors']], ['RepositoryRole'])
        pr = [r for r in rs['rules'] if r['type'] == 'pull_request'][0]['parameters']
        self.assertGreaterEqual(pr['required_approving_review_count'], 1); self.assertTrue(pr['require_code_owner_review']); self.assertTrue(pr['require_last_push_approval'])

    def test_the_checker_detects_the_weakness_of_the_current_file(self):
        problems = rc.check_main_ruleset(load('ruleset-main.json'))
        self.assertTrue(any('GitHub Actions app' in x for x in problems), problems)
        self.assertTrue(any('required_approving_review_count' in x for x in problems)); self.assertTrue(any('require_code_owner_review' in x for x in problems))

    def test_each_weakening_is_caught(self):
        base = load('ruleset-main-v2.json')
        def mutate(f):
            rs = copy.deepcopy(base); f(rs); return rc.check_main_ruleset(rs)
        pr = lambda rs: [r for r in rs['rules'] if r['type'] == 'pull_request'][0]['parameters']
        cases = {
            'actions bypass': lambda rs: rs['bypass_actors'].append({'actor_id': 15368, 'actor_type': 'Integration', 'bypass_mode': 'always'}),
            'actions bypass on pull_request only': lambda rs: rs['bypass_actors'].append({'actor_id': 15368, 'actor_type': 'Integration', 'bypass_mode': 'pull_request'}),
            'admin bypass always': lambda rs: rs['bypass_actors'].__setitem__(0, {'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'always'}),
            'org admin bypass': lambda rs: rs['bypass_actors'].append({'actor_id': 1, 'actor_type': 'OrganizationAdmin', 'bypass_mode': 'always'}),
            'zero approvals': lambda rs: pr(rs).update(required_approving_review_count=0),
            'no code owner': lambda rs: pr(rs).update(require_code_owner_review=False),
            'no last push approval': lambda rs: pr(rs).update(require_last_push_approval=False),
            'stale reviews kept': lambda rs: pr(rs).update(dismiss_stale_reviews_on_push=False),
            'no pull_request rule': lambda rs: rs.update(rules=[r for r in rs['rules'] if r['type'] != 'pull_request']),
            'force push allowed': lambda rs: rs.update(rules=[r for r in rs['rules'] if r['type'] != 'non_fast_forward']),
            'deletion allowed': lambda rs: rs.update(rules=[r for r in rs['rules'] if r['type'] != 'deletion']),
            'check dropped': lambda rs: [r for r in rs['rules'] if r['type'] == 'required_status_checks'][0]['parameters']['required_status_checks'].pop(),
            'evaluate only': lambda rs: rs.update(enforcement='evaluate'),
            'wrong branch': lambda rs: rs['conditions']['ref_name'].update(include=['refs/heads/other']),
            'disabled': lambda rs: rs.update(enforcement='disabled'),
        }
        for name, f in cases.items(): self.assertTrue(mutate(f), f'not detected: {name}')

    def test_the_live_shape_returned_by_the_api_is_understood(self):
        live = copy.deepcopy(load('ruleset-main-v2.json')); live.update(id=123, source_type='Repository', source='MacGuard/x', current_user_can_bypass='never', created_at='2026-10-21T00:00:00Z')
        self.assertEqual(rc.check_live([live]), [])
        live['bypass_actors'].append({'actor_id': 15368, 'actor_type': 'Integration', 'bypass_mode': 'always'}); self.assertTrue(rc.check_live([live]))
        self.assertEqual(rc.check_live([]), ['no active ruleset targets the default branch']); self.assertTrue(rc.check_live([load('ruleset-logs-branch.json')]))
        self.assertEqual(rc.check_live([load('ruleset-main-v2.json')], extra_checks=('another-check',)), ['main: reviewed by a code owner, checked, no history rewrite: required status check another-check is missing'])

    def test_every_required_check_is_a_job_that_runs_on_every_pull_request(self):
        import re
        ci = (ROOT / '.github' / 'workflows' / 'ci.yml').read_text(); jobs = set(re.findall(r'^  ([a-z][a-z0-9-]*):$', ci.split('\njobs:\n', 1)[1], re.M))
        names = {c['context'] for r in load('ruleset-main-v2.json')['rules'] if r['type'] == 'required_status_checks' for c in r['parameters']['required_status_checks']}
        self.assertEqual(names, set(rc.REQUIRED_CHECKS)); self.assertLessEqual(names, jobs, 'a required check that no job reports would block every merge')
        self.assertNotRegex(ci.split('\njobs:\n', 1)[0], r'paths(-ignore)?:', 'no path filter: a skipped required check stays pending')


class LogsRuleset(unittest.TestCase):
    def test_only_the_log_bot_writes_the_logs_branch_and_history_cannot_be_rewritten(self):
        rs = load('ruleset-logs-branch.json'); self.assertEqual(rc.check_logs_ruleset(rs), [])
        self.assertEqual(rs['conditions']['ref_name']['include'], ['refs/heads/logs'])
        for f in (lambda r: r.update(bypass_actors=[]), lambda r: r['bypass_actors'].append({'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'always'}), lambda r: r.update(rules=[x for x in r['rules'] if x['type'] != 'update']),
                  lambda r: r.update(rules=[x for x in r['rules'] if x['type'] != 'non_fast_forward']), lambda r: r['conditions']['ref_name'].update(include=['~DEFAULT_BRANCH'])):
            m = copy.deepcopy(rs); f(m); self.assertTrue(rc.check_logs_ruleset(m))

    def test_the_two_rulesets_never_target_the_same_branch(self):
        self.assertNotEqual(load('ruleset-main-v2.json')['conditions'], load('ruleset-logs-branch.json')['conditions'])


class Codeowners(unittest.TestCase):
    def test_the_file_covers_the_paths_that_decide_what_is_published(self):
        self.assertEqual(rc.check_codeowners(CODEOWNERS, root=ROOT), [])
        rules = rc.parse_codeowners(CODEOWNERS)
        for path in ('config/sources.json', 'config/policy.json', '.github/workflows/daily.yml', '.github/workflows/brand-new.yml', '.github/CODEOWNERS', 'scripts/decide.py', 'scripts/sub/dir/new.py', 'tests/test_decide.py', 'admin/worker/src/proposals.js', 'admin/worker/migrations/0005_source_proposals.sql'):
            self.assertEqual(rc.owners_of(rules, path), ['@MacGuard'], path)
        for path in ('README.md', 'logs/log.jsonl', 'docs/index.md'): self.assertEqual(rc.owners_of(rules, path), [], f'{path} is not owned on purpose')

    def test_every_weakening_is_caught(self):
        self.assertIn('<OWNER>', ''.join(rc.check_codeowners(CODEOWNERS.replace('@MacGuard', '<OWNER>'))))
        self.assertTrue(rc.check_codeowners('\n'.join(l for l in CODEOWNERS.splitlines() if not l.startswith('/scripts/'))))
        self.assertTrue(rc.check_codeowners('\n'.join(l for l in CODEOWNERS.splitlines() if not l.startswith('/config/'))))
        self.assertTrue(rc.check_codeowners('\n'.join(l for l in CODEOWNERS.splitlines() if not l.startswith('/.github/'))))
        self.assertTrue(rc.check_codeowners(CODEOWNERS + '\n/config/sources.json\n'), 'a later line without owner un-owns the file')
        self.assertTrue(rc.check_codeowners(CODEOWNERS.replace('/scripts/                       @MacGuard', '/scripts/ not an owner')))
        self.assertTrue(rc.check_codeowners(CODEOWNERS + '\n/does-not-exist/   @MacGuard\n', root=ROOT))

    def test_the_last_matching_pattern_wins_so_a_later_broad_line_cannot_hide_a_hole(self):
        rules = rc.parse_codeowners('/config/ @a\n/config/sources.json @b\n'); self.assertEqual(rc.owners_of(rules, 'config/sources.json'), ['@b']); self.assertEqual(rc.owners_of(rules, 'config/policy.json'), ['@a'])

    def test_the_cli_exits_non_zero_on_a_problem(self):
        run = lambda *a: subprocess.run([sys.executable, str(ROOT / 'scripts' / 'ruleset_check.py'), *a], capture_output=True, text=True)
        self.assertEqual(run('main', str(HARD / 'ruleset-main-v2.json')).returncode, 0); self.assertEqual(run('logs', str(HARD / 'ruleset-logs-branch.json')).returncode, 0)
        self.assertEqual(run('codeowners', str(ROOT / '.github' / 'CODEOWNERS'), '--root', str(ROOT)).returncode, 0)
        bad = run('main', str(HARD / 'ruleset-main.json')); self.assertEqual(bad.returncode, 1); self.assertIn('PROBLEM', bad.stdout)


class Probe(unittest.TestCase):
    def test_the_probe_refuses_to_touch_the_real_repository_and_is_valid_shell(self):
        sh = ROOT / 'scripts' / 'ruleset_probe.sh'; text = sh.read_text()
        self.assertEqual(subprocess.run(['bash', '-n', str(sh)], capture_output=True).returncode, 0)
        for repo in ('MacGuard/macguard-yara-channel', 'macguard/MacGuard-YARA-Channel', 'someone/else', 'MacGuard/some-test-repo'):
            r = subprocess.run(['bash', str(sh), repo, '--yes-this-is-the-sandbox'], capture_output=True, text=True, env={'PATH': '/usr/bin:/bin', 'PROBE_DRY': '1'})
            self.assertEqual(r.returncode, 2, f'{repo}: {r.stdout}{r.stderr}')
        r = subprocess.run(['bash', str(sh), 'MacGuard/macguard-ruleset-sandbox'], capture_output=True, text=True, env={'PATH': '/usr/bin:/bin', 'PROBE_DRY': '1'}); self.assertEqual(r.returncode, 2, 'needs the explicit confirmation flag')
        r = subprocess.run(['bash', str(sh), 'MacGuard/macguard-ruleset-sandbox', '--yes-this-is-the-sandbox'], capture_output=True, text=True, env={'PATH': '/usr/bin:/bin', 'PROBE_DRY': '1'})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr); self.assertIn('DRY RUN', r.stdout)
        self.assertIn("REAL='macguard/macguard-yara-channel'", text)   # the real repository is named only to be refused

    def test_the_probe_workflow_template_has_minimal_permissions_and_expects_every_bypass_attempt_to_fail(self):
        text = (HARD / 'probe' / 'probe.yml').read_text()
        self.assertIn('workflow_dispatch', text); self.assertNotIn('pull_request', text.split('jobs:')[0].replace('pull-requests', ''))
        self.assertIn('contents: write', text); self.assertIn('pull-requests: write', text)
        for must in ('expect_fail main-direct-push', 'expect_fail main-contents-api', 'expect_fail merge-without-review', 'expect_ok logs-push'): self.assertIn(must, text)

    def test_the_probe_workflow_passes_actionlint_when_it_is_installed(self):
        import shutil
        if not shutil.which('actionlint'): self.skipTest('actionlint not installed')
        r = subprocess.run(['actionlint', str(HARD / 'probe' / 'probe.yml')], capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == '__main__':
    unittest.main()
