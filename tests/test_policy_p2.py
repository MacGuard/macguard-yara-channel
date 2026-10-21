"""Persistent administrative policy in the pipeline (phase 2): decide.py consumes the prohibitions, persistent rejections are really wired, and a failing or
unreachable policy service can only delay additions (fail safe). Offline: no network, no cosign (the signature check is injected), no Worker.
Negative scenarios NF-xx are those of docs/audit/quarantine-decision-memory-and-withdrawal-spec.md section 18."""
import hashlib, http.server, json, os, pathlib, random, subprocess, sys, tempfile, threading, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import decide, policy_snapshot as ps  # noqa: E402

NOW = 1_800_000_000
PY = sys.executable
SHA = lambda c: c * 64


def f(path, state='VALIDATED', sha=None, reasons=None, deps=None, source='nextron'):
    return {'path': path, 'sha256': sha or path.ljust(64, '0')[:64].replace('/', '0'), 'bytes': 10, 'source': source, 'state': state, 'reasons': reasons or [], 'depends_on': deps or []}


def r(code, sev): return {'code': code, 'severity': sev, 'detail': code}
def ok_dyn(files, **kw):
    d = {'verdict': 'ok', 'set_root': decide.set_root(files), 'canaries_detected': 5, 'canaries_expected': 5}; d.update(kw); return d
def approve(sha, by='alice'): return {sha: {'state': 'APPROVED_PENDING_VALIDATION', 'by': by}}


def pol(pid, path, source='nextron', scope='path', sha=None, version=1):
    sha = sha or SHA('a')
    return {'id': pid, 'version': version, 'scope': scope, 'scope_key': ps.scope_key(scope, source, path, sha), 'source': source, 'path': path, 'sha256': sha, 'criticality': 'CRITICAL', 'withdrawal': 'REQUESTED', 'created_at': '2026-10-21T00:00:00.000Z'}


def mk_view(policies=(), rejected=(), seq=10, dmax=5, lifted=()):
    pols = sorted(policies, key=lambda p: p['id']); rej = sorted(rejected)
    return {'schema': 1, 'generated_at': '2026-10-21T00:00:00.000Z', 'audit_head': {'seq': seq, 'hash': '0' * 64}, 'decisions_max_id': dmax, 'policies': pols,
            'lifted': [{'id': i, 'version': 2, 'lifted_via': 'DIRECT'} for i in lifted], 'rejected': rej, 'policy_set_sha256': ps.digest(pols), 'rejected_sha256': ps.digest(rej), 'breakglass_reviews_overdue': 0}


def fake_verifier(path, bundle):
    """Stands in for cosign: valid only if the bundle names the daily workflow and signs exactly these bytes."""
    try: b = json.loads(pathlib.Path(bundle).read_text())
    except Exception: return 'unreadable bundle'
    if b.get('signer') != 'daily': return 'certificate identity does not match'
    if b.get('signs') != hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest(): return 'signature does not match the blob'
    return None


class Dirs:
    def __init__(self, tc):
        self.d = tempfile.TemporaryDirectory(); tc.addCleanup(self.d.cleanup)
        self.snap, self.logs = pathlib.Path(self.d.name) / 'snap', pathlib.Path(self.d.name) / 'logs'; self.snap.mkdir(); self.logs.mkdir()

    def save(self, view, age=3600, pin=True, signer='daily', tlog_time=True, pin_hash=None, tamper=False):
        raw = (json.dumps(view, sort_keys=True, indent=1) + '\n').encode(); h = hashlib.sha256(raw).hexdigest()
        bundle = {'signer': signer, 'signs': h, 'verificationMaterial': {'tlogEntries': [{'integratedTime': str(NOW - age)}] if tlog_time else []}}
        if tamper: raw = raw.replace(b'"seq": 10', b'"seq": 99')
        (self.snap / ps.SNAPSHOT_FILE).write_bytes(raw); (self.snap / ps.BUNDLE_FILE).write_text(json.dumps(bundle))
        if pin: self.pin(pin_hash or h, 5)
        return h

    def pin(self, h, seq):
        with (self.logs / 'log.jsonl').open('a') as fh: fh.write(json.dumps({'event': 'policy.snapshot', 'seq': seq, 'details': {'snapshot_sha256': h}}) + '\n')

    def resolve(self, status, data):
        return ps.resolve(status, data, self.snap, self.logs, NOW, fake_verifier)


def plan(doc, files, previous=None, **kw):
    """decide() exactly as dynamic_gate.decide_now calls it, with the dynamic evidence for what was approved."""
    first = decide.decide(files, previous, None, None, None, False, previously_rejected=doc['rejected'], **ps.decide_args(doc))
    return decide.decide(files, previous, None, ok_dyn(first['approved']), None, True, previously_rejected=doc['rejected'], **ps.decide_args(doc), **kw)


class Identity(unittest.TestCase):
    def test_python_and_worker_agree_on_the_shared_identity_vectors(self):
        for v in json.loads((ROOT / 'tests/fixtures/policy_identity_vectors.json').read_text())['vectors']:
            self.assertEqual(ps.scope_key('path', v['source'], v['path'], None), v['key'], v)

    def test_the_view_the_real_worker_produced_parses_and_its_digests_recompute_in_python(self):
        view = json.loads((ROOT / 'tests/fixtures/policy_snapshot_view.json').read_text())
        self.assertIsNone(ps.validate_view(view)); self.assertEqual(ps.digest(view['policies']), view['policy_set_sha256']); self.assertEqual(ps.digest(view['rejected']), view['rejected_sha256'])
        self.assertEqual(ps.digest([]), '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945', 'sha256 of "[]", the empty set the Worker also reports')


class DecideWithPolicies(unittest.TestCase):
    def test_PY01_a_path_policy_removes_a_clean_file_and_the_file_is_visible_in_the_panel_queue(self):
        files = [f('rules/p.yar'), f('rules/a.yar')]; p = pol('p1', 'rules/p.yar', sha=files[0]['sha256'])
        res = decide.decide(files, dynamic_required=False, policies=[p])
        self.assertEqual([a['path'] for a in res['approved']], ['rules/a.yar'])
        ex = res['excluded'][0]; self.assertEqual((ex['path'], ex['state']), ('rules/p.yar', 'QUARANTINED')); self.assertIn('blocked-by-policy', [x['code'] for x in ex['reasons']])
        self.assertEqual([s['path'] for s in res['submissions']], ['rules/p.yar']); self.assertEqual(res['submissions'][0]['reasons'], ['blocked-by-policy'])
        self.assertEqual(res['policy']['applied'], [{'id': 'p1', 'version': 1, 'path': 'rules/p.yar', 'sha256': files[0]['sha256']}])

    def test_PY02_an_empty_policy_set_changes_nothing(self):
        files = [f('rules/a.yar'), f('rules/q.yar', 'QUARANTINED', reasons=[r('costly-regex', 'review')])]
        base = decide.decide(files, dynamic=ok_dyn([files[0]])); with_empty = decide.decide(files, dynamic=ok_dyn([files[0]]), policies=[])
        with_empty.pop('policy'); self.assertEqual(json.dumps(base, sort_keys=True), json.dumps(with_empty, sort_keys=True)); self.assertNotIn('policy', base); self.assertNotIn('withdrawn', base)

    def test_PY03_an_approval_never_waives_a_prohibition(self):
        q = f('rules/slow.yar', 'QUARANTINED', sha=SHA('d'), reasons=[r('costly-regex', 'review')])
        self.assertEqual([a['path'] for a in decide.decide([q], decisions=approve(SHA('d')), dynamic_required=False)['approved']], ['rules/slow.yar'], 'sanity: without the policy the approval waives it')
        res = decide.decide([q], decisions=approve(SHA('d')), dynamic_required=False, policies=[pol('p1', 'rules/slow.yar')])
        self.assertEqual(res['approved'], []); self.assertNotIn('waived-by-review', [x['code'] for e in res['excluded'] for x in e['reasons']])
        res = decide.decide([f('rules/a.yar', sha=SHA('b'))], decisions=approve(SHA('b')), dynamic_required=False, policies=[pol('p1', 'rules/a.yar')]); self.assertEqual(res['approved'], [])

    def test_PY04_a_content_policy_follows_the_bytes_not_the_path(self):
        moved, same_path = f('rules/moved.yar', sha=SHA('c')), f('rules/orig.yar', sha=SHA('e'))
        res = decide.decide([moved, same_path], dynamic_required=False, policies=[pol('p1', 'rules/orig.yar', scope='content', sha=SHA('c'))])
        self.assertEqual([a['path'] for a in res['approved']], ['rules/orig.yar'], 'the same bytes at another path are out, other bytes at the path are in')

    def test_PY05_a_path_policy_also_blocks_the_next_version_of_the_file_and_shows_it_for_review(self):
        new = f('rules/p.yar', sha=SHA('9')); res = decide.decide([new], dynamic_required=False, policies=[pol('p1', 'rules/p.yar', sha=SHA('1'))])
        self.assertEqual(res['approved'], []); self.assertEqual([s['path'] for s in res['submissions']], ['rules/p.yar'])

    def test_PY07_an_approval_is_never_inherited_by_another_hash(self):
        q = f('rules/x.yar', 'QUARANTINED', sha=SHA('2'), reasons=[r('costly-regex', 'review')])
        self.assertEqual(decide.decide([q], decisions=approve(SHA('1')), dynamic_required=False, policies=[])['approved'], [])

    def test_PY08_a_lifted_policy_lets_the_file_back_only_through_every_gate(self):
        good, bad = f('rules/g.yar'), f('rules/b.yar', 'QUARANTINED', reasons=[r('compile-error', 'corrupt')])
        for pols in ([pol('p1', 'rules/g.yar'), pol('p2', 'rules/b.yar')], []):
            res = decide.decide([good, bad], dynamic_required=False, policies=pols)
            self.assertEqual([a['path'] for a in res['approved']], [] if pols else ['rules/g.yar'], 'after the lift only the file that passes comes back')

    def test_PY09_dependents_of_a_withdrawn_rule_leave_with_it_and_return_when_it_does(self):
        files = [f('rules/a.yar'), f('rules/b.yar', deps=['rules/a.yar']), f('rules/c.yar', deps=['rules/b.yar']), f('rules/z.yar')]
        res = decide.decide(files, dynamic_required=False, policies=[pol('p1', 'rules/a.yar')])
        self.assertEqual([a['path'] for a in res['approved']], ['rules/z.yar'])
        self.assertEqual({e['path']: [x['code'] for x in e['reasons']][-1] for e in res['excluded']}, {'rules/a.yar': 'blocked-by-policy', 'rules/b.yar': 'dependency-not-validated', 'rules/c.yar': 'dependency-not-validated'})
        self.assertEqual(len(decide.decide(files, dynamic_required=False, policies=[])['approved']), 4)

    def test_PY10_a_withdrawal_never_bypasses_the_dynamic_gate_or_the_anomaly_guard(self):
        prev = {'files': [{'path': f'rules/p{i}.yar', 'sha256': f(f'rules/p{i}.yar')['sha256']} for i in range(10)]}
        files = [f(f'rules/p{i}.yar') for i in range(10)]
        res = decide.decide(files, prev, dynamic_required=False, policies=[pol('p1', 'rules/p0.yar'), pol('p2', 'rules/p1.yar')], anomaly={'max_removed_fraction': 0.15, 'max_changed_fraction': 0.40})
        self.assertFalse(res['publishable']); self.assertIn('unusually large change', res['blockers'][0])   # 2 of 10 removed: the guard is not skipped
        left = decide.decide(files, prev, dynamic=ok_dyn(files[1:]), dynamic_required=True, policies=[pol('p1', 'rules/p0.yar')])   # NF-16: the removal-only set fails its own dynamic verdict
        bad = decide.decide(files, prev, dynamic=ok_dyn(files[1:], verdict='regression'), dynamic_required=True, policies=[pol('p1', 'rules/p0.yar')])
        self.assertTrue(left['publishable']); self.assertFalse(bad['publishable']); self.assertIn('dynamic validation verdict', bad['blockers'][0])

    def test_PY11_a_policy_can_only_remove_files_never_add_one(self):
        rnd = random.Random(7)
        for _ in range(60):
            files = [f(f'rules/f{i}.yar', sha=hashlib.sha256(f'{i}-{rnd.random()}'.encode()).hexdigest(), deps=[f'rules/f{j}.yar' for j in range(i) if rnd.random() < 0.2]) for i in range(8)]
            for x in files:
                if rnd.random() < 0.2: x['state'], x['reasons'] = 'QUARANTINED', [r('costly-regex', 'review')]
            decisions = {x['sha256']: {'state': 'APPROVED_PENDING_VALIDATION', 'by': 'a'} for x in files if rnd.random() < 0.5}
            pols = [pol(f'p{k}', rnd.choice(files)['path']) for k in range(rnd.randint(0, 3))]
            without = {a['path'] for a in decide.decide(files, decisions=decisions, dynamic_required=False)['approved']}
            with_ = {a['path'] for a in decide.decide(files, decisions=decisions, dynamic_required=False, policies=pols)['approved']}
            self.assertTrue(with_ <= without)
            self.assertFalse({p['path'] for p in pols} & with_)

    def test_a_rejected_file_is_not_resurrected_into_the_queue_by_a_policy(self):
        res = decide.decide([f('rules/r.yar', 'REJECTED', reasons=[r('no-rules', 'reject')])], dynamic_required=False, policies=[pol('p1', 'rules/r.yar')])
        self.assertEqual((res['excluded'][0]['state'], res['submissions']), ('REJECTED', []))

    def test_a_published_file_removed_by_a_policy_is_a_withdrawal_not_a_failure(self):
        p = f('rules/p.yar'); prev = {'files': [{'path': 'rules/p.yar', 'sha256': p['sha256']}]}
        res = decide.decide([p, f('rules/a.yar')], prev, dynamic_required=False, policies=[pol('p1', 'rules/p.yar')])
        self.assertEqual(res['previously_published_failing'], []); self.assertEqual(res['withdrawn'], [{'path': 'rules/p.yar', 'was': p['sha256'], 'policy_id': 'p1'}]); self.assertEqual(res['public_stats']['previously_published_failing'], 0)
        self.assertEqual(res['public_stats']['examined'], 2); self.assertEqual((res['public_stats']['accepted'], res['public_stats']['quarantined']), (1, 1), 'the accounting invariant holds')

    def test_the_lowest_policy_id_is_cited_when_several_match(self):
        res = decide.decide([f('rules/p.yar')], dynamic_required=False, policies=[pol('p9', 'rules/p.yar'), pol('p2', 'rules/p.yar', scope='content', sha=f('rules/p.yar')['sha256'])])
        self.assertEqual(res['policy']['applied'][0]['id'], 'p2')

    def test_NF11_a_rejected_hash_stays_out_even_with_an_approval_a_clean_file_and_a_passing_dynamic_result(self):
        x = f('rules/x.yar', sha=SHA('7')); res = decide.decide([x], decisions=approve(SHA('7')), dynamic=ok_dyn([]), previously_rejected=[SHA('7')])
        self.assertEqual(res['approved'], []); self.assertEqual(res['excluded'][0]['state'], 'REJECTED'); self.assertEqual(decide.decide([f('rules/x.yar', sha=SHA('8'))], dynamic_required=False, previously_rejected=[SHA('7')])['approved'][0]['sha256'], SHA('8'), 'changed bytes are a new candidate')


class ModesAndRatchet(unittest.TestCase):
    def setUp(self): self.dirs = Dirs(self)

    def test_NF01_service_down_and_a_fresh_verified_snapshot_means_snapshot_mode_that_excludes_the_rule_and_still_allows_other_additions(self):
        p = pol('p1', 'rules/p.yar'); self.dirs.save(mk_view([p], [SHA('7')]))
        for status, data in ((0, {'error': 'unreachable'}), (503, {'error': 'boom'}), (200, 'truncated{'), (404, {})):
            doc, keep = self.dirs.resolve(status, data); self.assertEqual((doc['mode'], keep), ('snapshot', None), (status, doc['live']))
            prev = {'files': [{'path': 'rules/p.yar', 'sha256': SHA('a')}]}
            res = plan(doc, [f('rules/p.yar', sha=SHA('a')), f('rules/new.yar')], prev)
            self.assertEqual([a['path'] for a in res['approved']], ['rules/new.yar']); self.assertTrue(res['publishable'], res['blockers'])

    def test_NF02_no_snapshot_means_unknown_mode_nothing_added_or_modified_but_removals_flow(self):
        doc, keep = self.dirs.resolve(0, {'error': 'unreachable'}); self.assertEqual((doc['mode'], doc['policies']), ('unknown', []))
        prev = {'files': [{'path': 'rules/a.yar', 'sha256': f('rules/a.yar')['sha256']}, {'path': 'rules/b.yar', 'sha256': f('rules/b.yar')['sha256']}]}
        added = plan(doc, [f('rules/a.yar'), f('rules/b.yar'), f('rules/new.yar')], prev); self.assertFalse(added['publishable']); self.assertIn('only removals can be published', ' '.join(added['blockers']))
        modified = plan(doc, [f('rules/a.yar', sha=SHA('5')), f('rules/b.yar')], prev); self.assertFalse(modified['publishable'])
        removals = plan(doc, [f('rules/a.yar')], prev); self.assertTrue(removals['publishable'], removals['blockers'])
        first = plan(doc, [f('rules/a.yar')], None); self.assertFalse(first['publishable'], 'with no previous release everything is an addition: the first release needs a verified view')

    def test_NF03_a_snapshot_older_than_48_hours_by_the_signature_time_is_no_snapshot(self):
        self.dirs.save(mk_view([pol('p1', 'rules/p.yar')]), age=48 * 3600 + 1); doc, _ = self.dirs.resolve(0, {}); self.assertEqual(doc['mode'], 'unknown'); self.assertIn('older than 48 h', doc['snapshot'])
        self.dirs.save(mk_view([pol('p1', 'rules/p.yar')]), age=48 * 3600 - 60); self.assertEqual(self.dirs.resolve(0, {})[0]['mode'], 'snapshot')
        self.dirs.save(mk_view([pol('p1', 'rules/p.yar')]), age=-3600); self.assertEqual(self.dirs.resolve(0, {})[0]['mode'], 'unknown', 'a snapshot from the future')

    def test_NF04_a_tampered_or_wrongly_signed_snapshot_is_rejected(self):
        v = mk_view([pol('p1', 'rules/p.yar')])
        for name, kw in (('bytes changed after signing', {'tamper': True}), ('signed by another workflow', {'signer': 'other'}), ('bundle without a log time', {'tlog_time': False})):
            self.dirs.save(v, **kw); doc, _ = self.dirs.resolve(0, {}); self.assertEqual(doc['mode'], 'unknown', name); self.assertNotEqual(doc['snapshot'], 'verified', name)
        nopin = Dirs(self); nopin.save(v, pin=False); self.assertIn('no policy.snapshot pin', nopin.resolve(0, {})[0]['snapshot'])
        (nopin.snap / ps.BUNDLE_FILE).unlink(); self.assertEqual(nopin.resolve(0, {})[0]['snapshot'], 'no snapshot')

    def test_NF05_an_older_but_validly_signed_snapshot_does_not_match_the_newest_pin(self):
        old = mk_view([pol('p1', 'rules/p.yar')], seq=3); h_old = self.dirs.save(old, pin=False)
        newer = mk_view([pol('p1', 'rules/p.yar'), pol('p2', 'rules/q.yar')], seq=9); h_new = hashlib.sha256((json.dumps(newer, sort_keys=True, indent=1) + '\n').encode()).hexdigest()
        self.dirs.pin(h_old, 4); self.dirs.pin(h_new, 8)   # the newest pin names a newer snapshot: replaying the old, correctly signed file must fail
        doc, _ = self.dirs.resolve(0, {}); self.assertEqual(doc['mode'], 'unknown'); self.assertIn('not the one pinned', doc['snapshot'])

    def test_NF06_a_live_view_that_knows_less_than_the_snapshot_is_a_regression_that_keeps_the_blocks_and_blocks_additions(self):
        p = pol('p1', 'rules/p.yar'); self.dirs.save(mk_view([p], [SHA('7')], seq=10, dmax=5))
        for name, live in (('lower audit head', mk_view([p], [SHA('7')], seq=4)), ('missing policy', mk_view([], [SHA('7')], seq=12)), ('lower version', mk_view([pol('p1', 'rules/p.yar', version=0)], [SHA('7')], seq=12)),
                           ('missing rejection', mk_view([p], [], seq=12)), ('fewer decisions', mk_view([p], [SHA('7')], seq=12, dmax=1))):
            doc, keep = self.dirs.resolve(200, live); self.assertEqual((doc['mode'], keep), ('unknown', None), name); self.assertTrue(doc['regressions'], name)
            self.assertEqual([x['id'] for x in doc['policies']], ['p1'], f'{name}: the verified block still applies'); self.assertIn(SHA('7'), doc['rejected'])
            prev = {'files': [{'path': 'rules/old.yar', 'sha256': f('rules/old.yar')['sha256']}]}
            res = plan(doc, [f('rules/old.yar'), f('rules/p.yar', sha=SHA('a')), f('rules/new.yar')], prev); self.assertFalse(res['publishable'], name); self.assertNotIn('rules/p.yar', [a['path'] for a in res['approved']])

    def test_NF07_a_worker_that_returns_empty_lists_with_a_higher_audit_head_cannot_remove_what_was_verified(self):
        self.dirs.save(mk_view([pol('p1', 'rules/p.yar')], [SHA('7')], seq=10)); doc, _ = self.dirs.resolve(200, mk_view([], [], seq=500, dmax=900))
        self.assertEqual(doc['mode'], 'unknown'); self.assertEqual([x['id'] for x in doc['policies']], ['p1']); self.assertEqual(doc['rejected'], [SHA('7')])
        fresh = Dirs(self); doc2, keep = fresh.resolve(200, mk_view([], [], seq=500)); self.assertEqual((doc2['mode'], doc2['policies']), ('normal', [])); self.assertIsNotNone(keep)   # with nothing verified before, an empty view is just a view

    def test_a_policy_the_live_view_reports_as_lifted_is_dropped_and_the_view_is_still_accepted(self):
        p = pol('p1', 'rules/p.yar'); self.dirs.save(mk_view([p], seq=10)); doc, keep = self.dirs.resolve(200, mk_view([], seq=11, lifted=['p1']))
        self.assertEqual((doc['mode'], doc['policies']), ('normal', [])); self.assertIsNotNone(keep)

    def test_NF08_a_live_response_that_is_not_what_it_claims_is_unavailable(self):
        good = mk_view([pol('p1', 'rules/p.yar')])
        for name, bad in (('wrong schema', {**good, 'schema': 2}), ('digest of the policies', {**good, 'policy_set_sha256': '0' * 64}), ('digest of the rejections', {**good, 'rejected_sha256': '0' * 64, 'rejected': [SHA('1')]}),
                          ('missing field', {k: v for k, v in good.items() if k != 'audit_head'}), ('a path policy with a forged key', {**good, 'policies': [{**good['policies'][0], 'scope_key': 'path:nextron:rules/other.yar'}]}),
                          ('negative audit head', {**good, 'audit_head': {'seq': -1, 'hash': ''}}), ('a list', []), ('truncated body', 'x')):
            doc, keep = Dirs(self).resolve(200, bad); self.assertEqual((doc['mode'], keep), ('unknown', None), name); self.assertNotEqual(doc['live'], 'accepted', name)

    def test_the_accepted_live_view_becomes_the_next_snapshot_and_only_it(self):
        doc, keep = self.dirs.resolve(200, mk_view([pol('p1', 'rules/p.yar')])); self.assertEqual(doc['mode'], 'normal')
        out = pathlib.Path(self.dirs.d.name) / 'out'; cand = pathlib.Path(self.dirs.d.name) / 'c.json'; cand.write_text(json.dumps(keep)); ps.stage(cand, out); self.assertIsNone(ps.validate_view(json.loads((out / ps.SNAPSHOT_FILE).read_text())))
        bad = pathlib.Path(self.dirs.d.name) / 'bad.json'; bad.write_text(json.dumps({**keep, 'policy_set_sha256': '0' * 64}))
        with self.assertRaises(SystemExit): ps.stage(bad, out)

    def test_policy_check_rules(self):
        doc = {'mode': 'normal', 'policies': [pol('p1', 'rules/p.yar')], 'rejected': [SHA('7')]}
        prev = [{'path': 'rules/a.yar', 'sha256': SHA('1')}]
        self.assertEqual(ps.check_candidate([f('rules/a.yar', sha=SHA('1'))], doc, prev), [])
        self.assertEqual(len(ps.check_candidate([f('rules/p.yar', sha=SHA('2'))], doc, prev)), 1)
        self.assertEqual(len(ps.check_candidate([f('rules/z.yar', sha=SHA('7'))], doc, prev)), 1, 'a rejected hash')
        snap = {**doc, 'mode': 'snapshot'}; self.assertEqual(len(ps.check_candidate([f('rules/a.yar', sha=SHA('1')), f('rules/n.yar')], snap, prev)), 1, 'publication needs the LIVE view for additions')
        self.assertEqual(ps.check_candidate([f('rules/a.yar', sha=SHA('1'))], snap, prev), [], 'removals-only and unchanged files pass in any mode')


class Fake(http.server.BaseHTTPRequestHandler):
    routes = {}
    def log_message(self, *a): pass
    def _send(self, code, body):
        raw = json.dumps(body).encode(); self.send_response(code); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        if self.path.startswith('/oidc'): return self._send(200, {'value': 'tok'})
        code, body = self.routes.get(('GET', self.path), (404, {'error': 'not found'})); self._send(code, body)
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0)); self.rfile.read(n); code, body = self.routes.get(('POST', self.path), (404, {'error': 'not found'})); self._send(code, body)


class Cli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fake); threading.Thread(target=cls.srv.serve_forever, daemon=True).start(); cls.base = f'http://127.0.0.1:{cls.srv.server_port}'
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown(); cls.srv.server_close()

    def setUp(self): self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); self.cwd = pathlib.Path(self.tmp.name); (self.cwd / 'dist').mkdir(); Fake.routes = {}
    def env(self, up=True):
        e = {k: v for k, v in os.environ.items() if not k.startswith(('QUARANTINE', 'ACTIONS_ID', 'GITHUB_REPOSITORY'))}
        if up: e.update(QUARANTINE_URL=self.base, QUARANTINE_AUDIENCE='aud', ACTIONS_ID_TOKEN_REQUEST_URL=f'{self.base}/oidc?x=1', ACTIONS_ID_TOKEN_REQUEST_TOKEN='t')
        return e
    def qc(self, *args, up=True):
        return subprocess.run([PY, str(SCRIPTS / 'quarantine_client.py'), *args], cwd=self.cwd, env=self.env(up), capture_output=True, text=True, timeout=60)
    def write(self, name, obj): p = self.cwd / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(obj)); return p
    def cand(self, files): self.write('dist/candidate.json', {'files': [{'path': x['path'], 'sha256': x['sha256'], 'bytes': 10, 'source': x['source']} for x in files]})

    def test_decisions_writes_the_three_files_always_and_a_live_view_is_normal_mode(self):
        Fake.routes = {('GET', '/api/pipeline/decisions'): (200, {'schema': 1, 'decisions': {}, 'retest': []}), ('GET', '/api/pipeline/policy-snapshot'): (200, mk_view([pol('p1', 'rules/p.yar')], [SHA('7')]))}
        res = self.qc('decisions', '--out', 'dist/decisions.json'); self.assertEqual(res.returncode, 0, res.stderr); (self.cwd / 'dist').exists()
        doc = json.loads((self.cwd / 'dist/policies.json').read_text()); self.assertEqual((doc['mode'], [p['id'] for p in doc['policies']]), ('normal', ['p1'])); self.assertEqual(json.loads((self.cwd / 'dist/rejected.json').read_text()), [SHA('7')])
        self.assertTrue((self.cwd / 'dist/policy-snapshot.candidate.json').exists())

    def test_decisions_with_an_older_worker_that_has_no_endpoint_is_unknown_never_no_policies(self):
        Fake.routes = {('GET', '/api/pipeline/decisions'): (200, {'schema': 1, 'decisions': {}, 'retest': []})}
        self.assertEqual(self.qc('decisions', '--out', 'dist/decisions.json').returncode, 0); doc = json.loads((self.cwd / 'dist/policies.json').read_text())
        self.assertEqual(doc['mode'], 'unknown'); self.assertEqual(json.loads((self.cwd / 'dist/rejected.json').read_text()), []); self.assertFalse((self.cwd / 'dist/policy-snapshot.candidate.json').exists())
        down = self.qc('decisions', '--out', 'dist/decisions.json', up=False); self.assertEqual(down.returncode, 0); self.assertEqual(json.loads((self.cwd / 'dist/policies.json').read_text())['mode'], 'unknown')

    def test_NF12_policy_check_fails_before_signing_when_the_candidate_contains_a_prohibited_or_rejected_file(self):
        files = [f('rules/p.yar', sha=SHA('a')), f('rules/a.yar', sha=SHA('1'))]; self.cand(files); self.write('prev/manifest.json', {'files': [{'path': 'rules/a.yar', 'sha256': SHA('1')}, {'path': 'rules/p.yar', 'sha256': SHA('a')}]})
        Fake.routes = {('GET', '/api/pipeline/policy-snapshot'): (200, mk_view([pol('p1', 'rules/p.yar')]))}
        res = self.qc('policy-check', '--candidate', 'dist/candidate.json', '--previous', 'prev/manifest.json'); self.assertEqual(res.returncode, 1); self.assertIn('administrative prohibition p1', res.stdout)
        Fake.routes = {('GET', '/api/pipeline/policy-snapshot'): (200, mk_view([], [SHA('a')]))}
        res = self.qc('policy-check', '--candidate', 'dist/candidate.json', '--previous', 'prev/manifest.json'); self.assertEqual(res.returncode, 1); self.assertIn('was rejected', res.stdout)
        Fake.routes = {('GET', '/api/pipeline/policy-snapshot'): (200, mk_view([pol('p9', 'rules/other.yar')]))}
        res = self.qc('policy-check', '--candidate', 'dist/candidate.json', '--previous', 'prev/manifest.json'); self.assertEqual(res.returncode, 0, res.stdout)

    def test_NF17_with_the_service_down_policy_check_fails_on_additions_and_passes_on_removals_only(self):
        self.write('prev/manifest.json', {'files': [{'path': 'rules/a.yar', 'sha256': SHA('1')}, {'path': 'rules/b.yar', 'sha256': SHA('2')}]})
        self.cand([f('rules/a.yar', sha=SHA('1')), f('rules/new.yar', sha=SHA('3'))])
        for up in (True, False):   # the endpoint is missing / the service is unreachable
            res = self.qc('policy-check', '--candidate', 'dist/candidate.json', '--previous', 'prev/manifest.json', up=up); self.assertEqual(res.returncode, 1, (up, res.stdout)); self.assertIn('only removals can be published', res.stdout)
        self.cand([f('rules/a.yar', sha=SHA('1'))])
        for up in (True, False): self.assertEqual(self.qc('policy-check', '--candidate', 'dist/candidate.json', '--previous', 'prev/manifest.json', up=up).returncode, 0)

    def test_NF15_an_urgent_run_is_refused_for_an_unknown_lifted_or_confirmed_policy_and_asserted_after_the_gate(self):
        pid = '00000000-0000-4000-8000-000000000001'
        for code, body in ((404, {'error': 'unknown policy'}), (409, {'error': 'an urgent run needs an ACTIVE policy whose withdrawal is still requested (this one is LIFTED/CANCELLED)', 'code': 'not_urgent_eligible'}), (409, {'error': 'CONFIRMED', 'code': 'not_urgent_eligible'})):
            Fake.routes = {('POST', '/api/pipeline/urgent-run'): (code, body)}; res = self.qc('urgent', '--policy-id', pid, '--out', 'u.json'); self.assertNotEqual(res.returncode, 0); self.assertFalse((self.cwd / 'u.json').exists())
        self.assertNotEqual(self.qc('urgent', '--policy-id', 'rm -rf /; x', '--out', 'u.json').returncode, 0, 'an id that is not an id never reaches the service')
        p = pol(pid, 'rules/p.yar'); Fake.routes = {('POST', '/api/pipeline/urgent-run'): (200, {'policy': {k: p[k] for k in ('id', 'version', 'scope', 'scope_key', 'source', 'path', 'sha256', 'criticality')}})}
        self.assertEqual(self.qc('urgent', '--policy-id', pid, '--out', 'u.json').returncode, 0)
        self.write('dist/approved.json', {'files': [f('rules/a.yar')]}); self.assertEqual(self.qc('urgent-assert', '--policy', 'u.json', '--approved', 'dist/approved.json').returncode, 0)
        self.write('dist/approved.json', {'files': [f('rules/a.yar'), f('rules/p.yar')]}); res = self.qc('urgent-assert', '--policy', 'u.json', '--approved', 'dist/approved.json'); self.assertNotEqual(res.returncode, 0); self.assertIn('not effective', res.stderr)

    def test_NF10_a_given_rejected_or_policies_file_that_is_missing_or_invalid_stops_the_gate_and_decide(self):
        for script in ('dynamic_gate.py', 'decide.py'):
            for opt in ('--rejected', '--policies'):
                res = subprocess.run([PY, str(SCRIPTS / script), opt, str(self.cwd / 'missing.json'), '--classification', str(self.cwd / 'c.json')], cwd=self.cwd, capture_output=True, text=True, timeout=60)
                self.assertNotEqual(res.returncode, 0, (script, opt)); self.assertIn('was given but the file does not exist', res.stderr)
                (self.cwd / 'bad.json').write_text('{nope'); res = subprocess.run([PY, str(SCRIPTS / script), opt, str(self.cwd / 'bad.json'), '--classification', str(self.cwd / 'c.json')], cwd=self.cwd, capture_output=True, text=True, timeout=60)
                self.assertNotEqual(res.returncode, 0); self.assertIn('not valid JSON', res.stderr)
        (self.cwd / 'bad.json').write_text(json.dumps({'schema': 9, 'mode': 'normal', 'policies': []}))
        res = subprocess.run([PY, str(SCRIPTS / 'decide.py'), '--policies', str(self.cwd / 'bad.json'), '--classification', str(self.cwd / 'c.json')], cwd=self.cwd, capture_output=True, text=True, timeout=60); self.assertNotEqual(res.returncode, 0)

    def test_decide_cli_uses_the_rejected_and_policies_files(self):
        files = [f('rules/p.yar', sha=SHA('a')), f('rules/r.yar', sha=SHA('7')), f('rules/ok.yar', sha=SHA('1'))]
        self.write('dist/classification.json', {'files': files}); doc, _ = Dirs(self).resolve(200, mk_view([pol('p1', 'rules/p.yar')], [SHA('7')])); self.write('dist/policies.json', doc); self.write('dist/rejected.json', doc['rejected'])
        res = subprocess.run([PY, str(SCRIPTS / 'decide.py'), '--no-dynamic', '--rejected', 'dist/rejected.json', '--policies', 'dist/policies.json', '--out', 'dist/decision.json', '--approved-out', 'dist/approved.json'], cwd=self.cwd, capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr); out = json.loads((self.cwd / 'dist/decision.json').read_text())
        self.assertEqual([a['path'] for a in out['approved']], ['rules/ok.yar']); self.assertEqual(out['policy']['mode'], 'normal')


class Workflows(unittest.TestCase):
    daily = (ROOT / '.github/workflows/daily.yml').read_text()
    publish = (ROOT / '.github/workflows/publish.yml').read_text()

    @staticmethod
    def steps(text, job):
        body = text.split(f'\n  {job}:\n', 1)[1]; body = body.split('\n  ', 1)[0] if False else body
        return [s for s in ('\n' + body).split('\n      - ')[1:]]

    def index(self, steps, needle):
        for i, s in enumerate(steps):
            if needle in s: return i
        self.fail(f'no step contains {needle!r}')

    def test_WF01_the_daily_gate_gets_the_rejections_and_the_policies_and_they_are_produced_before_it(self):
        steps = self.steps(self.daily, 'review'); gate = self.index(steps, 'scripts/dynamic_gate.py'); fetch = self.index(steps, 'quarantine_client.py decisions')
        self.assertIn('--rejected dist/rejected.json', steps[gate]); self.assertIn('--policies dist/policies.json', steps[gate]); self.assertLess(fetch, gate)
        self.assertLess(self.index(steps, 'actions/cache/restore@'), fetch, 'the snapshot is restored before it is verified'); self.assertNotIn('continue-on-error', self.daily)

    def test_WF02_publish_runs_the_policy_check_before_anything_is_signed(self):
        steps = self.steps(self.publish, 'publish'); chk = self.index(steps, 'quarantine_client.py policy-check')
        for later in ('tlog.py checkpoint', 'seal.py', 'cosign sign-blob', 'gh release create'): self.assertLess(chk, self.index(steps, later), later)
        self.assertLess(self.index(steps, 'sigstore/cosign-installer@'), chk, 'cosign is needed to verify the snapshot'); self.assertNotIn('|| true', steps[chk])

    def test_NF14_a_candidate_built_on_a_superseded_release_cannot_publish_and_runs_are_serialized(self):
        pre = self.publish.split('\n  publish:\n', 1)[0]; self.assertIn("previous_rules_root", pre); self.assertIn('run the review again', pre)
        for text in (self.daily, self.publish): self.assertRegex(text, r'concurrency:\n  group: macguard-log\n  cancel-in-progress: false')

    def test_NF15_urgent_dispatch_is_admin_only_exclusive_with_acceptance_and_checked_before_any_gate(self):
        self.assertIn('urgent_policy_id:', self.daily); steps = self.steps(self.daily, 'review'); u = self.index(steps, 'quarantine_client.py urgent --policy-id')
        for later in ('apt-get install', 'unittest discover', 'prepare.py', 'dynamic_gate.py'): self.assertLess(u, self.index(steps, later), later)
        self.assertIn('permission', steps[u]); self.assertIn('"$PERM" = "admin"', steps[u]); self.assertIn("get('acceptance')", steps[u]); self.assertIn('sys.exit(', steps[u])
        for line in self.daily.splitlines():
            if 'inputs.urgent_policy_id' in line: self.assertRegex(line.strip(), r'^(if: inputs\.urgent_policy_id != ..( &&.*)?|URGENT_POLICY_ID: \$\{\{ inputs\.urgent_policy_id \}\})$', 'the id is only compared or passed through env, never expanded into a script')
        self.assertLess(self.index(steps, 'dynamic_gate.py'), self.index(steps, 'urgent-assert'))
        self.assertIn("!(github.event_name == 'workflow_dispatch' && inputs.acceptance)", self.daily, 'the acceptance guard of request-publish is untouched')

    def test_the_snapshot_is_signed_pinned_in_the_log_and_cached_in_that_order(self):
        steps = self.steps(self.daily, 'review'); k = self.index(steps, 'policy_snapshot.py stage')
        self.assertLess(steps[k].index('cosign sign-blob'), steps[k].index('tlog.py event')); self.assertIn('--code policy.snapshot', steps[k]); self.assertLess(k, self.index(steps, 'actions/cache/save@'))
        self.assertLess(self.index(steps, 'actions/cache/save@'), self.index(steps, 'commit_logs.sh'), 'the pin is committed after the snapshot exists')


if __name__ == '__main__':
    unittest.main()
