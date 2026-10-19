#!/usr/bin/env python3
"""End-to-end test of the acceptance chain with controlled synthetic candidates (no network, no upstream).

  change detection -> static validation -> dynamic gate (real YARA engine) -> culprit isolation -> quarantine service
  -> human approval/rejection through the real API -> revalidation -> (--publish) Sigstore signing -> complete release
  -> site build -> public verification, including a tamper check.

The quarantine service is the real worker handler (admin/worker) served over HTTP with an in-memory database; the pipeline
authenticates to it with an OIDC token minted by the test server's own keys (the production service verifies GitHub's).
Needs: yara/yarac, node 22+, python 3.12+.  With --publish also: cosign, gh, and a GitHub Actions job with id-token: write.

usage: chain_test.py [--workdir DIR] [--publish --repo OWNER/NAME --identity WORKFLOW_IDENTITY]"""
import argparse, base64, hashlib, json, os, pathlib, shutil, subprocess, sys, tempfile, time, urllib.request, urllib.error

ROOT = pathlib.Path(__file__).resolve().parents[1]
RESULTS = []
# The quarantine part emulates the Actions token endpoint; Sigstore signing needs the REAL one, so remember it before it is overwritten.
REAL_OIDC = {k: os.environ[k] for k in ('ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN') if k in os.environ}
def check(name, ok, detail=''):
    RESULTS.append(ok); print(('PASS ' if ok else 'FAIL ') + name + (f' — {detail}' if detail else ''), flush=True)
    return ok

GOOD = 'rule Good%d { strings: $a = "needle-%d" condition: $a }\n'
# two nested loops over constant ranges: nothing the static checks flag, but billions of iterations on any file
SLOW = 'rule Slow { condition: for any i in (0..60000) : ( for any j in (0..60000) : ( uint8(i) == 1 and uint8(j) == 2 and false ) ) }\n'
def upstream(version):
    f = {f'rules/synth/good{i}.yar': GOOD % (i, i) for i in range(1, 6)}
    f['rules/synth/base.yar'] = 'private rule IsMarker { strings: $m = "MARKER-XYZ" condition: $m }\n'
    f['rules/synth/user.yar'] = 'rule UsesMarker { strings: $a = "user-extra" condition: IsMarker and $a }\n'
    f['rules/synth/truncated.yar'] = 'rule Cut { strings: $a = "cut-me" condition: $a }\n'[:-12]
    f['rules/synth/corrupt.yar'] = 'rule Corrupt { \x01\x02 condition: true }\n'
    f['rules/synth/slow.yar'] = SLOW
    f['rules/synth/generic.yar'] = 'rule Generic { strings: $a = "the" condition: $a }\n'
    f['rules/synth/costly.yar'] = 'rule Costly { strings: $a = /(a+)+needle-costly/ condition: $a }\n'
    if version == 2:
        f['rules/synth/good1.yar'] = GOOD % (1, 11)                      # modified
        f['rules/synth/good6.yar'] = GOOD % (6, 6)                       # added
        del f['rules/synth/good5.yar']                                   # retired
        f['rules/synth/costly.yar'] = 'rule Costly { strings: $a = /(b+)+needle-costly/ condition: $a }\n'   # edited after approval: a new candidate
    return f

def write_dist(dist, files):
    shutil.rmtree(dist, ignore_errors=True); entries = []
    for p, t in files.items():
        (dist / p).parent.mkdir(parents=True, exist_ok=True); data = t.encode(); (dist / p).write_bytes(data)
        entries.append({'source': 'synth', 'path': p, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
    (dist / 'candidate.json').write_text(json.dumps({'schema': 1, 'sources': [{'id': 'synth', 'repository': 'synthetic/upstream', 'commit': 'a' * 40, 'kind': 'rules', 'license_check': {'ok': True, 'detail': 'synthetic'}}], 'files': entries, 'rejected': []}))

class Service:
    def __init__(self, work):
        self.port = 22000 + os.getpid() % 15000
        self.proc = subprocess.Popen(['node', str(ROOT / 'admin/worker/test/devserver.js'), str(self.port), '--empty'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.base = f'http://127.0.0.1:{self.port}'
        for _ in range(100):
            try: urllib.request.urlopen(self.base + '/__sessions', timeout=1); break
            except Exception: time.sleep(0.1)
        os.environ.update(QUARANTINE_URL=self.base, QUARANTINE_AUDIENCE='https://admin.example.test', ACTIONS_ID_TOKEN_REQUEST_URL=f'{self.base}/__oidc?workflow=daily.yml', ACTIONS_ID_TOKEN_REQUEST_TOKEN='test-request-token')
    def stop(self): self.proc.terminate(); self.proc.wait()
    def api(self, role, method, path, body=None):
        sid = json.load(urllib.request.urlopen(self.base + '/__sessions'))[role]; cookie = f'__Host-mg_session={sid}'
        me = json.load(urllib.request.urlopen(urllib.request.Request(self.base + '/api/me', headers={'Cookie': cookie}))) if role else {}
        req = urllib.request.Request(self.base + path, method=method, data=None if body is None else json.dumps(body).encode(), headers={'Cookie': cookie, 'X-CSRF-Token': me.get('csrf', ''), 'Origin': self.base, 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req) as r: return r.status, json.load(r)
        except urllib.error.HTTPError as e: return e.code, json.load(e)

def run_pipeline(dist, previous, decisions, engines, policy, sys_mods):
    rulecheck, dynamic_gate, quarantine_client = sys_mods
    cand = json.loads((dist / 'candidate.json').read_text())
    cls = rulecheck.classify(cand['files'], dist, policy, engines, {s['id']: s for s in cand['sources']})
    final, dyn = dynamic_gate.run(dist, cls, previous, policy, decisions, engines[0]['yara'], engines[0]['binary'], timeout_file=1)
    (dist / 'decision.json').write_text(json.dumps(final)); (dist / 'dynamic.json').write_text(json.dumps(dyn))
    return cls, final, dyn

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--workdir'); ap.add_argument('--publish', action='store_true'); ap.add_argument('--repo'); ap.add_argument('--identity'); a = ap.parse_args()
    sys.path.insert(0, str(ROOT / 'scripts'))
    import rulecheck, dynamic_gate, quarantine_client, make_public_candidate, decide
    yara, yarac = shutil.which('yara'), shutil.which('yarac')
    if not (yara and yarac and shutil.which('node')): sys.exit('yara, yarac and node are required')
    policy = json.loads((ROOT / 'config/policy.json').read_text()); policy['dynamic']['runs'] = 3
    engines = rulecheck.find_engines(['yarac']); engines[0]['yara'] = yara
    work = pathlib.Path(a.workdir or tempfile.mkdtemp(prefix='chain-')); work.mkdir(parents=True, exist_ok=True); dist = work / 'dist'
    svc = Service(work)
    try:
        # ---- run 1: first sight of the synthetic upstream --------------------------------------------------
        write_dist(dist, upstream(1)); mods = (rulecheck, dynamic_gate, quarantine_client)
        cls, final, dyn = run_pipeline(dist, None, None, engines, policy, mods)
        state = {pathlib.Path(c['path']).stem: c['state'] for c in cls}
        check('static: truncated and corrupt files are quarantined, never validated', state['truncated'] == 'QUARANTINED' and state['corrupt'] == 'QUARANTINED', f"truncated={state['truncated']} corrupt={state['corrupt']}")
        check('static: a costly regex is only sent for review', state['costly'] == 'QUARANTINED' and state['good1'] == 'VALIDATED')
        check('static: the dependency is detected and the dependent keeps working', next(c for c in cls if c['path'].endswith('user.yar'))['depends_on'] == ['rules/synth/base.yar'])
        approved1 = {pathlib.Path(f['path']).stem for f in final['approved']}
        check('dynamic: the rule that blocks the engine was isolated as the culprit', dyn.get('culprits') == ['rules/synth/slow.yar'], str(dyn.get('culprits')))
        check('dynamic: a rule matching the clean corpus was quarantined and the set re-measured', 'generic' not in approved1 and dyn['set_root'] == final['rules_root'])
        check('the remaining set passes every gate and is publishable', final['publishable'] and approved1 == {'good1', 'good2', 'good3', 'good4', 'good5', 'base', 'user'}, f"{sorted(approved1)} {final['blockers']}")
        qc_items = quarantine_client.build_submissions(final, dist)
        st, data = quarantine_client.call('POST', '/api/pipeline/submit', {'run_id': 'chain-1', 'candidates': qc_items})
        check('quarantine: candidates reach the private service', st == 200 and {r['status'] for r in data['results']} == {'created'} and len(qc_items) == 5, f"status {st}, {len(qc_items)} submitted")
        # ---- human decisions through the real API --------------------------------------------------------
        st, listing = svc.api('reviewer', 'GET', '/api/candidates?pageSize=100'); by = {c['path'].split('/')[-1][:-4]: c for c in listing['items']}
        check('panel: the reviewer sees all five with their reasons', st == 200 and set(by) == {'truncated', 'corrupt', 'slow', 'generic', 'costly'} and 'costly-regex' in by['costly']['reasons'])
        st, _ = svc.api('viewer', 'POST', '/api/decisions', {'action': 'approve', 'ids': [by['costly']['id']], 'reason': 'viewer must not', 'request_id': 'req_' + 'v' * 20, 'expect': {by['costly']['id']: 1}})
        check('panel: a read-only user cannot approve', st == 403)
        ids = [by[n]['id'] for n in ('costly', 'slow', 'truncated', 'generic')]
        st, res = svc.api('reviewer', 'POST', '/api/decisions', {'action': 'approve', 'ids': ids, 'confirm_count': 4, 'reason': 'reviewed by hand, please test', 'request_id': 'req_' + 'b' * 20, 'expect': {i: 1 for i in ids}})
        check('panel: batch approval of exactly the four selected', st == 200 and len(res['applied']) == 4)
        st, res = svc.api('reviewer', 'POST', '/api/decisions', {'action': 'reject', 'ids': [by['corrupt']['id']], 'reason': 'damaged upstream file', 'request_id': 'req_' + 'c' * 20, 'expect': {by['corrupt']['id']: 1}})
        check('panel: the corrupt file is rejected', st == 200)
        # ---- run 2: same candidates, now with the decisions ---------------------------------------------
        st, dm = quarantine_client.call('GET', '/api/pipeline/decisions')
        cls, final, dyn = run_pipeline(dist, None, dm['decisions'], engines, policy, mods)
        approved2 = {pathlib.Path(f['path']).stem for f in final['approved']}
        check('revalidation: approved rules that pass the technical checks are published', {'costly', 'generic'} <= approved2, str(sorted(approved2)))
        check('revalidation: approval cannot override a dynamic failure or truncation', 'slow' not in approved2 and 'truncated' not in approved2)
        check('revalidation: a rejected rule stays out', 'corrupt' not in approved2)
        check('revalidation: the final set was measured exactly as published', dyn['set_root'] == final['rules_root'] and final['publishable'], str(final['blockers']))
        # ---- run 3: upstream changes -----------------------------------------------------------------------
        prev_dir = work / 'previous'; shutil.rmtree(prev_dir, ignore_errors=True); (prev_dir).mkdir()
        for f in final['approved']:
            t = prev_dir / f['path']; t.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(dist / f['path'], t)
        (prev_dir / 'manifest.json').write_text(json.dumps({'files': [{'path': f['path'], 'sha256': f['sha256']} for f in final['approved']], 'rules_root': final['rules_root']}))
        write_dist(dist, upstream(2))
        cls, final3, dyn3 = run_pipeline(dist, prev_dir, dm['decisions'], engines, policy, mods)
        ch = final3['changes']; stems = {pathlib.Path(f['path']).stem for f in final3['approved']}
        check('changes: added, modified and retired files are detected by comparing manifests', ch['added'] >= 1 and ch['modified'] >= 1 and ch['removed'] >= 1 and 'good6' in stems and 'good5' not in stems, str(ch))
        check('changes: the edited rule is a NEW candidate: the earlier approval does not carry over', 'costly' not in stems)
        st, data = quarantine_client.call('POST', '/api/pipeline/submit', {'run_id': 'chain-3', 'candidates': quarantine_client.build_submissions(final3, dist)})
        if st != 200: print('submit run 3 failed:', st, data)
        res = {r['sha256']: r for r in data['results']}; rejected_hash = hashlib.sha256(upstream(1)['rules/synth/corrupt.yar'].encode()).hexdigest()
        check('pipeline: rejected content is excluded from the set and is not even re-submitted', rejected_hash not in res and 'corrupt' not in stems and not any(x['path'].endswith('corrupt.yar') for x in final3['submissions']))
        st, again = quarantine_client.call('POST', '/api/pipeline/submit', {'run_id': 'chain-3b', 'candidates': [{'sha256': rejected_hash, 'path': 'rules/synth/corrupt.yar', 'source': 'synth', 'bytes': 30, 'reasons': ['compile-error'], 'depends_on': []}]})
        check('quarantine: if it were submitted again the service recognises it and does not reopen it', st == 200 and again['results'][0]['status'] == 'known-rejected' and svc.api('reviewer', 'GET', f"/api/candidates/{again['results'][0]['id']}")[1]['state'] == 'REJECTED')
        new_costly = next((r for r in data['results'] if r['status'] == 'created' and r.get('previous')), None)
        check('quarantine: the new version of an approved rule is a new candidate linked to the earlier one', new_costly is not None)
        st, aud = svc.api('admin', 'GET', '/api/audit/verify')
        check('audit: the decision trail verifies as an unbroken chain', st == 200 and aud['ok'] and aud['entries'] >= 4, str(aud))
        make_public_candidate.build(dist, work / 'dist-public', prev_dir and json.loads((prev_dir / 'manifest.json').read_text()))
        leak = ''.join(p.read_text() for p in (work / 'dist-public').rglob('*') if p.is_file())
        check('privacy: nothing about quarantined or rejected rules is in the public candidate', all(n not in leak for n in ('truncated.yar', 'corrupt.yar', 'slow.yar')) and not (work / 'dist-public/rules/synth/slow.yar').exists())
        if a.publish: publish(work, a, final3, svc, check)
    finally:
        svc.stop()
    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed"); sys.exit(0 if all(RESULTS) else 1)

def publish(work, a, final, svc, check):
    """Sign, release, build the site and verify it publicly. Runs only in CI (OIDC, cosign, gh)."""
    pub = work / 'dist-public'; ws = work / 'ws'; shutil.rmtree(ws, ignore_errors=True)
    for d in ('scripts', 'config', 'web', 'docs-src'): shutil.copytree(ROOT / d, ws / d, ignore=shutil.ignore_patterns('__pycache__'))
    (ws / 'logs').mkdir(); shutil.copytree(pub, ws / 'dist'); env = {**os.environ}
    env.update(REAL_OIDC)
    def sh(*cmd, **kw):
        r = subprocess.run(cmd, cwd=ws, capture_output=True, text=True, env=env, **kw)
        if r.returncode: print(f"command failed: {' '.join(cmd)[:120]}\n{r.stderr[-600:]}", flush=True); raise SystemExit(1)
        return r
    sh(sys.executable, 'scripts/tlog.py', 'event', '--level', 'INFO', '--code', 'sources.fetched', '--run-id', 'chain', '--message', 'synthetic upstream')
    sh(sys.executable, 'scripts/tlog.py', 'entry-decision', '--dist', 'dist', '--decision', str(work / 'dist/decision.json'), '--run-id', 'chain')
    sh(sys.executable, 'scripts/tlog.py', 'event', '--level', 'INFO', '--code', 'release.approved', '--run-id', 'chain', '--message', 'chain test release')
    sh(sys.executable, 'scripts/tlog.py', 'checkpoint')
    cp = sorted((ws / 'logs/checkpoints').glob('*.txt'))[-1]
    sh('cosign', 'sign-blob', '--yes', '--bundle', str(cp.with_suffix('.sigstore.json')), str(cp)); shutil.copy(cp.with_suffix('.sigstore.json'), ws / 'logs/checkpoint.sigstore.json')
    sh(sys.executable, 'scripts/tlog.py', 'render')
    sh(sys.executable, 'scripts/seal.py'); sh('cosign', 'sign-blob', '--yes', '--bundle', 'dist/manifest.sigstore.json', 'dist/manifest.json')
    sh(sys.executable, 'scripts/tlog.py', 'release-proof', '--run-id', 'chain', '--manifest', 'dist/manifest.json', '--out', 'dist/inclusion-proof.json')
    sh('tar', '-czf', 'rules-release.tar.gz', '-C', 'dist', 'rules', 'manifest.json')
    check('release: the complete set was sealed and signed with Sigstore (keyless)', (ws / 'dist/manifest.sigstore.json').exists() and json.loads((ws / 'dist/manifest.json').read_text())['stats']['files'] == len(final['approved']))
    tag = f"chain-test-{os.environ.get('GITHUB_RUN_ID', int(time.time()))}"
    sh('gh', 'release', 'create', tag, '--repo', a.repo, '--prerelease', '--title', tag, '--notes', 'Synthetic chain test release; deleted at the end of the run.',
       'rules-release.tar.gz', 'dist/manifest.json', 'dist/manifest.sigstore.json', 'dist/inclusion-proof.json', 'logs/checkpoint.txt', 'logs/checkpoint.sigstore.json')
    try:
        site_ws = work / 'site-ws'; shutil.rmtree(site_ws, ignore_errors=True)
        for d in ('scripts', 'config', 'web', 'docs-src', 'logs'): shutil.copytree(ws / d, site_ws / d, ignore=shutil.ignore_patterns('__pycache__'))
        (site_ws / 'release').mkdir(); subprocess.run(['gh', 'release', 'download', tag, '--repo', a.repo, '--dir', str(site_ws / 'release')], check=True)
        check('release: every asset downloads from GitHub Releases', all((site_ws / 'release' / n).exists() for n in ('rules-release.tar.gz', 'manifest.json', 'manifest.sigstore.json', 'inclusion-proof.json')))
        hist = site_ws / 'history' / tag; hist.mkdir(parents=True); shutil.copy(site_ws / 'release/manifest.json', hist)
        view = json.loads(subprocess.run(['gh', 'release', 'view', tag, '--repo', a.repo, '--json', 'tagName,publishedAt,url,assets'], check=True, capture_output=True, text=True).stdout)
        (hist / 'meta.json').write_text(json.dumps({'tag': view['tagName'], 'published_at': view['publishedAt'], 'url': view['url'], 'asset_names': [x['name'] for x in view['assets']], 'package_bytes': next(x['size'] for x in view['assets'] if x['name'] == 'rules-release.tar.gz')}))
        built = subprocess.run([sys.executable, 'scripts/build_site.py'], cwd=site_ws, capture_output=True, text=True)
        if built.returncode: print(built.stdout[-1500:], built.stderr[-1500:], flush=True)   # a hidden build error cost a CI round trip
        built.check_returncode()
        site = site_ws / 'site'; check('site: built from the release, with catalog, history, stats and latest.json', all((site / n).exists() for n in ('catalog.json', 'releases.json', 'stats.json', 'latest.json', 'rules.html')))
        port = 23000 + os.getpid() % 15000; srv = subprocess.Popen([sys.executable, '-m', 'http.server', str(port), '--bind', '127.0.0.1', '--directory', str(site)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(1.5)
        try:
            ok = subprocess.run([sys.executable, str(ROOT / 'scripts/verify_live.py'), f'http://127.0.0.1:{port}/', '--identity', a.identity, '--repo', a.repo, '--external'], capture_output=True, text=True)
            check('public verification: signatures, every rule hash, catalog, proof, links and release assets', ok.returncode == 0 and 'LIVE VERIFICATION PASSED' in ok.stdout, ok.stdout.strip().splitlines()[-1] if ok.stdout.strip() else ok.stderr[-200:])
        finally: srv.terminate()
        victim = next((site / 'rules').rglob('*.yar')); victim.write_text(victim.read_text() + '\n// tampered\n')
        srv = subprocess.Popen([sys.executable, '-m', 'http.server', str(port), '--bind', '127.0.0.1', '--directory', str(site)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(1.5)
        try:
            bad = subprocess.run([sys.executable, str(ROOT / 'scripts/verify_live.py'), f'http://127.0.0.1:{port}/', '--identity', a.identity, '--repo', a.repo], capture_output=True, text=True)
            check('public verification: a tampered served rule is detected', bad.returncode != 0 and 'served bytes differ' in bad.stdout)
        finally: srv.terminate()
    finally:
        subprocess.run(['gh', 'release', 'delete', tag, '--repo', a.repo, '--yes', '--cleanup-tag'], capture_output=True)

if __name__ == '__main__': main()
