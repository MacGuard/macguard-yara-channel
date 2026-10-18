"""Integration tests of scripts/verify_public_release.py against the REAL published release.

Positive tests download the official release. Negative tests start from copies of those real files, damage exactly one thing and
check the exit code and the reported cause. Nothing here touches the official release. They need the network and cosign; if either is
missing they ERROR instead of skipping: a skipped verifier test proves nothing."""
import hashlib, http.server, io, json, os, pathlib, shutil, subprocess, sys, tarfile, tempfile, threading, unittest, urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/verify_public_release.py'
sys.path.insert(0, str(ROOT / 'scripts'))
import verify_public_release as V

REAL = None
def setUpModule():
    global REAL
    REAL = pathlib.Path(tempfile.mkdtemp(prefix='real-release-'))
    r = subprocess.run([sys.executable, str(SCRIPT), '--latest', '--output-dir', str(REAL), '--json'], capture_output=True, text=True)
    assert r.returncode == 0, f'the real release must verify before it can be used as a fixture: {r.stdout[-400:]} {r.stderr[-300:]}'
def tearDownModule(): shutil.rmtree(REAL, ignore_errors=True)

def run(*args, env=None):
    r = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env={**os.environ, **(env or {})})
    try: report = json.loads(r.stdout) if '--json' in args else None
    except Exception: report = None
    return r.returncode, report, r.stdout, r.stderr

def variant():
    d = pathlib.Path(tempfile.mkdtemp(prefix='variant-')); [shutil.copy2(p, d / p.name) for p in REAL.iterdir()]; return d
def repack(d, edit):
    """Rewrite rules-release.tar.gz after `edit(members: dict name -> bytes, order)`."""
    with tarfile.open(d / 'rules-release.tar.gz') as t: members = {m.name: (t.extractfile(m).read() if m.isreg() else None) for m in t.getmembers()}
    edit(members)
    with tarfile.open(d / 'rules-release.tar.gz', 'w:gz') as t:
        for n, data in members.items():
            if data is None: continue
            ti = tarfile.TarInfo(n); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
def failing(report, cid): return next((c for c in report['checks'] if c['id'] == cid and c['status'] == 'fail'), None)

class RealRelease(unittest.TestCase):
    def test_the_latest_public_release_verifies_end_to_end(self):
        code, rep, _, err = run('--latest', '--json'); self.assertEqual(code, 0, err)
        self.assertEqual(rep['result'], 'PASS'); ids = {c['id']: c['status'] for c in rep['checks']}
        for must in ('signature.manifest', 'signature.checkpoint', 'package.extract', 'files.sha256', 'merkle.rules_root', 'counts', 'checkpoint.matches_manifest', 'merkle.inclusion'): self.assertEqual(ids[must], 'pass', must)
        self.assertEqual(ids['consistency'], 'not_requested', 'a first verification must say that rollback protection is not established')
        self.assertEqual(rep['schemaVersion'], 1); self.assertRegex(rep['summary']['rules_root'], '^[0-9a-f]{64}$'); self.assertGreater(rep['summary']['yara_rules'], rep['summary']['files'])
    def test_an_earlier_release_whose_checkpoint_lives_in_the_repository_verifies(self):
        code, rep, _, err = run('--tag', 'rules-20261018-39103534527', '--json'); self.assertEqual(code, 0, err); self.assertIn('repository', rep['release']['note'])
    def test_the_directory_mode_verifies_the_same_files(self):
        code, rep, _, err = run('--directory', str(REAL), '--json'); self.assertEqual(code, 0, err); self.assertEqual(rep['release']['resolved_from'], 'directory')
    def test_consistency_between_two_real_releases_verifies(self):
        cp = urllib.request.urlopen('https://raw.githubusercontent.com/MacGuard/macguard-yara-channel/main/logs/checkpoints/00000020.txt').read()
        f = pathlib.Path(tempfile.mkdtemp()) / 'prev.txt'; f.write_bytes(cp); code, rep, _, err = run('--directory', str(REAL), '--previous-checkpoint', str(f), '--json')
        self.assertEqual(code, 0, err); self.assertEqual(next(c for c in rep['checks'] if c['id'] == 'consistency')['status'], 'pass')
    def test_trust_state_is_written_only_after_a_full_pass_and_prevents_rollback(self):
        ts = pathlib.Path(tempfile.mkdtemp()) / 'trust.json'; code, rep, _, err = run('--directory', str(REAL), '--trust-state', str(ts), '--json'); self.assertEqual(code, 0, err)
        saved = json.loads(ts.read_text()); self.assertEqual(saved['rules_root'], rep['summary']['rules_root'])
        ts.write_text(json.dumps({'size': saved['size'] + 50, 'root': 'ab' * 32})); code, rep, _, _ = run('--directory', str(REAL), '--trust-state', str(ts), '--json')
        self.assertEqual(code, 3); self.assertIn('ROLLBACK', failing(rep, 'consistency')['detail']); self.assertEqual(json.loads(ts.read_text())['size'], saved['size'] + 50, 'a failed run must not touch the trust state')

class Tampering(unittest.TestCase):
    def check(self, d, code, cid, *args, contains=None):
        got, rep, _, err = run('--directory', str(d), '--json', *args); self.assertEqual(got, code, f'{cid}: {err}\n{json.dumps(rep["checks"])[:600] if rep else ""}')
        f = failing(rep, cid); self.assertIsNotNone(f, f'expected {cid} to fail: {[(c["id"], c["status"]) for c in rep["checks"]]}')
        if contains: self.assertIn(contains, f['detail'])
        self.assertEqual(rep['result'], 'FAIL'); return rep
    def test_a_modified_rule_is_an_integrity_failure(self):
        d = variant(); name = next(n for n in json.loads((d / 'manifest.json').read_text())['files'] and [f['path'] for f in json.loads((d / 'manifest.json').read_text())['files']])
        repack(d, lambda m: m.__setitem__(name, m[name] + b'\n// tampered\n')); self.check(d, 1, 'files.sha256', contains='does not match')
    def test_a_deleted_rule_is_an_integrity_failure(self):
        d = variant(); name = json.loads((d / 'manifest.json').read_text())['files'][0]['path']; repack(d, lambda m: m.pop(name)); self.check(d, 1, 'files.sha256', contains='missing')
    def test_an_extra_file_is_an_integrity_failure(self):
        d = variant(); repack(d, lambda m: m.__setitem__('rules/extra/evil.yar', b'rule Evil { condition: true }')); self.check(d, 1, 'files.sha256', contains='not in the manifest')
    def test_a_manifest_changed_after_signing_fails_the_signature(self):
        d = variant(); m = json.loads((d / 'manifest.json').read_text()); m['files'][0]['sha256'] = '0' * 64; (d / 'manifest.json').write_text(json.dumps(m))
        self.check(d, 2, 'signature.manifest')
    def test_the_wrong_sigstore_bundle_is_rejected(self):
        d = variant(); shutil.copy(d / 'checkpoint.sigstore.json', d / 'manifest.sigstore.json'); self.check(d, 2, 'signature.manifest')
    def test_a_workflow_identity_that_is_not_the_publisher_is_rejected(self):
        self.check(REAL, 2, 'signature.manifest', '--identity', 'https://github.com/MacGuard/macguard-yara-channel/.github/workflows/evil.yml@refs/heads/main')
    def test_a_different_oidc_issuer_is_rejected(self):
        self.check(REAL, 2, 'signature.manifest', '--issuer', 'https://accounts.google.com')
    def test_a_checkpoint_changed_after_signing_fails_its_signature(self):
        d = variant(); lines = (d / 'checkpoint.txt').read_text().split('\n'); lines[1] = str(int(lines[1]) + 1); (d / 'checkpoint.txt').write_text('\n'.join(lines)); self.check(d, 2, 'signature.checkpoint')
    def test_a_forged_inclusion_proof_is_a_merkle_failure(self):
        d = variant(); p = json.loads((d / 'inclusion-proof.json').read_text()); p['proof'][0] = 'ff' * 32; (d / 'inclusion-proof.json').write_text(json.dumps(p)); self.check(d, 3, 'merkle.inclusion', contains='does not lead')
    def test_an_inclusion_proof_for_another_entry_is_rejected(self):
        d = variant(); p = json.loads((d / 'inclusion-proof.json').read_text()); e = json.loads(p['entry']); e['details']['rules_root'] = '0' * 64; p['entry'] = json.dumps(e, sort_keys=True, separators=(',', ':')); (d / 'inclusion-proof.json').write_text(json.dumps(p)); self.check(d, 3, 'merkle.inclusion')
    def test_a_forged_consistency_proof_is_rejected(self):
        d = variant(); c = json.loads((d / 'consistency.json').read_text()); c['proof'][0] = 'ee' * 32; (d / 'consistency.json').write_text(json.dumps(c))
        cp = pathlib.Path(tempfile.mkdtemp()) / 'prev.txt'; cp.write_bytes(urllib.request.urlopen('https://raw.githubusercontent.com/MacGuard/macguard-yara-channel/main/logs/checkpoints/00000020.txt').read())
        self.check(d, 3, 'consistency', '--previous-checkpoint', str(cp), contains='does not verify')
    def test_a_fork_at_the_same_size_is_detected(self):
        d = variant(); size = int((d / 'checkpoint.txt').read_text().split('\n')[1]); ts = d / 'trust.json'; ts.write_text(json.dumps({'size': size, 'root': 'cd' * 32}))
        self.check(d, 3, 'consistency', '--trust-state', str(ts), contains='FORK')
    def test_a_missing_artifact_is_an_incomplete_set(self):
        d = variant(); (d / 'inclusion-proof.json').unlink(); self.check(d, 6, 'artifacts', contains='inclusion-proof.json')
    def test_a_tar_with_path_traversal_is_refused(self):
        d = variant(); buf = io.BytesIO()
        with tarfile.open(d / 'rules-release.tar.gz', 'w:gz') as t:
            for n, data in (('../../evil.txt', b'x'), ('manifest.json', (d / 'manifest.json').read_bytes())):
                ti = tarfile.TarInfo(n); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
        self.check(d, 6, 'package.extract', contains='unsafe path'); self.assertFalse(pathlib.Path(tempfile.gettempdir(), 'evil.txt').exists())
    def test_a_malicious_symlink_is_refused(self):
        d = variant()
        with tarfile.open(d / 'rules-release.tar.gz', 'w:gz') as t:
            ti = tarfile.TarInfo('rules/link'); ti.type = tarfile.SYMTYPE; ti.linkname = '/etc/passwd'; t.addfile(ti)
        self.check(d, 6, 'package.extract', contains='link')
    def test_an_archive_that_expands_beyond_the_limit_is_refused(self):
        d = variant(); old = dict(V.LIMITS); V.LIMITS['file_bytes'] = 1000
        try: got = V.main(['--directory', str(d), '--json']) if False else None
        finally: V.LIMITS.update(old)
        # run the real extractor with a tiny limit instead of editing the script
        t = pathlib.Path(tempfile.mkdtemp()); (t / 'a.txt').write_bytes(b'0' * 5000)
        with tarfile.open(d / 'bomb.tar.gz', 'w:gz') as tf: tf.add(t / 'a.txt', 'rules/a.txt')
        V.LIMITS['file_bytes'] = 1000
        try:
            with self.assertRaises(V.Fail) as cm: V.safe_extract(d / 'bomb.tar.gz', pathlib.Path(tempfile.mkdtemp()))
        finally: V.LIMITS.update(old)
        self.assertEqual(cm.exception.code, 6)
    def test_without_cosign_nothing_is_reported_as_verified(self):
        got, rep, _, _ = run('--directory', str(REAL), '--cosign', '/nonexistent/cosign', '--json'); self.assertEqual(got, 5); self.assertEqual(rep['result'], 'FAIL')
        self.assertFalse(any(c['id'] == 'merkle.inclusion' and c['status'] == 'pass' for c in rep['checks']), 'no later check may pass without the signature tool')

class FakeGitHub(http.server.BaseHTTPRequestHandler):
    tags, latest_calls, requests, truncate, moved = {}, 0, [], None, False
    def log_message(self, *a): pass
    def _json(self, obj): b = json.dumps(obj).encode(); self.send_response(200); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        cls = type(self); cls.requests.append(self.path); base = f'http://127.0.0.1:{self.server.server_port}'
        def rel(tag): return {'tag_name': tag, 'draft': False, 'html_url': f'{base}/{tag}', 'published_at': '2026-10-18T00:00:00Z', 'assets': [{'name': p.name, 'size': p.stat().st_size, 'browser_download_url': f'{base}/dl/{tag}/{p.name}'} for p in sorted(REAL.iterdir())]}
        if self.path.endswith('/releases/latest'):
            cls.latest_calls += 1; return self._json(rel('tag-B' if cls.moved and cls.latest_calls > 1 else 'tag-A'))
        if '/releases/tags/' in self.path: return self._json(rel(self.path.rsplit('/', 1)[1]))
        if self.path.startswith('/dl/'):
            name = self.path.rsplit('/', 1)[1]; data = (REAL / name).read_bytes()
            if cls.truncate == name:   # promise everything, deliver half
                self.send_response(200); self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data[:len(data) // 2]); return
            self.send_response(200); self.send_header('Content-Length', str(len(data))); self.end_headers(); return self.wfile.write(data)
        self.send_response(404); self.end_headers()

class Network(unittest.TestCase):
    def serve(self):
        FakeGitHub.latest_calls, FakeGitHub.requests, FakeGitHub.truncate, FakeGitHub.moved = 0, [], None, False
        s = http.server.ThreadingHTTPServer(('127.0.0.1', 0), FakeGitHub); threading.Thread(target=s.serve_forever, daemon=True).start(); self.addCleanup(s.shutdown); return f'http://127.0.0.1:{s.server_port}'
    def test_the_pinned_download_flow_works_against_a_local_api(self):
        api = self.serve(); code, rep, _, err = run('--latest', '--api-url', api, '--json'); self.assertEqual(code, 0, err); self.assertEqual(rep['release']['tag'], 'tag-A')
    def test_a_truncated_download_is_a_network_failure_not_a_pass(self):
        api = self.serve(); FakeGitHub.truncate = 'rules-release.tar.gz'; code, rep, _, _ = run('--latest', '--api-url', api, '--json')
        self.assertEqual(code, 4); self.assertIn('incomplete download', json.dumps(rep)); self.assertNotEqual(rep['result'], 'PASS')
    def test_if_latest_moves_during_the_run_the_pinned_release_is_the_one_verified(self):
        api = self.serve(); FakeGitHub.moved = True; code, rep, _, err = run('--latest', '--api-url', api, '--json'); self.assertEqual(code, 0, err)
        self.assertEqual(rep['release']['tag'], 'tag-A'); self.assertTrue(rep['release']['latest_moved'])
        self.assertTrue(all('/tag-B/' not in p for p in FakeGitHub.requests), 'nothing may be downloaded from the release that appeared meanwhile')
    def test_a_network_error_is_exit_4(self):
        code, rep, _, _ = run('--latest', '--api-url', 'http://127.0.0.1:9', '--json'); self.assertEqual(code, 4); self.assertEqual(rep['result'], 'FAIL')
    def test_a_release_with_a_missing_mandatory_artifact_is_incomplete(self):
        api = self.serve(); orig = FakeGitHub.do_GET
        def patched(h):
            if h.path.endswith('/releases/tags/tag-A') or h.path.endswith('/releases/latest'):
                h.send_response(200); b = json.dumps({'tag_name': 'tag-A', 'draft': False, 'assets': [{'name': 'manifest.json', 'size': 1, 'browser_download_url': 'x'}]}).encode(); h.send_header('Content-Length', str(len(b))); h.end_headers(); h.wfile.write(b)
            else: orig(h)
        FakeGitHub.do_GET = patched
        try: code, rep, _, _ = run('--latest', '--api-url', api, '--json')
        finally: FakeGitHub.do_GET = orig
        self.assertIn(code, (4, 6), rep and rep['checks'])

class CommandLine(unittest.TestCase):
    def test_options_are_mutually_exclusive_and_one_is_required(self):
        self.assertNotEqual(run('--latest', '--tag', 'x')[0], 0); self.assertNotEqual(run()[0], 0)
    def test_the_human_report_names_the_checks_and_the_limits_of_what_it_proves(self):
        code, _, out, _ = run('--directory', str(REAL)); self.assertEqual(code, 0); self.assertIn('rules_root', out); self.assertIn('do not prove the rules are good', out); self.assertIn('rollback protection is NOT established', out)
if __name__ == '__main__': unittest.main()
