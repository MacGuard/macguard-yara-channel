import hashlib, json, os, pathlib, shutil, subprocess, sys, tempfile, time, unittest, urllib.request
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import decide, quarantine_client as qc

ROOT = pathlib.Path(__file__).resolve().parents[1]
NODE = shutil.which('node')
AUD = 'https://admin.example.test'

@unittest.skipUnless(NODE, 'node is required to run the real quarantine service (a skipped test is not a pass)')
class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 21000 + os.getpid() % 15000
        cls.srv = subprocess.Popen([NODE, str(ROOT / 'admin/worker/test/devserver.js'), str(cls.port), '--empty'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(100):
            try: urllib.request.urlopen(f'http://127.0.0.1:{cls.port}/__sessions', timeout=1); break
            except Exception: time.sleep(0.1)
        cls.base = f'http://127.0.0.1:{cls.port}'
    @classmethod
    def tearDownClass(cls): cls.srv.terminate(); cls.srv.wait()
    def env(self, workflow='daily.yml', url=None):
        os.environ.update(QUARANTINE_URL=url if url is not None else self.base, QUARANTINE_AUDIENCE=AUD, ACTIONS_ID_TOKEN_REQUEST_URL=f'{self.base}/__oidc?workflow={workflow}', ACTIONS_ID_TOKEN_REQUEST_TOKEN='test-request-token')
    def setUp(self): self.env(); self.d = pathlib.Path(tempfile.mkdtemp())
    def tearDown(self): shutil.rmtree(self.d, ignore_errors=True)
    def decision(self, rules):
        subs = []
        for name, text in rules.items():
            (self.d / name).parent.mkdir(parents=True, exist_ok=True); (self.d / name).write_text(text)
            subs.append({'path': name, 'sha256': hashlib.sha256(text.encode()).hexdigest(), 'bytes': len(text), 'source': 'community', 'reasons': ['costly-regex'], 'depends_on': []})
        return {'submissions': subs}
    def reviewer_call(self, method, path, body=None):
        sid = json.load(urllib.request.urlopen(self.base + '/__sessions'))['reviewer']; cookie = f'__Host-mg_session={sid}'
        me = json.load(urllib.request.urlopen(urllib.request.Request(self.base + '/api/me', headers={'Cookie': cookie})))
        req = urllib.request.Request(self.base + path, method=method, data=None if body is None else json.dumps(body).encode(), headers={'Cookie': cookie, 'X-CSRF-Token': me['csrf'], 'Origin': self.base, 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req) as r: return r.status, json.load(r)
        except urllib.error.HTTPError as e: return e.code, json.load(e)

    def test_full_loop_submit_review_decide_release(self):
        dec = self.decision({'rules/slow.yar': 'rule S { condition: true }', 'rules/other.yar': 'rule O { condition: true }'})
        st, data = qc.call('POST', '/api/pipeline/submit', {'run_id': '9', 'candidates': qc.build_submissions(dec, self.d)})
        self.assertEqual(st, 200); self.assertEqual([r['status'] for r in data['results']], ['created', 'created'])
        st, again = qc.call('POST', '/api/pipeline/submit', {'run_id': '10', 'candidates': qc.build_submissions(dec, self.d)}); self.assertEqual([r['status'] for r in again['results']], ['known', 'known'])
        st, listing = self.reviewer_call('GET', '/api/candidates?q=slow'); self.assertEqual(listing['total'], 1); cid, ver = listing['items'][0]['id'], listing['items'][0]['version']
        st, res = self.reviewer_call('POST', '/api/decisions', {'action': 'approve', 'ids': [cid], 'reason': 'regex checked by hand', 'request_id': 'req_' + 'a' * 20, 'expect': {cid: ver}}); self.assertEqual(st, 200)
        st, dm = qc.call('GET', '/api/pipeline/decisions'); sha = dec['submissions'][0]['sha256']
        self.assertEqual(dm['decisions'][sha]['state'], 'APPROVED_PENDING_VALIDATION'); self.assertNotIn(dec['submissions'][1]['sha256'], dm['decisions'])
        # the pipeline consumes the decision: the waivable finding is waived, a technical failure would not be
        cls = [{'path': 'rules/slow.yar', 'sha256': sha, 'bytes': 10, 'source': 'community', 'state': 'QUARANTINED', 'reasons': [{'code': 'costly-regex', 'severity': 'review', 'detail': ''}], 'depends_on': []}]
        out = decide.decide(cls, decisions=dm['decisions'], dynamic_required=False); self.assertEqual([a['path'] for a in out['approved']], ['rules/slow.yar'])
        # only the publish workflow may mark it released
        st, denied = qc.call('POST', '/api/pipeline/released', {'tag': 'rules-x', 'hashes': [sha]}); self.assertEqual(st, 403)
        self.env('publish.yml'); st, rel = qc.call('POST', '/api/pipeline/released', {'tag': 'rules-x', 'hashes': [sha]}); self.assertEqual((st, len(rel['changed'])), (200, 1))
    def test_the_service_being_down_is_reported_and_never_blocks(self):
        self.env(url='http://127.0.0.1:9')
        st, data = qc.call('GET', '/api/pipeline/decisions'); self.assertEqual(st, 0); self.assertIn('unreachable', data['error'])
    def test_no_configuration_is_reported_as_unavailable(self):
        os.environ.pop('QUARANTINE_URL', None); self.assertEqual(qc.call('GET', '/x')[0], 0)
    def test_a_token_for_the_wrong_audience_is_refused_by_the_service(self):
        os.environ['QUARANTINE_AUDIENCE'] = 'https://elsewhere.example'; st, data = qc.call('GET', '/api/pipeline/decisions'); self.assertEqual(st, 401)
    def test_submissions_carry_the_rule_content_but_never_more_than_1_mb(self):
        dec = self.decision({'rules/a.yar': 'rule A { condition: true }'}); items = qc.build_submissions(dec, self.d)
        self.assertIn('content_b64', items[0])
        (self.d / 'rules/a.yar').write_bytes(b'x' * 1_100_000); self.assertNotIn('content_b64', qc.build_submissions(dec, self.d)[0])
if __name__ == '__main__': unittest.main()


class ClientSafetyTests(unittest.TestCase):
    def test_the_token_is_only_sent_over_https_or_to_loopback(self):
        self.assertTrue(qc.insecure('http://example.com')); self.assertTrue(qc.insecure('ftp://x')); self.assertTrue(qc.insecure('http://127.0.0.1.evil.test'))
        self.assertFalse(qc.insecure('https://admin.example.test')); self.assertFalse(qc.insecure('http://127.0.0.1:8080')); self.assertFalse(qc.insecure('http://localhost:9'))
        os.environ['QUARANTINE_URL'] = 'http://admin.example.test'
        try: st, data = qc.call('GET', '/api/pipeline/decisions')
        finally: os.environ.pop('QUARANTINE_URL')
        self.assertEqual(st, 0); self.assertIn('https', data['error'])

    def test_redirects_are_not_followed_so_the_authorization_header_stays_with_the_service(self):
        import http.server, threading
        seen = []
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get('Authorization')))
                if self.path == '/start': self.send_response(302); self.send_header('Location', '/elsewhere'); self.end_headers()
                else: self.send_response(200); self.end_headers(); self.wfile.write(b'{}')
            def log_message(self, *a): pass
        srv = http.server.HTTPServer(('127.0.0.1', 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            req = urllib.request.Request(f'http://127.0.0.1:{srv.server_port}/start', headers={'Authorization': 'Bearer secret'})
            with self.assertRaises(urllib.error.HTTPError) as cm: qc.OPENER.open(req, timeout=5)
            self.assertEqual(cm.exception.code, 302); self.assertEqual([p for p, _ in seen], ['/start'])
        finally: srv.shutdown(); srv.server_close()

    def test_a_submission_path_cannot_leave_the_candidate_folder(self):
        d = pathlib.Path(tempfile.mkdtemp())
        try:
            (d / 'dist').mkdir(); (d / 'secret.txt').write_text('private')
            for bad in ('../secret.txt', str(d / 'secret.txt')):
                with self.assertRaises(ValueError): qc.build_submissions({'submissions': [{'path': bad, 'sha256': 'a' * 64, 'bytes': 1, 'source': 's', 'reasons': []}]}, d / 'dist')
        finally: shutil.rmtree(d, ignore_errors=True)
