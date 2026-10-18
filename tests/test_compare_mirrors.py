import http.server, json, pathlib, sys, threading, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import compare_mirrors as cm

LATEST = {'manifest_sha256': 'a' * 64, 'package_sha256': 'b' * 64, 'package_bytes': 10, 'rules_root': 'c' * 64, 'stats': {'files': 2}, 'log': {'size': 5, 'root': 'd' * 64}}

def serve(doc, code=200):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(code); self.end_headers(); self.wfile.write(json.dumps(doc).encode() if code == 200 else b'no')
        def log_message(self, *a): pass
    srv = http.server.HTTPServer(('127.0.0.1', 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f'http://127.0.0.1:{srv.server_port}/'

class CompareTests(unittest.TestCase):
    def run_case(self, a, b, code_b=200):
        sa, ua = serve(a); sb, ub = serve(b, code_b)
        try: return cm.main([ua, ub])
        finally: sa.shutdown(); sb.shutdown(); sa.server_close(); sb.server_close()
    def test_identical_releases(self): self.assertEqual(self.run_case(LATEST, dict(LATEST)), 0)
    def test_a_stale_mirror_is_reported(self):
        for field, value in (('manifest_sha256', 'e' * 64), ('package_sha256', 'e' * 64), ('rules_root', 'e' * 64), ('log', {'size': 4, 'root': 'd' * 64}), ('stats', {'files': 1})):
            self.assertEqual(self.run_case(LATEST, {**LATEST, field: value}), 3, field)
    def test_an_unreadable_host_is_not_reported_as_equal(self):
        self.assertEqual(self.run_case(LATEST, LATEST, code_b=404), 2)
        self.assertEqual(cm.main(['http://127.0.0.1:1/', 'http://127.0.0.1:1/']), 2)
