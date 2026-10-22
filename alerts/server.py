"""A small threaded HTTP server around alerts.api.App for local use and for the browser tests. It serves the static site and the API from ONE origin
(so cookies and CSRF work without CORS) and binds to 127.0.0.1 unless told otherwise. It is not a production server: no TLS, no process supervision."""
from __future__ import annotations
import http.server
import sys
from typing import Tuple
from urllib.parse import urlsplit, parse_qs

from . import api


def make_handler(app: api.App):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "macguard-alerts"
        sys_version = ""

        def _serve(self):
            u = urlsplit(self.path)
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(min(n, api.MAX_BODY + 1)) if n else b""
            if n > api.MAX_BODY:
                body = b"x" * (api.MAX_BODY + 1)
            req = api.Request(self.command, u.path, parse_qs(u.query, keep_blank_values=True), dict(self.headers.items()), body, self.client_address[0])
            resp = app.handle(req)
            self.send_response(resp.status)
            for k, v in resp.headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp.body) if self.command != "HEAD" else 0))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(resp.body)

        do_GET = do_POST = do_PATCH = do_DELETE = do_HEAD = _serve

        def log_message(self, fmt, *args):                       # the app's access log is already redacted; never log the raw request line
            line = app.access_log[-1] if app.access_log else ""
            sys.stderr.write(line + "\n")
    return H


def serve(app: api.App, host: str = "127.0.0.1", port: int = 8080) -> Tuple[http.server.ThreadingHTTPServer, str]:
    srv = http.server.ThreadingHTTPServer((host, port), make_handler(app))
    srv.daemon_threads = True
    return srv, f"http://{host}:{srv.server_address[1]}"
