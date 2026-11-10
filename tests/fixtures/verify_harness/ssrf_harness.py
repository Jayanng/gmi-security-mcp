"""Local SSRF test harness for the verify_finding oracle.

Deliberately vulnerable, local only, stdlib only. Collector is a
temporary HTTP server on 127.0.0.1 that records every request it
sees. vulnerable_fetch fetches any URL it is given, with no
allowlist, so a PoC can point it at the collector with a nonce
and prove the server-side request happened.
"""

import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer


class Collector:
    """A temporary local collector. Records request paths."""

    def __init__(self):
        self.seen_paths = []
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                collector.seen_paths.append(self.path)
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *args):
        self._server.shutdown()
        self._server.server_close()

    @property
    def url(self):
        return "http://127.0.0.1:%d/collect" % self.port


def vulnerable_fetch(url):
    """Vulnerable: fetches any URL, no allowlist, no check."""
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read().decode(errors="replace")
