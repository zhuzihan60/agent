"""Deterministic offline notification sink used by the Linux wiring harness."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
from pathlib import Path

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        count = int(COUNT.read_text() or "0") + 1
        COUNT.write_text(str(count))
        self.send_response(202); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *_): pass

COUNT = Path(sys.argv[2])
COUNT.write_text("0")
HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
