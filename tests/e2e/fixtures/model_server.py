"""Deterministic offline model endpoint used by the Linux wiring harness."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys
from pathlib import Path

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        _ = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        count = int(COUNT.read_text() or "0") + 1
        COUNT.write_text(str(count))
        body = {"diagnose": "fixture", "plan": {"operations": []}, "critic": {"approved": True}}
        encoded = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(encoded))); self.end_headers(); self.wfile.write(encoded)
    def log_message(self, *_): pass

COUNT = Path(sys.argv[2])
COUNT.write_text("0")
HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
