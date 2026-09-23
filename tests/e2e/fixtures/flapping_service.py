"""Finite disposable HTTP/service fault fixture; never used by product code."""
import http.server
import os
from pathlib import Path
import sys
import threading
import time

root=Path(sys.argv[1]);mode=sys.argv[2];port=int(sys.argv[3])
counter=root/'starts'
count=int(counter.read_text())+1 if counter.exists() else 1
counter.write_text(str(count))
if mode in ('startlimit','exit_loop') and (count<=3 or mode=='exit_loop'):
    raise SystemExit(3)
if mode=='relapse' and count>1:
    threading.Timer(15,lambda:os._exit(3)).start()

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if mode in ('hung','relapse') and count==1:
            time.sleep(120)
        self.send_response(503 if mode=='unrecovered' else 200)
        self.end_headers()
        self.wfile.write(b'healthy')
    def log_message(self,*args):
        pass

http.server.ThreadingHTTPServer(('127.0.0.1',port),Handler).serve_forever()
