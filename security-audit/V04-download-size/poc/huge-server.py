#!/usr/bin/env python3
# Sert un flux 'infini' pour prouver l'absence de plafond de telechargement.
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type","image/png"); self.end_headers()
        chunk = b"\x00" * (1<<20)
        try:
            while True: self.wfile.write(chunk)   # jamais termine
        except BrokenPipeError: pass
HTTPServer(("127.0.0.1",8082), H).serve_forever()
