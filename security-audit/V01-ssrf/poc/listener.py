#!/usr/bin/env python3
# Listens on 127.0.0.1:8081 and logs every connection (proof of SSRF).
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(2048)
        print("[SSRF] connection received:", self.client_address, data[:80])
with socketserver.TCPServer(("127.0.0.1", 8081), H) as s:
    print("SSRF listener on 127.0.0.1:8081"); s.serve_forever()
