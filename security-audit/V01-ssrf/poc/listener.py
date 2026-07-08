#!/usr/bin/env python3
# Ecoute sur 127.0.0.1:8081 et logge toute connexion (preuve de SSRF).
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(2048)
        print("[SSRF] connexion recue:", self.client_address, data[:80])
with socketserver.TCPServer(("127.0.0.1", 8081), H) as s:
    print("listener SSRF sur 127.0.0.1:8081"); s.serve_forever()
