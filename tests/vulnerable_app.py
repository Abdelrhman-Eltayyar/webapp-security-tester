#!/usr/bin/env python3
"""Deliberately weak local demo server used ONLY to test scan_web.py.
Binds to 127.0.0.1. Never deploy this."""
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

class H(BaseHTTPRequestHandler):
    server_version = "DemoServer/1.2.3"
    def log_message(self, *a): pass
    def send(self, code, body, ctype="text/html", extra=None):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        origin = self.headers.get("Origin")
        if origin:                       # CORS reflection with credentials (deliberate flaw)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if u.path == "/":
            self.send(200, "<html><body><a href='/search?q=test'>search</a>"
                           "<form method='post' action='/note'><input name='text'><input type='submit'></form>"
                           "<form method='post' action='/login'><input name='u'><input type='password' name='p'></form></body></html>",
                      extra={"Set-Cookie": "sessionid=abc123; Path=/"})
        elif u.path == "/search":
            v = q.get("q", [""])[0]
            if "'" in v:
                self.send(500, "You have an error in your SQL syntax; check the manual near '" + v + "' at line 1")
            else:
                self.send(200, "<html>Results for " + v + "</html>")      # unencoded reflection
        elif u.path == "/.env":
            self.send(200, "DB_PASSWORD=hunter2\nSECRET_KEY=abcdef\n", "text/plain")
        elif u.path == "/admin":
            self.send(200, "<html>Admin panel</html>")
        elif u.path == "/api/users":
            self.send(200, json.dumps([{"id": 1, "email": "a@x.com"}, {"id": 2, "email": "b@x.com"}]), "application/json")
        elif u.path == "/openapi.json":
            self.send(200, json.dumps({"openapi": "3.0.0"}), "application/json")
        else:
            self.send(404, "Traceback (most recent call last):\n  File \"/var/www/app.py\", line 10, in handler\nKeyError")
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0); self.rfile.read(n)
        if self.path == "/graphql":
            self.send(200, json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}), "application/json")
        else:
            self.send(500, "Traceback (most recent call last):\n  File \"/var/www/app.py\"\nJSONDecodeError")

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    HTTPServer(("127.0.0.1", port), H).serve_forever()
