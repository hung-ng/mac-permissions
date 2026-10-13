#!/usr/bin/env python3
import argparse
import hmac
import json
import os
import pathlib
import secrets
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from api import APIError, Client, default_token


def serve(endpoint, token_file, port=43188, open_browser=False):
    client = Client(endpoint, token_file)
    browser_token = secrets.token_hex(32)
    html = (pathlib.Path(__file__).parent / "controller.html").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, status, data, content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(data)

        def process(self, method):
            expected_host = "127.0.0.1:" + str(self.server.server_port)
            if self.headers.get("Host") != expected_host:
                self.send(403, b'{"error":"Invalid Host"}'); return
            path = urllib.parse.urlsplit(self.path).path
            if method == "GET" and path == "/":
                self.send(200, html, "text/html; charset=utf-8"); return
            if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + browser_token):
                self.send(401, b'{"error":"Open the controller URL printed in your terminal"}'); return
            origin = self.headers.get("Origin")
            if origin and origin != "http://" + expected_host:
                self.send(403, b'{"error":"Cross-origin request refused"}'); return
            routes = {"/api/status": "/v1/status", "/api/requests": "/v1/requests"}
            try:
                if method == "GET" and path in routes:
                    result = client.call("GET", routes[path])
                elif method == "POST" and path == "/api/action":
                    length = int(self.headers.get("Content-Length", "0"))
                    if length <= 0 or length > 4096 or self.headers.get("Transfer-Encoding"):
                        raise APIError("Invalid action body")
                    body = json.loads(self.rfile.read(length))
                    action = body.get("action")
                    if action not in ("approve", "deny", "retry", "cancel"):
                        raise APIError("Unsupported action")
                    request_id = body.get("id", "")
                    if len(request_id) != 36 or any(c not in "0123456789abcdef-" for c in request_id):
                        raise APIError("Invalid request")
                    result = client.call("POST", "/v1/requests/" + request_id + "/" + action, dict(fingerprint=body.get("fingerprint")))
                elif method == "POST" and path == "/api/probe":
                    # Fixed metadata-only path; the browser cannot submit arbitrary commands.
                    status = client.call("GET", "/v1/status")
                    result = client.call("POST", "/v1/requests", dict(operation="probe", path=status["suggestedProbePath"]))
                else:
                    self.send(404, b'{"error":"Unknown route"}'); return
                self.send(200, json.dumps(result).encode())
            except (APIError, ValueError, TypeError, OSError) as error:
                self.send(409, json.dumps(dict(error=str(error))).encode())

        def do_GET(self):
            self.process("GET")

        def do_POST(self):
            self.process("POST")

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    url = "http://127.0.0.1:" + str(server.server_port) + "/#" + browser_token
    print("Controller: " + url, flush=True)
    print("Keep this URL private. The owner credential stays in this controller process.", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the Mac Permissions controller on the owner's local computer")
    parser.add_argument("--endpoint", default="http://127.0.0.1:43187")
    parser.add_argument("--token-file", default=default_token("owner"))
    parser.add_argument("--port", type=int, default=43188)
    parser.add_argument("--open", action="store_true")
    options = parser.parse_args()
    try:
        serve(options.endpoint, options.token_file, options.port, options.open)
    except (APIError, OSError) as error:
        parser.exit(1, str(error) + "\n")
