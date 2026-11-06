#!/usr/bin/env python3
"""HTTP backend that replies with its name. Used by the lab, not by XDP."""

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = os.environ.get("BACKEND_NAME", "backend").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    pidfile = os.environ.get("PIDFILE")
    if pidfile:
        with open(pidfile, "w", encoding="ascii") as handle:
            handle.write(str(os.getpid()))
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
