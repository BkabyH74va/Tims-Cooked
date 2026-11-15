#!/usr/bin/env python3
"""AGX Probe HTTP Server — runs on PC, reachable by iPhone at http://<pc-ip>:8080

Endpoints:
  GET  /status   — server status
  GET  /probe    — probe info (target, addresses, instructions)
  POST /crash    — receive crash report from phone (JSON body)
  GET  /pdf/<file> — serve PDF crash probes from ../analysis/pdf

Usage:
    python agx_server.py
    # Then on iPhone Safari: http://198.51.100.1:8080/status
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
from pathlib import Path

HOST = "0.0.0.0"
PORT = 8080

PDF_DIR = Path(__file__).resolve().parent.parent / "analysis" / "pdf"

STATUS = {
    "server": "agx-probe-server",
    "version": "1.0.0",
    "target": "iPhone18,1 / V53AP / t8150 / iOS 27.0.1 (24A446)",
    "kext": "com.apple.AGXG18P",
    "bug": "AGXG18P channel-index OOB read",
    "helper_fn": "0xfffffe0008556f54",
    "fix_added_in": "27.3 beta",
    "endpoints": [
        "GET  /status",
        "GET  /probe",
        "POST /crash",
        "GET  /pdf/<filename>",
    ],
    "safety": "Never test on daily phone. Wrong index = kernel panic.",
}


class ProbeHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default logging to keep output clean
        pass

    def do_GET(self):
        if self.path == "/status":
            self._send_json(200, STATUS)
        elif self.path == "/probe":
            info = {
                "target_device": "iPhone18,1 (V53AP, t8150)",
                "ios_version": "27.0.1 (24A446)",
                "kext": "com.apple.AGXG18P",
                "bug_type": "channel-index OOB read",
                "helper_address": "0xfffffe0008556f54",
                "probe_method": "IOConnectCallMethod on AGXDeviceUserClient",
                "instructions": [
                    "1. Compile AGXProbe.swift in Xcode (free Apple ID OK)",
                    "2. Run on secondary iPhone (NOT daily phone)",
                    "3. Tap 'Start Probe' — iterates selectors 0..15 x index 0..255",
                    "4. Watch for app crash / respring / reboot",
                    "5. Pull crash logs: ipsw.exe idev crash pull -o analysis/ios/crashes",
                ],
                "pc_ip": "198.51.100.1",
                "server_port": PORT,
            }
            self._send_json(200, info)
        elif self.path.startswith("/pdf/"):
            filename = self.path[len("/pdf/"):]
            pdf_path = PDF_DIR / filename
            if pdf_path.exists() and pdf_path.suffix.lower() == ".pdf":
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Length", str(pdf_path.stat().st_size))
                self.end_headers()
                with open(pdf_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self._send_json(404, {"error": "PDF not found", "available": sorted(p.name for p in PDF_DIR.glob("*.pdf"))})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/crash":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
            except Exception:
                data = {"raw": body.decode("utf-8", "replace")}
            data["received_at"] = __import__("datetime").datetime.now().isoformat()
            data["client"] = self.client_address[0]

            # Save crash report
            crash_dir = Path(__file__).resolve().parent.parent / "analysis" / "ios" / "crashes"
            crash_dir.mkdir(parents=True, exist_ok=True)
            fname = crash_dir / f"phone_crash_{data.get('received_at', 'unknown').replace(':', '-').replace('.', '-')}.json"
            with open(fname, "w") as f:
                json.dump(data, f, indent=2)

            print(f"[!] Crash report from {self.client_address[0]} saved to {fname}")
            self._send_json(200, {"status": "received", "saved": str(fname)})
        else:
            self._send_json(404, {"error": "not found"})

    def _send_json(self, code, obj):
        body = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = HTTPServer((HOST, PORT), ProbeHandler)
    print(f"AGX Probe HTTP Server listening on {HOST}:{PORT}")
    print(f"  iPhone URL: http://<pc-ip>:{PORT}/status")
    print(f"  PDF dir: {PDF_DIR}")
    print(f"  Crash reports: analysis/ios/crashes/")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
