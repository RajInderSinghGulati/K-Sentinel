#!/usr/bin/env python3
"""
K-Sentinel dashboard bridge.

Serves the dashboard and streams the agent's incident log (JSON-lines, written
by `ksentinel-agent -i <file>`) to the browser as Server-Sent Events.

Usage (inside the VM, or anywhere the log file is visible):
    python3 scripts/dashboard_bridge.py --log /tmp/ks/inc.json [--port 8080] [--min-severity MEDIUM]
Then open  http://localhost:8080/?live=1

Lima forwards guest ports to the host automatically, so this works from macOS.
"""
import argparse
import http.server
import json
import os
import socketserver
import time
from functools import partial

RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class Handler(http.server.SimpleHTTPRequestHandler):
    log_path = ""
    min_rank = 2

    def log_message(self, *args):  # keep console quiet
        pass

    def do_GET(self):
        if self.path.split("?")[0] == "/events":
            return self._sse()
        return super().do_GET()

    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            # Start from the end of the file: only new events are streamed.
            while not os.path.exists(self.log_path):
                time.sleep(0.5)
            with open(self.log_path, "r") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        self.wfile.write(b": keep-alive\n\n")
                        self.wfile.flush()
                        time.sleep(0.3)
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if RANK.get(rec.get("severity", "INFO"), 0) < self.min_rank:
                        continue
                    self.wfile.write(b"data: " + line.strip().encode() + b"\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--log", required=True, help="agent incident log (-i file)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--min-severity", default="MEDIUM", choices=list(RANK))
    args = ap.parse_args()

    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dashboard")
    Handler.log_path = args.log
    Handler.min_rank = RANK[args.min_severity]
    srv = Server(("0.0.0.0", args.port), partial(Handler, directory=root))
    print(f"[bridge] http://localhost:{args.port}/?live=1  (log={args.log}, min={args.min_severity})")
    srv.serve_forever()


if __name__ == "__main__":
    main()
