#!/usr/bin/env python3
"""Peregrine alert sink: Alertmanager webhook receiver -> /var/log/peregrine-alerts.jsonl."""
import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG_PATH = "/var/log/peregrine-alerts.jsonl"


class SinkHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length))
            payload["_sink_received_utc"] = datetime.now(timezone.utc).isoformat()
            line = json.dumps(payload, separators=(",", ":")) + "\n"
            fd = os.open(LOG_PATH, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line)
            self.send_response(200)
            self.end_headers()
        except Exception:
            sys.exit(1)  # silent non-zero exit; systemd Restart=on-failure revives us

    def log_message(self, fmt, *args):  # keep journald quiet on every delivery
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9094), SinkHandler).serve_forever()
