"""Append-only JSON log service. Accepts POST /log, writes to JSONL file."""

import json
import os
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

LOG_FILE = Path(os.environ.get("LOG_FILE", "/data/agent.jsonl"))
LOG_PORT = int(os.environ.get("LOG_PORT", "8081"))


class LogHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/log":
            self.send_error(404)
            return
        content_type = self.headers.get("Content-Type", "")
        if "json" not in content_type:
            self.send_error(400, "Content-Type must be application/json")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            entry = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
            return
        entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        pass  # Suppress default logging


if __name__ == "__main__":
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    server = HTTPServer(("0.0.0.0", LOG_PORT), LogHandler)
    print(f"Log service listening on :{LOG_PORT}, writing to {LOG_FILE}")
    server.serve_forever()
