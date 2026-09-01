import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .config import SETTINGS
from .service import ObservatoryService


class ObservatoryHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, service: ObservatoryService):
        self.service = service
        super().__init__(address, ObservatoryHandler)


class ObservatoryHandler(BaseHTTPRequestHandler):
    server: ObservatoryHTTPServer

    def log_message(self, fmt, *args):
        return

    def _json(self, payload, status=200):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _static(self, filename: str):
        root = SETTINGS.web_dir.resolve()
        path = (root / filename).resolve()
        if root not in path.parents and path != root:
            self.send_error(403)
            return
        if not path.exists() or not path.is_file():
            self.send_error(404)
            return
        content = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(path.name)[0] or "application/octet-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    @staticmethod
    def _limit(query, default=100, maximum=1000):
        try:
            value = int(query.get("limit", [str(default)])[0])
        except (ValueError, TypeError):
            value = default
        return max(1, min(value, maximum))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        service = self.server.service

        if path == "/":
            self._static("index.html")
            return
        if path == "/topology.html":
            self._static("topology.html")
            return

        if path == "/api/live/status":
            self._json(service.state.status_snapshot())
            return

        if path.startswith("/api/live/"):
            snapshot = service.state.live_snapshot()
            status = snapshot["status"]
            if not status["live_data_available"]:
                # Fail-closed contract: no stale arrays are returned during an
                # invalid capture state.
                snapshot = {
                    "status": status,
                    "endpoints": [],
                    "flows": [],
                    "arp": [],
                    "packets": [],
                    "traffic": [],
                }

            limit = self._limit(query)
            if path == "/api/live/snapshot":
                self._json(snapshot)
                return
            if path == "/api/live/summary":
                endpoints = snapshot["endpoints"]
                latest = snapshot["traffic"][-1] if snapshot["traffic"] else {}
                self._json(
                    {
                        "status": status,
                        "verified_local_endpoints": sum(1 for row in endpoints if row["classification"] == "LOCAL_SUBNET_ENDPOINT"),
                        "infrastructure_records": sum(1 for row in endpoints if row["classification"] == "INFRASTRUCTURE"),
                        "sensor_records": sum(1 for row in endpoints if row["classification"] == "SENSOR"),
                        "active_flows": len(snapshot["flows"]),
                        "packets_per_second": latest.get("packets_per_second", 0),
                        "bytes_per_second": latest.get("bytes_per_second", 0),
                    }
                )
                return
            mapping = {
                "/api/live/endpoints": "endpoints",
                "/api/live/flows": "flows",
                "/api/live/arp": "arp",
                "/api/live/packets": "packets",
                "/api/live/traffic": "traffic",
            }
            key = mapping.get(path)
            if key:
                items = snapshot[key]
                if key == "packets":
                    items = items[-limit:]
                else:
                    items = items[:limit]
                self._json({"status": status, "items": items})
                return

        # History is deliberately namespaced away from live routes. The main
        # dashboard and topology never call these endpoints.
        if path == "/api/history/sessions":
            self._json({"items": service.history.list_sessions(self._limit(query, default=50, maximum=500))})
            return

        if path.startswith("/api/history/session/"):
            session_id = path.removeprefix("/api/history/session/").strip()
            record = service.history.get_session(session_id)
            if record is None:
                self._json({"error": "session not found"}, 404)
            else:
                self._json(record)
            return

        self._json({"error": "not found"}, 404)


def run_server(service: ObservatoryService):
    server = ObservatoryHTTPServer((SETTINGS.host, SETTINGS.port), service)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
