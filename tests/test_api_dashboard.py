import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from dashboard.app import app
from pathlib import Path


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = json.dumps({"items": [], "total": 0}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_DELETE(self):
        payload = b'{"cleared":1}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass


class DashboardProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=2)

    def test_dashboard_index_is_real_template(self):
        client = app.test_client()
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Delta", response.data)

    def test_traffic_table_hides_ipv6(self):
        script = (Path(__file__).parents[1] / "dashboard" / "static" / "js" / "main.js").read_text()
        self.assertIn("return '—';", script)
        self.assertNotIn("IPv6 address (open details)", script)
        self.assertIn("endpoint(item.src_ip, item.src_port, true)", script)
        self.assertIn("endpoint(alert.source_ip, alert.source_port)", script)

    def test_proxy_preserves_json_and_delete(self):
        base = f"http://127.0.0.1:{self.server.server_port}"
        client = app.test_client()
        with patch("dashboard.app.API_URL", base):
            response = client.get("/api/alerts?page=1")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["total"], 0)
            response = client.delete("/api/reset")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["cleared"], 1)

    def test_proxy_reports_unavailable_backend(self):
        client = app.test_client()
        with patch("dashboard.app.API_URL", "http://127.0.0.1:1"):
            response = client.get("/api/status")
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()["error"], "Delta-NIDS API unavailable")

    def test_export_adds_download_header(self):
        base = f"http://127.0.0.1:{self.server.server_port}"
        client = app.test_client()
        with patch("dashboard.app.API_URL", base):
            response = client.get("/api/alerts/export")
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment; filename=", response.headers["Content-Disposition"])


if __name__ == "__main__":
    unittest.main()
