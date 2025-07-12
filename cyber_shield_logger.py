#!/usr/bin/env python3
# cyber_shield_logger.py

import http.server
import socketserver
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import re

# === Config ===
PORT = 8080
LOGFILE = "cybershield_log.txt"
BLACKLIST_IPS = ["185.220.101.1", "45.155.205.100"]
XSS_PATTERN = r"(<script>|javascript:|onerror=|alert\(|<img\s)".lower()

# === Handler ===
class LoggerHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        ip = self.client_address[0]
        parsed_url = urlparse(self.path)
        query = parse_qs(parsed_url.query)
        is_xss = any(re.search(XSS_PATTERN, str(v).lower()) for v in query.values())

        # Log content
        with open(LOGFILE, "a") as f:
            f.write(f"\n[{datetime.now()}] IP: {ip}\n")
            f.write(f"Path: {self.path}\n")
            f.write(f"Headers:\n{self.headers}\n")
            if is_xss:
                f.write("⚠️ XSS Payload Detected!\n")
            if ip in BLACKLIST_IPS:
                f.write("🚫 Blacklisted IP detected!\n")
            f.write("="*40 + "\n")

        print(f"🔍 Request logged from: {ip}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"CyberShield Logger Active.")

# === Server Start ===
if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), LoggerHandler) as httpd:
        print(f"🚀 CyberShield Logger running on port {PORT}...")
        print("🔧 Press CTRL+C to stop.")
        httpd.serve_forever()
