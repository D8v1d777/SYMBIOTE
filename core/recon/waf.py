import requests
import urllib3
from typing import List, Optional

# Disable insecure request warnings for offensive operations
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WafDetector:
    """Professional WAF/CDN Fingerprinter with 20+ signature sets"""
    SIGNATURES = {
        "Cloudflare":    ["cloudflare", "cf-ray", "__cfduid", "server: cloudflare"],
        "Akamai":        ["akamai", "akamaighost", "x-check-cacheable"],
        "Sucuri":        ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
        "Imperva":       ["imperva", "incapsula", "visid_incap", "x-iinfo"],
        "AWS-WAF":       ["awselb", "x-amz-cf-id", "aws"],
        "ModSecurity":   ["mod_security", "modsecurity", "x-modsecurity"],
        "Barracuda":     ["barra_counter_scope", "barracuda_"],
        "F5-BIG-IP":     ["bigipserver", "f5", "ts01"],
        "Fortinet":      ["fortigate", "fortiweb"],
        "Citrix":        ["ns_af", "citrix"],
        "Wallarm":       ["wallarm"],
        "Radware":       ["x-denied-reason", "x-sid"],
        "Nginx-WAF":     ["naxsi", "x-page-speed"],
        "DenyAll":       ["denyall", "sessioncookie"],
        "Reblaze":       ["x-reblaze-protection", "rbzid"],
    }

    def __init__(self, colors=None):
        self.colors = colors or {
            "accent_error": "#FF4B4B",
            "accent_warning": "#FFA500"
        }

    def detect(self, target: str, callback=None):
        base_url = target if target.startswith("http") else f"http://{target}"
        detected = []
        try:
            r = requests.get(base_url, timeout=6, verify=False)
            all_headers = str(r.headers).lower()
            body_lower  = r.text.lower()

            for waf, sigs in self.SIGNATURES.items():
                if any(sig in all_headers or sig in body_lower for sig in sigs):
                    detected.append(waf)
                    if callback: callback(f"[WAF] Detected: {waf}", self.colors.get("accent_error"))

            # Provoke block
            provoke = f"{base_url}/?exec=/etc/passwd&XDEBUG_SESSION_START=1&sql=' OR 1=1--"
            r2 = requests.get(provoke, timeout=6, verify=False)
            if r2.status_code in [403, 406, 429, 501]:
                if not detected:
                    detected.append("GENERIC_BLOCK")
                if callback: callback(f"[WAF] Provocation blocked ({r2.status_code}): Generic WAF active", self.colors.get("accent_warning"))

        except Exception as e:
            if callback: callback(f"[WAF] Error: {e}")
        return detected or None
