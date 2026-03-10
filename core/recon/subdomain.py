import socket
import requests
from typing import List
from concurrent.futures import ThreadPoolExecutor

class SubdomainScanner:
    """Multi-source Subdomain Enumerator: crt.sh + HackerTarget + DNS brute"""
    COMMON_SUBS = [
        "www","mail","ftp","localhost","webmail","smtp","pop","ns1","ns2",
        "webdisk","admin","forum","vpn","api","dev","staging","test","app",
        "m","mobile","portal","dashboard","backend","cdn","static","assets",
        "blog","wiki","help","support","shop","store","status","monitor",
    ]

    def __init__(self, colors=None):
        self.colors = colors or {
            "accent_gold": "#FFD700",
            "accent_cyan": "#00FFFF"
        }

    def scan(self, domain: str, callback=None) -> List[str]:
        subdomains = set()

        # Source 1: crt.sh Certificate Transparency
        try:
            r = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=12)
            if r.ok:
                for entry in r.json():
                    for name in entry["name_value"].split("\n"):
                        name = name.strip().lower().lstrip("*.").rstrip(".")
                        if name.endswith(domain) and name not in subdomains:
                            subdomains.add(name)
                            if callback: callback(f"[CT] {name}")
        except: pass

        # Source 2: HackerTarget API
        try:
            r2 = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
            if r2.ok and "error" not in r2.text.lower():
                for line in r2.text.strip().splitlines():
                    host = line.split(",")[0].strip().lower()
                    if host.endswith(domain) and host not in subdomains:
                        subdomains.add(host)
                        if callback: callback(f"[HT] {host}")
        except: pass

        # Source 3: DNS Brute
        def _resolve(sub):
            fqdn = f"{sub}.{domain}"
            try:
                socket.gethostbyname(fqdn)
                return fqdn
            except: return None

        with ThreadPoolExecutor(max_workers=30) as ex:
            for res in ex.map(_resolve, self.COMMON_SUBS):
                if res and res not in subdomains:
                    subdomains.add(res)
                    if callback: callback(f"[DNS] {res}", self.colors.get("accent_gold"))

        if callback: callback(f"[SUBD] Total: {len(subdomains)} subdomains found.", self.colors.get("accent_cyan"))
        return sorted(subdomains)
