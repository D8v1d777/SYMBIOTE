"""
engines/intruder/photon_engine.py
Photon OSINT Web Crawler Engine — Hardened, Future-Proof Implementation.
Inspired by s0md3v/Photon. Fully native using requests + BeautifulSoup.

Capabilities:
  - Deep recursive web crawling with configurable depth & threads
  - URL extraction (internal / external / parameterized)
  - JavaScript file & endpoint discovery
  - Intel extraction (emails, social handles, phone numbers)
  - Secret / API key detection (AWS, Google, Stripe, JWT, etc.)
  - Subdomain harvesting from crawled pages
  - Wayback Machine seed fetching (archive.org CDX API)
  - Custom regex pattern matching
  - DNS data collection
  - Ninja mode (request via proxy services)
  - Rate-limiting & jitter to avoid WAF triggers
  - Full JSON export of all findings
"""
import asyncio
import hashlib
import json
import logging
import os
import random
import re
import socket
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Set
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent

_log = logging.getLogger("photon_engine")

# ─── Secret / API Key Patterns ───────────────────────────────────────────────
_SECRET_PATTERNS: Dict[str, str] = {
    "AWS Access Key":           r"(?:AKIA|ASIA)[0-9A-Z]{16}",
    "AWS Secret Key":           r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s:=\"']+([A-Za-z0-9/+=]{40})",
    "Google API Key":           r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth":             r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Stripe Live Key":          r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Publishable":       r"pk_live_[0-9a-zA-Z]{24,}",
    "Slack Token":              r"xox[bpors]-[0-9]{10,13}-[0-9A-Za-z\-]{24,}",
    "Slack Webhook":            r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}",
    "GitHub Token":             r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "JWT Token":                r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Private Key":              r"-----BEGIN (?:RSA|EC|DSA|OPENSSH)? ?PRIVATE KEY-----",
    "Heroku API":               r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Mailgun API Key":          r"key-[0-9a-zA-Z]{32}",
    "Twilio Account SID":       r"AC[a-z0-9]{32}",
    "SendGrid API Key":         r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "Square Access Token":      r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret":      r"sq0csp-[0-9A-Za-z\-_]{43}",
    "Firebase URL":             r"https://[a-z0-9-]+\.firebaseio\.com",
    "Telegram Bot Token":       r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
    "Discord Bot Token":        r"[MN][A-Za-z0-9]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}",
    "Generic API Key":          r"(?i)(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|secret)['\"\s:=]+['\"]?([A-Za-z0-9_\-]{16,64})['\"]?",
    "Password in URL":          r"(?i)(?:password|passwd|pwd)[=:][^\s&;]{3,40}",
    "Bearer Token":             r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",
}

# ─── Intel Extraction Patterns ────────────────────────────────────────────────
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)
_PHONE_RE = re.compile(
    r"(?:\+?\d{1,3}[\s\-]?)?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}"
)
_SOCIAL_PATTERNS: Dict[str, re.Pattern] = {
    "Twitter":   re.compile(r"(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,15})", re.I),
    "Facebook":  re.compile(r"facebook\.com/([A-Za-z0-9.]{2,})", re.I),
    "Instagram": re.compile(r"instagram\.com/([A-Za-z0-9_.]{1,30})", re.I),
    "LinkedIn":  re.compile(r"linkedin\.com/(?:in|company)/([A-Za-z0-9\-_.]+)", re.I),
    "GitHub":    re.compile(r"github\.com/([A-Za-z0-9\-]{1,39})", re.I),
    "YouTube":   re.compile(r"youtube\.com/(?:channel|user|c)/([A-Za-z0-9_\-]+)", re.I),
    "TikTok":    re.compile(r"tiktok\.com/@([A-Za-z0-9_.]+)", re.I),
}

# ─── Common JS Endpoint Patterns ─────────────────────────────────────────────
_JS_ENDPOINT_RE = re.compile(
    r"""(?:"|'|`)(/[a-zA-Z0-9_\-/.]+(?:\?[a-zA-Z0-9_=&]+)?)(?:"|'|`)""",
)

# ─── User-Agent Pool ─────────────────────────────────────────────────────────
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.2210.91",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class PhotonFindings:
    """Aggregated OSINT findings from a Photon crawl session."""
    target: str = ""
    internal_urls: Set[str] = field(default_factory=set)
    external_urls: Set[str] = field(default_factory=set)
    param_urls: Set[str] = field(default_factory=set)
    js_files: Set[str] = field(default_factory=set)
    js_endpoints: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    social_handles: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    secrets: List[Dict[str, str]] = field(default_factory=list)
    subdomains: Set[str] = field(default_factory=set)
    files: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    custom_matches: List[str] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    wayback_urls: Set[str] = field(default_factory=set)
    pages_crawled: int = 0
    errors: List[str] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0

    def to_dict(self) -> dict:
        """Serializable dict for JSON export."""
        return {
            "target": self.target,
            "summary": {
                "pages_crawled": self.pages_crawled,
                "internal_urls": len(self.internal_urls),
                "external_urls": len(self.external_urls),
                "param_urls": len(self.param_urls),
                "js_files": len(self.js_files),
                "js_endpoints": len(self.js_endpoints),
                "emails": len(self.emails),
                "phones": len(self.phones),
                "secrets": len(self.secrets),
                "subdomains": len(self.subdomains),
                "elapsed_seconds": round(self.end_time - self.start_time, 2),
            },
            "internal_urls": sorted(self.internal_urls),
            "external_urls": sorted(self.external_urls),
            "param_urls": sorted(self.param_urls),
            "js_files": sorted(self.js_files),
            "js_endpoints": sorted(self.js_endpoints),
            "emails": sorted(self.emails),
            "phones": sorted(self.phones),
            "social_handles": {k: sorted(v) for k, v in self.social_handles.items() if v},
            "secrets": self.secrets,
            "subdomains": sorted(self.subdomains),
            "files": {k: sorted(v) for k, v in self.files.items() if v},
            "custom_matches": self.custom_matches,
            "dns_records": self.dns_records,
            "wayback_urls": sorted(self.wayback_urls),
            "errors": self.errors,
        }


# ─── Engine ───────────────────────────────────────────────────────────────────

class PhotonEngine(BaseEngine):
    """
    Photon OSINT Web Crawler Engine.
    Hardened, async-ready, multi-threaded recursive crawler with full
    intel extraction, secret scanning, and Wayback Machine integration.
    """

    VERSION = "2.0.0"
    TOOL_ID = "photon"
    CATEGORY = "intruder"

    # Tunable defaults (overridable via Request.params)
    DEFAULT_DEPTH = 3
    DEFAULT_THREADS = 15
    DEFAULT_TIMEOUT = 8
    DEFAULT_DELAY = 0.0
    MAX_PAGES = 500           # Hard safety cap
    MAX_DEPTH = 10            # Hard safety cap
    MAX_THREADS = 50          # Hard safety cap

    FILE_EXTENSIONS = {
        "documents": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".txt", ".rtf"],
        "archives":  [".zip", ".rar", ".tar", ".gz", ".7z", ".bz2"],
        "configs":   [".xml", ".json", ".yaml", ".yml", ".ini", ".cfg", ".env", ".conf", ".toml"],
        "media":     [".jpg", ".jpeg", ".png", ".gif", ".svg", ".mp4", ".mp3", ".wav"],
        "code":      [".py", ".rb", ".php", ".java", ".go", ".c", ".cpp", ".sh", ".bat", ".ps1"],
        "database":  [".sql", ".db", ".sqlite", ".bak", ".dump"],
    }

    # Ninja mode proxies (web-based proxy passthrough services)
    NINJA_SERVICES = [
        "https://api.allorigins.win/raw?url={}",
        "https://api.codetabs.com/v1/proxy?quest={}",
    ]

    def __init__(self, bus=None):
        super().__init__(bus)
        self._session: Optional[requests.Session] = None
        self._findings: Optional[PhotonFindings] = None
        self._visited: Set[str] = set()
        self._content_hashes: Set[str] = set()   # Dedup by content hash
        self._lock = asyncio.Lock()
        self._stop_flag = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def initialize(self) -> None:
        self._session = self._build_session()
        self._ready = True
        self._log("PhotonEngine v{} initialized.".format(self.VERSION))

    async def teardown(self) -> None:
        if self._session:
            self._session.close()
        self._ready = False

    def _build_session(self, cookies: str = "", custom_headers: Optional[Dict] = None) -> requests.Session:
        s = requests.Session()
        s.headers["User-Agent"] = random.choice(_USER_AGENTS)
        s.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        s.headers["Accept-Language"] = "en-US,en;q=0.9"
        s.headers["Accept-Encoding"] = "gzip, deflate"
        s.headers["Connection"] = "keep-alive"
        if cookies:
            for pair in cookies.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    s.cookies.set(k.strip(), v.strip())
        if custom_headers:
            s.headers.update(custom_headers)
        # Retry adapter
        from urllib3.util.retry import Retry
        from requests.adapters import HTTPAdapter
        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    # ── Core Contract ─────────────────────────────────────────────────────────

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        try:
            findings = await self._crawl(req)
            findings.end_time = time.time()
            elapsed = (findings.end_time - findings.start_time) * 1000
            return await self._after(Response(
                request_id=req.id,
                success=True,
                data=findings.to_dict(),
                elapsed_ms=elapsed,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        """Streaming crawl with real-time event emission."""
        self._stop_flag = False
        params = req.params
        url = (params.get("url") or req.target or "").strip()

        # ── Validate ──────────────────────────────────────────────────────────
        if not url:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data="No target URL provided.")
            return

        url = self._normalise_url(url)
        if not url:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data="Invalid URL.")
            return

        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        depth = min(int(params.get("depth", self.DEFAULT_DEPTH)), self.MAX_DEPTH)
        threads = min(int(params.get("threads", self.DEFAULT_THREADS)), self.MAX_THREADS)
        timeout = int(params.get("timeout", self.DEFAULT_TIMEOUT))
        delay = float(params.get("delay", self.DEFAULT_DELAY))
        max_pages = min(int(params.get("max_pages", self.MAX_PAGES)), self.MAX_PAGES)
        cookies = params.get("cookies", "")
        custom_regex = params.get("regex", "")
        wayback = params.get("wayback", False)
        ninja = params.get("ninja", False)
        only_urls = params.get("only_urls", False)
        export_json = params.get("export_json", True)

        # Rebuild session with cookies if provided
        if cookies:
            self._session = self._build_session(cookies=cookies)
        elif not self._session:
            self._session = self._build_session()

        # Reset state
        self._visited = set()
        self._content_hashes = set()
        findings = PhotonFindings(target=url, start_time=time.time())
        self._findings = findings

        yield StreamEvent(
            engine_id=self.TOOL_ID, kind="progress",
            data=f"PHOTON v{self.VERSION} | Target: {url} | Depth: {depth} | Threads: {threads}"
        )

        display_limit = 25  # Limit output spam for UI cleanly
        emails_shown = 0
        phones_shown = 0
        js_shown = 0
        secrets_shown = 0

        # ── Wayback Machine Seeds ────────────────────────────────────────────
        seed_urls = {url}
        if wayback:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data="Fetching Wayback Machine seeds...")
            wb_urls = await asyncio.to_thread(self._fetch_wayback_seeds, url, timeout)
            findings.wayback_urls = wb_urls
            seed_urls.update(wb_urls)
            yield StreamEvent(
                engine_id=self.TOOL_ID, kind="result",
                data=f"Wayback Machine: {len(wb_urls)} archived URL(s) recovered",
                severity="INFO",
            )

        # ── DNS Enumeration ──────────────────────────────────────────────────
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data="Resolving DNS records...")
        dns_data = await asyncio.to_thread(self._enumerate_dns, domain)
        findings.dns_records = dns_data
        for rtype, records in dns_data.items():
            if records:
                yield StreamEvent(
                    engine_id=self.TOOL_ID, kind="result",
                    data=f"DNS {rtype}: {', '.join(records[:5])}{'...' if len(records) > 5 else ''}",
                    severity="INFO",
                )

        # ── BFS Crawl ────────────────────────────────────────────────────────
        current_level = seed_urls
        for level in range(1, depth + 1):
            if self._stop_flag or findings.pages_crawled >= max_pages:
                break

            next_level: Set[str] = set()
            to_crawl = [u for u in current_level if u not in self._visited]
            if not to_crawl:
                break

            yield StreamEvent(
                engine_id=self.TOOL_ID, kind="progress",
                data=f"Depth {level}/{depth} — {len(to_crawl)} URL(s) to process"
            )

            # Threaded page fetching
            page_results = await asyncio.to_thread(
                self._fetch_pages_threaded, to_crawl, threads, timeout, delay, ninja, max_pages - findings.pages_crawled
            )

            for page_url, html, status_code in page_results:
                if self._stop_flag or findings.pages_crawled >= max_pages:
                    break

                self._visited.add(page_url)
                findings.pages_crawled += 1

                if html is None:
                    continue

                # Content dedup
                content_hash = hashlib.md5(html[:2048].encode(errors="ignore")).hexdigest()
                if content_hash in self._content_hashes:
                    continue
                self._content_hashes.add(content_hash)

                # ── Extract everything ────────────────────────────────────────
                page_parsed = urlparse(page_url)
                links = self._extract_links(html, page_url, domain)

                for link in links["internal"]:
                    findings.internal_urls.add(link)
                    if self._has_params(link):
                        findings.param_urls.add(link)
                    next_level.add(link)

                for link in links["external"]:
                    findings.external_urls.add(link)

                # Subdomains
                for link in links["internal"] | links["external"]:
                    sub = urlparse(link).netloc.lower()
                    root = self._extract_root_domain(domain)
                    if sub.endswith(root) and sub != domain:
                        findings.subdomains.add(sub)

                # JS files
                for js in links["js_files"]:
                    if js not in findings.js_files:
                        findings.js_files.add(js)
                        if js_shown < display_limit:
                            yield StreamEvent(
                                engine_id=self.TOOL_ID, kind="result",
                                data=f"JS File: {js}", severity="INFO",
                            )
                            js_shown += 1
                        elif js_shown == display_limit:
                            yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data="[+] Additional JS files discovered...", severity="INFO")
                            js_shown += 1

                # Files by extension
                for link in links["internal"] | links["external"]:
                    ext = self._get_extension(link)
                    for cat, exts in self.FILE_EXTENSIONS.items():
                        if ext in exts:
                            findings.files[cat].add(link)

                if not only_urls:
                    # Intel extraction
                    intel = self._extract_intel(html, page_url)

                    for email in intel["emails"]:
                        if email not in findings.emails:
                            findings.emails.add(email)
                            if emails_shown < display_limit:
                                yield StreamEvent(
                                    engine_id=self.TOOL_ID, kind="result",
                                    data=f"EMAIL: {email}", severity="WARN",
                                )
                                emails_shown += 1
                            elif emails_shown == display_limit:
                                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data="[+] Additional Emails identified...", severity="WARN")
                                emails_shown += 1

                    for phone in intel["phones"]:
                        findings.phones.add(phone)

                    for platform_name, handles in intel["social"].items():
                        for h in handles:
                            if h not in findings.social_handles[platform_name]:
                                findings.social_handles[platform_name].add(h)
                                yield StreamEvent(
                                    engine_id=self.TOOL_ID, kind="result",
                                    data=f"SOCIAL [{platform_name}]: @{h}", severity="INFO",
                                )

                    # Secret scanning
                    for secret in intel["secrets"]:
                        if secret not in findings.secrets:
                            findings.secrets.append(secret)
                            if secrets_shown < display_limit:
                                yield StreamEvent(
                                    engine_id=self.TOOL_ID, kind="result",
                                    data=f"SECRET [{secret['type']}]: {secret['match'][:60]}...",
                                    severity="ALERT",
                                )
                                secrets_shown += 1
                            elif secrets_shown == display_limit:
                                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data="[+] Additional Secrets discovered...", severity="ALERT")
                                secrets_shown += 1

                    # JS endpoint extraction
                    if page_url.endswith(".js") or "javascript" in html[:200].lower():
                        endpoints = self._extract_js_endpoints(html)
                        for ep in endpoints:
                            findings.js_endpoints.add(ep)

                    # Custom regex
                    if custom_regex:
                        for m in re.finditer(custom_regex, html):
                            match_str = m.group(0)[:200]
                            findings.custom_matches.append(match_str)
                            yield StreamEvent(
                                engine_id=self.TOOL_ID, kind="result",
                                data=f"REGEX MATCH: {match_str}", severity="WARN",
                            )

                # Periodic progress updates
                if findings.pages_crawled % 10 == 0:
                    yield StreamEvent(
                        engine_id=self.TOOL_ID, kind="progress",
                        data=(
                            f"Progress: {findings.pages_crawled} pages | "
                            f"{len(findings.internal_urls)} internal | "
                            f"{len(findings.param_urls)} param | "
                            f"{len(findings.emails)} emails | "
                            f"{len(findings.secrets)} secrets"
                        ),
                    )

            current_level = next_level

        # ── JS Deep Analysis ──────────────────────────────────────────────────
        unvisited_js = findings.js_files - self._visited
        if unvisited_js and not only_urls:
            yield StreamEvent(
                engine_id=self.TOOL_ID, kind="progress",
                data=f"Deep-scanning {len(unvisited_js)} JavaScript file(s)..."
            )
            js_results = await asyncio.to_thread(
                self._fetch_pages_threaded,
                list(unvisited_js)[:50], threads, timeout, delay, ninja, 50,
            )
            for js_url, js_body, _ in js_results:
                if js_body:
                    endpoints = self._extract_js_endpoints(js_body)
                    findings.js_endpoints.update(endpoints)
                    for secret in self._scan_secrets(js_body, js_url):
                        if secret not in findings.secrets:
                            findings.secrets.append(secret)
                            if secrets_shown < display_limit:
                                yield StreamEvent(
                                    engine_id=self.TOOL_ID, kind="result",
                                    data=f"SECRET [{secret['type']}] in JS: {secret['match'][:60]}...",
                                    severity="ALERT",
                                )
                                secrets_shown += 1
                            elif secrets_shown == display_limit:
                                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data="[+] Additional JS Secrets discovered...", severity="ALERT")
                                secrets_shown += 1

        # ── Finalise ──────────────────────────────────────────────────────────
        findings.end_time = time.time()
        elapsed = findings.end_time - findings.start_time

        # Export JSON
        if export_json:
            export_path = await asyncio.to_thread(self._export_json, findings, domain)
            yield StreamEvent(
                engine_id=self.TOOL_ID, kind="result",
                data=f"Results exported → {export_path}", severity="INFO",
            )

        # Summary event
        summary = (
            f"PHOTON COMPLETE in {elapsed:.1f}s | "
            f"{findings.pages_crawled} pages crawled | "
            f"{len(findings.internal_urls)} internal URLs | "
            f"{len(findings.external_urls)} external URLs | "
            f"{len(findings.param_urls)} parameterised URLs | "
            f"{len(findings.js_files)} JS files | "
            f"{len(findings.js_endpoints)} JS endpoints | "
            f"{len(findings.emails)} emails | "
            f"{len(findings.secrets)} secrets | "
            f"{len(findings.subdomains)} subdomains"
        )
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete", data=summary)
        self._emit("photon.scan_complete", findings.to_dict())

    # ── Page Fetching ─────────────────────────────────────────────────────────

    def _fetch_pages_threaded(
        self, urls: List[str], threads: int, timeout: int,
        delay: float, ninja: bool, limit: int,
    ) -> List[tuple]:
        """Fetch pages concurrently. Returns [(url, html_or_None, status_code)]."""
        results = []
        with ThreadPoolExecutor(max_workers=min(threads, len(urls), self.MAX_THREADS)) as pool:
            futures = {}
            for i, url in enumerate(urls[:limit]):
                f = pool.submit(self._fetch_one, url, timeout, ninja)
                futures[f] = url

            for future in as_completed(futures):
                try:
                    r = future.result()
                    results.append(r)
                except Exception as e:
                    results.append((futures[future], None, 0))
                    _log.debug("Fetch error for %s: %s", futures[future], e)

                if delay > 0:
                    time.sleep(delay + random.uniform(0, delay * 0.3))

        return results

    def _fetch_one(self, url: str, timeout: int, ninja: bool) -> tuple:
        """Fetch a single URL. Returns (url, html, status_code)."""
        try:
            if ninja:
                proxy_tpl = random.choice(self.NINJA_SERVICES)
                fetch_url = proxy_tpl.format(url)
            else:
                fetch_url = url

            # Rotate UA per request for stealth
            self._session.headers["User-Agent"] = random.choice(_USER_AGENTS)

            r = self._session.get(
                fetch_url, timeout=timeout, verify=False,
                allow_redirects=True,
            )
            content_type = r.headers.get("Content-Type", "")
            # Only parse text-based responses
            if any(t in content_type for t in ["text/", "javascript", "json", "xml"]):
                return (url, r.text, r.status_code)
            return (url, None, r.status_code)
        except requests.RequestException as e:
            _log.debug("Fetch failed for %s: %s", url, e)
            return (url, None, 0)

    # ── Link Extraction ───────────────────────────────────────────────────────

    def _extract_links(self, html: str, page_url: str, target_domain: str) -> Dict[str, Set[str]]:
        """Extract and classify all links from HTML."""
        internal: Set[str] = set()
        external: Set[str] = set()
        js_files: Set[str] = set()

        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return {"internal": internal, "external": external, "js_files": js_files}

        root_domain = self._extract_root_domain(target_domain)

        # All tags that can contain URLs
        link_attrs = [
            ("a", "href"), ("link", "href"), ("area", "href"),
            ("script", "src"), ("img", "src"), ("iframe", "src"),
            ("video", "src"), ("source", "src"), ("form", "action"),
            ("embed", "src"), ("object", "data"),
        ]

        for tag, attr in link_attrs:
            for el in soup.find_all(tag, **{attr: True}):
                raw = el.get(attr, "").strip()
                if not raw or raw.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
                    continue

                resolved = urljoin(page_url, raw)
                parsed = urlparse(resolved)

                # Normalise: strip fragments, enforce scheme
                clean = parsed._replace(fragment="").geturl()
                if not parsed.scheme.startswith("http"):
                    continue

                netloc = parsed.netloc.lower()

                # JS files
                if clean.endswith(".js") or (tag == "script" and attr == "src"):
                    js_files.add(clean)

                # Classify
                if netloc.endswith(root_domain):
                    internal.add(clean)
                else:
                    external.add(clean)

        # Also look for URLs in inline scripts / comments
        for match in re.finditer(r'(?:href|src|action|url)\s*[=:]\s*["\']([^"\']{5,})["\']', html):
            raw = match.group(1).strip()
            if raw.startswith(("http://", "https://")):
                parsed = urlparse(raw)
                if parsed.netloc.lower().endswith(root_domain):
                    internal.add(raw)
                else:
                    external.add(raw)
            elif raw.startswith("/"):
                internal.add(urljoin(page_url, raw))

        return {"internal": internal, "external": external, "js_files": js_files}

    # ── Intel Extraction ──────────────────────────────────────────────────────

    def _extract_intel(self, html: str, source_url: str) -> Dict[str, Any]:
        """Extract emails, phones, social handles, and secrets from page content."""
        result: Dict[str, Any] = {
            "emails": set(),
            "phones": set(),
            "social": defaultdict(set),
            "secrets": [],
        }

        # Emails
        for m in _EMAIL_RE.finditer(html):
            email = m.group(0).lower()
            # Filter out common false positives
            if not any(email.endswith(f) for f in [".png", ".jpg", ".gif", ".svg", ".css", ".js"]):
                result["emails"].add(email)

        # Phones (only if numeric density is reasonable)
        for m in _PHONE_RE.finditer(html):
            phone = m.group(0).strip()
            digits = re.sub(r"\D", "", phone)
            if 7 <= len(digits) <= 15:
                result["phones"].add(phone)

        # Social handles
        for platform_name, pattern in _SOCIAL_PATTERNS.items():
            for m in pattern.finditer(html):
                handle = m.group(1).strip("/").lower()
                if len(handle) > 1 and handle not in ("login", "signup", "share", "intent"):
                    result["social"][platform_name].add(handle)

        # Secrets
        result["secrets"] = self._scan_secrets(html, source_url)

        return result

    def _scan_secrets(self, text: str, source_url: str) -> List[Dict[str, str]]:
        """Scan text for API keys, tokens, and secrets."""
        found = []
        seen = set()
        for label, pattern in _SECRET_PATTERNS.items():
            try:
                for m in re.finditer(pattern, text):
                    match_str = m.group(0)[:120]
                    sig = f"{label}:{match_str}"
                    if sig not in seen:
                        seen.add(sig)
                        found.append({
                            "type": label,
                            "match": match_str,
                            "source": source_url,
                        })
            except re.error:
                continue
        return found

    # ── JS Endpoint Extraction ────────────────────────────────────────────────

    def _extract_js_endpoints(self, js_body: str) -> Set[str]:
        """Extract API endpoints from JavaScript source code."""
        endpoints: Set[str] = set()
        for m in _JS_ENDPOINT_RE.finditer(js_body):
            path = m.group(1)
            if len(path) > 2 and not path.startswith("//"):
                endpoints.add(path)

        # Also look for fetch / axios / XMLHttpRequest patterns
        for m in re.finditer(r'(?:fetch|axios\.(?:get|post|put|delete)|\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*)["\']([^"\']+)["\']', js_body):
            endpoints.add(m.group(1))

        return endpoints

    # ── Wayback Machine ───────────────────────────────────────────────────────

    def _fetch_wayback_seeds(self, url: str, timeout: int) -> Set[str]:
        """Fetch archived URLs from the Wayback Machine CDX API."""
        seeds: Set[str] = set()
        domain = urlparse(url).netloc
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original&collapse=urlkey&limit=200"
        try:
            r = requests.get(cdx_url, timeout=timeout)
            if r.ok:
                for line in r.text.strip().splitlines():
                    line = line.strip()
                    if line.startswith("http"):
                        seeds.add(line)
        except requests.RequestException as e:
            _log.debug("Wayback fetch failed: %s", e)
        return seeds

    # ── DNS Enumeration ───────────────────────────────────────────────────────

    def _enumerate_dns(self, domain: str) -> Dict[str, List[str]]:
        """Resolve common DNS record types."""
        records: Dict[str, List[str]] = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 4
            resolver.lifetime = 4

            for rtype in record_types:
                try:
                    answers = resolver.resolve(domain, rtype)
                    records[rtype] = [str(r) for r in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    pass
                except Exception:
                    pass
        except ImportError:
            # Fallback: basic socket resolution
            try:
                ips = socket.getaddrinfo(domain, None)
                records["A"] = list(set(ip[4][0] for ip in ips if ip[0] == socket.AF_INET))
                records["AAAA"] = list(set(ip[4][0] for ip in ips if ip[0] == socket.AF_INET6))
            except socket.gaierror:
                pass
        return records

    # ── Export ────────────────────────────────────────────────────────────────

    def _export_json(self, findings: PhotonFindings, domain: str) -> str:
        """Export findings to JSON file in intel/ directory."""
        out_dir = Path("intel") / "photon"
        out_dir.mkdir(parents=True, exist_ok=True)
        sanitised = re.sub(r"[^\w.\-]", "_", domain)
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_path = out_dir / f"{sanitised}_{ts}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(findings.to_dict(), f, indent=2, ensure_ascii=False)
        return str(out_path)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _normalise_url(url: str) -> Optional[str]:
        """Normalise and validate a URL."""
        url = url.strip()
        if not url:
            return None
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        parsed = urlparse(url)
        if not parsed.hostname:
            return None
        return url

    @staticmethod
    def _has_params(url: str) -> bool:
        return "?" in url and "=" in url

    @staticmethod
    def _get_extension(url: str) -> str:
        path = urlparse(url).path
        if "." in path:
            return "." + path.rsplit(".", 1)[-1].lower()[:10]
        return ""

    @staticmethod
    def _extract_root_domain(domain: str) -> str:
        """Extract root domain (e.g. 'sub.example.com' -> 'example.com')."""
        try:
            import tldextract
            ext = tldextract.extract(domain)
            return f"{ext.domain}.{ext.suffix}" if ext.suffix else domain
        except ImportError:
            parts = domain.split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else domain

    def stop(self):
        """Graceful stop signal for long-running crawls."""
        self._stop_flag = True

    def health_check(self) -> HealthStatus:
        return HealthStatus(
            engine_id=self.TOOL_ID,
            status="OK" if self._ready else "DOWN",
            latency_ms=0.0,
            message=f"Photon v{self.VERSION} {'ready' if self._ready else 'not initialized'}",
        )
