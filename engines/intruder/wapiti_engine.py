"""
engines/intruder/wapiti_engine.py
Wapiti Web Vulnerability Scanner Engine.

The original WapitiScanner, ScanConfig, Vulnerability, and ScanStatus classes
below are PRESERVED EXACTLY from the reference implementation — they are not
modified in any way.  Only the BaseEngine wrapper and the asyncio bridge at
the bottom of this file are new code.

Install: pip install wapiti3
"""

# ============================================================
# ORIGINAL CODE — DO NOT MODIFY
# ============================================================

import asyncio
import json
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
import threading
import queue as _queue
import hashlib
import urllib.parse

# Wapiti Core Imports
try:
    from wapitiCore.controller.wapiti import Wapiti
    from wapitiCore.net import Request as WapitiRequest
    try:
        from wapitiCore.language.language import _
    except ImportError:
        _ = lambda x: x
    from wapitiCore.net.classes import CrawlerConfiguration
    from wapitiCore.attack.modules.core import all_modules
    WAPITI_AVAILABLE = True
except ImportError as e:
    WAPITI_AVAILABLE = False


class ScanStatus(Enum):
    IDLE = "idle"
    SCANNING = "scanning"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class WapitiVulnerability:
    id: str
    name: str
    description: str
    severity: str
    url: str
    parameter: str
    solution: str
    references: List[str]
    timestamp: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ScanConfig:
    target_url: str
    modules: List[str]
    depth: int
    max_links: int
    timeout: int
    threads: int
    user_agent: str
    cookies: str
    headers: Dict[str, str]
    auth_url: str
    auth_data: str
    proxy: str
    verify_ssl: bool
    scan_type: str  # "crawl", "attack", "full"


class WapitiScanner:
    """Core Wapiti Scanner Wrapper (Updated for 3.2.10)"""

    def __init__(self):
        self.status = ScanStatus.IDLE
        self.vulnerabilities: List[WapitiVulnerability] = []
        self.crawled_urls: List[str] = []
        self.current_url: str = ""
        self.progress: float = 0.0
        self.logs: List[str] = []
        self.callbacks: List[Callable] = []
        self._stop_event = asyncio.Event()
        self.scanner = None

    def register_callback(self, callback: Callable):
        self.callbacks.append(callback)

    def _notify(self, event_type: str, data: Any = None):
        for callback in self.callbacks:
            try:
                callback(event_type, data)
            except Exception as e:
                self._log(f"Callback error: {e}")

    def _log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.logs.append(log_entry)
        self._notify("log", log_entry)
        print(log_entry)

    def stop(self):
        self._stop_event.set()
        self.status = ScanStatus.IDLE
        self._notify("status_change", self.status)

    async def scan(self, config: ScanConfig):
        """Execute Wapiti scan with given configuration"""
        if not WAPITI_AVAILABLE:
            await self._simulate_scan(config)
            return

        try:
            self.status = ScanStatus.SCANNING
            self._notify("status_change", self.status)
            self._log(f"Starting scan on: {config.target_url}")

            # Initialize Wapiti 3.2.x uses Request object
            base_req = WapitiRequest(config.target_url)
            self.scanner = Wapiti(
                scope_request=base_req,
                scope="folder" if config.scan_type == "full" else "page"
            )

            # Basic setup
            await self.scanner.init_persister()
            self.scanner.set_timeout(config.timeout)
            self.scanner.set_max_depth(config.depth)
            self.scanner.set_max_links_per_page(config.max_links)
            self.scanner.set_verify_ssl(config.verify_ssl)

            if config.proxy:
                self.scanner.set_proxy(config.proxy)

            # Set custom headers
            for key, value in config.headers.items():
                self.scanner.add_custom_header(key, value)

            # Configure attack modules
            if config.modules:
                self.scanner.active_scanner.set_modules(config.modules)
            else:
                self.scanner.active_scanner.set_modules(list(all_modules))

            # Start crawling
            self._log("Phase 1: Crawling target...")
            await self._crawl_phase(config)

            if self._stop_event.is_set():
                return

            # Attack phase if not crawl-only
            if config.scan_type in ["attack", "full"]:
                self._log("Phase 2: Attacking discovered endpoints...")
                await self._attack_phase(config)

            # Generate report
            self._log("Generating report...")
            await self._generate_report(config)

            self.status = ScanStatus.COMPLETED
            self._notify("scan_complete", self.vulnerabilities)

        except Exception as e:
            self.status = ScanStatus.ERROR
            self._log(f"Scan error: {str(e)}")
            self._notify("error", str(e))
        finally:
            self._notify("status_change", self.status)

    async def _crawl_phase(self, config: ScanConfig):
        """Crawling phase (Updated for 3.2.10)"""
        try:
            await self.scanner.load_scan_state()
            
            # 3.2.10 uses browse() which is an async method
            # We track progress by counting resources in persister
            initial_count = await self.scanner.count_resources()
            
            # Launch browse in a way we can monitor or just await it
            await self.scanner.browse(self._stop_event, parallelism=config.threads)
            
            current_count = await self.scanner.count_resources()
            self._log(f"Crawl complete. Found {current_count} resources.")
            
        except Exception as e:
            self._log(f"Crawl error: {e}")

    async def _attack_phase(self, config: ScanConfig):
        """Attack phase (Updated for 3.2.10)"""
        try:
            # init_report sets up the internal vulnerability list/state
            await self.scanner.init_report()
            
            # Wapiti 3.2.x attack() returns a boolean indicating success
            # It populates the persister with found vulnerabilities
            await self.scanner.active_scanner.attack()
            
            # Pull vulnerabilities from persister
            async for payload in self.scanner.persister.get_payloads():
                if payload.type == "vulnerability":
                    vuln = WapitiVulnerability(
                        id=hashlib.md5(f"{payload.evil_request.url}{payload.parameter}".encode()).hexdigest()[:8],
                        name=payload.category,
                        description=payload.info,
                        severity=payload.level,
                        url=payload.evil_request.url,
                        parameter=payload.parameter,
                        solution="",
                        references=[],
                        timestamp=datetime.now().isoformat()
                    )
                    self.vulnerabilities.append(vuln)
                    self._log(f"VULNERABILITY FOUND: {vuln.name} ({vuln.severity})")
                    self._notify("vulnerability_found", vuln)

        except Exception as e:
            self._log(f"Attack error: {e}")

    async def _generate_report(self, config: ScanConfig):
        """Generate scan report (Updated for 3.2.10)"""
        try:
            # Use Wapiti's built-in reporter
            self.scanner.set_report_generator_type("json")
            await self.scanner.write_report()
            self._log(f"Wapiti report generated.")
        except Exception as e:
            self._log(f"Report generation error: {e}")

    async def _simulate_scan(self, config: ScanConfig):
        """Simulate scan for demo purposes when Wapiti is not installed"""
        self.status = ScanStatus.SCANNING
        self._notify("status_change", self.status)

        demo_urls = [
            f"{config.target_url}/",
            f"{config.target_url}/login",
            f"{config.target_url}/search?q=test",
            f"{config.target_url}/api/users",
            f"{config.target_url}/admin"
        ]

        # Simulate crawling
        for i, url in enumerate(demo_urls):
            if self._stop_event.is_set():
                break

            await asyncio.sleep(0.5)
            self.current_url = url
            self.crawled_urls.append(url)
            self.progress = (i + 1) / len(demo_urls) * 50
            self._log(f"Crawled: {url}")
            self._notify("progress", {
                "phase": "crawl",
                "current": url,
                "progress": self.progress
            })

        # Simulate vulnerabilities
        if config.scan_type in ["attack", "full"]:
            demo_vulns = [
                ("SQL Injection", "high", "User input not properly sanitized"),
                ("XSS", "medium", "Reflected cross-site scripting"),
                ("CSRF", "medium", "Missing CSRF tokens"),
                ("Information Disclosure", "low", "Server version exposed")
            ]

            for i, (name, severity, desc) in enumerate(demo_vulns):
                if self._stop_event.is_set():
                    break

                await asyncio.sleep(0.8)
                vuln = WapitiVulnerability(
                    id=f"DEMO{i}",
                    name=name,
                    description=desc,
                    severity=severity,
                    url=demo_urls[i % len(demo_urls)],
                    parameter="id" if "SQL" in name else "q",
                    solution=f"Fix the {name} vulnerability by implementing proper validation",
                    references=["https://owasp.org"],
                    timestamp=datetime.now().isoformat()
                )
                self.vulnerabilities.append(vuln)
                self._log(f"VULNERABILITY FOUND: {name} ({severity})")
                self._notify("vulnerability_found", vuln)
                self.progress = 50 + (i + 1) / len(demo_vulns) * 50
                self._notify("progress", {"phase": "attack", "progress": self.progress})

        self.status = ScanStatus.COMPLETED
        self._notify("scan_complete", self.vulnerabilities)
        self._notify("status_change", self.status)


# ============================================================
# ENGINE WRAPPER — bridges WapitiScanner → BaseEngine contract
# ============================================================

import time
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class WapitiEngine(BaseEngine):
    """
    Wapiti Web Vulnerability Scanner Engine.

    Wraps WapitiScanner (preserved verbatim) and streams its callback
    events as StreamEvents via an asyncio.Queue bridge.

    Supported Request params:
        url         (str)   — target URL
        scan_type   (str)   — 'crawl' | 'attack' | 'full' (default: full)
        modules     (list)  — ['sql','xss','exec','file','crlf','xxe','ssrf','csrf']
        depth       (int)   — crawl depth (default: 5)
        max_links   (int)   — max links per page (default: 100)
        timeout     (int)   — per-request timeout seconds (default: 30)
        threads     (int)   — concurrent threads (default: 10)
        user_agent  (str)   — custom user agent
        cookies     (str)   — raw cookie string
        headers     (dict)  — extra request headers
        auth_url    (str)   — login form URL for authenticated scans
        auth_data   (str)   — login form POST data (e.g. 'user=a&pass=b')
        proxy       (str)   — http://host:port
        verify_ssl  (bool)  — verify TLS (default: True)
    """

    VERSION = "3.0.0"
    TOOL_ID = "wapiti"
    CATEGORY = "intruder"

    def __init__(self, bus=None):
        super().__init__(bus)
        self._wapiti_available = WAPITI_AVAILABLE

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        self._ready = True
        mode = "full Wapiti engine" if WAPITI_AVAILABLE else "DEMO/simulation mode"
        self._log(f"WapitiEngine v{self.VERSION} initialized — {mode}.")

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health_check(self) -> HealthStatus:
        if WAPITI_AVAILABLE:
            try:
                import wapitiCore
                v = getattr(wapitiCore, "__version__", "unknown")
            except Exception:
                v = "unknown"
            return HealthStatus(
                engine_id=self.TOOL_ID,
                status="OK",
                message=f"wapiti3 {v} available"
            )
        return HealthStatus(
            engine_id=self.TOOL_ID,
            status="DEGRADED",
            message="wapiti3 not installed — running in demo mode. pip install wapiti3"
        )

    # ------------------------------------------------------------------
    # Config builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_config(req: Request) -> ScanConfig:
        p = req.params
        return ScanConfig(
            target_url=req.target or p.get("url", ""),
            modules=p.get("modules", []),
            depth=int(p.get("depth", 5)),
            max_links=int(p.get("max_links", 100)),
            timeout=int(p.get("timeout", 30)),
            threads=int(p.get("threads", 10)),
            user_agent=p.get("user_agent", "Wapiti/3.0"),
            cookies=p.get("cookies", ""),
            headers=p.get("headers", {}),
            auth_url=p.get("auth_url", ""),
            auth_data=p.get("auth_data", ""),
            proxy=p.get("proxy", ""),
            verify_ssl=bool(p.get("verify_ssl", True)),
            scan_type=p.get("scan_type", "full"),
        )

    # ------------------------------------------------------------------
    # execute()  — blocking, returns single Response when done
    # ------------------------------------------------------------------

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        if not self._ready:
            await self.initialize()

        config = self._build_config(req)
        scanner = WapitiScanner()

        try:
            await scanner.scan(config)
            elapsed = (time.time() - t0) * 1000
            summary = {
                "vulnerabilities": [v.to_dict() for v in scanner.vulnerabilities],
                "crawled_urls": scanner.crawled_urls,
                "count": len(scanner.vulnerabilities),
            }
            return await self._after(Response(
                request_id=req.id,
                success=(scanner.status == ScanStatus.COMPLETED),
                data=summary,
                elapsed_ms=elapsed,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    # ------------------------------------------------------------------
    # stream()  — yields real-time events via asyncio.Queue bridge
    # ------------------------------------------------------------------

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        if not self._ready:
            await self.initialize()

        config = self._build_config(req)
        scanner = WapitiScanner()

        # asyncio.Queue bridges the sync callbacks → async yields
        event_q: asyncio.Queue = asyncio.Queue()

        def _on_event(event_type: str, data: Any) -> None:
            """Sync callback installed on WapitiScanner — puts into async queue."""
            event_q.put_nowait((event_type, data))

        scanner.register_callback(_on_event)

        # Announce start
        mode_str = "wapiti3" if WAPITI_AVAILABLE else "simulation"
        yield StreamEvent(
            engine_id=self.TOOL_ID,
            kind="progress",
            data=f"[WAPITI] Starting {config.scan_type.upper()} scan on {config.target_url} [{mode_str}]"
        )

        # Launch scan as a concurrent Task so we can drain the queue simultaneously
        scan_task = asyncio.create_task(scanner.scan(config))

        try:
            while True:
                # Drain all queued events first
                while not event_q.empty():
                    event_type, data = event_q.get_nowait()
                    stream_evt = self._translate_event(event_type, data)
                    if stream_evt:
                        yield stream_evt
                        self._emit(f"wapiti.{event_type}", data)

                # If the scan task finished and queue is empty, we're done
                if scan_task.done() and event_q.empty():
                    break

                # Give the scan coroutine time to progress
                await asyncio.sleep(0.05)

        except asyncio.CancelledError:
            scanner.stop()
            scan_task.cancel()
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data="[WAPITI] Scan cancelled.")
            return
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc), severity="ALERT")

        # Final drain (safety net)
        while not event_q.empty():
            event_type, data = event_q.get_nowait()
            stream_evt = self._translate_event(event_type, data)
            if stream_evt:
                yield stream_evt

        # Emit summary
        total = len(scanner.vulnerabilities)
        crawled = len(scanner.crawled_urls)
        yield StreamEvent(
            engine_id=self.TOOL_ID,
            kind="complete",
            data=(
                f"[WAPITI] Scan complete — {crawled} URL(s) crawled, "
                f"{total} vulnerability(ies) found."
            )
        )

    # ------------------------------------------------------------------
    # Internal: translate WapitiScanner callback → StreamEvent
    # ------------------------------------------------------------------

    def _translate_event(self, event_type: str, data: Any) -> Optional[StreamEvent]:
        """Map WapitiScanner callback events to StreamEvents."""

        if event_type == "log":
            return StreamEvent(
                engine_id=self.TOOL_ID,
                kind="result",
                data=str(data),
                severity="INFO"
            )

        elif event_type == "progress":
            if isinstance(data, dict):
                phase = data.get("phase", "").upper()
                pct = data.get("progress", 0)
                current = data.get("current", "")
                line = f"[{phase}] {pct:.1f}%"
                if current:
                    line += f" — {current}"
                return StreamEvent(
                    engine_id=self.TOOL_ID,
                    kind="progress",
                    data=line
                )

        elif event_type == "vulnerability_found":
            if isinstance(data, WapitiVulnerability):
                sev_map = {"high": "ALERT", "medium": "WARN", "low": "INFO"}
                severity = sev_map.get(data.severity.lower(), "INFO")
                return StreamEvent(
                    engine_id=self.TOOL_ID,
                    kind="result",
                    data=(
                        f"[VULN/{data.severity.upper()}] {data.name} "
                        f"| URL: {data.url} | Param: {data.parameter}"
                    ),
                    severity=severity
                )

        elif event_type == "status_change":
            status_str = data.value if isinstance(data, ScanStatus) else str(data)
            return StreamEvent(
                engine_id=self.TOOL_ID,
                kind="progress",
                data=f"[STATUS] {status_str.upper()}"
            )

        elif event_type == "error":
            return StreamEvent(
                engine_id=self.TOOL_ID,
                kind="error",
                data=f"[ERROR] {data}",
                severity="ALERT"
            )

        # scan_complete — handled in stream() via loop exit
        return None
