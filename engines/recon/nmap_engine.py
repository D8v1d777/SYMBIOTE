"""
engines/recon/nmap_engine.py

NmapEngine — async port scanning with nmap binary primary,
pure-socket fallback. Follows StalkEngine contract exactly.

StreamEvent kinds: "progress" | "result" | "error" | "complete"
Severity levels:   "INFO" | "WARN" | "ALERT" | "CRITICAL"
"""

from __future__ import annotations

import asyncio
import ipaddress
import shutil
import socket
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Dict, List, Optional

from registry.event_bus import bus

# ── Import StreamEvent from wherever base.py lives in your project ──
try:
    from core.base import StreamEvent
except ImportError:
    # Inline fallback so the engine is portable during dev
    import time as _time
    from dataclasses import dataclass as _dc, field as _field

    @_dc
    class StreamEvent:
        engine_id: str
        kind: str
        data: Any = None
        severity: str = "INFO"
        ts: float = _field(default_factory=_time.time)

        def to_dict(self) -> dict:
            return self.__dict__


# ── Constants ────────────────────────────────────────────────────────
TOOL_ID   = "nmap"
CATEGORY  = "recon"
ENGINE_ID = f"{CATEGORY}.{TOOL_ID}"

# TTL → OS heuristic (same logic as StalkEngine)
_TTL_OS_MAP: Dict[int, str] = {
    64:  "Linux / macOS",
    128: "Windows",
    255: "Cisco IOS / Solaris",
    254: "Cisco IOS",
}

# Common port → service name for socket fallback
_PORT_SERVICES: Dict[int, str] = {
    21: "FTP",       22: "SSH",       23: "Telnet",
    25: "SMTP",      53: "DNS",       80: "HTTP",
    110: "POP3",     111: "SUNRPC",   135: "MSRPC",
    139: "NetBIOS",  143: "IMAP",     443: "HTTPS",
    445: "SMB",      993: "IMAPS",    995: "POP3S",
    1433: "MSSQL",   1723: "PPTP",    3306: "MySQL",
    3389: "RDP",     5432: "Postgres",5900: "VNC",
    6379: "Redis",   8080: "HTTP-Alt",8443: "HTTPS-Alt",
    8888: "Jupyter", 9200: "Elastic", 27017: "MongoDB",
}

# Risk weights per service
_RISK_WEIGHTS: Dict[str, int] = {
    "Telnet": 30, "FTP": 20,    "SMB": 25,   "RDP": 20,
    "VNC":    25, "MongoDB": 20,"Redis": 20, "Elastic": 15,
    "MSSQL":  15, "MySQL": 10,  "SSH": 5,    "HTTP": 3,
    "HTTPS":  1,
}


# ── Data containers ──────────────────────────────────────────────────
@dataclass
class PortResult:
    port:     int
    protocol: str
    state:    str          # "open" | "filtered" | "closed"
    service:  str
    version:  str
    banner:   str
    risk:     int


@dataclass
class NmapScanResult:
    target:      str
    resolved_ip: str
    os_guess:    str
    ttl:         int
    ports:       List[PortResult] = field(default_factory=list)
    risk_score:  int = 0
    scan_time:   float = 0.0
    backend:     str = "nmap"   # "nmap" | "socket"


# ── Helpers ──────────────────────────────────────────────────────────
def _guess_os_from_ttl(ttl: int) -> str:
    for threshold, name in _TTL_OS_MAP.items():
        if ttl >= threshold - 5 and ttl <= threshold:
            return name
    return "Unknown"


def _get_ttl(host: str) -> int:
    """Best-effort TTL probe via ICMP (requires elevated on Windows)."""
    try:
        import struct
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(1)
        # ICMP echo request
        payload = struct.pack("bbHHh", 8, 0, 0, 1, 1) + b"\x00" * 8
        sock.sendto(payload, (host, 0))
        data, _ = sock.recvfrom(1024)
        ttl = data[8]  # TTL field in IP header
        sock.close()
        return ttl
    except Exception:
        return 0


def _calc_risk(ports: List[PortResult]) -> int:
    score = 0
    for p in ports:
        if p.state == "open":
            score += _RISK_WEIGHTS.get(p.service, 2)
    return min(score, 100)


def _severity_for_risk(score: int) -> str:
    if score >= 70: return "CRITICAL"
    if score >= 40: return "ALERT"
    if score >= 15: return "WARN"
    return "INFO"


async def _grab_banner(host: str, port: int, timeout: float = 1.5) -> str:
    """Async banner grab — sends HTTP HEAD or raw newline."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        probe = b"HEAD / HTTP/1.0\r\n\r\n" if port in (80, 8080, 443, 8443) else b"\r\n"
        writer.write(probe)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        return data.decode(errors="ignore").strip().split("\n")[0][:120]
    except Exception:
        return ""


# ── Backend: nmap binary ─────────────────────────────────────────────
async def _run_nmap_binary(
    target: str,
    ports: str,
    timing: str,
    extra_args: List[str],
) -> Optional[ET.Element]:
    """
    Run nmap with -oX - (XML to stdout) and return parsed XML root.
    Returns None if nmap binary is unavailable or fails.
    """
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return None

    cmd = [
        nmap_bin, "-sV", "--version-intensity", "5",
        "-T", timing, "-p", ports, "-oX", "-",
        *extra_args, target
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        if proc.returncode != 0:
            return None
        return ET.fromstring(stdout.decode(errors="ignore"))
    except (asyncio.TimeoutError, Exception):
        return None


def _parse_nmap_xml(root: ET.Element, target: str) -> NmapScanResult:
    """Extract ports and host info from nmap XML output."""
    result = NmapScanResult(
        target=target,
        resolved_ip=target,
        os_guess="Unknown",
        ttl=0,
        backend="nmap",
    )

    host_el = root.find(".//host")
    if host_el is None:
        return result

    # Resolved IP
    addr_el = host_el.find("address[@addrtype='ipv4']")
    if addr_el is not None:
        result.resolved_ip = addr_el.get("addr", target)

    # OS from nmap detection
    os_el = host_el.find(".//osmatch")
    if os_el is not None:
        result.os_guess = os_el.get("name", "Unknown")

    # Ports
    for port_el in host_el.findall(".//port"):
        state_el  = port_el.find("state")
        service_el = port_el.find("service")

        state   = state_el.get("state", "unknown") if state_el is not None else "unknown"
        service = service_el.get("name", "unknown") if service_el is not None else "unknown"
        version = ""
        if service_el is not None:
            parts = [
                service_el.get("product", ""),
                service_el.get("version", ""),
                service_el.get("extrainfo", ""),
            ]
            version = " ".join(p for p in parts if p).strip()

        result.ports.append(PortResult(
            port=int(port_el.get("portid", 0)),
            protocol=port_el.get("protocol", "tcp"),
            state=state,
            service=service.upper() if service != "unknown" else _PORT_SERVICES.get(
                int(port_el.get("portid", 0)), "Unknown"
            ),
            version=version,
            banner="",
            risk=0,
        ))

    return result


# ── Backend: pure-socket fallback ────────────────────────────────────
async def _socket_scan_port(
    host: str, port: int, timeout: float
) -> Optional[PortResult]:
    """Check a single port — returns PortResult if open, else None."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        service = _PORT_SERVICES.get(port, "Unknown")
        return PortResult(
            port=port, protocol="tcp", state="open",
            service=service, version="", banner="", risk=0,
        )
    except Exception:
        return None


async def _run_socket_fallback(
    target: str,
    port_list: List[int],
    timeout: float,
    concurrency: int,
) -> NmapScanResult:
    """Concurrent socket scan with asyncio.Semaphore throttle."""
    result = NmapScanResult(
        target=target,
        resolved_ip=target,
        os_guess="Unknown",
        ttl=0,
        backend="socket",
    )

    # Resolve hostname
    try:
        result.resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        pass

    sem = asyncio.Semaphore(concurrency)

    async def _guarded(port: int) -> Optional[PortResult]:
        async with sem:
            return await _socket_scan_port(result.resolved_ip, port, timeout)

    tasks = [_guarded(p) for p in port_list]
    results = await asyncio.gather(*tasks)
    result.ports = [r for r in results if r is not None]
    return result


# ── Main async engine ────────────────────────────────────────────────
async def stream(
    target: str,
    ports: str = "1-1024",
    timing: str = "4",
    grab_banners: bool = True,
    socket_timeout: float = 1.0,
    socket_concurrency: int = 150,
    extra_nmap_args: Optional[List[str]] = None,
) -> AsyncGenerator[StreamEvent, None]:
    """
    NmapEngine main stream.

    Yields StreamEvent objects following the StalkEngine contract:
      kind="progress"  — status updates
      kind="result"    — individual port discoveries
      kind="error"     — non-fatal warnings / fallback notices
      kind="complete"  — final summary with full NmapScanResult

    Args:
        target:              Hostname or IP to scan.
        ports:               Port range string, e.g. "1-1024", "22,80,443"
        timing:              Nmap timing template 0-5 (default "4" = aggressive).
        grab_banners:        Whether to grab service banners after discovery.
        socket_timeout:      Per-port timeout for socket fallback (seconds).
        socket_concurrency:  Max concurrent socket probes in fallback mode.
        extra_nmap_args:     Extra flags forwarded to nmap binary.
    """
    t_start = time.time()
    extra_nmap_args = extra_nmap_args or []

    # ── 1. Start ──────────────────────────────────────────────────
    yield StreamEvent(
        engine_id=ENGINE_ID,
        kind="progress",
        data={"msg": f"[NMAP] Starting scan → target={target} ports={ports}"},
        severity="INFO",
    )
    bus.emit(f"{ENGINE_ID}.start", {"target": target, "ports": ports}, source=ENGINE_ID)

    # ── 2. Resolve target ─────────────────────────────────────────
    try:
        resolved = socket.gethostbyname(target)
        yield StreamEvent(
            engine_id=ENGINE_ID,
            kind="progress",
            data={"msg": f"[NMAP] Resolved {target} → {resolved}"},
            severity="INFO",
        )
    except socket.gaierror as exc:
        yield StreamEvent(
            engine_id=ENGINE_ID,
            kind="error",
            data={"msg": f"[NMAP] DNS resolution failed: {exc}", "target": target},
            severity="ALERT",
        )
        yield StreamEvent(
            engine_id=ENGINE_ID,
            kind="complete",
            data={"error": str(exc), "target": target},
            severity="ALERT",
        )
        return

    # ── 3. TTL / OS probe ─────────────────────────────────────────
    yield StreamEvent(
        engine_id=ENGINE_ID,
        kind="progress",
        data={"msg": "[NMAP] Probing TTL for OS fingerprint..."},
        severity="INFO",
    )
    ttl = await asyncio.get_event_loop().run_in_executor(None, _get_ttl, resolved)
    os_guess = _guess_os_from_ttl(ttl) if ttl else "Unknown (unprivileged)"
    yield StreamEvent(
        engine_id=ENGINE_ID,
        kind="progress",
        data={"msg": f"[NMAP] TTL={ttl or '?'}  OS guess → {os_guess}"},
        severity="INFO",
    )

    # ── 4. Choose backend ─────────────────────────────────────────
    nmap_available = bool(shutil.which("nmap"))
    backend = "nmap" if nmap_available else "socket"

    yield StreamEvent(
        engine_id=ENGINE_ID,
        kind="progress",
        data={"msg": f"[NMAP] Backend selected: {backend.upper()}"},
        severity="INFO" if nmap_available else "WARN",
    )

    if not nmap_available:
        yield StreamEvent(
            engine_id=ENGINE_ID,
            kind="error",
            data={"msg": "[NMAP] nmap binary not found — falling back to socket scanner"},
            severity="WARN",
        )

    # ── 5. Run scan ───────────────────────────────────────────────
    scan_result: NmapScanResult

    if backend == "nmap":
        yield StreamEvent(
            engine_id=ENGINE_ID,
            kind="progress",
            data={"msg": f"[NMAP] Executing: nmap -sV -T{timing} -p {ports} {target}"},
            severity="INFO",
        )
        xml_root = await _run_nmap_binary(target, ports, timing, extra_nmap_args)

        if xml_root is not None:
            scan_result = _parse_nmap_xml(xml_root, target)
        else:
            yield StreamEvent(
                engine_id=ENGINE_ID,
                kind="error",
                data={"msg": "[NMAP] Binary run failed — switching to socket fallback"},
                severity="WARN",
            )
            backend = "socket"

    if backend == "socket":
        # Build port list from range string
        port_list: List[int] = []
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                port_list.extend(range(int(lo), int(hi) + 1))
            else:
                port_list.append(int(part))

        yield StreamEvent(
            engine_id=ENGINE_ID,
            kind="progress",
            data={"msg": f"[NMAP] Socket scan: {len(port_list)} ports  concurrency={socket_concurrency}"},
            severity="INFO",
        )
        scan_result = await _run_socket_fallback(
            target, port_list, socket_timeout, socket_concurrency
        )

    scan_result.ttl      = ttl
    scan_result.os_guess = os_guess
    scan_result.resolved_ip = resolved

    # ── 6. Stream per-port results ────────────────────────────────
    open_ports = [p for p in scan_result.ports if p.state == "open"]

    yield StreamEvent(
        engine_id=ENGINE_ID,
        kind="progress",
        data={"msg": f"[NMAP] Scan complete — {len(open_ports)} open ports found"},
        severity="INFO" if open_ports else "WARN",
    )

    for port_result in sorted(open_ports, key=lambda p: p.port):
        # Banner grab
        if grab_banners and not port_result.banner:
            port_result.banner = await _grab_banner(resolved, port_result.port)

        # Per-port risk weight
        port_result.risk = _RISK_WEIGHTS.get(port_result.service, 2)

        sev = "CRITICAL" if port_result.risk >= 20 else \
              "ALERT"    if port_result.risk >= 10 else \
              "WARN"     if port_result.risk >= 5  else "INFO"

        msg = (
            f"[NMAP] OPEN  {port_result.port:>5}/{port_result.protocol:<3}  "
            f"{port_result.service:<12}  {port_result.version or port_result.banner or ''}"
        ).rstrip()

        yield StreamEvent(
            engine_id=ENGINE_ID,
            kind="result",
            data={
                "port":     port_result.port,
                "protocol": port_result.protocol,
                "state":    port_result.state,
                "service":  port_result.service,
                "version":  port_result.version,
                "banner":   port_result.banner,
                "risk":     port_result.risk,
                "msg":      msg,
            },
            severity=sev,
        )

        bus.emit(
            f"{ENGINE_ID}.port_open",
            {"target": target, "port": port_result.port, "service": port_result.service},
            source=ENGINE_ID,
        )

    # ── 7. Risk scoring ───────────────────────────────────────────
    scan_result.risk_score = _calc_risk(open_ports)
    scan_result.scan_time  = round(time.time() - t_start, 2)
    risk_sev = _severity_for_risk(scan_result.risk_score)

    yield StreamEvent(
        engine_id=ENGINE_ID,
        kind="progress",
        data={
            "msg": (
                f"[NMAP] Risk score: {scan_result.risk_score}/100  "
                f"({risk_sev})  |  Scan time: {scan_result.scan_time}s  "
                f"|  Backend: {scan_result.backend.upper()}"
            )
        },
        severity=risk_sev,
    )

    # ── 8. Complete ───────────────────────────────────────────────
    bus.emit(
        f"{ENGINE_ID}.complete",
        {
            "target":     target,
            "open_ports": len(open_ports),
            "risk_score": scan_result.risk_score,
            "os_guess":   scan_result.os_guess,
            "scan_time":  scan_result.scan_time,
        },
        source=ENGINE_ID,
    )

    yield StreamEvent(
        engine_id=ENGINE_ID,
        kind="complete",
        data={
            "target":      scan_result.target,
            "resolved_ip": scan_result.resolved_ip,
            "os_guess":    scan_result.os_guess,
            "ttl":         scan_result.ttl,
            "open_ports":  [p.__dict__ for p in open_ports],
            "risk_score":  scan_result.risk_score,
            "scan_time":   scan_result.scan_time,
            "backend":     scan_result.backend,
            "msg": (
                f"[NMAP] Done. {len(open_ports)} open ports  "
                f"Risk={scan_result.risk_score}/100  "
                f"OS={scan_result.os_guess}"
            ),
        },
        severity=risk_sev,
    )


# ── Compatibility Wrapper ───────────────────────────────────────────
try:
    from engines.base import BaseEngine, Request, Response, HealthStatus
except ImportError:
    # Minimal fallback for BaseEngine
    class BaseEngine:
        def __init__(self, bus=None): self.bus = bus
    class Request: pass
    class Response: pass
    class HealthStatus: pass

class NmapEngine(BaseEngine):
    """
    Class-based wrapper to satisfy existing Registry/UI imports.
    Calls the top-level 'stream' function internally.
    """
    TOOL_ID  = TOOL_ID
    CATEGORY = CATEGORY
    VERSION  = "1.0.0"

    async def initialize(self) -> None:
        self._ready = True

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        target = req.target or req.params.get("target", "127.0.0.1")
        ports  = req.params.get("ports", "1-1024")
        
        async for event in stream(target=target, ports=ports):
            yield event

    async def execute(self, req: Request) -> Response:
        # Simple collect-all implementation for sync execution
        results = []
        async for event in self.stream(req):
            if event.kind == "result":
                results.append(event.data)
        
        return Response(
            request_id=req.id,
            success=True,
            data={"open_ports": results},
            elapsed_ms=0 # Not tracked here
        )

    def health_check(self) -> HealthStatus:
        import shutil
        nmap_bin = shutil.which("nmap")
        return HealthStatus(
            engine_id=self.TOOL_ID,
            status="OK" if nmap_bin else "DEGRADED",
            message="Binary mode" if nmap_bin else "Socket fallback mode"
        )
