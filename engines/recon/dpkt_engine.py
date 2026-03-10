import asyncio
import os
import time
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class DpktEngine(BaseEngine):
    """
    Industrial Wrapper for DPKT (Fast packet creation/parsing).
    Processes PCAP files for lightning fast protocol extraction and anomaly detection.
    """
    VERSION = "1.0.0"
    TOOL_ID = "dpkt"
    CATEGORY = "recon"

    async def initialize(self) -> None:
        self._ready = True
        self._log("DpktEngine initialized.")

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        pcap_file = req.target  # Can be local file or interface name metaphor
        mode = req.params.get("mode", "parse_pcap")

        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[DPKT] Analyzing PCAP/Traffic on: {pcap_file}...")
        await asyncio.sleep(0.5)

        try:
            import dpkt
            import socket
        except ImportError:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data="dpkt is not installed (pip install dpkt).", severity="ALERT")
            return

        if not os.path.isfile(pcap_file):
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=f"[DPKT] File not found: {pcap_file}. Need a valid .pcap file.", severity="ALERT")
            return

        try:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[DPKT] Parsing {pcap_file} for HTTP/DNS anomalies...")
            with open(pcap_file, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                count = 0
                http_count = 0
                dns_count = 0

                for ts, buf in pcap:
                    count += 1
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if not isinstance(eth.data, dpkt.ip.IP): continue
                        ip = eth.data
                        if not isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)): continue
                        
                        transport = ip.data
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)

                        # Check HTTP
                        if isinstance(transport, dpkt.tcp.TCP) and (transport.dport == 80 or transport.sport == 80):
                            if len(transport.data) > 0:
                                try:
                                    http = dpkt.http.Request(transport.data)
                                    yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=f"[DPKT] HTTP {http.method} -> {http.uri} ({src_ip} -> {dst_ip})", severity="INFO")
                                    http_count += 1
                                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                                    pass
                        
                        # Check DNS
                        if isinstance(transport, dpkt.udp.UDP) and (transport.dport == 53 or transport.sport == 53):
                            if len(transport.data) > 0:
                                try:
                                    dns = dpkt.dns.DNS(transport.data)
                                    if dns.qd:
                                        for qname in dns.qd:
                                            yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=f"[DPKT] DNS Query: {qname.name} ({src_ip})", severity="INFO")
                                            dns_count += 1
                                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                                    pass

                        if count > 5000:
                            yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data="[DPKT] Reached parsing limit (5000 pkts). Halting.", severity="WARN")
                            break

                    except Exception:
                        continue # Malformed packet handling

                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=f"[DPKT] Parsed {count} packets. Identified {http_count} HTTP requests, {dns_count} DNS queries.", severity="ALERT")

        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=f"DPKT parsing error: {str(exc)}", severity="ALERT")

        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete", data="DPKT analysis complete.")

    async def execute(self, req: Request) -> Response:
        events = []
        async for evt in self.stream(req):
            events.append(evt)
        return Response(success=True, data=events, events_emitted=len(events))

    def health_check(self) -> HealthStatus:
        try:
            import dpkt
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="dpkt available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="dpkt not installed")
