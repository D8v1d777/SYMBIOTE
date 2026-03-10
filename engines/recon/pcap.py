"""
engines/recon/pcap.py
PacketCaptureEngine — PyShark passive stealth recon.
Zero active probes, feeds discovered hosts/services to other recon engines.
"""
import asyncio
import threading
import time
from typing import AsyncGenerator, List

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class PacketCaptureEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "pcap"
    CATEGORY = "recon"

    async def initialize(self) -> None:
        self._ready = True
        self._log("PacketCaptureEngine initialized. Passive stealth mode ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        iface = req.params.get("interface", "")
        count = req.params.get("count", 50)
        bpf = req.params.get("bpf_filter", "")
        try:
            packets = await asyncio.to_thread(self._passive_capture, iface, count, bpf)
            hosts = self._extract_hosts(packets)
            self._emit("pcap.hosts", {"unique_hosts": len(hosts)})
            return await self._after(Response(
                request_id=req.id, success=True,
                data={"packets": packets, "hosts": hosts},
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        iface = req.params.get("interface", "")
        count = req.params.get("count", 30)
        bpf = req.params.get("bpf_filter", "")
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[PCAP] Stealth passive capture on {iface or 'default'} ({count} pkts)...")
        queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_event_loop()

        def _do_capture():
            try:
                import pyshark
                kw = {"packet_count": count}
                if iface:
                    kw["interface"] = iface
                if bpf:
                    kw["bpf_filter"] = bpf
                cap = pyshark.LiveCapture(**kw)
                for pkt in cap.sniff_continuously(packet_count=count):
                    row = {"ts": str(pkt.sniff_time), "layer": pkt.highest_layer, "len": int(pkt.length)}
                    loop.call_soon_threadsafe(queue.put_nowait, row)
            except Exception as exc:
                loop.call_soon_threadsafe(queue.put_nowait, {"error": str(exc)})
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)

        t = threading.Thread(target=_do_capture, daemon=True)
        t.start()
        while True:
            item = await queue.get()
            if item is None:
                break
            yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=item)
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _passive_capture(self, iface: str, count: int, bpf: str) -> List[dict]:
        try:
            import pyshark
            kw = {"packet_count": count}
            if iface:
                kw["interface"] = iface
            if bpf:
                kw["bpf_filter"] = bpf
            cap = pyshark.LiveCapture(**kw)
            packets = []
            for pkt in cap.sniff_continuously(packet_count=count):
                packets.append({"layer": pkt.highest_layer, "length": int(pkt.length)})
            return packets
        except ImportError:
            return [{"error": "pyshark not installed"}]

    def _extract_hosts(self, packets: List[dict]) -> List[str]:
        return list(set(p.get("src", "") for p in packets if p.get("src")))

    def health_check(self) -> HealthStatus:
        try:
            import pyshark  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="PyShark available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="pyshark not installed")
