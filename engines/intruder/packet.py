"""
engines/intruder/packet.py
PacketEngine — PyShark live packet capture, BPF filter builder, realtime streaming.
"""
import asyncio
import threading
import time
from typing import AsyncGenerator, List

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class PacketEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "packet"
    CATEGORY = "intruder"

    async def initialize(self) -> None:
        self._ready = True
        self._log("PacketEngine initialized. PyShark/TShark backend ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        iface = req.params.get("interface", "")
        count = req.params.get("count", 10)
        bpf = req.params.get("bpf_filter", "")
        try:
            packets = await asyncio.to_thread(self._capture, iface, count, bpf)
            self._emit("packet.capture", {"interface": iface, "count": len(packets)})
            return await self._after(Response(
                request_id=req.id, success=True,
                data={"packets": packets, "count": len(packets)},
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        iface = req.params.get("interface", "")
        count = req.params.get("count", 20)
        bpf = req.params.get("bpf_filter", "")
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[PKT] Sniffing {iface or 'default'} | BPF: '{bpf}' | Count: {count}")
        queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_event_loop()
        captured = []

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
                    summary = {
                        "ts": str(pkt.sniff_time),
                        "layer": pkt.highest_layer,
                        "length": int(pkt.length),
                        "summary": str(pkt),
                    }
                    captured.append(summary)
                    loop.call_soon_threadsafe(queue.put_nowait, summary)
            except Exception as exc:
                loop.call_soon_threadsafe(queue.put_nowait, {"error": str(exc)})
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)  # sentinel

        t = threading.Thread(target=_do_capture, daemon=True)
        t.start()

        while True:
            item = await queue.get()
            if item is None:
                break
            self._emit("packet.stream", item)
            yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=item)

        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete",
                          data=f"Capture complete. {len(captured)} packets.")

    def _capture(self, iface: str, count: int, bpf: str) -> List[dict]:
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
                packets.append({"ts": str(pkt.sniff_time), "layer": pkt.highest_layer,
                                 "length": int(pkt.length)})
            return packets
        except ImportError:
            return [{"error": "pyshark/tshark not installed"}]

    def health_check(self) -> HealthStatus:
        try:
            import pyshark  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="PyShark available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="pyshark not installed")
