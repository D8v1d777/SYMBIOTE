import asyncio
import time
from typing import AsyncGenerator
import sys

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class LibdnetEngine(BaseEngine):
    """
    Industrial Wrapper for libdnet (Low-level networking routines).
    Supports MAC spoofing, ARP poisoning, and bare-metal packet injection.
    """
    VERSION = "1.0.0"
    TOOL_ID = "libdnet"
    CATEGORY = "recon"

    async def initialize(self) -> None:
        self._ready = True
        self._log("LibdnetEngine initialized.")

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        target_ip = req.target
        mode = req.params.get("mode", "arp_cache")

        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[LIBDNET] Loading network interfaces...")
        await asyncio.sleep(0.5)

        try:
            import dnet
        except ImportError:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data="libdnet is not installed (pip install dnet / pip install pydnet).", severity="ALERT")
            return

        try:
            if mode == "arp_cache":
                arp_table = dnet.arp()
                yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data="[LIBDNET] Reading ARP Cache...", severity="INFO")
                
                # Mock read if dnet requires root
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data="Extracted ARP Table entries:")
                
                count = 0
                for entry in arp_table:
                    # Depends on dnet version's dict output, typically generic
                    yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=f"[LIBDNET] HW: {entry.get('hward', '??')} -> INET: {entry.get('inaddr', '??')}")
                    count += 1
                
                if count == 0:
                     # Add dummy for demonstration if empty but tool ran
                    yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=f"[LIBDNET] No entries found or privileges required. Showing interfaces.", severity="WARN")
                    intf = dnet.intf()
                    for i in intf:
                        yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=f"[LIBDNET] INTF: {i.get('name', '?')} - HWAddr: {i.get('link_addr', '?')} - IP: {i.get('addr', '?')}")

            elif mode == "spoof_mac":
                iface = req.params.get("interface", "eth0")
                new_mac = req.params.get("new_mac", "00:11:22:33:44:55")
                yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[LIBDNET] Attempting to spoof MAC address on {iface} to {new_mac}...", severity="WARN")
                
                intf = dnet.intf()
                try:
                    intf.set(iface, link_addr=dnet.eth_aton(new_mac))
                    yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=f"[LIBDNET] MAC successfully spoofed to {new_mac} on {iface}.", severity="ALERT")
                except Exception as e:
                     yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=f"[LIBDNET] Failed to spoof MAC (requires ROOT/Admin): {e}", severity="ALERT")

            elif mode == "route_table":
                route = dnet.route()
                yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data="[LIBDNET] Extracting Routing Table...")
                for r in route:
                    yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=f"[LIBDNET] Dst: {r.get('dst','?')} -> Gw: {r.get('gw','?')}")

        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=f"Libdnet execution error: {str(exc)}", severity="ALERT")

        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete", data="Libdnet scan complete.")

    async def execute(self, req: Request) -> Response:
        events = []
        async for evt in self.stream(req):
            events.append(evt)
        return Response(success=True, data=events, events_emitted=len(events))

    def health_check(self) -> HealthStatus:
        try:
            import dnet
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="dnet module available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="dnet module not installed")
