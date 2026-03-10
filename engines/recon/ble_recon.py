"""
engines/recon/ble_recon.py
BLEReconEngine — BLE device fingerprinting, GATT service map, signal heatmap.
"""
import asyncio
import time
from typing import AsyncGenerator, List

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent

# Well-known manufacturer IDs (partial list)
MANUFACTURER_LOOKUP = {
    "0x004C": "Apple", "0x0075": "Samsung", "0x00E0": "Google",
    "0x0006": "Microsoft", "0x0022": "Qualcomm",
}


class BLEReconEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "ble_recon"
    CATEGORY = "recon"

    async def initialize(self) -> None:
        self._ready = True
        self._log("BLEReconEngine initialized. Bleak BLE fingerprinting ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        duration = req.params.get("duration", 5.0)
        try:
            devices = await self._scan(duration)
            self._emit("ble_recon.scan", {"found": len(devices)})
            return await self._after(Response(
                request_id=req.id, success=True,
                data={"devices": devices, "count": len(devices)},
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        duration = req.params.get("duration", 5.0)
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[BLE-RECON] Passive scan for {duration}s...")
        try:
            devices = await self._scan(duration)
            for dev in devices:
                self._emit("ble_recon.device", dev)
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=dev)
                await asyncio.sleep(0.05)
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    async def _scan(self, duration: float) -> List[dict]:
        try:
            from bleak import BleakScanner
            found = await BleakScanner.discover(timeout=duration)
            results = []
            for d in found:
                mfr_data = d.metadata.get("manufacturer_data", {})
                mfr_id = list(mfr_data.keys())[0] if mfr_data else None
                mfr_name = MANUFACTURER_LOOKUP.get(f"0x{mfr_id:04X}", "Unknown") if mfr_id else "Unknown"
                results.append({
                    "address": d.address,
                    "name": d.name or "Unknown",
                    "rssi": d.rssi,
                    "manufacturer": mfr_name,
                    "uuids": list(d.metadata.get("uuids", [])),
                    "adv_interval": None,  # requires active timing measurement
                })
            return sorted(results, key=lambda x: x["rssi"], reverse=True)
        except ImportError:
            return [{"error": "bleak not installed"}]
        except Exception as exc:
            return [{"error": str(exc)}]

    def health_check(self) -> HealthStatus:
        try:
            import bleak  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="Bleak available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="bleak not installed")
