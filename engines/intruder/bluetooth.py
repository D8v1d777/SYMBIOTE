"""
engines/intruder/bluetooth.py
BluetoothEngine — Bleak BLE scan, GATT service mapper, advertisement fingerprinting.
"""
import asyncio
import time
from typing import AsyncGenerator, List

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class BluetoothEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "bluetooth"
    CATEGORY = "intruder"

    async def initialize(self) -> None:
        self._ready = True
        self._log("BluetoothEngine initialized. Bleak BLE backend ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        action = req.params.get("action", "scan")
        duration = req.params.get("duration", 5.0)
        try:
            devices = await self._scan(duration)
            self._emit("bluetooth.scan", {"found": len(devices)})
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
                          data=f"[BLE] Starting {duration}s advertisement scan...")
        try:
            devices = await self._scan(duration)
            for dev in devices:
                self._emit("bluetooth.device", dev, severity="INFO")
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=dev)
                await asyncio.sleep(0.05)
            if not devices:
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result",
                                  data={"message": "No BLE devices found."})
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete", data="BLE scan complete.")

    async def _scan(self, duration: float) -> List[dict]:
        try:
            from bleak import BleakScanner
            discovered = await BleakScanner.discover(timeout=duration)
            return [
                {
                    "address": d.address,
                    "name": d.name or "Unknown",
                    "rssi": d.rssi,
                    "manufacturer_data": str(d.metadata.get("manufacturer_data", {})),
                    "uuids": list(d.metadata.get("uuids", [])),
                }
                for d in discovered
            ]
        except ImportError:
            return [{"error": "bleak not installed"}]
        except Exception as exc:
            return [{"error": str(exc)}]

    async def gatt_map(self, address: str) -> dict:
        """Map all GATT services and characteristics for a device."""
        try:
            from bleak import BleakClient
            services = {}
            async with BleakClient(address) as client:
                for service in client.services:
                    chars = {c.uuid: c.properties for c in service.characteristics}
                    services[service.uuid] = {"handle": service.handle, "chars": chars}
            return {"address": address, "services": services}
        except Exception as exc:
            return {"address": address, "error": str(exc)}

    def health_check(self) -> HealthStatus:
        try:
            import bleak  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="Bleak available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="bleak not installed")
