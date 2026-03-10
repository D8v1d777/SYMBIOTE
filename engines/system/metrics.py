"""
engines/system/metrics.py
SystemMetricsEngine — psutil realtime CPU/mem/net/disk telemetry.
"""
import asyncio
import time
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class SystemMetricsEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "sys_metrics"
    CATEGORY = "system"

    async def initialize(self) -> None:
        self._ready = True
        self._log("SystemMetricsEngine initialized. psutil ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        try:
            metrics = self._snapshot()
            self._emit("metrics.snapshot", metrics)
            return await self._after(Response(
                request_id=req.id, success=True, data=metrics,
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        interval = req.params.get("interval", 1.0)
        count = req.params.get("count", 10)
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[METRICS] Streaming {count} snapshots @ {interval}s interval...")
        for _ in range(count):
            await asyncio.sleep(interval)
            snap = self._snapshot()
            self._emit("metrics.realtime", snap)
            yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=snap)
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _snapshot(self) -> dict:
        try:
            import psutil
            net = psutil.net_io_counters()
            return {
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "mem_percent": psutil.virtual_memory().percent,
                "mem_used_mb": round(psutil.virtual_memory().used / 1024 / 1024, 1),
                "disk_percent": psutil.disk_usage("/").percent,
                "net_sent_mb": round(net.bytes_sent / 1024 / 1024, 2),
                "net_recv_mb": round(net.bytes_recv / 1024 / 1024, 2),
                "thread_count": len(psutil.Process().threads()),
                "ts": time.time(),
            }
        except ImportError:
            return {"error": "psutil not installed"}

    def health_check(self) -> HealthStatus:
        try:
            import psutil  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="psutil available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="psutil not installed")
