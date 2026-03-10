"""
engines/intruder/remote.py
RemoteEngine — RPyC remote Python execution bridge.
Execute arbitrary Python remotely, inject code, bridge to target processes.
"""
import asyncio
import time
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class RemoteEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "remote"
    CATEGORY = "intruder"

    async def initialize(self) -> None:
        self._ready = True
        self._log("RemoteEngine initialized. RPyC bridge ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        host = req.target
        port = req.params.get("port", 18861)
        code = req.params.get("code", "import platform; platform.node()")
        try:
            result = await asyncio.to_thread(self._exec_remote, host, port, code)
            self._emit("remote.exec", {"host": host, "code_len": len(code)}, severity="ALERT")
            return await self._after(Response(
                request_id=req.id, success=True, data=result,
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        host = req.target
        port = req.params.get("port", 18861)
        code = req.params.get("code", "import os; os.getcwd()")
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[REMOTE] Connecting RPyC bridge → {host}:{port}...")
        await asyncio.sleep(0.05)
        try:
            result = await asyncio.to_thread(self._exec_remote, host, port, code)
            self._emit("remote.stream", {"host": host, "result": str(result)}, severity="ALERT")
            yield StreamEvent(engine_id=self.TOOL_ID, kind="result",
                              data={"host": host, "result": str(result)}, severity="ALERT")
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _exec_remote(self, host: str, port: int, code: str):
        try:
            import rpyc
            conn = rpyc.classic.connect(host, port=port)
            result = conn.execute(code)
            conn.close()
            return {"output": str(result), "host": host}
        except ImportError:
            return {"error": "rpyc not installed"}
        except Exception as exc:
            return {"error": str(exc)}

    def health_check(self) -> HealthStatus:
        try:
            import rpyc  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="RPyC available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="rpyc not installed")
