"""
engines/system/ipython_engine.py
IPythonEngine — Embedded IPython REPL kernel.
"""
import asyncio
import time
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class IPythonEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "ipython"
    CATEGORY = "system"

    async def initialize(self) -> None:
        self._ready = True
        self._log("IPythonEngine initialized. Embedded REPL kernel ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        code = req.params.get("code", "")
        try:
            result = await asyncio.to_thread(self._exec, code)
            return await self._after(Response(
                request_id=req.id, success=True, data=result,
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        code = req.params.get("code", "print('IPython REPL ready')")
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[REPL] Executing: {code[:60]}...")
        try:
            result = await asyncio.to_thread(self._exec, code)
            yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=result)
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _exec(self, code: str) -> dict:
        try:
            from IPython import get_ipython
            from IPython.core.interactiveshell import InteractiveShell
            import io, contextlib
            buf = io.StringIO()
            shell = InteractiveShell.instance()
            with contextlib.redirect_stdout(buf):
                result = shell.run_cell(code)
            return {"output": buf.getvalue(), "success": not result.error_in_exec}
        except ImportError:
            # Fallback to exec
            from io import StringIO
            import contextlib
            buf = StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    exec(code, {})
                return {"output": buf.getvalue(), "success": True}
            except Exception as exc:
                return {"output": str(exc), "success": False}

    def health_check(self) -> HealthStatus:
        try:
            import IPython  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="IPython available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED",
                                message="IPython not installed, using exec fallback")
