"""
engines/analysis/dependency.py
DependencyEngine — Safety CVE scanning for Python dependency trees.
"""
import asyncio
import json
import subprocess
import time
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class DependencyEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "dependency"
    CATEGORY = "analysis"

    async def initialize(self) -> None:
        self._ready = True
        self._log("DependencyEngine initialized. Safety CVE scanner ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        req_file = req.params.get("requirements_file", "requirements.txt")
        try:
            vulns = await asyncio.to_thread(self._scan, req_file)
            self._emit("dependency.vulns", {"file": req_file, "count": len(vulns)})
            return await self._after(Response(
                request_id=req.id, success=True,
                data={"vulnerabilities": vulns, "count": len(vulns)},
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        req_file = req.params.get("requirements_file", "requirements.txt")
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[DEPS] Scanning {req_file} for CVEs...")
        try:
            vulns = await asyncio.to_thread(self._scan, req_file)
            for v in vulns:
                self._emit("dependency.cve", v, severity="CRITICAL")
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=v, severity="CRITICAL")
                await asyncio.sleep(0.05)
            if not vulns:
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result",
                                  data={"status": "clean", "file": req_file})
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _scan(self, req_file: str) -> list:
        try:
            result = subprocess.run(
                ["safety", "check", "-r", req_file, "--json"],
                capture_output=True, text=True, timeout=60,
            )
            data = json.loads(result.stdout or "[]")
            return data if isinstance(data, list) else []
        except FileNotFoundError:
            return [{"error": "safety not installed"}]
        except Exception as exc:
            return [{"error": str(exc)}]

    def health_check(self) -> HealthStatus:
        try:
            subprocess.run(["safety", "--version"], capture_output=True, timeout=5)
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="Safety available")
        except Exception as e:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message=str(e))
