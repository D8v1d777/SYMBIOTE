"""
engines/analysis/static_audit.py
StaticAuditEngine — Bandit AST security scanner for Python code.
"""
import asyncio
import json
import subprocess
import tempfile
import time
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class StaticAuditEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "static_audit"
    CATEGORY = "analysis"

    async def initialize(self) -> None:
        self._ready = True
        self._log("StaticAuditEngine initialized. Bandit AST scanner ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        path = req.target or req.params.get("path", ".")
        try:
            result = await asyncio.to_thread(self._run_bandit, path)
            severity_counts = self._count_severities(result)
            self._emit("audit.static", {"path": path, **severity_counts})
            return await self._after(Response(
                request_id=req.id, success=True,
                data={"results": result, "summary": severity_counts},
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        path = req.target or req.params.get("path", ".")
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[AUDIT] Running Bandit AST scan on: {path}")
        await asyncio.sleep(0.05)
        try:
            issues = await asyncio.to_thread(self._run_bandit, path)
            for issue in issues:
                sev = issue.get("issue_severity", "LOW")
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=issue,
                                  severity="CRITICAL" if sev == "HIGH" else sev)
                await asyncio.sleep(0.02)
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _run_bandit(self, path: str) -> list:
        try:
            result = subprocess.run(
                ["bandit", "-r", path, "-f", "json", "-q"],
                capture_output=True, text=True, timeout=60,
            )
            data = json.loads(result.stdout or "{}")
            return data.get("results", [])
        except FileNotFoundError:
            return [{"error": "bandit not installed or not on PATH"}]
        except Exception as exc:
            return [{"error": str(exc)}]

    def _count_severities(self, issues: list) -> dict:
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for i in issues:
            sev = i.get("issue_severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def health_check(self) -> HealthStatus:
        try:
            subprocess.run(["bandit", "--version"], capture_output=True, timeout=5)
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="Bandit available")
        except Exception as e:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message=str(e))
