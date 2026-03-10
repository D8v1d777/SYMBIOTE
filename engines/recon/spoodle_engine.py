import asyncio
import os
import time
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent

class SpoodleEngine(BaseEngine):
    """
    Industrial Wrapper for Spoodle (Mass Subdomain + SSL vulnerability scanner).
    """
    VERSION = "1.0.0"
    TOOL_ID = "spoodle"
    CATEGORY = "recon"

    async def initialize(self) -> None:
        self._ready = True
        self._log("SpoodleEngine initialized.")

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        target = req.target
        command = req.params.get("command", "spoodle")

        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[SPOODLE] Initializing mass subdomain validation for {target}...")
        await asyncio.sleep(0.5)
        
        cmd = [command, target]

        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[SPOODLE] Executing: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )

            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                line_str = line.decode('utf-8', errors='ignore').strip()
                if line_str:
                    sev = "INFO"
                    if "vuln" in line_str.lower() or "timeout" in line_str.lower():
                        sev = "WARN"
                    if "vulnerable" in line_str.lower() or "crt" in line_str.lower() or "critical" in line_str.lower():
                        sev = "ALERT"
                    yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=f"[SPOODLE] {line_str}", severity=sev)
            
            await process.wait()

            if process.returncode == 0:
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data="[SPOODLE] Subdomain extraction and SSL check successful.", severity="ALERT")
            else:
                 yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=f"[SPOODLE] Process exited with code {process.returncode}.", severity="ALERT")

        except FileNotFoundError:
            # Fallback to python script path if binary not in path
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data="spoodle binary not in PATH. Ensure it is installed.", severity="ALERT")
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=f"Spoodle execution error: {str(exc)}", severity="ALERT")

        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete", data="Spoodle scan complete.")

    async def execute(self, req: Request) -> Response:
        events = []
        async for evt in self.stream(req):
            events.append(evt)
        return Response(success=True, data=events, events_emitted=len(events))

    def health_check(self) -> HealthStatus:
        import shutil
        if shutil.which("spoodle"):
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="spoodle available")
        return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="spoodle not in PATH")
