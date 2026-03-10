import asyncio
import os
import time
import subprocess
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class BloodHoundEngine(BaseEngine):
    """
    Industrial Wrapper for BloodHound.py (Python ingestor).
    Extracts Active Directory Data for graph enumeration.
    """
    VERSION = "1.0.0"
    TOOL_ID = "bloodhound"
    CATEGORY = "recon"

    async def initialize(self) -> None:
        self._ready = True
        self._log("BloodHoundEngine initialized.")

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        target_domain = req.target
        username = req.params.get("username", "")
        password = req.params.get("password", "")
        dc_ip = req.params.get("dc_ip", "")
        collection = req.params.get("collection", "All")

        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[BLOODHOUND] Initializing Python Ingestor for {target_domain}...")
        await asyncio.sleep(0.5)

        cmd = ["bloodhound-python", "-d", target_domain, "-c", collection]
        if username and password:
            cmd.extend(["-u", username, "-p", password])
        if dc_ip:
            cmd.extend(["-dc", dc_ip])

        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[BLOODHOUND] Executing: {' '.join(cmd).replace(password, '***') if password else ' '.join(cmd)}")

        try:
            # We don't want bare execution blocking the event loop; wrapping in thread/asyncio
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
                    severity = "INFO"
                    if "error" in line_str.lower() or "failed" in line_str.lower() or "exception" in line_str.lower():
                        severity = "ALERT"
                    elif "resolving" in line_str.lower() or "connecting" in line_str.lower():
                         severity = "WARN"
                    yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=f"[BLOODHOUND] {line_str}", severity=severity)
            
            await process.wait()

            if process.returncode == 0:
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data="[BLOODHOUND] Ingestion completed. JSON output generated in current directory.", severity="ALERT")
            else:
                 yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=f"[BLOODHOUND] Process exited with code {process.returncode}.", severity="ALERT")

        except FileNotFoundError:
             yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data="bloodhound-python is not installed or not in PATH. (pip install bloodhound)", severity="ALERT")
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=f"BloodHound execution error: {str(exc)}", severity="ALERT")

        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete", data="BloodHound enumeration complete.")

    async def execute(self, req: Request) -> Response:
        events = []
        async for evt in self.stream(req):
            events.append(evt)
        return Response(success=True, data=events, events_emitted=len(events))

    def health_check(self) -> HealthStatus:
        import shutil
        if shutil.which("bloodhound-python"):
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="bloodhound-python available")
        return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="bloodhound-python not in PATH")
