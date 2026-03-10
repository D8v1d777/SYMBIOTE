import asyncio
import os
import time
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent

class DirsearchEngine(BaseEngine):
    """
    Industrial Wrapper for Dirsearch (Web Path Brute-forcer).
    High performance asynchronous endpoint discovery.
    """
    VERSION = "1.0.0"
    TOOL_ID = "dirsearch"
    CATEGORY = "intruder"

    async def initialize(self) -> None:
        self._ready = True
        self._log("DirsearchEngine initialized.")

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        url = req.target
        extensions = req.params.get("extensions", "php,asp,aspx,jsp,html,zip,jar,sql")
        wordlist = req.params.get("wordlist", "")
        max_rate = req.params.get("max_rate", "0")

        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[DIRSEARCH] Spinning up path enumeration for {url}...")
        await asyncio.sleep(0.5)
        
        cmd = ["dirsearch", "-u", url, "-e", extensions, "--format=simple"]
        if wordlist:
            cmd.extend(["-w", wordlist])
        if max_rate != "0":
            cmd.extend(["--max-rate", max_rate])

        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[DIRSEARCH] Executing: {' '.join(cmd)}")

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
                # Filter out loading bars and color codes, just read raw
                line_str = line.decode('utf-8', errors='ignore').strip()
                
                # Check for standard Dirsearch output line formats if formatted as simple
                if line_str and not line_str.startswith("_"):
                     if "Target:" in line_str or "Extensions:" in line_str or "[*]" in line_str or "Wordlist" in line_str or "Error" in line_str:
                         continue
                     sev = "INFO"
                     if " 200 " in line_str or " 301 " in line_str or " 302 " in line_str:
                         sev = "ALERT"
                     elif " 403 " in line_str or " 401 " in line_str:
                         sev = "WARN"
                     
                     if line_str:
                        yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=f"[DIRSEARCH] {line_str}", severity=sev)
            
            await process.wait()

            if process.returncode == 0:
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data="[DIRSEARCH] Subdomain extraction complete.", severity="SUCCESS")
            else:
                 yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=f"[DIRSEARCH] Exited with code {process.returncode}.", severity="ALERT")

        except FileNotFoundError:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data="dirsearch not in PATH. Ensure pip install dirsearch.", severity="ALERT")
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=f"Dirsearch execution error: {str(exc)}", severity="ALERT")

        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete", data="Dirsearch routing complete.")

    async def execute(self, req: Request) -> Response:
        events = []
        async for evt in self.stream(req):
            events.append(evt)
        return Response(success=True, data=events, events_emitted=len(events))

    def health_check(self) -> HealthStatus:
        import shutil
        if shutil.which("dirsearch"):
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="dirsearch available")
        return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="dirsearch not in PATH")
