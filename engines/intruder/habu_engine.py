import asyncio
import os
import time
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent

class HabuEngine(BaseEngine):
    """
    Industrial Wrapper for Habu (Python Network Hacking Toolkit).
    Utilizes powerful TCP flag manipulation and active network attacks.
    """
    VERSION = "1.0.0"
    TOOL_ID = "habu"
    CATEGORY = "intruder"

    async def initialize(self) -> None:
        self._ready = True
        self._log("HabuEngine initialized.")

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        target = req.target
        command = req.params.get("command", "habu.ping")
        extra_args = req.params.get("extra", "")

        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[HABU] Preparing {command} on {target}...")
        await asyncio.sleep(0.5)
        
        # Habu installs multiple CLI binaries like habu.ping, habu.synflood, etc.
        cmd = [command]
        if target:
            cmd.append(target)
        if extra_args:
            cmd.extend(extra_args.split())

        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[HABU] Executing: {' '.join(cmd)}")

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
                    yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=f"[HABU] {line_str}", severity="INFO")
            
            await process.wait()

            if process.returncode == 0:
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=f"[{command}] Successful.", severity="ALERT")
            else:
                yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=f"[{command}] Exited with code {process.returncode}.", severity="ALERT")

        except FileNotFoundError:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=f"Binary '{command}' not in PATH. Please 'pip install habu'.", severity="ALERT")
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=f"Habu execution error: {str(exc)}", severity="ALERT")

        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete", data="Habu operation complete.")

    async def execute(self, req: Request) -> Response:
        events = []
        async for evt in self.stream(req):
            events.append(evt)
        return Response(success=True, data=events, events_emitted=len(events))

    def health_check(self) -> HealthStatus:
        import shutil
        if shutil.which("habu.arping"):
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="habu binaries available")
        return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="habu binaries not in PATH")
