"""
engines/intruder/crackmapexec.py
CrackMapExec Engine - Wraps the external CrackMapExec tool.
Executes CME out-of-process and streams the stdout to the UI.
"""
import asyncio
import os
import sys
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class CrackMapExecEngine(BaseEngine):
    VERSION = "6.1.0"
    TOOL_ID = "crackmapexec"
    CATEGORY = "intruder"

    def __init__(self, bus=None):
        super().__init__(bus)
        # Point to the entry script inside the copied folder
        # The main entry point is cme/crackmapexec.py inside cme_src
        self.cme_path = os.path.join(
            os.path.dirname(__file__), 
            "cme_src", 
            "cme", 
            "crackmapexec.py"
        )
        self.python_exe = sys.executable

    def health_check(self) -> HealthStatus:
        if os.path.exists(self.cme_path):
            return HealthStatus(
                engine_id=self.TOOL_ID,
                status="OK",
                latency_ms=0.0,
                message="CrackMapExec suite ready"
            )
        return HealthStatus(
            engine_id=self.TOOL_ID,
            status="DEGRADED",
            latency_ms=0.0,
            message="cme/crackmapexec.py not found in cme_src"
        )

    async def execute(self, req: Request) -> Response:
        """
        Executes CME synchronously and waits for completion.
        """
        t0 = asyncio.get_event_loop().time()
        
        protocol = req.params.get("protocol", "smb")
        extra_args = req.params.get("args", "")
        
        # Set up environment with PYTHONPATH pointing to cme_src
        env = os.environ.copy()
        cme_root = os.path.dirname(self.cme_path) # e:\VulnScanner\engines\intruder\cme_src\cme
        cme_src = os.path.dirname(cme_root)      # e:\VulnScanner\engines\intruder\cme_src
        
        if "PYTHONPATH" in env:
            env["PYTHONPATH"] = f"{cme_src}{os.pathsep}{env['PYTHONPATH']}"
        else:
            env["PYTHONPATH"] = cme_src

        cmd = [self.python_exe, self.cme_path, protocol, req.target]
        if extra_args:
            cmd.extend(extra_args.split())

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            stdout, stderr = await process.communicate()
            
            output = stdout.decode('utf-8', 'ignore') if stdout else ""
            err_out = stderr.decode('utf-8', 'ignore') if stderr else ""
            
            self._emit("crackmapexec.exec", {"target": req.target, "cmd": " ".join(cmd)}, severity="INFO")
            
            elapsed = (asyncio.get_event_loop().time() - t0) * 1000
            
            if process.returncode != 0:
                combined = (output + "\n" + err_out).strip()
                return await self._after(Response(
                    request_id=req.id, success=False, error=combined or f"Exit code {process.returncode}", elapsed_ms=elapsed
                ))
                
            return await self._after(Response(
                request_id=req.id, success=True, data=output, elapsed_ms=elapsed
            ))
            
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        """
        Streams CME output line-by-line.
        """
        protocol = req.params.get("protocol", "smb")
        extra_args = req.params.get("args", "")
        
        env = os.environ.copy()
        cme_src = os.path.dirname(os.path.dirname(self.cme_path))
        if "PYTHONPATH" in env:
            env["PYTHONPATH"] = f"{cme_src}{os.pathsep}{env['PYTHONPATH']}"
        else:
            env["PYTHONPATH"] = cme_src

        cmd = [self.python_exe, self.cme_path, protocol, req.target]
        if extra_args:
            cmd.extend(extra_args.split())

        yield StreamEvent(
            engine_id=self.TOOL_ID, 
            kind="progress",
            data=f"[CME] Running: {' '.join(cmd)}"
        )
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,  # Merge stderr into stdout
                env=env
            )
            
            if process.stdout:
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    decoded_line = line.decode('utf-8', 'ignore').strip()
                    if decoded_line:
                        yield StreamEvent(
                            engine_id=self.TOOL_ID, 
                            kind="result",
                            data=decoded_line
                        )
                        
            await process.wait()
            
            if process.returncode != 0:
                yield StreamEvent(
                    engine_id=self.TOOL_ID, 
                    kind="error",
                    data=f"CME Exited with code {process.returncode}"
                )
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
            
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")
