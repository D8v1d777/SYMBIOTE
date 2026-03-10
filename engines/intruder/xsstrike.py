"""
engines/intruder/xsstrike.py
XSStrike Engine — Wraps the XSStrike XSS detection suite.

XSStrike (https://github.com/s0md3v/XSStrike) is a standalone Python tool,
NOT a pip library.  It is designed to be invoked as a script, so we execute
it out-of-process exactly the same way we wrap CrackMapExec.

Expected layout on-disk:
    engines/intruder/xsstrike_src/
        xsstrike.py          ← main entry point
        core/                ← fuzzer, crawler, config, etc.
        ...

Setup (one-time):
    cd engines/intruder
    git clone https://github.com/s0md3v/XSStrike.git xsstrike_src
    pip install -r xsstrike_src/requirements.txt
"""
import asyncio
import os
import sys
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class XSStrikeEngine(BaseEngine):
    """
    XSStrike XSS Audit Engine.

    Supported Request params:
        url          (str)  — target URL with or without query params
        mode         (str)  — 'reflected' (default) | 'crawl' | 'dom' | 'fuzzer'
        data         (str)  — POST body, e.g. 'q=test&submit=1'
        cookies      (str)  — raw cookie header, e.g. 'session=abc123'
        headers      (str)  — extra headers as 'Key:Value,...'
        crawl_depth  (int)  — link depth when mode='crawl' (default 2)
        threads      (int)  — concurrent threads (default 2)
        timeout      (int)  — per-request timeout in seconds (default 10)
        proxy        (str)  — HTTP proxy, e.g. 'http://127.0.0.1:8080'
        extra_args   (str)  — any raw extra flags appended verbatim
    """
    VERSION = "3.1.5"
    TOOL_ID = "xsstrike"
    CATEGORY = "intruder"

    def __init__(self, bus=None):
        super().__init__(bus)
        # Locate the bundled XSStrike entry-point
        self._src_dir = os.path.join(
            os.path.dirname(__file__),
            "xsstrike_src"
        )
        self._entry = os.path.join(self._src_dir, "xsstrike.py")
        self._python = sys.executable

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        self._ready = os.path.isfile(self._entry)
        status = "ready" if self._ready else "xsstrike_src not found — clone the repo first"
        self._log(f"XSStrikeEngine v{self.VERSION}: {status}")

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health_check(self) -> HealthStatus:
        if os.path.isfile(self._entry):
            return HealthStatus(
                engine_id=self.TOOL_ID,
                status="OK",
                latency_ms=0.0,
                message="XSStrike suite ready"
            )
        return HealthStatus(
            engine_id=self.TOOL_ID,
            status="DEGRADED",
            latency_ms=0.0,
            message=(
                "xsstrike_src/xsstrike.py not found. "
                "Run: git clone https://github.com/s0md3v/XSStrike.git "
                "engines/intruder/xsstrike_src"
            )
        )

    # ------------------------------------------------------------------
    # Command builder
    # ------------------------------------------------------------------

    def _build_cmd(self, req: Request):
        """Construct the subprocess argument list from a Request."""
        url = req.target or req.params.get("url", "")
        mode = req.params.get("mode", "reflected")
        data = req.params.get("data", "")
        cookies = req.params.get("cookies", "")
        headers = req.params.get("headers", "")
        crawl_depth = req.params.get("crawl_depth", 2)
        threads = req.params.get("threads", 2)
        timeout = req.params.get("timeout", 10)
        proxy = req.params.get("proxy", "")
        extra_args = req.params.get("extra_args", "")

        cmd = [self._python, self._entry, "--url", url]

        # Mode flags
        if mode == "crawl":
            cmd += ["--crawl", "--level", str(crawl_depth)]
        elif mode == "dom":
            cmd += ["--dom"]
        elif mode == "fuzzer":
            cmd += ["--fuzzer"]
        # 'reflected' is the default — no extra flag needed

        if data:
            cmd += ["--data", data]
        if cookies:
            cmd += ["--cookie", cookies]
        if headers:
            cmd += ["--headers", headers]
        if proxy:
            cmd += ["--proxy"]
        if threads:
            cmd += ["--threads", str(threads)]
        if timeout:
            cmd += ["--timeout", str(timeout)]
        # Suppress the colour codes so log output is clean in the Qt terminal
        cmd += ["--no-color"]

        if extra_args:
            cmd += extra_args.split()

        return cmd

    def _make_env(self) -> dict:
        """Ensure xsstrike_src is on PYTHONPATH so its internal imports resolve."""
        env = os.environ.copy()
        entry = self._src_dir
        if "PYTHONPATH" in env:
            env["PYTHONPATH"] = f"{entry}{os.pathsep}{env['PYTHONPATH']}"
        else:
            env["PYTHONPATH"] = entry
        return env

    # ------------------------------------------------------------------
    # execute()  — blocking, waits for completion
    # ------------------------------------------------------------------

    async def execute(self, req: Request) -> Response:
        t0 = asyncio.get_event_loop().time()

        if not os.path.isfile(self._entry):
            return await self._on_error(
                FileNotFoundError(
                    "XSStrike not found. Clone https://github.com/s0md3v/XSStrike "
                    "into engines/intruder/xsstrike_src/"
                ),
                req
            )

        cmd = self._build_cmd(req)
        env = self._make_env()

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self._src_dir,
                env=env
            )
            stdout, stderr = await process.communicate()

            output = stdout.decode("utf-8", "ignore") if stdout else ""
            err_out = stderr.decode("utf-8", "ignore") if stderr else ""

            self._emit(
                "xsstrike.exec",
                {"target": req.target, "cmd": " ".join(cmd)},
                severity="INFO"
            )

            elapsed = (asyncio.get_event_loop().time() - t0) * 1000

            if process.returncode not in (0, None):
                combined = (output + "\n" + err_out).strip()
                return await self._after(Response(
                    request_id=req.id,
                    success=False,
                    error=combined or f"XSStrike exited with code {process.returncode}",
                    elapsed_ms=elapsed
                ))

            return await self._after(Response(
                request_id=req.id,
                success=True,
                data=output,
                elapsed_ms=elapsed
            ))

        except Exception as exc:
            return await self._on_error(exc, req)

    # ------------------------------------------------------------------
    # stream()  — yields output line-by-line in real time
    # ------------------------------------------------------------------

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        if not os.path.isfile(self._entry):
            yield StreamEvent(
                engine_id=self.TOOL_ID,
                kind="error",
                data=(
                    "[XSStrike] Tool not found. "
                    "Clone https://github.com/s0md3v/XSStrike into "
                    "engines/intruder/xsstrike_src/ then restart."
                ),
                severity="ALERT"
            )
            return

        cmd = self._build_cmd(req)
        env = self._make_env()

        yield StreamEvent(
            engine_id=self.TOOL_ID,
            kind="progress",
            data=f"[XSS] Launching: {' '.join(cmd)}"
        )

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,   # merge stderr → stdout
                cwd=self._src_dir,
                env=env
            )

            if process.stdout:
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    text = line.decode("utf-8", "ignore").strip()
                    if not text:
                        continue

                    # Classify output severity for richer UI colouring
                    severity = "INFO"
                    if any(kw in text.lower() for kw in [
                        "xss", "vulnerable", "payload", "injected", "confirmed"
                    ]):
                        severity = "ALERT"
                    elif any(kw in text.lower() for kw in [
                        "warning", "waf", "detected", "filter"
                    ]):
                        severity = "WARN"

                    yield StreamEvent(
                        engine_id=self.TOOL_ID,
                        kind="result",
                        data=text,
                        severity=severity
                    )
                    self._emit("xsstrike.output", {"line": text}, severity=severity)

            await process.wait()

            if process.returncode not in (0, None):
                yield StreamEvent(
                    engine_id=self.TOOL_ID,
                    kind="error",
                    data=f"[XSS] XSStrike exited with code {process.returncode}",
                    severity="WARN"
                )

        except Exception as exc:
            yield StreamEvent(
                engine_id=self.TOOL_ID,
                kind="error",
                data=str(exc),
                severity="ALERT"
            )

        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")
