"""
engines/intruder/ropchain.py
ROPChainEngine — ROPGadget integration.
Gadget search, quality scoring, chain assembly.
"""
import asyncio
import time
from typing import AsyncGenerator, List

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class ROPChainEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "ropchain"
    CATEGORY = "intruder"

    async def initialize(self) -> None:
        self._ready = True
        self._log("ROPChainEngine initialized.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        binary = req.params.get("binary", "")
        arch = req.params.get("arch", "x86_64")
        try:
            gadgets = self._search_gadgets(binary, arch)
            scored = self._score_gadgets(gadgets)
            self._emit("ropchain.gadgets", {"count": len(gadgets), "binary": binary})
            return await self._after(Response(
                request_id=req.id, success=True,
                data={"gadgets": scored, "count": len(scored)},
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        binary = req.params.get("binary", req.target)
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[ROP] Scanning binary: {binary}")
        await asyncio.sleep(0.1)
        try:
            gadgets = self._search_gadgets(binary, req.params.get("arch", "x86_64"))
            scored = self._score_gadgets(gadgets)
            for g in scored[:20]:  # stream top 20
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=g)
                await asyncio.sleep(0.01)
            self._emit("ropchain.stream", {"ranked_gadgets": len(scored)}, severity="INFO")
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete", data=f"ROPChain scan done.")

    def _search_gadgets(self, binary: str, arch: str) -> List[dict]:
        try:
            import subprocess
            result = subprocess.run(
                ["ROPgadget", "--binary", binary, "--all"],
                capture_output=True, text=True, timeout=30
            )
            gadgets = []
            for line in result.stdout.splitlines():
                if " : " in line:
                    addr, insns = line.split(" : ", 1)
                    gadgets.append({"addr": addr.strip(), "insns": insns.strip()})
            return gadgets
        except Exception as exc:
            return [{"addr": "N/A", "insns": f"[ROPChain] Error: {exc}"}]

    def _score_gadgets(self, gadgets: List[dict]) -> List[dict]:
        def quality(g: dict) -> int:
            insns = g["insns"]
            score = 10
            if "ret" in insns: score += 5
            if "pop" in insns: score += 3
            if "jmp" not in insns and "call" not in insns: score += 2
            if "nop" in insns: score -= 3
            return score
        for g in gadgets:
            g["quality_score"] = quality(g)
        return sorted(gadgets, key=lambda x: x["quality_score"], reverse=True)

    def health_check(self) -> HealthStatus:
        try:
            import subprocess
            subprocess.run(["ROPgadget", "--help"], capture_output=True, timeout=5)
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="ROPgadget available")
        except Exception as e:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message=str(e))
