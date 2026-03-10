"""
engines/analysis/android.py
AndroidAnalysisEngine — Androguard DEX decompilation, class analysis.
"""
import asyncio
import time
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class AndroidAnalysisEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "android_analysis"
    CATEGORY = "analysis"

    async def initialize(self) -> None:
        self._ready = True
        self._log("AndroidAnalysisEngine initialized. DEX/Androguard ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        apk_path = req.target or req.params.get("apk_path", "")
        try:
            result = await asyncio.to_thread(self._analyze_dex, apk_path)
            self._emit("android.dex", {"apk": apk_path, "classes": result.get("class_count")})
            return await self._after(Response(
                request_id=req.id, success=True, data=result,
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        apk_path = req.target or req.params.get("apk_path", "")
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[DEX] Decompiling: {apk_path}")
        await asyncio.sleep(0.1)
        try:
            result = await asyncio.to_thread(self._analyze_dex, apk_path)
            for cls in result.get("interesting_classes", []):
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data={"class": cls})
                await asyncio.sleep(0.01)
            yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=result)
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _analyze_dex(self, apk_path: str) -> dict:
        try:
            from androguard.misc import AnalyzeAPK
            a, d, dx = AnalyzeAPK(apk_path)
            classes = list(dx.get_classes())
            interesting = [c.name for c in classes if any(
                kw in c.name.lower() for kw in ["crypt", "exec", "shell", "root", "su", "net", "http"]
            )][:30]
            return {
                "apk": apk_path,
                "class_count": len(classes),
                "interesting_classes": interesting,
                "methods_count": sum(1 for _ in dx.get_methods()),
                "strings_count": sum(1 for _ in dx.get_strings()),
            }
        except ImportError:
            return {"error": "androguard not installed"}
        except Exception as exc:
            return {"error": str(exc)}

    def health_check(self) -> HealthStatus:
        try:
            import androguard  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="Androguard available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="androguard not installed")
