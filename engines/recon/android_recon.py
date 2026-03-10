"""
engines/recon/android_recon.py
AndroidReconEngine — Androguard APK deep analysis, permission risk scoring.
"""
import asyncio
import time
from typing import AsyncGenerator, List

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent

# Permission risk weights
PERMISSION_RISK = {
    "READ_CONTACTS": 3, "READ_SMS": 5, "SEND_SMS": 5, "READ_CALL_LOG": 4,
    "CAMERA": 4, "RECORD_AUDIO": 5, "ACCESS_FINE_LOCATION": 5, "ACCESS_COARSE_LOCATION": 3,
    "INTERNET": 2, "READ_EXTERNAL_STORAGE": 2, "WRITE_EXTERNAL_STORAGE": 2,
    "RECEIVE_BOOT_COMPLETED": 3, "READ_PHONE_STATE": 4, "PROCESS_OUTGOING_CALLS": 4,
    "BIND_ACCESSIBILITY_SERVICE": 5,
}


class AndroidReconEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "android_recon"
    CATEGORY = "recon"

    async def initialize(self) -> None:
        self._ready = True
        self._log("AndroidReconEngine initialized. Androguard backend ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        apk_path = req.target or req.params.get("apk_path", "")
        try:
            result = await asyncio.to_thread(self._analyze, apk_path)
            self._emit("android.analysis", {"apk": apk_path, "risk": result.get("risk_score")})
            return await self._after(Response(
                request_id=req.id, success=True, data=result,
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        apk_path = req.target or req.params.get("apk_path", "")
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[ANDROID] Analyzing APK: {apk_path}")
        await asyncio.sleep(0.1)
        try:
            result = await asyncio.to_thread(self._analyze, apk_path)
            # Stream permission findings individually
            for perm in result.get("permissions", []):
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data={"permission": perm})
                await asyncio.sleep(0.01)
            yield StreamEvent(engine_id=self.TOOL_ID, kind="result",
                              data={"summary": result})
            self._emit("android.stream", result)
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _analyze(self, apk_path: str) -> dict:
        try:
            from androguard.misc import AnalyzeAPK
            a, d, dx = AnalyzeAPK(apk_path)
            permissions = a.get_permissions()
            risk_score = sum(PERMISSION_RISK.get(p.split(".")[-1], 1) for p in permissions)
            activities = a.get_activities()
            services = a.get_services()
            receivers = a.get_receivers()
            return {
                "package": a.get_package(),
                "version": a.get_androidversion_name(),
                "min_sdk": a.get_min_sdk_version(),
                "permissions": permissions,
                "risk_score": risk_score,
                "activities_count": len(activities),
                "services_count": len(services),
                "receivers_count": len(receivers),
                "top_risky_perms": [p for p in permissions if PERMISSION_RISK.get(p.split(".")[-1], 0) >= 4],
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
