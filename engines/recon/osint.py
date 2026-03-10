"""
engines/recon/osint.py
OsintEngine — Aggregated OSINT collection via requests + BeautifulSoup.
"""
import asyncio
import time
from typing import AsyncGenerator, Dict, List

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class OsintEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "osint"
    CATEGORY = "recon"

    SOURCES = ["whois", "headers", "robots", "sitemap"]

    async def initialize(self) -> None:
        self._ready = True
        self._log("OsintEngine initialized. Requests/BS4 OSINT layer ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        target = req.target
        sources = req.params.get("sources", self.SOURCES)
        try:
            results = await asyncio.to_thread(self._aggregate, target, sources)
            self._emit("osint.result", {"target": target, "sources": sources})
            return await self._after(Response(
                request_id=req.id, success=True, data=results,
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        target = req.target
        sources = req.params.get("sources", self.SOURCES)
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[OSINT] Aggregating intel on {target}...")
        for source in sources:
            await asyncio.sleep(0.1)
            data = await asyncio.to_thread(self._fetch_source, target, source)
            yield StreamEvent(engine_id=self.TOOL_ID, kind="result",
                              data={"source": source, "data": data})
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _aggregate(self, target: str, sources: List[str]) -> Dict:
        return {src: self._fetch_source(target, src) for src in sources}

    def _fetch_source(self, target: str, source: str) -> dict:
        try:
            import requests
            from bs4 import BeautifulSoup
            base = f"https://{target}" if not target.startswith("http") else target
            if source == "headers":
                r = requests.get(base, timeout=5, verify=False)
                return dict(r.headers)
            elif source == "robots":
                r = requests.get(f"{base}/robots.txt", timeout=5, verify=False)
                return {"content": r.text[:2000]}
            elif source == "sitemap":
                r = requests.get(f"{base}/sitemap.xml", timeout=5, verify=False)
                soup = BeautifulSoup(r.text, "xml")
                urls = [loc.text for loc in soup.find_all("loc")][:50]
                return {"urls": urls}
            elif source == "whois":
                import subprocess
                out = subprocess.run(["whois", target], capture_output=True, text=True, timeout=8)
                return {"output": out.stdout[:3000]}
        except Exception as exc:
            return {"error": str(exc)}

    def health_check(self) -> HealthStatus:
        try:
            import requests  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="requests+bs4 available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="requests not installed")
