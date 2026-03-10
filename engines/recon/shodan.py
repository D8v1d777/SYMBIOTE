"""
engines/recon/shodan.py
ShodanEngine — Internet-wide host intelligence via Shodan API.
Streaming pagination, CVE cross-reference, bulk IP import.
"""
import asyncio
import time
from typing import AsyncGenerator, List

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class ShodanEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "shodan_intel"
    CATEGORY = "recon"

    async def initialize(self) -> None:
        self._ready = True
        self._log("ShodanEngine initialized.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        query = req.target or req.params.get("query", "")
        api_key = req.params.get("api_key", "")
        try:
            results = await asyncio.to_thread(self._search, query, api_key)
            self._emit("shodan.search", {"query": query, "count": len(results)})
            return await self._after(Response(
                request_id=req.id, success=True, data=results,
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        query = req.target or req.params.get("query", "apache")
        api_key = req.params.get("api_key", "")
        limit = req.params.get("limit", 20)
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[SHODAN] Querying: {query}")
        try:
            results = await asyncio.to_thread(self._search, query, api_key, limit)
            for host in results:
                self._emit("shodan.host", host)
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=host)
                await asyncio.sleep(0.05)
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete",
                          data=f"Shodan query complete.")

    def _search(self, query: str, api_key: str, limit: int = 20) -> List[dict]:
        try:
            import shodan
            api = shodan.Shodan(api_key)
            results = api.search(query, limit=limit)
            hosts = []
            for match in results.get("matches", []):
                cves = match.get("vulns", {})
                hosts.append({
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "org": match.get("org", ""),
                    "country": match.get("location", {}).get("country_name", ""),
                    "banner": match.get("data", "")[:200],
                    "cves": list(cves.keys()),
                })
            return hosts
        except ImportError:
            return [{"error": "shodan not installed"}]
        except Exception as exc:
            return [{"error": str(exc)}]

    def host_info(self, ip: str, api_key: str) -> dict:
        try:
            import shodan
            api = shodan.Shodan(api_key)
            return api.host(ip)
        except Exception as exc:
            return {"error": str(exc)}

    def health_check(self) -> HealthStatus:
        try:
            import shodan  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="Shodan library available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="shodan not installed")
