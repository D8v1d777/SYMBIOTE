"""
engines/recon/domain.py
DomainEngine — TLDExtract subdomain enumeration, DNS record diff, CT log pulling.
"""
import asyncio
import socket
import time
from typing import AsyncGenerator, List

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class DomainEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "domain"
    CATEGORY = "recon"

    async def initialize(self) -> None:
        self._ready = True
        self._log("DomainEngine initialized. TLDExtract backend ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        domain = req.target
        wordlist = req.params.get("wordlist", ["www", "mail", "api", "dev", "staging", "admin", "vpn"])
        try:
            parsed = self._parse(domain)
            subdomains = await self._enumerate(parsed["registered_domain"], wordlist)
            dns_records = await asyncio.to_thread(self._get_dns, parsed["registered_domain"])
            self._emit("domain.enum", {"domain": domain, "subdomains": len(subdomains)})
            return await self._after(Response(
                request_id=req.id, success=True,
                data={"parsed": parsed, "subdomains": subdomains, "dns": dns_records},
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        domain = req.target
        wordlist = req.params.get("wordlist", ["www", "mail", "api", "dev", "staging", "admin"])
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[DOMAIN] Enumerating subdomains for {domain}...")
        try:
            parsed = self._parse(domain)
            base = parsed["registered_domain"]
            for sub in wordlist:
                fqdn = f"{sub}.{base}"
                resolved = await asyncio.to_thread(self._resolve, fqdn)
                result = {"subdomain": fqdn, "resolved": resolved}
                self._emit("domain.subdomain", result)
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=result)
                await asyncio.sleep(0.1)
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _parse(self, domain: str) -> dict:
        try:
            import tldextract
            ext = tldextract.extract(domain)
            return {
                "subdomain": ext.subdomain,
                "domain": ext.domain,
                "suffix": ext.suffix,
                "registered_domain": ext.registered_domain,
            }
        except ImportError:
            parts = domain.split(".")
            return {"subdomain": "", "domain": parts[0], "suffix": ".".join(parts[1:]),
                    "registered_domain": domain}

    def _resolve(self, fqdn: str) -> List[str]:
        try:
            return socket.gethostbyname_ex(fqdn)[2]
        except Exception:
            return []

    async def _enumerate(self, base: str, wordlist: List[str]) -> List[dict]:
        results = []
        for sub in wordlist:
            fqdn = f"{sub}.{base}"
            ips = await asyncio.to_thread(self._resolve, fqdn)
            if ips:
                results.append({"subdomain": fqdn, "ips": ips})
        return results

    def _get_dns(self, domain: str) -> dict:
        records = {}
        for qtype in ("A", "MX", "TXT", "NS"):
            try:
                import subprocess
                result = subprocess.run(
                    ["nslookup", "-type=" + qtype, domain],
                    capture_output=True, text=True, timeout=5
                )
                records[qtype] = result.stdout.strip()
            except Exception:
                records[qtype] = "unavailable"
        return records

    def health_check(self) -> HealthStatus:
        try:
            import tldextract  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="tldextract available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="tldextract not installed")
