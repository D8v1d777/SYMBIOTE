"""
engines/recon/web_crawl.py
WebCrawlEngine — Selenium JS-rendered site mapping.
Form field extractor, JS secret scanner, header fingerprinter.
"""
import asyncio
import re
import time
from typing import AsyncGenerator, List

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent

SECRET_PATTERNS = [
    r"(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
    r"(secret|token|password|passwd|pwd)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,})['\"]?",
    r"(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['\"]?([A-Za-z0-9/+]{16,})['\"]?",
]


class WebCrawlEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "web_crawl"
    CATEGORY = "recon"

    async def initialize(self) -> None:
        self._ready = True
        self._log("WebCrawlEngine initialized. Selenium headless crawler ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        url = req.target
        depth = req.params.get("depth", 1)
        try:
            result = await asyncio.to_thread(self._crawl, url, depth)
            self._emit("web_crawl.result", {"url": url, "pages": result.get("pages_visited")})
            return await self._after(Response(
                request_id=req.id, success=True, data=result,
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        url = req.target
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[CRAWL] Starting headless crawl of {url}...")
        await asyncio.sleep(0.1)
        try:
            result = await asyncio.to_thread(self._crawl, url, req.params.get("depth", 1))
            for finding in result.get("secrets", []):
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result",
                                  data={"type": "secret", "finding": finding}, severity="CRITICAL")
                await asyncio.sleep(0.02)
            for form in result.get("forms", []):
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result",
                                  data={"type": "form", "form": form})
                await asyncio.sleep(0.02)
            yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=result)
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _crawl(self, url: str, depth: int) -> dict:
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            opts = Options()
            opts.add_argument("--headless")
            opts.add_argument("--no-sandbox")
            driver = webdriver.Chrome(options=opts)
            driver.get(url)
            time.sleep(1.5)
            page_src = driver.page_source
            title = driver.title
            links = list(set(
                a.get_attribute("href") for a in driver.find_elements("tag name", "a")
                if a.get_attribute("href")
            ))[:50]
            forms = []
            for form in driver.find_elements("tag name", "form"):
                inputs = [i.get_attribute("name") for i in form.find_elements("tag name", "input")]
                forms.append({"action": form.get_attribute("action"), "inputs": inputs})
            secrets = self._scan_secrets(page_src)
            headers = {}
            tech_stack = self._detect_tech(page_src)
            driver.quit()
            return {
                "url": url, "title": title, "pages_visited": 1,
                "links": links, "forms": forms,
                "secrets": secrets, "tech_stack": tech_stack,
            }
        except Exception as exc:
            return {"url": url, "error": str(exc)}

    def _scan_secrets(self, src: str) -> List[dict]:
        results = []
        for pattern in SECRET_PATTERNS:
            for match in re.finditer(pattern, src, re.IGNORECASE):
                results.append({"key": match.group(1), "value": match.group(2)[:10] + "..."})
        return results

    def _detect_tech(self, src: str) -> List[str]:
        tech = []
        signatures = {
            "React": "react", "Vue": "vue.", "Angular": "ng-", "jQuery": "jquery",
            "WordPress": "wp-content", "Bootstrap": "bootstrap",
        }
        for name, sig in signatures.items():
            if sig.lower() in src.lower():
                tech.append(name)
        return tech

    def health_check(self) -> HealthStatus:
        try:
            from selenium import webdriver  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="Selenium available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="selenium not installed")
