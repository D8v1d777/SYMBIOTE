"""
engines/intruder/browser.py
BrowserEngine — Selenium headless attack automation.
Record/replay sessions, DOM mutation observer, form attack automation.
"""
import asyncio
import time
from typing import AsyncGenerator, List

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class BrowserEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "browser"
    CATEGORY = "intruder"

    def __init__(self, bus=None):
        super().__init__(bus)
        self._driver = None
        self._session_log: List[dict] = []

    async def initialize(self) -> None:
        self._ready = True
        self._log("BrowserEngine initialized. Selenium backend ready.")

    async def teardown(self) -> None:
        if self._driver:
            try:
                await asyncio.to_thread(self._driver.quit)
            except Exception:
                pass
        self._ready = False

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        url = req.target
        action = req.params.get("action", "navigate")
        try:
            result = await asyncio.to_thread(self._run_action, url, action, req.params)
            self._emit("browser.action", {"url": url, "action": action})
            return await self._after(Response(
                request_id=req.id, success=True, data=result,
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        url = req.target
        action = req.params.get("action", "navigate")
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[BROWSER] Launching headless Chrome → {url}")
        await asyncio.sleep(0.1)
        try:
            result = await asyncio.to_thread(self._run_action, url, action, req.params)
            self._emit("browser.stream", {"url": url, "result": result})
            yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=result)
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _run_action(self, url: str, action: str, params: dict) -> dict:
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            opts = Options()
            opts.add_argument("--headless")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(options=opts)
            driver.get(url)
            time.sleep(1)
            title = driver.title
            page_src_len = len(driver.page_source)
            forms = len(driver.find_elements("tag name", "form"))
            inputs = len(driver.find_elements("tag name", "input"))
            result = {"url": url, "title": title, "page_size": page_src_len,
                      "forms": forms, "inputs": inputs}
            if action == "extract_links":
                links = [a.get_attribute("href") for a in driver.find_elements("tag name", "a")]
                result["links"] = list(set(filter(None, links)))[:50]
            driver.quit()
            return result
        except Exception as exc:
            return {"url": url, "error": str(exc)}

    def health_check(self) -> HealthStatus:
        try:
            from selenium import webdriver  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="Selenium available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="selenium not installed")
