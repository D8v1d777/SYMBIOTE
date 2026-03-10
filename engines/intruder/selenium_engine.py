import asyncio
import os
import time
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent

class SeleniumEngine(BaseEngine):
    """
    Industrial Wrapper for Selenium (Browser automation).
    Headless Web Crawler enabling dynamic JS interaction, snapshotting, and stealth DOM scanning.
    """
    VERSION = "1.0.0"
    TOOL_ID = "selenium"
    CATEGORY = "web"

    async def initialize(self) -> None:
        self._ready = True
        self._log("SeleniumEngine initialized.")

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        url = req.target
        take_screenshot = req.params.get("screenshot", True)

        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[SELENIUM] Preparing Headless Browser for {url}...")
        await asyncio.sleep(0.5)
        
        try:
             from selenium import webdriver
             from selenium.webdriver.common.by import By
             from selenium.webdriver.common.keys import Keys
             from selenium.webdriver.chrome.options import Options
             from selenium.webdriver.support.ui import WebDriverWait
             from selenium.webdriver.support import expected_conditions as EC
        except ImportError:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data="Selenium or Webdriver dependencies not installed (pip install selenium).", severity="ALERT")
            return

        try:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data="[SELENIUM] Launching Chrome Headless Instance...", severity="INFO")
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            # Spoof User Agent
            chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

            # Emulate synchronous execution inside an async loop using Executor
            def run_webdriver(target_url):
                logs = []
                driver = webdriver.Chrome(options=chrome_options)
                try:
                    driver.get(target_url)
                    logs.append({"type": "progress", "msg": f"Navigated to {target_url} - Title: {driver.title}"})
                    
                    # Dynamically injected links map
                    links = driver.find_elements(By.TAG_NAME, 'a')
                    logs.append({"type": "result", "msg": f"Extracted {len(links)} DOM anchor tags (Potential Hidden JS routes)."})
                    
                    # Store 5 sample links heavily reliant on client side execution
                    for i, a in enumerate(links[:5]):
                        href = a.get_attribute('href')
                        if href:
                             logs.append({"type": "info", "msg": f"  -> {href}"})
                    
                    if take_screenshot:
                         name = target_url.replace("https://", "").replace("http://", "").replace("/", "_") + ".png"
                         path = os.path.join(os.getcwd(), name)
                         driver.save_screenshot(path)
                         logs.append({"type": "alert", "msg": f"Snapshot captured: {path}"})

                    return logs
                finally:
                    driver.quit()

            # Execute blocking Webdriver call in a separate thread
            loop = asyncio.get_running_loop()
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                result_logs = await loop.run_in_executor(pool, run_webdriver, url)

            for item in result_logs:
                sev = "INFO"
                if item["type"] == "alert": sev = "ALERT"
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=f"[SELENIUM] {item['msg']}", severity=sev)
                await asyncio.sleep(0.05)
            
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=f"Selenium execution error: {str(exc)}", severity="ALERT")

        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete", data="Browser interaction complete.")

    async def execute(self, req: Request) -> Response:
        events = []
        async for evt in self.stream(req):
            events.append(evt)
        return Response(success=True, data=events, events_emitted=len(events))

    def health_check(self) -> HealthStatus:
        try:
            import selenium
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="selenium available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="selenium not installed")
