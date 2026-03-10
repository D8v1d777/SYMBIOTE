"""
engines/intruder/cctv_cam.py
CCTVCamEngine — Exposed CCTV Camera Intelligence Scanner.
Scrapes insecam.org for publicly exposed camera feeds by country code.
Ported and re-architected from L0p4 Toolkit (CCTV module).
"""
import asyncio
import re
import time
from dataclasses import dataclass, asdict, field
from typing import AsyncGenerator, Dict, List, Optional

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


@dataclass
class CamFeed:
    url: str
    country: str
    page: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CountryInfo:
    code: str
    name: str
    count: int

    def to_dict(self) -> dict:
        return asdict(self)


class CCTVCamEngine(BaseEngine):
    """
    Exposed CCTV Camera Intelligence Scanner.

    Params (Request.params):
      - country_code  : str  — ISO country code (e.g. "US", "JP", "RU"). Required.
      - max_pages     : int  — Maximum pages to scrape (default: 5, max honours site structure).
      - save_txt      : bool — If True, also write results to cams/<code>.txt (default: False).

    Streams StreamEvents:
      - progress : scanning status messages
      - countries: dict of available country codes (kind="countries" on first warmup)
      - result   : CamFeed dict for each discovered feed
      - complete : summary when done
      - error    : on failure

    Health check requires the `requests` package (bundled with the project).
    """

    VERSION = "1.0.0"
    TOOL_ID = "cctv_cam"
    CATEGORY = "intruder"

    BASE_URL = "http://www.insecam.org"
    HEADERS = {
        "Accept": "*/*",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; AppleWebKit/537.36 Chrome/122 Safari/537.36)",
    }

    def __init__(self, bus=None):
        super().__init__(bus)
        self._countries: Dict[str, CountryInfo] = {}

    # ---- Lifecycle -----------------------------------------------------------

    async def initialize(self) -> None:
        self._ready = True
        self._log("CCTVCamEngine initialized. Insecam scraper ready.")

    # ---- Core Operation ------------------------------------------------------

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        country = req.params.get("country_code", "").strip().upper()
        max_pages = int(req.params.get("max_pages", 5))
        save_txt = bool(req.params.get("save_txt", False))

        if not country:
            return await self._on_error(ValueError("'country_code' param is required (e.g. 'US')."), req)

        try:
            feeds = await asyncio.to_thread(self._scrape_country, country, max_pages)

            if save_txt:
                await asyncio.to_thread(self._save_to_file, country, feeds)

            self._emit("cctv_cam.scan_complete", {
                "country": country,
                "count": len(feeds),
                "feeds": [f.to_dict() for f in feeds],
            })

            return await self._after(Response(
                request_id=req.id,
                success=True,
                data={
                    "country": country,
                    "feeds": [f.to_dict() for f in feeds],
                    "count": len(feeds),
                },
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        country = req.params.get("country_code", "").strip().upper()
        max_pages = int(req.params.get("max_pages", 5))
        save_txt = bool(req.params.get("save_txt", False))

        if not country:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error",
                              data="'country_code' param is required.")
            return

        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[CAM] Targeting region: {country} — querying insecam.org...")

        try:
            # Determine page count
            page_count = await asyncio.to_thread(self._get_page_count, country)
            pages_to_scan = min(page_count, max_pages)
            yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                              data=f"[CAM] Found {page_count} page(s). Scanning {pages_to_scan} page(s)...")

            feeds: List[CamFeed] = []
            for page in range(pages_to_scan):
                page_feeds = await asyncio.to_thread(self._scrape_page, country, page)
                for feed in page_feeds:
                    feeds.append(feed)
                    self._emit("cctv_cam.feed_found", feed.to_dict())
                    yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=feed.to_dict())

            if save_txt:
                await asyncio.to_thread(self._save_to_file, country, feeds)
                yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                                  data=f"[CAM] Results saved to cams/{country}.txt")

            yield StreamEvent(engine_id=self.TOOL_ID, kind="complete",
                              data=f"[CAM] Scan complete. {len(feeds)} feeds found in {country}.")

        except Exception as exc:
            self._log(f"CCTVCamEngine stream error: {exc}", level="ERROR")
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))

    # ---- Country Listing -----------------------------------------------------

    async def get_countries(self) -> Dict[str, CountryInfo]:
        """Fetch available countries from insecam.org and cache result."""
        if not self._countries:
            countries = await asyncio.to_thread(self._fetch_countries)
            self._countries = countries
        return self._countries

    def _fetch_countries(self) -> Dict[str, CountryInfo]:
        try:
            import requests
            resp = requests.get(f"{self.BASE_URL}/en/jsoncountries/",
                                headers=self.HEADERS, timeout=10)
            data = resp.json()
            raw = data.get("countries", {})
            result: Dict[str, CountryInfo] = {}
            for code, info in raw.items():
                result[code] = CountryInfo(
                    code=code,
                    name=info.get("country", code),
                    count=int(info.get("count", 0)),
                )
            return result
        except Exception as e:
            self._log(f"Could not fetch countries: {e}", level="WARNING")
            return {}

    # ---- Scraping Helpers ----------------------------------------------------

    def _get_page_count(self, country: str) -> int:
        """Determine total page count for a given country."""
        try:
            import requests
            resp = requests.get(f"{self.BASE_URL}/en/bycountry/{country}",
                                headers=self.HEADERS, timeout=10)
            matches = re.findall(r'pagenavigator\("\?page=", (\d+)', resp.text)
            return int(matches[0]) if matches else 1
        except Exception:
            return 1

    def _scrape_page(self, country: str, page: int) -> List[CamFeed]:
        """Scrape a single results page and return all IP:port camera URLs."""
        try:
            import requests
            resp = requests.get(
                f"{self.BASE_URL}/en/bycountry/{country}/?page={page}",
                headers=self.HEADERS,
                timeout=10,
            )
            urls = re.findall(r"http://\d+\.\d+\.\d+\.\d+:\d+", resp.text)
            return [CamFeed(url=u, country=country, page=page) for u in urls]
        except Exception:
            return []

    def _scrape_country(self, country: str, max_pages: int) -> List[CamFeed]:
        """Scrape all pages (up to max_pages) for a country. Blocking."""
        page_count = self._get_page_count(country)
        pages_to_scan = min(page_count, max_pages)
        feeds: List[CamFeed] = []
        for page in range(pages_to_scan):
            feeds.extend(self._scrape_page(country, page))
            time.sleep(0.2)  # polite crawl delay
        return feeds

    def _save_to_file(self, country: str, feeds: List[CamFeed]) -> str:
        """Write feed URLs to cams/<country>.txt. Returns file path."""
        import os
        os.makedirs("cams", exist_ok=True)
        path = f"cams/{country}.txt"
        with open(path, "w") as f:
            for feed in feeds:
                f.write(feed.url + "\n")
        return path

    # ---- Observability -------------------------------------------------------

    def health_check(self) -> HealthStatus:
        try:
            import requests  # noqa
            return HealthStatus(
                engine_id=self.TOOL_ID,
                status="OK",
                message="requests available — insecam scraper ready",
            )
        except ImportError:
            return HealthStatus(
                engine_id=self.TOOL_ID,
                status="DEGRADED",
                message="requests library not installed",
            )
