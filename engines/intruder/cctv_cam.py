"""
engines/intruder/cctv_cam.py

CCTVCamEngine — Public CCTV Camera Intelligence Scanner.
Aggregates publicly listed/indexed camera feeds from multiple open directories.

Sources (all public indexes — no authentication, no private systems):
  • insecam.org       — country-browsable public cam index
  • opentopia.com     — public webcam directory
  • earthcam.com      — public live cam network
  • webcamtaxi.com    — public city/country webcam index
  • camstreamer.com   — public stream directory

Ported and re-architected from L0p4 Toolkit (CCTV module).
Follows StalkEngine / NmapEngine StreamEvent contract.
"""

import asyncio
import os
import re
import time
from dataclasses import asdict, dataclass, field
from typing import AsyncGenerator, Dict, List, Optional

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


# ── Data containers ──────────────────────────────────────────────────
@dataclass
class CamFeed:
    url:      str
    country:  str
    source:   str        # which index site found this
    city:     str  = ""
    label:    str  = ""
    page:     int  = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CountryInfo:
    code:  str
    name:  str
    count: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SourceStats:
    source:  str
    found:   int = 0
    failed:  bool = False
    reason:  str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── Source definitions ───────────────────────────────────────────────
# Each entry: (source_id, display_name, enabled)
SOURCES = {
    "insecam":     ("insecam.org",     True),
    "opentopia":   ("opentopia.com",   True),
    "earthcam":    ("earthcam.com",    True),
    "webcamtaxi":  ("webcamtaxi.com",  True),
    "camstreamer": ("camstreamer.com", True),
}


class CCTVCamEngine(BaseEngine):
    """
    Public CCTV Camera Intelligence Scanner.
    Aggregates feeds from multiple open public camera directory sites.

    Params (Request.params):
      country_code : str        — ISO 2-letter code e.g. "US", "JP", "DE". Required.
      max_pages    : int        — Max pages per source (default 5).
      save_txt     : bool       — Write results to cams/<CODE>.txt (default False).
      sources      : list[str]  — Which sources to use (default: all enabled).
                                  Options: insecam, opentopia, earthcam,
                                           webcamtaxi, camstreamer

    StreamEvent kinds:
      progress  — status messages
      result    — CamFeed dict per discovered feed
      source    — per-source summary after each source completes
      complete  — final aggregate summary
      error     — non-fatal source errors (engine continues with other sources)
    """

    VERSION  = "2.0.0"
    TOOL_ID  = "cctv_cam"
    CATEGORY = "intruder"

    # ── Source base URLs ─────────────────────────────────────────────
    _INSECAM_BASE    = "http://www.insecam.org"
    _OPENTOPIA_BASE  = "http://www.opentopia.com"
    _EARTHCAM_BASE   = "https://www.earthcam.com"
    _WEBCAMTAXI_BASE = "https://www.webcamtaxi.com"
    _CAMSTREAM_BASE  = "https://www.camstreamer.com"

    _HEADERS = {
        "Accept":          "text/html,application/xhtml+xml,*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
    }

    # Country code → full name fallback map (covers top regions)
    _CC_NAMES: Dict[str, str] = {
        "US": "United States",  "GB": "United Kingdom", "DE": "Germany",
        "FR": "France",         "JP": "Japan",          "CN": "China",
        "RU": "Russia",         "KR": "South Korea",    "BR": "Brazil",
        "IN": "India",          "AU": "Australia",      "CA": "Canada",
        "IT": "Italy",          "ES": "Spain",          "NL": "Netherlands",
        "SE": "Sweden",         "NO": "Norway",         "FI": "Finland",
        "PL": "Poland",         "UA": "Ukraine",        "TR": "Turkey",
        "TH": "Thailand",       "SG": "Singapore",      "TW": "Taiwan",
        "HK": "Hong Kong",      "MX": "Mexico",         "AR": "Argentina",
        "ZA": "South Africa",   "EG": "Egypt",          "SA": "Saudi Arabia",
        "AE": "UAE",            "IL": "Israel",         "CZ": "Czech Republic",
        "AT": "Austria",        "CH": "Switzerland",    "BE": "Belgium",
        "PT": "Portugal",       "RO": "Romania",        "HU": "Hungary",
        "GR": "Greece",         "DK": "Denmark",        "NZ": "New Zealand",
        "PH": "Philippines",    "ID": "Indonesia",      "MY": "Malaysia",
        "VN": "Vietnam",        "CL": "Chile",          "CO": "Colombia",
        "PE": "Peru",
    }

    def __init__(self, bus=None):
        super().__init__(bus)
        self._countries: Dict[str, CountryInfo] = {}

    # ── Lifecycle ────────────────────────────────────────────────────
    async def initialize(self) -> None:
        self._ready = True
        self._log(f"CCTVCamEngine v{self.VERSION} initialized. "
                  f"{len(SOURCES)} sources configured.")

    # ── Execute (non-streaming) ──────────────────────────────────────
    async def execute(self, req: Request) -> Response:
        t0      = time.time()
        country = req.params.get("country_code", "").strip().upper()
        if not country:
            return await self._on_error(
                ValueError("'country_code' param required (e.g. 'US')."), req
            )

        max_pages    = int(req.params.get("max_pages", 5))
        save_txt     = bool(req.params.get("save_txt", False))
        
        # Resolve sources: handle both string (comma-separated) or list
        src_input = req.params.get("sources")
        if isinstance(src_input, str):
            src_filter = [s.strip() for s in src_input.split(",") if s.strip()]
        elif isinstance(src_input, list):
            src_filter = src_input
        else:
            src_filter = list(SOURCES.keys())

        all_feeds: List[CamFeed] = []
        for src_id in src_filter:
            if src_id not in SOURCES:
                continue
            feeds = await asyncio.to_thread(
                self._scrape_source, src_id, country, max_pages
            )
            all_feeds.extend(feeds)

        if save_txt:
            await asyncio.to_thread(self._save_to_file, country, all_feeds)

        self._emit("cctv_cam.scan_complete", {
            "country": country,
            "count":   len(all_feeds),
            "feeds":   [f.to_dict() for f in all_feeds],
        })

        return await self._after(Response(
            request_id=req.id,
            success=True,
            data={
                "country": country,
                "feeds":   [f.to_dict() for f in all_feeds],
                "count":   len(all_feeds),
            },
            elapsed_ms=(time.time() - t0) * 1000,
        ))

    # ── Stream ───────────────────────────────────────────────────────
    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        country = req.params.get("country_code", "").strip().upper()
        if not country:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error",
                              data={"msg": "'country_code' param required."})
            return

        max_pages  = int(req.params.get("max_pages", 5))
        save_txt   = bool(req.params.get("save_txt", False))
        
        # Resolve sources: handle both string (comma-separated) or list
        src_input = req.params.get("sources")
        if isinstance(src_input, str):
            src_filter = [s.strip() for s in src_input.split(",") if s.strip()]
        elif isinstance(src_input, list):
            src_filter = src_input
        else:
            src_filter = list(SOURCES.keys())
            
        cc_name    = self._CC_NAMES.get(country, country)

        yield StreamEvent(
            engine_id=self.TOOL_ID, kind="progress",
            data={
                "msg": (
                    f"[CAM] Starting scan → region={country} ({cc_name})  "
                    f"sources={src_filter}  max_pages={max_pages}"
                )
            },
            severity="INFO",
        )

        all_feeds:   List[CamFeed]    = []
        src_stats:   List[SourceStats] = []

        for src_id in src_filter:
            if src_id not in SOURCES:
                yield StreamEvent(
                    engine_id=self.TOOL_ID, kind="error",
                    data={"msg": f"[CAM] Unknown source '{src_id}' — skipping"},
                    severity="WARN",
                )
                continue

            _, display = SOURCES[src_id]
            stat = SourceStats(source=display)

            yield StreamEvent(
                engine_id=self.TOOL_ID, kind="progress",
                data={"msg": f"[CAM] ▶ Querying {display} for {country}..."},
                severity="INFO",
            )

            try:
                feeds = await asyncio.to_thread(
                    self._scrape_source, src_id, country, max_pages
                )
                stat.found = len(feeds)

                for feed in feeds:
                    all_feeds.append(feed)
                    self._emit("cctv_cam.feed_found", feed.to_dict())
                    yield StreamEvent(
                        engine_id=self.TOOL_ID,
                        kind="result",
                        data={
                            **feed.to_dict(),
                            "msg": (
                                f"[CAM] [{display}] "
                                f"{feed.label or feed.url}  "
                                f"{feed.city or ''}"
                            ).rstrip(),
                        },
                        severity="ALERT",
                    )

            except Exception as exc:
                stat.failed = True
                stat.reason = str(exc)
                self._log(f"[CAM] {display} error: {exc}", level="WARNING")
                yield StreamEvent(
                    engine_id=self.TOOL_ID, kind="error",
                    data={"msg": f"[CAM] {display} failed: {exc}", "source": src_id},
                    severity="WARN",
                )

            src_stats.append(stat)

            # Per-source summary
            yield StreamEvent(
                engine_id=self.TOOL_ID, kind="source",
                data={
                    **stat.to_dict(),
                    "msg": (
                        f"[CAM] {display} → "
                        f"{'✓' if not stat.failed else '✗'}  "
                        f"{stat.found} feeds found"
                    ),
                },
                severity="INFO" if not stat.failed else "WARN",
            )

            await asyncio.sleep(0.5)   # polite inter-source delay

        # Save output
        if save_txt and all_feeds:
            await asyncio.to_thread(self._save_to_file, country, all_feeds)
            yield StreamEvent(
                engine_id=self.TOOL_ID, kind="progress",
                data={"msg": f"[CAM] Saved {len(all_feeds)} feeds → cams/{country}.txt"},
                severity="INFO",
            )

        # Final complete
        total   = len(all_feeds)
        by_src  = {s.source: s.found for s in src_stats}
        self._emit("cctv_cam.scan_complete",
                   {"country": country, "count": total, "by_source": by_src})

        yield StreamEvent(
            engine_id=self.TOOL_ID, kind="complete",
            data={
                "msg":      f"[CAM] Done. {total} feeds found in {country} ({cc_name})",
                "country":  country,
                "total":    total,
                "by_source": by_src,
                "feeds":    [f.to_dict() for f in all_feeds],
            },
            severity="INFO" if total == 0 else "ALERT",
        )

    # ── Country listing ──────────────────────────────────────────────
    async def get_countries(self) -> Dict[str, CountryInfo]:
        if not self._countries:
            fetched = await asyncio.to_thread(self._fetch_insecam_countries)
            # Merge with our static map so we always have good names
            for code, name in self._CC_NAMES.items():
                if code not in fetched:
                    fetched[code] = CountryInfo(code=code, name=name, count=0)
            self._countries = fetched
        return self._countries

    # ────────────────────────────────────────────────────────────────
    # SOURCE SCRAPERS
    # ────────────────────────────────────────────────────────────────

    def _scrape_source(self, src_id: str, country: str,
                       max_pages: int) -> List[CamFeed]:
        dispatch = {
            "insecam":     self._scrape_insecam,
            "opentopia":   self._scrape_opentopia,
            "earthcam":    self._scrape_earthcam,
            "webcamtaxi":  self._scrape_webcamtaxi,
            "camstreamer": self._scrape_camstreamer,
        }
        fn = dispatch.get(src_id)
        return fn(country, max_pages) if fn else []

    # ── insecam.org ──────────────────────────────────────────────────
    def _fetch_insecam_countries(self) -> Dict[str, CountryInfo]:
        try:
            import requests
            resp = requests.get(
                f"{self._INSECAM_BASE}/en/jsoncountries/",
                headers=self._HEADERS, timeout=10
            )
            raw = resp.json().get("countries", {})
            return {
                code: CountryInfo(
                    code=code,
                    name=info.get("country", code),
                    count=int(info.get("count", 0)),
                )
                for code, info in raw.items()
            }
        except Exception as e:
            self._log(f"insecam countries fetch failed: {e}", level="WARNING")
            return {}

    def _scrape_insecam(self, country: str, max_pages: int) -> List[CamFeed]:
        import requests
        feeds: List[CamFeed] = []

        # Get page count
        try:
            r = requests.get(
                f"{self._INSECAM_BASE}/en/bycountry/{country}",
                headers=self._HEADERS, timeout=10
            )
            matches = re.findall(r'pagenavigator\("\?page=", (\d+)', r.text)
            page_count = int(matches[0]) if matches else 1
        except Exception:
            page_count = 1

        for page in range(min(page_count, max_pages)):
            try:
                r = requests.get(
                    f"{self._INSECAM_BASE}/en/bycountry/{country}/?page={page}",
                    headers=self._HEADERS, timeout=10
                )
                urls = re.findall(r"http://\d+\.\d+\.\d+\.\d+:\d+", r.text)
                # Also grab any labels near the URLs
                labels = re.findall(
                    r'<div class="camera-title"[^>]*>(.*?)</div>', r.text
                )
                for i, url in enumerate(urls):
                    feeds.append(CamFeed(
                        url=url, country=country, source="insecam.org",
                        label=labels[i].strip() if i < len(labels) else "",
                        page=page,
                    ))
                time.sleep(0.3)
            except Exception:
                continue

        return feeds

    # ── opentopia.com ────────────────────────────────────────────────
    def _scrape_opentopia(self, country: str, max_pages: int) -> List[CamFeed]:
        """
        Opentopia lists webcams by country code.
        URL pattern: /webcams/country/<CC>?show=latest&page=N
        """
        import requests
        feeds: List[CamFeed] = []
        cc_lower = country.lower()

        for page in range(1, max_pages + 1):
            try:
                r = requests.get(
                    f"{self._OPENTOPIA_BASE}/webcams/country/{cc_lower}"
                    f"?show=latest&page={page}",
                    headers=self._HEADERS, timeout=10
                )
                if r.status_code == 404:
                    break

                # Extract embed/iframe src URLs
                iframes = re.findall(
                    r'<iframe[^>]+src=["\']([^"\']+)["\']', r.text, re.IGNORECASE
                )
                # Extract direct cam links
                links = re.findall(
                    r'href=["\'](/webcam/\d+[^"\']*)["\']', r.text, re.IGNORECASE
                )
                # Camera titles
                titles = re.findall(
                    r'<h2 class="cam-title"[^>]*>(.*?)</h2>', r.text
                )

                for i, path in enumerate(links):
                    url = f"{self._OPENTOPIA_BASE}{path}"
                    feeds.append(CamFeed(
                        url=url, country=country, source="opentopia.com",
                        label=titles[i].strip() if i < len(titles) else "",
                        page=page,
                    ))

                for src in iframes:
                    if src.startswith("http"):
                        feeds.append(CamFeed(
                            url=src, country=country,
                            source="opentopia.com", page=page,
                        ))

                if not links and not iframes:
                    break

                time.sleep(0.3)
            except Exception:
                continue

        return feeds

    # ── earthcam.com ─────────────────────────────────────────────────
    def _scrape_earthcam(self, country: str, max_pages: int) -> List[CamFeed]:
        """
        EarthCam organises cams by country.
        URL pattern: /world/<country_name>/
        """
        import requests
        feeds: List[CamFeed] = []
        cc_name = self._CC_NAMES.get(country, "").lower().replace(" ", "-")
        if not cc_name:
            return feeds

        for page in range(1, max_pages + 1):
            try:
                url = (
                    f"{self._EARTHCAM_BASE}/world/{cc_name}/"
                    if page == 1
                    else f"{self._EARTHCAM_BASE}/world/{cc_name}/?page={page}"
                )
                r = requests.get(url, headers=self._HEADERS, timeout=10)
                if r.status_code == 404:
                    break

                # cam thumbnail links
                cam_paths = re.findall(
                    r'href=["\'](/[a-z0-9_/-]+cam[^"\']*)["\']',
                    r.text, re.IGNORECASE
                )
                titles = re.findall(
                    r'<div class="cam-title"[^>]*>(.*?)</div>', r.text
                )
                cities = re.findall(
                    r'<span class="cam-location"[^>]*>(.*?)</span>', r.text
                )

                for i, path in enumerate(cam_paths):
                    full = f"{self._EARTHCAM_BASE}{path}"
                    feeds.append(CamFeed(
                        url=full, country=country, source="earthcam.com",
                        label=titles[i].strip() if i < len(titles) else "",
                        city=cities[i].strip()  if i < len(cities)  else "",
                        page=page,
                    ))

                if not cam_paths:
                    break

                time.sleep(0.4)
            except Exception:
                continue

        return feeds

    # ── webcamtaxi.com ───────────────────────────────────────────────
    def _scrape_webcamtaxi(self, country: str, max_pages: int) -> List[CamFeed]:
        """
        WebcamTaxi has cams by country slug.
        URL pattern: /webcams/<country-slug>/
        """
        import requests
        feeds: List[CamFeed] = []

        # Build country slug
        cc_name = self._CC_NAMES.get(country, "").lower().replace(" ", "-")
        if not cc_name:
            return feeds

        for page in range(1, max_pages + 1):
            try:
                url = (
                    f"{self._WEBCAMTAXI_BASE}/webcams/{cc_name}/"
                    if page == 1
                    else f"{self._WEBCAMTAXI_BASE}/webcams/{cc_name}/page/{page}/"
                )
                r = requests.get(url, headers=self._HEADERS, timeout=10)
                if r.status_code == 404:
                    break

                # Extract cam page links
                cam_links = re.findall(
                    r'href=["\']'
                    r'(https://www\.webcamtaxi\.com/[a-z]{2}/[^"\']+\.html)["\']',
                    r.text
                )
                titles = re.findall(
                    r'<h3 class="[^"]*title[^"]*"[^>]*>(.*?)</h3>', r.text
                )
                cities = re.findall(
                    r'<p class="[^"]*location[^"]*"[^>]*>(.*?)</p>', r.text
                )

                seen = set()
                for i, link in enumerate(cam_links):
                    if link in seen:
                        continue
                    seen.add(link)
                    feeds.append(CamFeed(
                        url=link, country=country, source="webcamtaxi.com",
                        label=titles[i].strip() if i < len(titles) else "",
                        city=cities[i].strip()  if i < len(cities)  else "",
                        page=page,
                    ))

                if not cam_links:
                    break

                time.sleep(0.3)
            except Exception:
                continue

        return feeds

    # ── camstreamer.com ──────────────────────────────────────────────
    def _scrape_camstreamer(self, country: str, max_pages: int) -> List[CamFeed]:
        """
        CamStreamer public stream directory.
        URL pattern: /streams/?country=<CC>&page=<N>
        """
        import requests
        feeds: List[CamFeed] = []

        for page in range(1, max_pages + 1):
            try:
                r = requests.get(
                    f"{self._CAMSTREAM_BASE}/streams/",
                    params={"country": country, "page": page},
                    headers=self._HEADERS, timeout=10
                )
                if r.status_code == 404:
                    break

                # Stream URLs (HLS / RTMP / embed)
                stream_urls = re.findall(
                    r'(https?://[^\s"\'<>]+\.(?:m3u8|flv|mp4|stream)[^\s"\'<>]*)',
                    r.text
                )
                embed_urls = re.findall(
                    r'<iframe[^>]+src=["\']([^"\']+)["\']', r.text, re.IGNORECASE
                )
                titles = re.findall(
                    r'<h\d[^>]*class="[^"]*stream[^"]*"[^>]*>(.*?)</h\d>', r.text
                )
                cities = re.findall(
                    r'<span[^>]*class="[^"]*city[^"]*"[^>]*>(.*?)</span>', r.text
                )

                all_urls = list(dict.fromkeys(stream_urls + embed_urls))
                for i, url in enumerate(all_urls):
                    feeds.append(CamFeed(
                        url=url, country=country, source="camstreamer.com",
                        label=titles[i].strip() if i < len(titles) else "",
                        city=cities[i].strip()  if i < len(cities)  else "",
                        page=page,
                    ))

                if not all_urls:
                    break

                time.sleep(0.3)
            except Exception:
                continue

        return feeds

    # ── File output ──────────────────────────────────────────────────
    def _save_to_file(self, country: str, feeds: List[CamFeed]) -> str:
        os.makedirs("cams", exist_ok=True)
        path = f"cams/{country}.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# SYMBIOTE CCTVCamEngine — {country} — {len(feeds)} feeds\n")
            f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            # Group by source
            by_source: Dict[str, List[CamFeed]] = {}
            for feed in feeds:
                by_source.setdefault(feed.source, []).append(feed)
            for src, src_feeds in by_source.items():
                f.write(f"\n## {src} ({len(src_feeds)} feeds)\n")
                for feed in src_feeds:
                    line = feed.url
                    if feed.label:
                        line += f"  # {feed.label}"
                    if feed.city:
                        line += f"  [{feed.city}]"
                    f.write(line + "\n")
        return path

    # ── Health check ─────────────────────────────────────────────────
    def health_check(self) -> HealthStatus:
        missing = []
        try:
            import requests  # noqa
        except ImportError:
            missing.append("requests")

        if missing:
            return HealthStatus(
                engine_id=self.TOOL_ID,
                status="DEGRADED",
                message=f"Missing packages: {missing}",
            )
        return HealthStatus(
            engine_id=self.TOOL_ID,
            status="OK",
            message=f"v{self.VERSION} — {len(SOURCES)} sources ready",
        )