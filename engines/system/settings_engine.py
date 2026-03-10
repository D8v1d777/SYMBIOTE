"""
engines/system/settings_engine.py
SettingsEngine — alembic-managed SQLite persistence for all app configuration.
"""
import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional, AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent

SETTINGS_FILE = Path("settings.json")

# ── Default rules (read + write) ────────────────────────────────────────────
# Every key defined here is guaranteed to exist in the live settings dict.
# On-disk values always take precedence; missing keys are filled from here
# and immediately written back so the file stays in sync.
DEFAULTS: dict = {
    "shodan_key":          "",
    "fuzz_wordlist":       "",
    "ws_port":             9999,
    "theme":               "Terminal Green",
    "proxy":               "",
    "log_retention_days":  30,
    # ── NEW RULES (read/write) ───────────────────────────────────────────────
    "max_threads":         50,   # Max concurrent scan/attack threads
    "request_timeout":     10,   # HTTP request timeout in seconds
}


class SettingsEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "settings_db"
    CATEGORY = "system"

    def __init__(self, bus=None):
        super().__init__(bus)
        self._data: Dict[str, Any] = {}
        self._listeners = []

    async def initialize(self) -> None:
        self._data = self._load()
        self._save()          # commit any newly-added defaults back to disk
        self._ready = True
        self._log("SettingsEngine initialized. Configuration loaded.")

    def _load(self) -> dict:
        """Load settings from disk and merge with DEFAULTS.

        On-disk values win over defaults.  Any key present in DEFAULTS but
        missing from the file (e.g. newly-added rules) is injected with its
        default value.  This makes every key readable AND writeable at all
        times without clobbering existing user choices.
        """
        merged = dict(DEFAULTS)          # start from a fresh copy of defaults
        if SETTINGS_FILE.exists():
            try:
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    on_disk = json.load(f)
                merged.update(on_disk)   # on-disk values override defaults
            except Exception as exc:
                self._log(f"settings.json parse error — using defaults: {exc}", level="WARNING")
        return merged

    def _save(self) -> None:
        with open(SETTINGS_FILE, "w") as f:
            json.dump(self._data, f, indent=2)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value
        self._save()
        self._emit("settings.changed", {"key": key, "value": value})

    def update(self, data: dict) -> None:
        self._data.update(data)
        self._save()
        self._emit("settings.bulk_update", {"keys": list(data.keys())})

    def all(self) -> dict:
        return dict(self._data)

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        action = req.params.get("action", "get_all")
        try:
            if action == "get_all":
                result = self.all()
            elif action == "set":
                self.set(req.params["key"], req.params["value"])
                result = {"ok": True}
            elif action == "get":
                result = {"key": req.params["key"], "value": self.get(req.params["key"])}
            else:
                result = {"error": f"Unknown action: {action}"}
            return await self._after(Response(
                request_id=req.id, success=True, data=result,
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=self.all())
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def health_check(self) -> HealthStatus:
        return HealthStatus(
            engine_id=self.TOOL_ID,
            status="OK" if self._ready else "DOWN",
            message=f"{len(self._data)} settings loaded",
        )
