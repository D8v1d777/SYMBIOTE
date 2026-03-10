"""
registry/health_aggregator.py
Polls all registered engines for health status every N seconds.
Fans results out via event_bus → WebSocket dashboard feed.
"""
import threading
import time
from typing import Dict, List

from engines.base import HealthStatus


class HealthAggregator(threading.Thread):
    """
    Background daemon thread that polls all engine.health_check() methods
    periodically and broadcasts aggregated results to the event bus.
    """

    def __init__(self, registry, bus=None, interval: float = 5.0):
        super().__init__(daemon=True, name="HealthAggregator")
        self._registry = registry
        from registry.event_bus import bus as global_bus
        self._bus = bus or global_bus
        self._interval = interval
        self._stop_event = threading.Event()
        self._last_report: Dict[str, dict] = {}

    def run(self) -> None:
        while not self._stop_event.wait(self._interval):
            self._poll()

    def stop(self) -> None:
        self._stop_event.set()

    def _poll(self) -> None:
        statuses: List[dict] = []
        for engine in self._registry.list_engines():
            try:
                t0 = time.time()
                status = engine.health_check()
                status.latency_ms = round((time.time() - t0) * 1000, 2)
                statuses.append(status.to_dict())
                self._last_report[engine.TOOL_ID] = status.to_dict()
            except Exception as exc:
                statuses.append(HealthStatus(
                    engine_id=engine.TOOL_ID,
                    status="DOWN",
                    message=str(exc),
                ).to_dict())

        self._bus.emit(
            "health.report",
            {"engines": statuses, "ts": time.time()},
            source="HealthAggregator",
            severity="INFO",
        )

    def last_report(self) -> Dict[str, dict]:
        return dict(self._last_report)
