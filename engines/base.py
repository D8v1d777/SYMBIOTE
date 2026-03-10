"""
engines/base.py
Abstract BaseEngine contract — every engine in the suite must extend this.
Enforces lifecycle, observability, and streaming interface.
"""
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Dict, Optional


# ---- Shared result models ---------------------------------------------------

@dataclass
class HealthStatus:
    engine_id: str
    status: str          # "OK" | "DEGRADED" | "DOWN"
    latency_ms: float = 0.0
    message: str = ""
    last_checked: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "engine_id": self.engine_id,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "message": self.message,
            "last_checked": self.last_checked,
        }


@dataclass
class EngineMetrics:
    engine_id: str
    total_requests: int = 0
    total_errors: int = 0
    avg_latency_ms: float = 0.0
    uptime_seconds: float = 0.0
    last_active: Optional[float] = None

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class Request:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class Response:
    request_id: str = ""
    success: bool = True
    data: Any = None
    error: str = ""
    elapsed_ms: float = 0.0
    events_emitted: int = 0
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class StreamEvent:
    engine_id: str
    kind: str           # "progress" | "result" | "error" | "complete"
    data: Any = None
    severity: str = "INFO"
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return self.__dict__


# ---- Base Engine ------------------------------------------------------------

class BaseEngine(ABC):
    """
    Org-level engine contract.  Every tool in the suite extends this class.

    Subclasses MUST define:
      VERSION, TOOL_ID, CATEGORY
    and implement:
      execute(), stream(), health_check()
    """

    VERSION: str = "1.0.0"
    TOOL_ID: str = "base"
    CATEGORY: str = "generic"

    def __init__(self, bus=None):
        from registry.event_bus import bus as global_bus
        self._bus = bus or global_bus
        self._started_at: float = time.time()
        self._metrics = EngineMetrics(engine_id=self.TOOL_ID)
        self._ready: bool = False

    # ---- Lifecycle -----------------------------------------------------------

    async def initialize(self) -> None:
        """Called once at startup. Override for async setup (connections, etc.)."""
        self._ready = True

    async def teardown(self) -> None:
        """Called on graceful shutdown. Override for cleanup."""
        self._ready = False

    # ---- Core Operation (must implement) ------------------------------------

    @abstractmethod
    async def execute(self, req: Request) -> Response:
        """Primary execution path. Returns a completed Response."""

    @abstractmethod
    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        """
        Streaming execution path for realtime dashboard feed.
        Must yield at least one StreamEvent per operation.
        """
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")  # pragma: no cover

    # ---- Observability (optional override) ----------------------------------

    def health_check(self) -> HealthStatus:
        return HealthStatus(
            engine_id=self.TOOL_ID,
            status="OK" if self._ready else "DOWN",
            latency_ms=0.0,
            message="Engine ready" if self._ready else "Not initialized",
        )

    def get_metrics(self) -> EngineMetrics:
        self._metrics.uptime_seconds = time.time() - self._started_at
        return self._metrics

    # ---- Internal Hooks (override as needed) --------------------------------

    async def _before(self, req: Request) -> Request:
        """Pre-processing hook: validate, inject auth, rate-limit."""
        return req

    async def _after(self, res: Response) -> Response:
        """Post-processing hook: log, emit metrics."""
        self._metrics.total_requests += 1
        if not res.success:
            self._metrics.total_errors += 1
        self._metrics.last_active = time.time()
        return res

    async def _on_error(self, err: Exception, req: Request) -> Response:
        """Error handler. Returns a failed Response."""
        self._metrics.total_errors += 1
        self._emit("engine.error", {"engine": self.TOOL_ID, "error": str(err), "target": req.target})
        return Response(request_id=req.id, success=False, error=str(err))

    # ---- Helpers -------------------------------------------------------------

    def _emit(self, topic: str, data: Any, severity: str = "INFO") -> None:
        """Publish an event to the global bus."""
        self._bus.emit(topic, data, source=self.TOOL_ID, severity=severity)

    def _log(self, msg: str, level: str = "INFO") -> None:
        """Emit a log event to the bus."""
        self._emit("engine.log", {"engine": self.TOOL_ID, "msg": msg, "level": level}, severity=level)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} tool_id={self.TOOL_ID} v{self.VERSION}>"
