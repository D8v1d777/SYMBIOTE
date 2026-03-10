"""
registry/event_bus.py
Central pub/sub event bus for cross-engine communication and WebSocket telemetry.
All engines publish here; dashboard and WS server subscribe.
"""
import asyncio
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class Event:
    topic: str
    data: Any
    source: str = ""
    severity: str = "INFO"   # INFO | WARN | ALERT | CRITICAL
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "topic": self.topic,
            "data": self.data,
            "source": self.source,
            "severity": self.severity,
            "ts": self.ts,
        }


@dataclass
class AttackEvent(Event):
    """Typed event emitted by every Intruder engine."""
    tool_id: str = ""
    payload: str = ""

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({"tool_id": self.tool_id, "payload": self.payload})
        return d


class EventBus:
    """Thread-safe, async-compatible publish/subscribe event hub."""

    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._wildcard: List[Callable] = []
        self._lock = threading.Lock()
        self._history: List[Event] = []
        self._max_history = 500

    # ---- Subscription --------------------------------------------------------

    def subscribe(self, topic: str, callback: Callable) -> None:
        """Subscribe to a specific topic (or '*' for all events)."""
        with self._lock:
            if topic == "*":
                self._wildcard.append(callback)
            else:
                self._subscribers.setdefault(topic, []).append(callback)

    def unsubscribe(self, topic: str, callback: Callable) -> None:
        with self._lock:
            if topic == "*" and callback in self._wildcard:
                self._wildcard.remove(callback)
            elif topic in self._subscribers:
                self._subscribers[topic] = [
                    c for c in self._subscribers[topic] if c != callback
                ]

    # ---- Publishing ----------------------------------------------------------

    def publish(self, event: Event) -> None:
        """Publish an event synchronously (thread-safe)."""
        with self._lock:
            self._history.append(event)
            if len(self._history) > self._max_history:
                self._history.pop(0)
            callbacks = list(self._subscribers.get(event.topic, []) + self._wildcard)

        for cb in callbacks:
            try:
                cb(event)
            except Exception as exc:
                print(f"[EventBus] Callback error: {exc}")

    async def publish_async(self, event: Event) -> None:
        """Publish and await coroutine callbacks."""
        self.publish(event)

    def emit(self, topic: str, data: Any, source: str = "", severity: str = "INFO") -> None:
        """Convenience wrapper: emit(`topic`, `data`)."""
        self.publish(Event(topic=topic, data=data, source=source, severity=severity))

    # ---- Inspection ----------------------------------------------------------

    def get_history(self, topic: Optional[str] = None, limit: int = 100) -> List[Event]:
        with self._lock:
            events = self._history if topic is None else [
                e for e in self._history if e.topic == topic
            ]
            return events[-limit:]

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()

    def topics(self) -> List[str]:
        with self._lock:
            return list(self._subscribers.keys())


# Global singleton
bus = EventBus()
