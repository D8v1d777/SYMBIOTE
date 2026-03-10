"""
server/ws_server.py
WebSocket broadcast server (trio_websocket fallback: websockets).
All engines publish to event_bus → this server fans out to connected dashboard clients.
"""
import asyncio
import json
import threading
import time
from typing import Set

from registry.event_bus import bus, Event

# ---- Try trio_websocket first, fall back to websockets ----
try:
    import trio
    import trio_websocket
    _BACKEND = "trio"
except ImportError:
    try:
        import websockets
        _BACKEND = "websockets"
    except ImportError:
        _BACKEND = "none"


class WSServer(threading.Thread):
    """
    Background WebSocket server.
    Subscribes to the global event_bus and broadcasts every event to all
    connected dashboard clients as JSON.

    Binds on ws://localhost:<port>  (default 9999).
    """

    def __init__(self, port: int = 9999):
        super().__init__(daemon=True, name="WSServer")
        self.port = port
        self._clients: Set = set()
        self._queue: asyncio.Queue = None
        self._loop: asyncio.AbstractEventLoop = None
        self._ready = False

        # Subscribe to ALL events from the bus
        bus.subscribe("*", self._on_event)

    def _on_event(self, event: Event) -> None:
        """Called from engine threads — enqueue for async broadcast."""
        if self._queue and self._loop:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, event.to_dict())

    def run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._queue = asyncio.Queue()
        self._loop.run_until_complete(self._serve())

    async def _serve(self) -> None:
        if _BACKEND == "websockets":
            import websockets
            async with websockets.serve(self._handler, "localhost", self.port):
                self._ready = True
                bus.emit("ws_server.started", {"port": self.port, "backend": _BACKEND}, source="WSServer")
                await asyncio.Future()  # run forever
        elif _BACKEND == "none":
            bus.emit("ws_server.degraded", {"reason": "no WS library installed"}, source="WSServer")
            await asyncio.sleep(0)
        else:
            bus.emit("ws_server.degraded", {"reason": "trio backend not wired for thread mode"}, source="WSServer")
            await asyncio.sleep(0)

    async def _handler(self, websocket, path="") -> None:
        self._clients.add(websocket)
        try:
            async for _ in websocket:
                pass  # ignore client messages for now
        finally:
            self._clients.discard(websocket)

    async def _broadcaster(self) -> None:
        while True:
            payload = await self._queue.get()
            msg = json.dumps(payload)
            dead = set()
            for ws in list(self._clients):
                try:
                    await ws.send(msg)
                except Exception:
                    dead.add(ws)
            self._clients -= dead

    @property
    def is_ready(self) -> bool:
        return self._ready

    def client_count(self) -> int:
        return len(self._clients)
