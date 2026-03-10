"""
engines/intruder/serial_io.py
SerialEngine — PySerial for hardware/IoT attack surface interfacing.
TTY interaction, baud rate scan, command injection over serial.
"""
import asyncio
import time
from typing import AsyncGenerator, List

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent

COMMON_BAUD_RATES = [115200, 57600, 38400, 19200, 9600, 4800, 2400, 1200]


class SerialEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "serial"
    CATEGORY = "intruder"

    async def initialize(self) -> None:
        self._ready = True
        self._log("SerialEngine initialized. PySerial backend ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        port = req.target or req.params.get("port", "COM1")
        action = req.params.get("action", "list_ports")
        try:
            result = await asyncio.to_thread(self._run_action, port, action, req.params)
            self._emit("serial.action", {"port": port, "action": action})
            return await self._after(Response(
                request_id=req.id, success=True, data=result,
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        port = req.target or req.params.get("port", "COM1")
        action = req.params.get("action", "baud_scan")
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[SERIAL] Connecting to {port}...")
        await asyncio.sleep(0.05)
        try:
            if action == "baud_scan":
                for baud in COMMON_BAUD_RATES:
                    await asyncio.sleep(0.05)
                    yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                                      data=f"[SERIAL] Testing {port} @ {baud} baud...")
                result = await asyncio.to_thread(self._baud_scan, port)
            else:
                result = await asyncio.to_thread(self._run_action, port, action, req.params)
            self._emit("serial.stream", result)
            yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=result)
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _run_action(self, port: str, action: str, params: dict) -> dict:
        try:
            import serial
            import serial.tools.list_ports as lp
            if action == "list_ports":
                return {"ports": [p.device for p in lp.comports()]}
            elif action == "send":
                cmd = params.get("command", "")
                with serial.Serial(port, baudrate=params.get("baud", 115200), timeout=2) as s:
                    s.write(cmd.encode() + b"\n")
                    response = s.read(512)
                    return {"port": port, "sent": cmd, "response": response.decode(errors="replace")}
        except ImportError:
            return {"error": "pyserial not installed"}
        except Exception as exc:
            return {"error": str(exc)}

    def _baud_scan(self, port: str) -> dict:
        try:
            import serial
            responsive = []
            for baud in COMMON_BAUD_RATES:
                try:
                    with serial.Serial(port, baudrate=baud, timeout=0.5) as s:
                        s.write(b"\r\n")
                        data = s.read(64)
                        if data:
                            responsive.append({"baud": baud, "response_bytes": len(data)})
                except Exception:
                    pass
            return {"port": port, "responsive_bauds": responsive}
        except ImportError:
            return {"error": "pyserial not installed"}

    def health_check(self) -> HealthStatus:
        try:
            import serial  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="PySerial available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="pyserial not installed")
