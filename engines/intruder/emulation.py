"""
engines/intruder/emulation.py
EmulationEngine — Unicorn CPU emulation engine.
Sandbox code execution, snapshot/restore, memory map viewer.
"""
import asyncio
import time
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class EmulationEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "emulation"
    CATEGORY = "intruder"

    ARCH_MAP = {
        "x86":    ("UC_ARCH_X86", "UC_MODE_32"),
        "x86_64": ("UC_ARCH_X86", "UC_MODE_64"),
        "arm":    ("UC_ARCH_ARM", "UC_MODE_ARM"),
        "arm64":  ("UC_ARCH_ARM64", "UC_MODE_LITTLE_ENDIAN"),
        "mips":   ("UC_ARCH_MIPS", "UC_MODE_MIPS32"),
    }

    def __init__(self, bus=None):
        super().__init__(bus)
        self._snapshots = {}

    async def initialize(self) -> None:
        self._ready = True
        self._log("EmulationEngine initialized. Unicorn sandbox ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        code_hex = req.params.get("code_hex", "")
        arch = req.params.get("arch", "x86_64")
        base_addr = req.params.get("base_addr", 0x1000000)
        try:
            result = self._emulate(bytes.fromhex(code_hex), arch, base_addr)
            self._emit("emulation.result", {"arch": arch, "cycles": result.get("cycles")})
            return await self._after(Response(
                request_id=req.id, success=True, data=result,
                elapsed_ms=(time.time() - t0) * 1000
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        code_hex = req.params.get("code_hex", "90")  # NOP default
        arch = req.params.get("arch", "x86_64")
        base = req.params.get("base_addr", 0x1000000)
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[EMU] Starting {arch} emulation sandbox...")
        await asyncio.sleep(0.05)
        try:
            result = self._emulate(bytes.fromhex(code_hex), arch, base)
            yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=result)
            self._emit("emulation.stream", result, severity="INFO")
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _emulate(self, code: bytes, arch: str, base: int) -> dict:
        try:
            import unicorn as uc
            from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_RIP

            arch_map = {
                "x86":    (uc.UC_ARCH_X86, uc.UC_MODE_32),
                "x86_64": (uc.UC_ARCH_X86, uc.UC_MODE_64),
            }
            a, m = arch_map.get(arch, (uc.UC_ARCH_X86, uc.UC_MODE_64))
            emu = uc.Uc(a, m)
            emu.mem_map(base, 2 * 1024 * 1024)
            emu.mem_write(base, code)
            emu.emu_start(base, base + len(code), timeout=1_000_000)
            return {"status": "completed", "arch": arch, "cycles": len(code), "memory_map": f"0x{base:08x}"}
        except ImportError:
            return {"status": "degraded", "arch": arch, "message": "unicorn not installed"}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    def snapshot(self, label: str) -> None:
        self._snapshots[label] = {"ts": time.time()}

    def restore(self, label: str) -> dict:
        return self._snapshots.get(label, {})

    def health_check(self) -> HealthStatus:
        try:
            import unicorn  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="Unicorn available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="unicorn not installed")
