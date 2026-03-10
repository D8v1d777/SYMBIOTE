"""
engines/intruder/disassembly.py
DisassemblyEngine — Capstone multi-architecture disassembler.
CFG generation, instruction analysis, streaming disasm output.
"""
import asyncio
import time
from typing import AsyncGenerator, List

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class DisassemblyEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "disassembly"
    CATEGORY = "intruder"

    ARCH_MAP = {
        "x86":    (0, 0),   # CS_ARCH_X86, CS_MODE_32
        "x86_64": (0, 64),
        "arm":    (1, 0),
        "arm64":  (2, 0),
        "mips":   (3, 0),
    }

    async def initialize(self) -> None:
        self._ready = True
        self._log("DisassemblyEngine initialized. Capstone backend ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        code_hex = req.params.get("code_hex", "")
        arch = req.params.get("arch", "x86_64")
        base = req.params.get("base_addr", 0x400000)
        try:
            instructions = self._disassemble(bytes.fromhex(code_hex), arch, base)
            self._emit("disasm.result", {"arch": arch, "count": len(instructions)})
            return await self._after(Response(
                request_id=req.id, success=True,
                data={"instructions": instructions, "count": len(instructions)},
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        code_hex = req.params.get("code_hex", "4831c0")
        arch = req.params.get("arch", "x86_64")
        base = req.params.get("base_addr", 0x400000)
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[DISASM] Disassembling {arch} bytecode...")
        await asyncio.sleep(0.05)
        try:
            instructions = self._disassemble(bytes.fromhex(code_hex), arch, base)
            for insn in instructions:
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=insn)
                await asyncio.sleep(0.005)
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _disassemble(self, code: bytes, arch: str, base: int) -> List[dict]:
        try:
            import capstone as cs
            arch_map = {
                "x86":    (cs.CS_ARCH_X86, cs.CS_MODE_32),
                "x86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
                "arm":    (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
                "arm64":  (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
                "mips":   (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32),
            }
            a, m = arch_map.get(arch, (cs.CS_ARCH_X86, cs.CS_MODE_64))
            md = cs.Cs(a, m)
            md.detail = True
            return [
                {"addr": f"0x{i.address:08x}", "mnemonic": i.mnemonic, "op_str": i.op_str,
                 "bytes": i.bytes.hex()}
                for i in md.disasm(code, base)
            ]
        except ImportError:
            return [{"addr": "N/A", "mnemonic": "??", "op_str": "capstone not installed", "bytes": code.hex()}]

    def health_check(self) -> HealthStatus:
        try:
            import capstone  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="Capstone available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="capstone not installed")
