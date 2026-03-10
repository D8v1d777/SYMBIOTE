"""
engines/analysis/elf.py
ELFAnalysisEngine — pyelftools ELF parsing, DWARF, sections, symbols.
"""
import asyncio
import time
from typing import AsyncGenerator

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class ELFAnalysisEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "elf_analysis"
    CATEGORY = "analysis"

    async def initialize(self) -> None:
        self._ready = True
        self._log("ELFAnalysisEngine initialized. pyelftools ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        path = req.target or req.params.get("path", "")
        try:
            result = await asyncio.to_thread(self._analyze, path)
            self._emit("elf.analysis", {"path": path, "type": result.get("type")})
            return await self._after(Response(
                request_id=req.id, success=True, data=result,
                elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        path = req.target or req.params.get("path", "")
        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress", data=f"[ELF] Analyzing: {path}")
        await asyncio.sleep(0.05)
        try:
            result = await asyncio.to_thread(self._analyze, path)
            for section in result.get("sections", []):
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data={"section": section})
                await asyncio.sleep(0.01)
            yield StreamEvent(engine_id=self.TOOL_ID, kind="result", data=result)
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _analyze(self, path: str) -> dict:
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.dynamic import DynamicSection
            with open(path, "rb") as f:
                elf = ELFFile(f)
                sections = [
                    {"name": s.name, "type": s["sh_type"], "size": s["sh_size"]}
                    for s in elf.iter_sections()
                ]
                symbols = []
                for sec in elf.iter_sections():
                    if hasattr(sec, "iter_symbols"):
                        symbols += [sym.name for sym in sec.iter_symbols() if sym.name]
                return {
                    "path": path,
                    "type": elf["e_type"],
                    "machine": elf["e_machine"],
                    "entry": hex(elf["e_entry"]),
                    "sections": sections,
                    "symbols_count": len(symbols),
                    "has_dwarf": elf.has_dwarf_info(),
                }
        except ImportError:
            return {"error": "pyelftools not installed"}
        except Exception as exc:
            return {"error": str(exc)}

    def health_check(self) -> HealthStatus:
        try:
            import elftools  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="pyelftools available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="pyelftools not installed")
