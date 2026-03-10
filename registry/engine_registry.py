"""
registry/engine_registry.py
Auto-discovers and manages all engine modules at startup.
Provides hot-reload capability per engine.
"""
import importlib
import inspect
import time
from typing import Dict, List, Optional, Type

from engines.base import BaseEngine, HealthStatus


class EngineRegistry:
    """
    Global registry of all engines.
    Engines are auto-discovered by scanning the engines/ directory.
    """

    ENGINE_MODULES = [
        # Intruder Pack
        "engines.intruder.exploit",
        "engines.intruder.ropchain",
        "engines.intruder.emulation",
        "engines.intruder.disassembly",
        "engines.intruder.ssh_brute",
        "engines.intruder.browser",
        "engines.intruder.serial_io",
        "engines.intruder.bluetooth",
        "engines.intruder.remote",
        "engines.intruder.packet",
        "engines.intruder.stalk",
        "engines.intruder.cctv_cam",
        "engines.intruder.crackmapexec",
        "engines.intruder.xsstrike",
        "engines.intruder.httpie_engine",
        "engines.intruder.wapiti_engine",
        "engines.intruder.spider_engine",
        # Recon Pack
        "engines.recon.shodan",
        "engines.recon.domain",
        "engines.recon.pcap",
        "engines.recon.android_recon",
        "engines.recon.ble_recon",
        "engines.recon.web_crawl",
        "engines.recon.osint",
        # Analysis Pack
        "engines.analysis.elf",
        "engines.analysis.static_audit",
        "engines.analysis.dependency",
        "engines.analysis.android",
        # System
        "engines.system.metrics",
        "engines.system.settings_engine",
        "engines.system.ipython_engine",
    ]

    def __init__(self, bus=None):
        from registry.event_bus import bus as global_bus
        self._bus = bus or global_bus
        self._engines: Dict[str, BaseEngine] = {}
        self._classes: Dict[str, Type[BaseEngine]] = {}
        self._load_errors: Dict[str, str] = {}

    def load_all(self) -> None:
        """Discover and instantiate all registered engine modules."""
        for mod_path in self.ENGINE_MODULES:
            self._load_module(mod_path)
        self._bus.emit(
            "registry.loaded",
            {"loaded": len(self._engines), "errors": len(self._load_errors)},
            source="EngineRegistry",
        )

    def _load_module(self, mod_path: str) -> bool:
        """Load a single engine module. Returns True on success."""
        try:
            module = importlib.import_module(mod_path)
            # Find the engine class (subclass of BaseEngine)
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, BaseEngine) and obj is not BaseEngine and hasattr(obj, "TOOL_ID"):
                    engine = obj(bus=self._bus)
                    self._engines[obj.TOOL_ID] = engine
                    self._classes[obj.TOOL_ID] = obj
                    return True
        except Exception as exc:
            self._load_errors[mod_path] = str(exc)
        return False

    def get(self, tool_id: str) -> Optional[BaseEngine]:
        return self._engines.get(tool_id)

    def list_engines(self) -> List[BaseEngine]:
        return list(self._engines.values())

    def list_ids(self) -> List[str]:
        return list(self._engines.keys())

    def reload(self, tool_id: str) -> bool:
        """Hot-reload a single engine by tool_id."""
        cls = self._classes.get(tool_id)
        if not cls:
            return False
        try:
            mod = importlib.reload(inspect.getmodule(cls))
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if issubclass(obj, BaseEngine) and obj is not BaseEngine:
                    self._engines[tool_id] = obj(bus=self._bus)
                    self._classes[tool_id] = obj
                    return True
        except Exception as exc:
            self._load_errors[tool_id] = str(exc)
        return False

    def health_summary(self) -> List[dict]:
        return [e.health_check().to_dict() for e in self._engines.values()]

    def errors(self) -> Dict[str, str]:
        return dict(self._load_errors)


# Global singleton
registry = EngineRegistry()
