"""
payloads/payload_models.py
Core payload data models for the versioned payload store.
"""
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Payload:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    arch: str = "x86_64"          # x86 | x86_64 | arm | arm64 | mips
    platform: str = "linux"       # linux | windows | macos | android
    stage: str = "shellcode"      # shellcode | stager | dropper | reflective_dll
    encoding: List[str] = field(default_factory=list)  # ["b64", "xor", "zstd"]
    tags: List[str] = field(default_factory=list)
    raw: bytes = b""
    version: str = "1.0.0"
    author: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    cve_refs: List[str] = field(default_factory=list)
    tested: bool = False
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "description": self.description,
            "arch": self.arch, "platform": self.platform, "stage": self.stage,
            "encoding": self.encoding, "tags": self.tags,
            "raw_hex": self.raw.hex(), "version": self.version,
            "author": self.author, "cve_refs": self.cve_refs,
            "created_at": self.created_at, "tested": self.tested, "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Payload":
        p = cls(**{k: v for k, v in d.items() if k != "raw_hex"})
        p.raw = bytes.fromhex(d.get("raw_hex", ""))
        return p
