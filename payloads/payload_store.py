"""
payloads/payload_store.py
Versioned, tagged payload library with search and encoder integration.
"""
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

from payloads.payload_models import Payload
from payloads.encoder_chain import EncoderChain

STORE_PATH = Path("payloads/store.json")

# ---- Built-in starters ------------------------------------------------------
BUILT_IN_PAYLOADS = [
    {
        "id": "builtin-nop-sled-x86", "name": "NOP Sled x86",
        "arch": "x86", "platform": "linux", "stage": "shellcode",
        "tags": ["nop", "x86", "classic"], "raw_hex": "90" * 64,
        "encoding": [], "version": "1.0.0", "tested": True,
        "description": "Classic 64-byte NOP sled for x86 stack pivots.",
    },
    {
        "id": "builtin-rev-shell-ps1", "name": "PowerShell Rev Shell",
        "arch": "x86_64", "platform": "windows", "stage": "stager",
        "tags": ["powershell", "windows", "reverse", "b64"],
        "raw_hex": "23".encode("utf-8").hex(),  # placeholder
        "encoding": ["b64"], "version": "1.0.0", "tested": True,
        "description": "Base64-encoded PowerShell reverse shell stager.",
    },
]


class PayloadStore:
    """
    Versioned payload library.
    Persistence: JSON file (store.json).
    """

    def __init__(self, path: Path = STORE_PATH):
        self._path = path
        self._payloads: Dict[str, Payload] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                with open(self._path) as f:
                    data = json.load(f)
                for d in data:
                    p = Payload(**{k: v for k, v in d.items() if k != "raw_hex"})
                    p.raw = bytes.fromhex(d.get("raw_hex", ""))
                    self._payloads[p.id] = p
            except Exception:
                pass
        # Seed built-ins
        for bi in BUILT_IN_PAYLOADS:
            if bi["id"] not in self._payloads:
                p = Payload(**{k: v for k, v in bi.items() if k != "raw_hex"})
                p.raw = bytes.fromhex(bi.get("raw_hex", ""))
                self._payloads[p.id] = p

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w") as f:
            json.dump([p.to_dict() for p in self._payloads.values()], f, indent=2)

    # ---- CRUD ----------------------------------------------------------------

    def add(self, payload: Payload) -> Payload:
        payload.updated_at = time.time()
        self._payloads[payload.id] = payload
        self._save()
        return payload

    def get(self, payload_id: str) -> Optional[Payload]:
        return self._payloads.get(payload_id)

    def remove(self, payload_id: str) -> bool:
        if payload_id in self._payloads:
            del self._payloads[payload_id]
            self._save()
            return True
        return False

    # ---- Search --------------------------------------------------------------

    def search(self, query: str = "", arch: str = "", platform: str = "",
               tags: Optional[List[str]] = None) -> List[Payload]:
        results = list(self._payloads.values())
        if query:
            q = query.lower()
            results = [p for p in results if q in p.name.lower() or q in p.description.lower()]
        if arch:
            results = [p for p in results if p.arch == arch]
        if platform:
            results = [p for p in results if p.platform == platform]
        if tags:
            results = [p for p in results if any(t in p.tags for t in tags)]
        return results

    def all(self) -> List[Payload]:
        return list(self._payloads.values())

    # ---- Encoding ------------------------------------------------------------

    def encode_payload(self, payload_id: str, encoding_spec: List[str], **kwargs) -> Optional[bytes]:
        p = self.get(payload_id)
        if not p:
            return None
        chain = EncoderChain.from_spec(encoding_spec, **kwargs)
        return chain.encode(p.raw)

    def stats(self) -> dict:
        all_p = self.all()
        return {
            "total": len(all_p),
            "by_arch": {a: len([p for p in all_p if p.arch == a]) for a in set(p.arch for p in all_p)},
            "by_platform": {pl: len([p for p in all_p if p.platform == pl]) for pl in set(p.platform for p in all_p)},
            "tested": len([p for p in all_p if p.tested]),
        }


# Global singleton
store = PayloadStore()
