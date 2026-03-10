"""
payloads/encoder_chain.py
Stackable encoder pipeline: XOR → Base64 → ZStd → custom plugins.
"""
import base64
import os
from typing import Callable, List


class Encoder:
    name: str = "base"

    def encode(self, data: bytes) -> bytes:
        return data

    def decode(self, data: bytes) -> bytes:
        return data


class XorEncoder(Encoder):
    name = "xor"

    def __init__(self, key: bytes = b"\xAA"):
        self.key = key

    def encode(self, data: bytes) -> bytes:
        k = self.key
        return bytes(b ^ k[i % len(k)] for i, b in enumerate(data))

    def decode(self, data: bytes) -> bytes:
        return self.encode(data)  # XOR is symmetric


class Base64Encoder(Encoder):
    name = "b64"

    def encode(self, data: bytes) -> bytes:
        return base64.b64encode(data)

    def decode(self, data: bytes) -> bytes:
        return base64.b64decode(data)


class ZstdEncoder(Encoder):
    name = "zstd"

    def encode(self, data: bytes) -> bytes:
        try:
            import zstandard as zstd
            cctx = zstd.ZstdCompressor()
            return cctx.compress(data)
        except ImportError:
            return data  # passthrough if not installed

    def decode(self, data: bytes) -> bytes:
        try:
            import zstandard as zstd
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(data)
        except ImportError:
            return data


class EncoderChain:
    """
    Stacks encoders in order. encode() applies left-to-right.
    decode() applies right-to-left.
    Usage:
        chain = EncoderChain().add("xor", key=b"\\xde\\xad").add("b64")
        encoded = chain.encode(raw_bytes)
    """

    _REGISTRY = {
        "xor": XorEncoder,
        "b64": Base64Encoder,
        "zstd": ZstdEncoder,
    }

    def __init__(self):
        self._chain: List[Encoder] = []

    def add(self, name: str, **kwargs) -> "EncoderChain":
        cls = self._REGISTRY.get(name)
        if not cls:
            raise ValueError(f"Unknown encoder: {name}")
        self._chain.append(cls(**kwargs))
        return self

    def encode(self, data: bytes) -> bytes:
        for enc in self._chain:
            data = enc.encode(data)
        return data

    def decode(self, data: bytes) -> bytes:
        for enc in reversed(self._chain):
            data = enc.decode(data)
        return data

    def describe(self) -> str:
        return " → ".join(e.name for e in self._chain) or "(empty)"

    @classmethod
    def from_spec(cls, spec: List[str], **kwargs) -> "EncoderChain":
        """Build from a list like ['xor', 'b64']."""
        chain = cls()
        for name in spec:
            chain.add(name, **kwargs)
        return chain
