"""
engines/intruder/habu_engine.py

HabuEngine — Full habu toolkit integration for SYMBIOTE.
Wraps all four habu module groups into one unified async streaming engine.

Modules integrated:
  habu.net     → network recon (TCP connect, DNS, geolocation, ports)
  habu.crypto  → hashing, encoding, decoding, cracking helpers
  habu.fernet  → symmetric encryption/decryption (Fernet AES-128-CBC)
  habu.asym    → asymmetric RSA key gen, encrypt, decrypt, sign, verify
  habu.shodan  → Shodan host/search queries via habu's CLI wrappers
  habu.censys  → Censys IPv4/cert/website search via habu wrappers

Follows StalkEngine / NmapEngine StreamEvent contract exactly.
StreamEvent kinds : "progress" | "result" | "error" | "complete"
Severity levels   : "INFO" | "WARN" | "ALERT" | "CRITICAL"
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Dict, List, Optional

from registry.event_bus import bus

try:
    from core.base import StreamEvent
except ImportError:
    import time as _t
    from dataclasses import dataclass as _dc, field as _f

    @_dc
    class StreamEvent:
        engine_id: str
        kind: str
        data: Any = None
        severity: str = "INFO"
        ts: float = _f(default_factory=_t.time)
        def to_dict(self) -> dict: return self.__dict__


# ── Constants ────────────────────────────────────────────────────────
TOOL_ID   = "habu"
CATEGORY  = "intruder"
ENGINE_ID = f"{CATEGORY}.{TOOL_ID}"

# habu CLI binary name (installed via pip install habu)
_HABU_BIN = "habu"


# ── Helpers ──────────────────────────────────────────────────────────
async def _run_habu_cmd(*args: str, timeout: int = 30) -> tuple[str, str, int]:
    """
    Run a habu CLI subcommand asynchronously.
    Returns (stdout, stderr, returncode).
    """
    cmd = [_HABU_BIN, *args]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return (
            stdout.decode(errors="replace").strip(),
            stderr.decode(errors="replace").strip(),
            proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        return "", f"habu command timed out after {timeout}s", 1
    except FileNotFoundError:
        return "", "habu binary not found — pip install habu", 127


def _habu_available() -> bool:
    import shutil
    return shutil.which(_HABU_BIN) is not None


def _parse_json_or_lines(raw: str) -> Any:
    """Try JSON parse first, fall back to line list."""
    try:
        return json.loads(raw)
    except Exception:
        return [l for l in raw.splitlines() if l.strip()]


# ════════════════════════════════════════════════════════════════════
# MODULE: habu.net  — network recon
# ════════════════════════════════════════════════════════════════════
async def _stream_net(
    target: str,
    ops: List[str],
) -> AsyncGenerator[StreamEvent, None]:
    """
    habu.net operations:
      tcp_connect  — test TCP connectivity to host:port
      dns          — DNS lookup (A/MX/NS/TXT)
      geo          — IP geolocation
      ports        — common port scan via habu
      asn          — ASN/BGP info
      traceroute   — habu traceroute
    """
    ops = ops or ["dns", "geo", "ports"]

    yield StreamEvent(
        engine_id=ENGINE_ID, kind="progress",
        data={"msg": f"[HABU.NET] Starting network recon → {target}  ops={ops}"},
        severity="INFO",
    )

    # ── DNS ──────────────────────────────────────────────────────
    if "dns" in ops:
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="progress",
            data={"msg": f"[HABU.NET] DNS lookup → {target}"},
            severity="INFO",
        )
        for record_type in ["a", "mx", "ns", "txt"]:
            stdout, stderr, rc = await _run_habu_cmd(
                "dns", target, "--type", record_type.upper()
            )
            if rc == 0 and stdout:
                parsed = _parse_json_or_lines(stdout)
                yield StreamEvent(
                    engine_id=ENGINE_ID, kind="result",
                    data={
                        "msg":    f"[HABU.NET] DNS {record_type.upper()} → {stdout[:200]}",
                        "op":     "dns",
                        "type":   record_type.upper(),
                        "target": target,
                        "result": parsed,
                    },
                    severity="INFO",
                )
            elif stderr:
                yield StreamEvent(
                    engine_id=ENGINE_ID, kind="error",
                    data={"msg": f"[HABU.NET] DNS {record_type.upper()} error: {stderr}"},
                    severity="WARN",
                )

    # ── Geolocation ──────────────────────────────────────────────
    if "geo" in ops:
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="progress",
            data={"msg": f"[HABU.NET] Geolocating {target}..."},
            severity="INFO",
        )
        stdout, stderr, rc = await _run_habu_cmd("geoip", target)
        if rc == 0 and stdout:
            parsed = _parse_json_or_lines(stdout)
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":    f"[HABU.NET] GeoIP → {stdout[:300]}",
                    "op":     "geo",
                    "target": target,
                    "result": parsed,
                },
                severity="INFO",
            )

    # ── ASN lookup ───────────────────────────────────────────────
    if "asn" in ops:
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="progress",
            data={"msg": f"[HABU.NET] ASN lookup → {target}"},
            severity="INFO",
        )
        stdout, stderr, rc = await _run_habu_cmd("asn", target)
        if rc == 0 and stdout:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":    f"[HABU.NET] ASN → {stdout[:200]}",
                    "op":     "asn",
                    "target": target,
                    "result": _parse_json_or_lines(stdout),
                },
                severity="INFO",
            )

    # ── TCP connect test ─────────────────────────────────────────
    if "tcp_connect" in ops:
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="progress",
            data={"msg": f"[HABU.NET] TCP connect test → {target}"},
            severity="INFO",
        )
        stdout, stderr, rc = await _run_habu_cmd("tcpconnect", target)
        if stdout:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":    f"[HABU.NET] TCP → {stdout[:200]}",
                    "op":     "tcp_connect",
                    "target": target,
                    "result": _parse_json_or_lines(stdout),
                },
                severity="ALERT" if rc == 0 else "INFO",
            )

    # ── Port scan ────────────────────────────────────────────────
    if "ports" in ops:
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="progress",
            data={"msg": f"[HABU.NET] Port scan → {target}"},
            severity="INFO",
        )
        stdout, stderr, rc = await _run_habu_cmd(
            "portscan", target, timeout=60
        )
        if rc == 0 and stdout:
            lines = stdout.splitlines()
            for line in lines:
                if line.strip():
                    yield StreamEvent(
                        engine_id=ENGINE_ID, kind="result",
                        data={
                            "msg":    f"[HABU.NET] PORT → {line}",
                            "op":     "ports",
                            "target": target,
                            "result": line,
                        },
                        severity="ALERT" if "open" in line.lower() else "INFO",
                    )

    # ── Traceroute ───────────────────────────────────────────────
    if "traceroute" in ops:
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="progress",
            data={"msg": f"[HABU.NET] Traceroute → {target}"},
            severity="INFO",
        )
        stdout, stderr, rc = await _run_habu_cmd(
            "traceroute", target, timeout=60
        )
        if stdout:
            for line in stdout.splitlines():
                if line.strip():
                    yield StreamEvent(
                        engine_id=ENGINE_ID, kind="result",
                        data={
                            "msg":    f"[HABU.NET] HOP → {line}",
                            "op":     "traceroute",
                            "target": target,
                            "hop":    line,
                        },
                        severity="INFO",
                    )


# ════════════════════════════════════════════════════════════════════
# MODULE: habu.crypto  — hashing + encoding
# ════════════════════════════════════════════════════════════════════
async def _stream_crypto(
    data_input: str,
    ops: List[str],
) -> AsyncGenerator[StreamEvent, None]:
    """
    habu.crypto operations:
      hash_all    — MD5/SHA1/SHA256/SHA512 of input
      b64_encode  — Base64 encode
      b64_decode  — Base64 decode
      hex_encode  — Hex encode
      hex_decode  — Hex decode
      identify    — Identify hash type via habu
      crack       — Hash crack attempt via habu wordlist
    """
    ops = ops or ["hash_all", "b64_encode", "identify"]

    yield StreamEvent(
        engine_id=ENGINE_ID, kind="progress",
        data={"msg": f"[HABU.CRYPTO] Processing input ({len(data_input)} chars)  ops={ops}"},
        severity="INFO",
    )

    encoded = data_input.encode(errors="replace")

    # ── Hash all ─────────────────────────────────────────────────
    if "hash_all" in ops:
        hashes = {
            "md5":    hashlib.md5(encoded).hexdigest(),
            "sha1":   hashlib.sha1(encoded).hexdigest(),
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "sha512": hashlib.sha512(encoded).hexdigest(),
        }
        for algo, digest in hashes.items():
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":    f"[HABU.CRYPTO] {algo.upper()} → {digest}",
                    "op":     "hash",
                    "algo":   algo,
                    "input":  data_input[:80],
                    "result": digest,
                },
                severity="INFO",
            )

        # Also run habu's hash command if available
        stdout, _, rc = await _run_habu_cmd("hash", data_input)
        if rc == 0 and stdout:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":    f"[HABU.CRYPTO] habu hash → {stdout[:300]}",
                    "op":     "habu_hash",
                    "result": _parse_json_or_lines(stdout),
                },
                severity="INFO",
            )

    # ── Base64 ───────────────────────────────────────────────────
    if "b64_encode" in ops:
        b64 = base64.b64encode(encoded).decode()
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="result",
            data={
                "msg":    f"[HABU.CRYPTO] B64 encode → {b64[:120]}",
                "op":     "b64_encode",
                "result": b64,
            },
            severity="INFO",
        )

    if "b64_decode" in ops:
        try:
            decoded = base64.b64decode(data_input).decode(errors="replace")
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":    f"[HABU.CRYPTO] B64 decode → {decoded[:120]}",
                    "op":     "b64_decode",
                    "result": decoded,
                },
                severity="INFO",
            )
        except Exception as e:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="error",
                data={"msg": f"[HABU.CRYPTO] B64 decode failed: {e}"},
                severity="WARN",
            )

    # ── Hex ──────────────────────────────────────────────────────
    if "hex_encode" in ops:
        hexed = encoded.hex()
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="result",
            data={
                "msg":    f"[HABU.CRYPTO] Hex encode → {hexed[:120]}",
                "op":     "hex_encode",
                "result": hexed,
            },
            severity="INFO",
        )

    if "hex_decode" in ops:
        try:
            decoded = bytes.fromhex(data_input).decode(errors="replace")
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":    f"[HABU.CRYPTO] Hex decode → {decoded[:120]}",
                    "op":     "hex_decode",
                    "result": decoded,
                },
                severity="INFO",
            )
        except Exception as e:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="error",
                data={"msg": f"[HABU.CRYPTO] Hex decode failed: {e}"},
                severity="WARN",
            )

    # ── Identify hash type ───────────────────────────────────────
    if "identify" in ops:
        stdout, _, rc = await _run_habu_cmd("hashid", data_input)
        if rc == 0 and stdout:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":    f"[HABU.CRYPTO] Hash ID → {stdout[:200]}",
                    "op":     "identify",
                    "result": _parse_json_or_lines(stdout),
                },
                severity="INFO",
            )

    # ── Crack ────────────────────────────────────────────────────
    if "crack" in ops:
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="progress",
            data={"msg": f"[HABU.CRYPTO] Attempting hash crack via habu..."},
            severity="WARN",
        )
        stdout, stderr, rc = await _run_habu_cmd(
            "hashcrack", data_input, timeout=60
        )
        if rc == 0 and stdout:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":    f"[HABU.CRYPTO] CRACK → {stdout[:200]}",
                    "op":     "crack",
                    "result": stdout,
                },
                severity="CRITICAL",
            )
        else:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={"msg": "[HABU.CRYPTO] Hash crack: no match found", "op": "crack"},
                severity="INFO",
            )


# ════════════════════════════════════════════════════════════════════
# MODULE: habu.fernet  — symmetric encryption
# ════════════════════════════════════════════════════════════════════
async def _stream_fernet(
    op: str,
    plaintext:  Optional[str] = None,
    ciphertext: Optional[str] = None,
    key:        Optional[str] = None,
) -> AsyncGenerator[StreamEvent, None]:
    """
    habu.fernet operations:
      keygen    — generate a new Fernet key
      encrypt   — encrypt plaintext with key
      decrypt   — decrypt ciphertext with key
    """
    yield StreamEvent(
        engine_id=ENGINE_ID, kind="progress",
        data={"msg": f"[HABU.FERNET] op={op}"},
        severity="INFO",
    )

    if op == "keygen":
        stdout, stderr, rc = await _run_habu_cmd("fernetkeygen")
        if rc == 0 and stdout:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":    f"[HABU.FERNET] New key → {stdout.strip()}",
                    "op":     "keygen",
                    "key":    stdout.strip(),
                },
                severity="ALERT",
            )
        else:
            # Fallback: use cryptography library directly
            try:
                from cryptography.fernet import Fernet
                new_key = Fernet.generate_key().decode()
                yield StreamEvent(
                    engine_id=ENGINE_ID, kind="result",
                    data={
                        "msg":    f"[HABU.FERNET] New key (fallback) → {new_key}",
                        "op":     "keygen",
                        "key":    new_key,
                    },
                    severity="ALERT",
                )
            except ImportError:
                yield StreamEvent(
                    engine_id=ENGINE_ID, kind="error",
                    data={"msg": "[HABU.FERNET] cryptography package not installed"},
                    severity="CRITICAL",
                )

    elif op == "encrypt":
        if not plaintext or not key:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="error",
                data={"msg": "[HABU.FERNET] encrypt requires plaintext + key"},
                severity="CRITICAL",
            )
            return

        stdout, stderr, rc = await _run_habu_cmd(
            "fernetencrypt", "--key", key, plaintext
        )
        if rc == 0 and stdout:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":       f"[HABU.FERNET] Encrypted → {stdout[:120]}",
                    "op":        "encrypt",
                    "ciphertext": stdout.strip(),
                },
                severity="INFO",
            )
        else:
            # Fallback
            try:
                from cryptography.fernet import Fernet
                f   = Fernet(key.encode())
                ct  = f.encrypt(plaintext.encode()).decode()
                yield StreamEvent(
                    engine_id=ENGINE_ID, kind="result",
                    data={
                        "msg":        f"[HABU.FERNET] Encrypted (fallback) → {ct[:120]}",
                        "op":         "encrypt",
                        "ciphertext": ct,
                    },
                    severity="INFO",
                )
            except Exception as e:
                yield StreamEvent(
                    engine_id=ENGINE_ID, kind="error",
                    data={"msg": f"[HABU.FERNET] Encrypt failed: {e}"},
                    severity="CRITICAL",
                )

    elif op == "decrypt":
        if not ciphertext or not key:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="error",
                data={"msg": "[HABU.FERNET] decrypt requires ciphertext + key"},
                severity="CRITICAL",
            )
            return

        stdout, stderr, rc = await _run_habu_cmd(
            "fernetdecrypt", "--key", key, ciphertext
        )
        if rc == 0 and stdout:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":      f"[HABU.FERNET] Decrypted → {stdout[:200]}",
                    "op":       "decrypt",
                    "plaintext": stdout.strip(),
                },
                severity="INFO",
            )
        else:
            try:
                from cryptography.fernet import Fernet
                f  = Fernet(key.encode())
                pt = f.decrypt(ciphertext.encode()).decode()
                yield StreamEvent(
                    engine_id=ENGINE_ID, kind="result",
                    data={
                        "msg":       f"[HABU.FERNET] Decrypted (fallback) → {pt[:200]}",
                        "op":        "decrypt",
                        "plaintext": pt,
                    },
                    severity="INFO",
                )
            except Exception as e:
                yield StreamEvent(
                    engine_id=ENGINE_ID, kind="error",
                    data={"msg": f"[HABU.FERNET] Decrypt failed: {e}"},
                    severity="CRITICAL",
                )


# ════════════════════════════════════════════════════════════════════
# MODULE: habu.asym  — asymmetric RSA
# ════════════════════════════════════════════════════════════════════
async def _stream_asym(
    op:         str,
    key_size:   int           = 2048,
    plaintext:  Optional[str] = None,
    ciphertext: Optional[str] = None,
    pub_key:    Optional[str] = None,
    priv_key:   Optional[str] = None,
    message:    Optional[str] = None,
    signature:  Optional[str] = None,
) -> AsyncGenerator[StreamEvent, None]:
    """
    habu.asym operations:
      keygen   — generate RSA key pair
      encrypt  — RSA encrypt with public key
      decrypt  — RSA decrypt with private key
      sign     — sign message with private key
      verify   — verify signature with public key
    """
    yield StreamEvent(
        engine_id=ENGINE_ID, kind="progress",
        data={"msg": f"[HABU.ASYM] RSA op={op}  key_size={key_size}"},
        severity="INFO",
    )

    if op == "keygen":
        stdout, stderr, rc = await _run_habu_cmd(
            "asymkeygen", "--bits", str(key_size)
        )
        if rc == 0 and stdout:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":    f"[HABU.ASYM] RSA-{key_size} key pair generated",
                    "op":     "keygen",
                    "result": _parse_json_or_lines(stdout),
                },
                severity="ALERT",
            )
        else:
            # Fallback via cryptography lib
            try:
                from cryptography.hazmat.primitives.asymmetric import rsa, padding
                from cryptography.hazmat.primitives import serialization
                priv = rsa.generate_private_key(
                    public_exponent=65537, key_size=key_size
                )
                pub  = priv.public_key()
                priv_pem = priv.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ).decode()
                pub_pem = pub.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode()
                yield StreamEvent(
                    engine_id=ENGINE_ID, kind="result",
                    data={
                        "msg":      f"[HABU.ASYM] RSA-{key_size} key pair (fallback)",
                        "op":       "keygen",
                        "pub_key":  pub_pem,
                        "priv_key": priv_pem,
                    },
                    severity="ALERT",
                )
            except Exception as e:
                yield StreamEvent(
                    engine_id=ENGINE_ID, kind="error",
                    data={"msg": f"[HABU.ASYM] keygen failed: {e}"},
                    severity="CRITICAL",
                )

    elif op in ("encrypt", "decrypt", "sign", "verify"):
        cmd_map = {
                         # habu cmd    positional arg
            "encrypt": ("asymencrypt", plaintext  or ""),
            "decrypt": ("asymdecrypt", ciphertext or ""),
            "sign":    ("asymsign",    message    or ""),
            "verify":  ("asymverify",  message    or ""),
        }
        cmd, arg = cmd_map[op]
        key_arg  = pub_key if op in ("encrypt", "verify") else priv_key

        if not arg or not key_arg:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="error",
                data={"msg": f"[HABU.ASYM] {op}: missing required input or key"},
                severity="CRITICAL",
            )
            return

        extra = ["--sig", signature] if op == "verify" and signature else []
        stdout, stderr, rc = await _run_habu_cmd(
            cmd, "--key", key_arg, *extra, arg
        )

        sev = "CRITICAL" if op == "verify" and rc == 0 else "INFO"
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="result",
            data={
                "msg":    f"[HABU.ASYM] {op} → {'OK' if rc == 0 else 'FAILED'}  {stdout[:120]}",
                "op":     op,
                "rc":     rc,
                "result": stdout.strip(),
            },
            severity=sev,
        )


# ════════════════════════════════════════════════════════════════════
# MODULE: habu.shodan  — Shodan OSINT
# ════════════════════════════════════════════════════════════════════
async def _stream_shodan(
    query:   str,
    api_key: Optional[str] = None,
    mode:    str = "host",
) -> AsyncGenerator[StreamEvent, None]:
    """
    habu.shodan operations:
      host    — host info for IP
      search  — Shodan search query
      count   — result count for query
    """
    yield StreamEvent(
        engine_id=ENGINE_ID, kind="progress",
        data={"msg": f"[HABU.SHODAN] mode={mode}  query={query}"},
        severity="INFO",
    )

    env = os.environ.copy()
    if api_key:
        env["SHODAN_API_KEY"] = api_key

    cmd_map = {
        "host":   ["shodanhost",   query],
        "search": ["shodansearch", query],
        "count":  ["shodancount",  query],
    }
    args = cmd_map.get(mode, cmd_map["host"])
    stdout, stderr, rc = await _run_habu_cmd(*args, timeout=30)

    if rc == 0 and stdout:
        results = _parse_json_or_lines(stdout)

        if isinstance(results, list):
            for item in results:
                text = json.dumps(item) if isinstance(item, dict) else str(item)
                yield StreamEvent(
                    engine_id=ENGINE_ID, kind="result",
                    data={
                        "msg":    f"[HABU.SHODAN] → {text[:200]}",
                        "op":     f"shodan_{mode}",
                        "query":  query,
                        "result": item,
                    },
                    severity="ALERT",
                )
        else:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":    f"[HABU.SHODAN] → {stdout[:300]}",
                    "op":     f"shodan_{mode}",
                    "query":  query,
                    "result": results,
                },
                severity="ALERT",
            )
        bus.emit(f"{ENGINE_ID}.shodan", {"query": query, "mode": mode}, source=ENGINE_ID)
    else:
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="error",
            data={"msg": f"[HABU.SHODAN] Failed: {stderr or 'no output'}"},
            severity="WARN",
        )


# ════════════════════════════════════════════════════════════════════
# MODULE: habu.censys  — Censys OSINT
# ════════════════════════════════════════════════════════════════════
async def _stream_censys(
    query:     str,
    api_id:    Optional[str] = None,
    api_secret: Optional[str] = None,
    mode:      str = "ipv4",
) -> AsyncGenerator[StreamEvent, None]:
    """
    habu.censys operations:
      ipv4     — search IPv4 hosts
      certs    — search certificates
      websites — search websites
    """
    yield StreamEvent(
        engine_id=ENGINE_ID, kind="progress",
        data={"msg": f"[HABU.CENSYS] mode={mode}  query={query}"},
        severity="INFO",
    )

    env = os.environ.copy()
    if api_id:     env["CENSYS_API_ID"]     = api_id
    if api_secret: env["CENSYS_API_SECRET"] = api_secret

    cmd_map = {
        "ipv4":     ["censysipv4",     query],
        "certs":    ["censyscerts",    query],
        "websites": ["censyswebsites", query],
    }
    args = cmd_map.get(mode, cmd_map["ipv4"])
    stdout, stderr, rc = await _run_habu_cmd(*args, timeout=30)

    if rc == 0 and stdout:
        results = _parse_json_or_lines(stdout)

        if isinstance(results, list):
            for item in results:
                text = json.dumps(item) if isinstance(item, dict) else str(item)
                yield StreamEvent(
                    engine_id=ENGINE_ID, kind="result",
                    data={
                        "msg":    f"[HABU.CENSYS] → {text[:200]}",
                        "op":     f"censys_{mode}",
                        "query":  query,
                        "result": item,
                    },
                    severity="ALERT",
                )
        else:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="result",
                data={
                    "msg":    f"[HABU.CENSYS] → {stdout[:300]}",
                    "op":     f"censys_{mode}",
                    "query":  query,
                    "result": results,
                },
                severity="ALERT",
            )
        bus.emit(f"{ENGINE_ID}.censys", {"query": query, "mode": mode}, source=ENGINE_ID)
    else:
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="error",
            data={"msg": f"[HABU.CENSYS] Failed: {stderr or 'no output'}"},
            severity="WARN",
        )


# ════════════════════════════════════════════════════════════════════
# MAIN STREAM — unified entry point
# ════════════════════════════════════════════════════════════════════
async def stream(
    module: str,
    # habu.net
    target:          Optional[str]       = None,
    net_ops:         Optional[List[str]] = None,
    # habu.crypto
    data_input:      Optional[str]       = None,
    crypto_ops:      Optional[List[str]] = None,
    # habu.fernet
    fernet_op:       Optional[str]       = None,
    plaintext:       Optional[str]       = None,
    ciphertext:      Optional[str]       = None,
    fernet_key:      Optional[str]       = None,
    # habu.asym
    asym_op:         Optional[str]       = None,
    key_size:        int                 = 2048,
    pub_key:         Optional[str]       = None,
    priv_key:        Optional[str]       = None,
    asym_message:    Optional[str]       = None,
    signature:       Optional[str]       = None,
    # habu.shodan
    shodan_query:    Optional[str]       = None,
    shodan_api_key:  Optional[str]       = None,
    shodan_mode:     str                 = "host",
    # habu.censys
    censys_query:    Optional[str]       = None,
    censys_api_id:   Optional[str]       = None,
    censys_api_sec:  Optional[str]       = None,
    censys_mode:     str                 = "ipv4",
) -> AsyncGenerator[StreamEvent, None]:
    """
    HabuEngine unified stream.

    module : "net" | "crypto" | "fernet" | "asym" | "shodan" | "censys"

    Examples
    --------
    # Network recon
    async for e in stream("net", target="scanme.nmap.org", net_ops=["dns","geo","ports"]):
        ...

    # Hash + encode
    async for e in stream("crypto", data_input="password123", crypto_ops=["hash_all","identify"]):
        ...

    # Fernet encrypt
    async for e in stream("fernet", fernet_op="keygen"):
        ...
    async for e in stream("fernet", fernet_op="encrypt",
                          plaintext="secret", fernet_key="<key>"):
        ...

    # RSA key gen
    async for e in stream("asym", asym_op="keygen", key_size=2048):
        ...

    # Shodan host lookup
    async for e in stream("shodan", shodan_query="8.8.8.8",
                          shodan_api_key="YOUR_KEY", shodan_mode="host"):
        ...

    # Censys IPv4 search
    async for e in stream("censys", censys_query="apache",
                          censys_api_id="ID", censys_api_sec="SECRET"):
        ...
    """
    t_start = time.time()

    # ── Pre-flight ────────────────────────────────────────────────
    yield StreamEvent(
        engine_id=ENGINE_ID, kind="progress",
        data={"msg": f"[HABU] Engine starting → module={module.upper()}"},
        severity="INFO",
    )

    if not _habu_available():
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="error",
            data={"msg": "[HABU] habu binary not found — pip install habu"},
            severity="WARN",
        )
        # Don't return — crypto/fernet/asym have pure-Python fallbacks

    bus.emit(f"{ENGINE_ID}.start", {"module": module}, source=ENGINE_ID)

    # ── Dispatch ──────────────────────────────────────────────────
    if module == "net":
        if not target:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="error",
                data={"msg": "[HABU.NET] 'target' is required"},
                severity="CRITICAL",
            )
        else:
            async for evt in _stream_net(target, net_ops or ["dns", "geo", "ports"]):
                yield evt

    elif module == "crypto":
        if not data_input:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="error",
                data={"msg": "[HABU.CRYPTO] 'data_input' is required"},
                severity="CRITICAL",
            )
        else:
            async for evt in _stream_crypto(
                data_input, crypto_ops or ["hash_all", "b64_encode", "identify"]
            ):
                yield evt

    elif module == "fernet":
        if not fernet_op:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="error",
                data={"msg": "[HABU.FERNET] 'fernet_op' required: keygen|encrypt|decrypt"},
                severity="CRITICAL",
            )
        else:
            async for evt in _stream_fernet(
                fernet_op, plaintext, ciphertext, fernet_key
            ):
                yield evt

    elif module == "asym":
        if not asym_op:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="error",
                data={"msg": "[HABU.ASYM] 'asym_op' required: keygen|encrypt|decrypt|sign|verify"},
                severity="CRITICAL",
            )
        else:
            async for evt in _stream_asym(
                asym_op, key_size, plaintext, ciphertext,
                pub_key, priv_key, asym_message, signature,
            ):
                yield evt

    elif module == "shodan":
        if not shodan_query:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="error",
                data={"msg": "[HABU.SHODAN] 'shodan_query' required"},
                severity="CRITICAL",
            )
        else:
            async for evt in _stream_shodan(
                shodan_query, shodan_api_key, shodan_mode
            ):
                yield evt

    elif module == "censys":
        if not censys_query:
            yield StreamEvent(
                engine_id=ENGINE_ID, kind="error",
                data={"msg": "[HABU.CENSYS] 'censys_query' required"},
                severity="CRITICAL",
            )
        else:
            async for evt in _stream_censys(
                censys_query, censys_api_id, censys_api_sec, censys_mode
            ):
                yield evt

    else:
        yield StreamEvent(
            engine_id=ENGINE_ID, kind="error",
            data={
                "msg": (
                    f"[HABU] Unknown module '{module}'. "
                    "Valid: net | crypto | fernet | asym | shodan | censys"
                )
            },
            severity="CRITICAL",
        )

    # ── Complete ──────────────────────────────────────────────────
    elapsed = round(time.time() - t_start, 2)
    bus.emit(
        f"{ENGINE_ID}.complete",
        {"module": module, "elapsed": elapsed},
        source=ENGINE_ID,
    )
    yield StreamEvent(
        engine_id=ENGINE_ID, kind="complete",
        data={
            "msg":     f"[HABU] Module {module.upper()} done in {elapsed}s",
            "module":  module,
            "elapsed": elapsed,
        },
        severity="INFO",
    )


# ── Compatibility Wrapper ───────────────────────────────────────────
try:
    from engines.base import BaseEngine, Request, Response, HealthStatus
except ImportError:
    # Minimal fallback for BaseEngine
    class BaseEngine:
        def __init__(self, bus=None): self.bus = bus
    class Request: pass
    class Response: pass
    class HealthStatus: pass

class HabuEngine(BaseEngine):
    """
    Class-based wrapper to satisfy existing Registry/UI imports.
    Calls the top-level 'stream' function internally.
    """
    TOOL_ID  = TOOL_ID
    CATEGORY = CATEGORY
    VERSION  = "1.0.0"

    async def initialize(self) -> None:
        self._ready = True

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        module = req.params.get("module", "net")
        
        async for event in stream(
            module=module,
            target=req.target or req.params.get("target"),
            net_ops=req.params.get("net_ops"),
            data_input=req.params.get("data_input"),
            crypto_ops=req.params.get("crypto_ops"),
            fernet_op=req.params.get("fernet_op"),
            plaintext=req.params.get("plaintext"),
            ciphertext=req.params.get("ciphertext"),
            fernet_key=req.params.get("fernet_key"),
            asym_op=req.params.get("asym_op"),
            key_size=req.params.get("key_size", 2048),
            pub_key=req.params.get("pub_key"),
            priv_key=req.params.get("priv_key"),
            asym_message=req.params.get("asym_message"),
            signature=req.params.get("signature"),
            shodan_query=req.params.get("shodan_query"),
            shodan_api_key=req.params.get("shodan_api_key"),
            shodan_mode=req.params.get("shodan_mode", "host"),
            censys_query=req.params.get("censys_query"),
            censys_api_id=req.params.get("censys_api_id"),
            censys_api_sec=req.params.get("censys_api_sec"),
            censys_mode=req.params.get("censys_mode", "ipv4")
        ):
            yield event

    async def execute(self, req: Request) -> Response:
        results = []
        async for event in self.stream(req):
            if event.kind == "result":
                results.append(event.data)
        
        return Response(
            request_id=req.id,
            success=True,
            data={"results": results},
            elapsed_ms=0
        )

    def health_check(self) -> HealthStatus:
        if _habu_available():
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="Habu binary found")
        return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="Habu binary not in PATH")
