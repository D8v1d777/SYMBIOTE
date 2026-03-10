"""
pybuster.py
Asynchronous web directory/file brute-forcing engine.
"""
import asyncio
import aiohttp
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set
import time
from pathlib import Path

class ScanMode(Enum):
    DIR = "DIR"
    FILE = "FILE"

@dataclass
class PyBusterConfig:
    target: str
    wordlist_path: str
    threads: int = 50
    extensions: List[str] = field(default_factory=list)
    recursive: bool = False
    status_codes: List[int] = field(default_factory=lambda: [200, 204, 301, 302, 307, 401, 403])
    user_agent: str = "PyBuster/1.0"
    timeout: int = 10

class PyBusterEngine:
    def __init__(self, config: PyBusterConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.results = []
        self._callback = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=self.config.threads, ssl=False)
        self.session = aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": self.config.user_agent},
            timeout=aiohttp.ClientTimeout(total=self.config.timeout)
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    def set_callback(self, callback):
        self._callback = callback

    async def scan(self) -> List[dict]:
        """Main entry point for scanning"""
        self.results = []
        base_url = self.config.target.rstrip("/")
        
        # Load wordlist
        words = []
        try:
            with open(self.config.wordlist_path, "r", errors="ignore") as f:
                words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except Exception as e:
            if self._callback: self._callback(f"Error loading wordlist: {e}")
            return []

        # Prepare paths
        paths_to_check = []
        for word in words:
            paths_to_check.append(word)
            if self.config.extensions:
                for ext in self.config.extensions:
                    paths_to_check.append(f"{word}.{ext.strip('.')}")

        # Worker queue
        queue = asyncio.Queue()
        for p in paths_to_check:
            queue.put_nowait(p)

        # Semaphore for concurrency control
        sem = asyncio.Semaphore(self.config.threads)

        async def worker():
            while not queue.empty():
                path = await queue.get()
                async with sem:
                    await self._check_path(base_url, path)
                queue.task_done()

        tasks = [asyncio.create_task(worker()) for _ in range(self.config.threads)]
        await asyncio.gather(*tasks)
        
        return self.results

    async def _check_path(self, base_url: str, path: str):
        url = f"{base_url}/{path.lstrip('/')}"
        try:
            async with self.session.get(url, allow_redirects=False) as response:
                if response.status in self.config.status_codes:
                    result = {
                        "url": url,
                        "path": f"/{path}",
                        "status": response.status,
                        "size": response.content_length or 0
                    }
                    self.results.append(result)
                    if self._callback:
                        self._callback(result)
                    
                    # Simple recursion (if enabled and it's a directory-like path)
                    # Note: Full industrial recursion would be more complex
                    if self.config.recursive and response.status in [200, 301, 302]:
                        # Logic for adding new paths could be here
                        pass
        except:
            pass
