"""
engines/intruder/httpie_engine.py
HTTPie Engine — Uses HTTPie's internal Python API programmatically.

HTTPie (https://httpie.io) is a pip-installable library whose internals
can be called directly from Python — no subprocess needed.

Install: pip install httpie

Supported Request params:
    method          (str)   — GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS (default: GET)
    url             (str)   — target URL
    data            (dict)  — body fields  (JSON by default, or form with form=True)
    headers         (dict)  — extra request headers
    auth            (list)  — [username, password]
    auth_type       (str)   — 'basic' | 'digest' | 'bearer'  (default: basic)
    cookies         (str)   — raw cookie string  'name=val; name2=val2'
    query_params    (dict)  — appended to URL as ?k=v&...
    form            (bool)  — send as multipart/form-data instead of JSON
    json_data       (bool)  — force JSON content-type (default: True)
    files           (dict)  — {field: /path/to/file} for uploads
    session         (str)   — persist cookies/auth under a named session file
    timeout         (int)   — seconds (default: 30)
    verify_ssl      (bool)  — validate TLS cert (default: True)
    follow          (bool)  — follow redirects (default: False)
    max_redirects   (int)   — max redirect hops (default: 10)
    proxy           (str)   — http://host:port applied to both http + https
    cert_file       (str)   — path to client TLS cert
    cert_key_file   (str)   — path to client TLS key
    ssl_version     (str)   — 'tls1' | 'tls1.1' | 'tls1.2' | 'tls1.3'
    print_what      (str)   — 'HhBb' subset — H=req-headers h=resp-headers B=req-body b=resp-body
    verbose         (bool)  — shorthand for print_what='HhBb'
    download        (bool)  — HTTPie download mode
    output_file     (str)   — destination path for download
    check_status    (bool)  — non-zero exit on 4xx/5xx
    offline         (bool)  — build request without sending
    stream          (bool)  — stream response (for large payloads)
    format_options  (str)   — e.g. 'json.sort_keys:true,json.indent:2'
    extra_args      (list)  — raw extra CLI-style flags appended verbatim
"""
import asyncio
import io
import json
import sys
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

from engines.base import BaseEngine, HealthStatus, Request, Response, StreamEvent


# ---------------------------------------------------------------------------
# Internal Python API wrapper  (embedded from reference implementation)
# ---------------------------------------------------------------------------

class _HTTPiePythonAPI:
    """
    Thin wrapper over httpie.core.main() that:
      - converts Python kwargs into HTTPie CLI-style arg lists
      - captures stdout/stderr and returns structured dicts
      - restores sys.argv and IO streams after every call
    """

    def __init__(self):
        from httpie.context import Environment  # lazy — avoids import-time crash
        self.env = Environment()

    # ------------------------------------------------------------------
    # Arg builder
    # ------------------------------------------------------------------

    def _build_args(
        self,
        method: str = "GET",
        url: str = "",
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        auth: Optional[List[str]] = None,
        auth_type: str = "basic",
        cookies: Optional[str] = None,
        session: Optional[str] = None,
        download: bool = False,
        output_file: Optional[str] = None,
        follow: bool = False,
        max_redirects: int = 10,
        timeout: Optional[int] = None,
        verify_ssl: bool = True,
        offline: bool = False,
        form: bool = False,
        json_data: bool = True,
        query_params: Optional[Dict] = None,
        files: Optional[Dict] = None,
        proxy: Optional[str] = None,
        cert_file: Optional[str] = None,
        cert_key_file: Optional[str] = None,
        ssl_version: Optional[str] = None,
        print_what: Optional[str] = None,
        verbose: bool = False,
        check_status: bool = False,
        stream_mode: bool = False,
        format_options: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
        **_ignored,
    ) -> List[str]:
        args: List[str] = []

        # Method
        args.append(method.upper())

        # URL (with optional query params)
        if query_params:
            qs = "&".join(f"{k}={v}" for k, v in query_params.items())
            url = f"{url}?{qs}"
        args.append(url)

        # Body Items (JSON or form fields)
        if data:
            for key, value in data.items():
                if isinstance(value, (dict, list, bool, int, float)):
                    args.append(f"{key}:={json.dumps(value)}")
                else:
                    args.append(f"{key}={value}")

        # Headers
        if headers:
            for key, value in headers.items():
                args.append(f"{key}:{value}")

        # Cookies via header
        if cookies:
            args.append(f"Cookie:{cookies}")

        # Auth
        if auth:
            args.extend(["-a", f"{auth[0]}:{auth[1]}"])
            if auth_type != "basic":
                args.extend(["--auth-type", auth_type])

        # Session file
        if session:
            args.append(f"--session={session}")

        # Download
        if download:
            args.append("--download")
            if output_file:
                args.extend(["--output", output_file])

        # Redirects
        if follow:
            args.append("--follow")
            if max_redirects != 10:
                args.extend(["--max-redirects", str(max_redirects)])

        # Timeout
        if timeout is not None:
            args.extend(["--timeout", str(timeout)])

        # SSL
        if not verify_ssl:
            args.append("--verify=no")
        if cert_file:
            args.extend(["--cert", cert_file])
        if cert_key_file:
            args.extend(["--cert-key", cert_key_file])
        if ssl_version:
            args.extend(["--ssl", ssl_version])

        # Proxy (applied to both schemes)
        if proxy:
            args.extend(["--proxy", f"http:{proxy}", "--proxy", f"https:{proxy}"])

        # Content type mode
        if offline:
            args.append("--offline")
        if form:
            args.append("--form")
        elif json_data:
            args.append("--json")

        # File uploads
        if files:
            for field, path in files.items():
                args.append(f"{field}@{path}")

        # Output control
        if verbose:
            args.append("--verbose")
        elif print_what:
            args.extend(["--print", print_what])

        # Misc
        if check_status:
            args.append("--check-status")
        if stream_mode:
            args.append("--stream")
        if format_options:
            args.extend(["--format-options", format_options])

        # Strip colour codes so Qt terminal stays clean
        args.append("--no-color")

        # Suppress stdin read (non-interactive callers)
        args.append("--ignore-stdin")

        # Verbatim extras
        if extra_args:
            args.extend(extra_args)

        return args

    # ------------------------------------------------------------------
    # Executor  — captures stdout / stderr, restores all global state
    # ------------------------------------------------------------------

    def execute(self, args: List[str]) -> Dict[str, Any]:
        from httpie.core import main as httpie_main  # lazy import

        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()

        old_stdout, old_stderr = sys.stdout, sys.stderr
        old_argv = sys.argv

        sys.stdout = stdout_buf
        sys.stderr = stderr_buf
        sys.argv = ["http"] + args

        exit_code = 1
        try:
            result = httpie_main()
            exit_code = result if isinstance(result, int) else 0
        except SystemExit as exc:
            exit_code = exc.code if isinstance(exc.code, int) else 1
        except Exception as exc:
            sys.stderr.write(str(exc))
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            sys.argv = old_argv

        return {
            "exit_status": exit_code,
            "success": exit_code == 0,
            "stdout": stdout_buf.getvalue(),
            "stderr": stderr_buf.getvalue(),
            "args": args,
        }

    # ------------------------------------------------------------------
    # High-level method shortcuts
    # ------------------------------------------------------------------

    def _call(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        return self.execute(self._build_args(method=method, url=url, **kwargs))

    def get(self, url: str, **kw):     return self._call("GET",     url, **kw)
    def post(self, url: str, **kw):    return self._call("POST",    url, **kw)
    def put(self, url: str, **kw):     return self._call("PUT",     url, **kw)
    def patch(self, url: str, **kw):   return self._call("PATCH",   url, **kw)
    def delete(self, url: str, **kw):  return self._call("DELETE",  url, **kw)
    def head(self, url: str, **kw):    return self._call("HEAD",    url, **kw)
    def options(self, url: str, **kw): return self._call("OPTIONS", url, **kw)

    # Parser spec (for discovery / autocomplete)
    def get_parser_spec(self):
        from httpie.cli.definition import parser  # noqa
        return parser

    # Plugin introspection
    def list_plugins(self) -> Dict[str, List[str]]:
        from httpie.plugins import plugin_manager
        return {
            "auth":       [p.auth_type for p in plugin_manager.get_auth_plugins()],
            "formatters": [f.__name__ for f in plugin_manager.get_formatters()],
        }


# ---------------------------------------------------------------------------
# BaseEngine subclass
# ---------------------------------------------------------------------------

class HTTPieEngine(BaseEngine):
    """
    HTTPie Intruder Engine.

    Executes HTTP requests using HTTPie's internal Python API.
    Streams request/response output line-by-line to the UI event bus.
    """

    VERSION = "3.9.0"
    TOOL_ID = "httpie"
    CATEGORY = "intruder"

    def __init__(self, bus=None):
        super().__init__(bus)
        self._api: Optional[_HTTPiePythonAPI] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        try:
            self._api = _HTTPiePythonAPI()
            self._ready = True
            self._log(f"HTTPieEngine v{self.VERSION} initialized — internal Python API ready.")
        except ImportError:
            self._ready = False
            self._log("HTTPieEngine: httpie not installed. Run: pip install httpie", level="ERROR")

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health_check(self) -> HealthStatus:
        try:
            from httpie.core import main  # noqa  — just check importability
            try:
                from httpie import __version__ as hv
            except Exception:
                hv = "unknown"
            return HealthStatus(
                engine_id=self.TOOL_ID,
                status="OK",
                latency_ms=0.0,
                message=f"HTTPie {hv} Python API ready"
            )
        except ImportError:
            return HealthStatus(
                engine_id=self.TOOL_ID,
                status="DEGRADED",
                latency_ms=0.0,
                message="httpie not installed — run: pip install httpie"
            )

    # ------------------------------------------------------------------
    # execute()  — blocking
    # ------------------------------------------------------------------

    async def execute(self, req: Request) -> Response:
        t0 = time.time()
        if not self._api:
            await self.initialize()
        if not self._ready:
            return await self._on_error(
                ImportError("httpie not installed. Run: pip install httpie"), req
            )

        params = req.params
        method = params.get("method", "GET").upper()
        url = req.target or params.get("url", "")

        try:
            result = await asyncio.to_thread(
                self._api._call, method, url, **self._extract_kwargs(params)
            )
            self._emit(
                "httpie.exec",
                {"method": method, "url": url, "exit": result["exit_status"]},
                severity="INFO"
            )
            elapsed = (time.time() - t0) * 1000
            if result["success"]:
                return await self._after(Response(
                    request_id=req.id,
                    success=True,
                    data=result["stdout"],
                    elapsed_ms=elapsed
                ))
            else:
                err = (result["stderr"] or result["stdout"] or
                       f"HTTPie exited with code {result['exit_status']}")
                return await self._after(Response(
                    request_id=req.id,
                    success=False,
                    error=err,
                    elapsed_ms=elapsed
                ))
        except Exception as exc:
            return await self._on_error(exc, req)

    # ------------------------------------------------------------------
    # stream()  — yields live output line-by-line
    # ------------------------------------------------------------------

    async def stream(self, req: Request) -> AsyncGenerator[StreamEvent, None]:
        if not self._api:
            await self.initialize()

        if not self._ready:
            yield StreamEvent(
                engine_id=self.TOOL_ID,
                kind="error",
                data="[HTTPie] httpie not installed — run: pip install httpie",
                severity="ALERT"
            )
            return

        params = req.params
        method = params.get("method", "GET").upper()
        url = req.target or params.get("url", "")

        # Build the arg list so we can show it as a command preview
        try:
            kwargs = self._extract_kwargs(params)
            args = self._api._build_args(method=method, url=url, **kwargs)
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error", data=str(exc))
            return

        # Announce
        readable_cmd = f"http {' '.join(args)}"
        yield StreamEvent(
            engine_id=self.TOOL_ID,
            kind="progress",
            data=f"[HTTPie] {method} {url}"
        )
        yield StreamEvent(
            engine_id=self.TOOL_ID,
            kind="progress",
            data=f"[CMD] {readable_cmd}"
        )

        # Run in thread (HTTPie is sync)
        try:
            result = await asyncio.to_thread(self._api.execute, args)
        except Exception as exc:
            yield StreamEvent(engine_id=self.TOOL_ID, kind="error",
                              data=str(exc), severity="ALERT")
            yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")
            return

        # --- Stream stdout line-by-line ---
        stdout = result.get("stdout", "") or ""
        for line in stdout.splitlines():
            if not line.strip():
                continue

            # Classify line for colour coding
            severity = "INFO"
            line_lo = line.lower()
            if any(k in line_lo for k in ["http/1", "http/2", "http/3", "status:"]):
                # HTTP status line — highlight based on code
                severity = "ALERT" if any(
                    f" {c}" in line for c in ["4", "5"]
                ) else "INFO"
            elif any(k in line_lo for k in [
                "authorization", "cookie", "set-cookie", "token", "bearer",
                "x-api-key", "password", "secret"
            ]):
                severity = "WARN"

            yield StreamEvent(
                engine_id=self.TOOL_ID,
                kind="result",
                data=line,
                severity=severity
            )
            self._emit("httpie.output", {"line": line}, severity=severity)

        # Stderr (warnings, errors)
        stderr = result.get("stderr", "") or ""
        for line in stderr.splitlines():
            if line.strip():
                yield StreamEvent(
                    engine_id=self.TOOL_ID,
                    kind="error",
                    data=f"[STDERR] {line}",
                    severity="WARN"
                )

        # Final status
        if result["success"]:
            yield StreamEvent(
                engine_id=self.TOOL_ID,
                kind="complete",
                data=f"[HTTPie] {method} {url} completed successfully."
            )
        else:
            yield StreamEvent(
                engine_id=self.TOOL_ID,
                kind="error",
                data=f"[HTTPie] Exited with code {result['exit_status']}",
                severity="WARN"
            )
            yield StreamEvent(engine_id=self.TOOL_ID, kind="complete")

    # ------------------------------------------------------------------
    # Public utility — plugin/feature discovery
    # ------------------------------------------------------------------

    def list_plugins(self) -> Dict[str, List[str]]:
        """Return available HTTPie auth plugins and formatters."""
        if not self._api:
            try:
                self._api = _HTTPiePythonAPI()
            except Exception:
                return {}
        return self._api.list_plugins()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_kwargs(params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map engine Request.params keys → _HTTPiePythonAPI._build_args kwargs.
        Only passes keys that _build_args actually understands.
        """
        mapping = {
            "data", "headers", "auth", "auth_type", "cookies", "session",
            "download", "output_file", "follow", "max_redirects", "timeout",
            "verify_ssl", "offline", "form", "json_data", "query_params",
            "files", "proxy", "cert_file", "cert_key_file", "ssl_version",
            "print_what", "verbose", "check_status", "stream_mode",
            "format_options", "extra_args",
        }
        return {k: v for k, v in params.items() if k in mapping}
