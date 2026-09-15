from __future__ import annotations
import asyncio
import json
import subprocess
from typing import Any, Optional
from .config import Config


class CodebaseMemoryClient:

    def __init__(self, cfg: Config):
        self._server = cfg.mcp_server
        self._args = cfg.mcp_args
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._lock = asyncio.Lock()
        self._req_id = 0
        self._available: Optional[bool] = None

    async def _ensure_started(self):
        if self._proc is not None:
            return
        try:
            self._proc = await asyncio.create_subprocess_exec(
                self._server,
                *self._args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await self._send_raw({"jsonrpc": "2.0", "method": "initialize", "id": 0,
                                   "params": {"protocolVersion": "2024-11-05",
                                              "capabilities": {},
                                              "clientInfo": {"name": "pentest", "version": "0.1"}}})
            await self._send_raw({"jsonrpc": "2.0", "method": "notifications/initialized",
                                   "params": {}})
            self._available = True
        except (FileNotFoundError, OSError):
            self._available = False

    async def _send_raw(self, payload: dict) -> Optional[dict]:
        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            return None
        line = json.dumps(payload) + "\n"
        self._proc.stdin.write(line.encode())
        await self._proc.stdin.drain()
        if "id" in payload:
            resp_line = await asyncio.wait_for(self._proc.stdout.readline(), timeout=30)
            return json.loads(resp_line.decode())
        return None

    async def _call(self, tool: str, args: dict) -> Any:
        async with self._lock:
            await self._ensure_started()
            if not self._available:
                return None
            self._req_id += 1
            req = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "id": self._req_id,
                "params": {"name": tool, "arguments": args},
            }
            try:
                resp = await self._send_raw(req)
                if resp and "result" in resp:
                    content = resp["result"].get("content", [])
                    texts = [c["text"] for c in content if c.get("type") == "text"]
                    raw = "\n".join(texts)
                    try:
                        return json.loads(raw)
                    except json.JSONDecodeError:
                        return raw
            except (asyncio.TimeoutError, Exception):
                return None

    async def index_repository(self, repo_path: str) -> Optional[dict]:
        return await self._call("index_repository", {"repo_path": repo_path})

    async def search_graph(
        self,
        name_pattern: Optional[str] = None,
        label: Optional[str] = None,
        qn_pattern: Optional[str] = None,
        limit: int = 20,
    ) -> list[dict]:
        args: dict = {"limit": limit}
        if name_pattern:
            args["name_pattern"] = name_pattern
        if label:
            args["label"] = label
        if qn_pattern:
            args["qn_pattern"] = qn_pattern
        result = await self._call("search_graph", args)
        if isinstance(result, list):
            return result
        return []

    async def trace_path(
        self,
        function_name: str,
        mode: str = "calls",
        depth: int = 5,
    ) -> Optional[dict]:
        return await self._call("trace_path", {"function_name": function_name,
                                               "mode": mode, "depth": depth})

    async def get_code_snippet(self, qualified_name: str) -> Optional[str]:
        result = await self._call("get_code_snippet", {"qualified_name": qualified_name})
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            return result.get("snippet") or result.get("code")
        return None

    async def search_code(self, pattern: str, limit: int = 50) -> list[dict]:
        result = await self._call("search_code", {"pattern": pattern, "limit": limit})
        if isinstance(result, list):
            return result
        return []

    async def get_architecture(self, aspects: Optional[list[str]] = None) -> Optional[dict]:
        args: dict = {}
        if aspects:
            args["aspects"] = aspects
        return await self._call("get_architecture", args)

    async def query_graph(self, query: str) -> Any:
        return await self._call("query_graph", {"query": query})

    async def close(self):
        if self._proc and self._proc.stdin:
            try:
                self._proc.stdin.close()
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except Exception:
                self._proc.kill()
