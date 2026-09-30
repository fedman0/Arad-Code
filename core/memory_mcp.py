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

    async def list_projects(self) -> list[dict]:
        result = await self._call("list_projects", {})
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("projects", [])
        return []

    async def find_project_for_repo(self, repo_path: str) -> Optional[str]:
        from pathlib import Path
        repo = str(Path(repo_path).resolve())
        projects = await self.list_projects()
        for p in projects:
            if str(Path(p.get("root_path", "")).resolve()) == repo:
                return p.get("name")
        return None

    async def index_repository(self, repo_path: str) -> Optional[dict]:
        return await self._call("index_repository", {"repo_path": repo_path})

    async def _call_raw_text(self, tool: str, args: dict) -> str:
        result = await self._call(tool, args)
        if result is None:
            return ""
        if isinstance(result, str):
            return result
        return json.dumps(result, indent=2)

    async def search_graph(
        self,
        name_pattern: Optional[str] = None,
        label: Optional[str] = None,
        qn_pattern: Optional[str] = None,
        limit: int = 20,
        project: Optional[str] = None,
    ) -> str:
        args: dict = {"limit": limit}
        if name_pattern:
            args["name_pattern"] = name_pattern
        if label:
            args["label"] = label
        if qn_pattern:
            args["qn_pattern"] = qn_pattern
        if project:
            args["project"] = project
        return await self._call_raw_text("search_graph", args)

    async def trace_path(
        self,
        function_name: str,
        mode: str = "calls",
        depth: int = 5,
        project: Optional[str] = None,
    ) -> str:
        args: dict = {"function_name": function_name, "mode": mode, "depth": depth}
        if project:
            args["project"] = project
        return await self._call_raw_text("trace_path", args)

    async def get_code_snippet(self, qualified_name: str, project: Optional[str] = None) -> str:
        args: dict = {"qualified_name": qualified_name}
        if project:
            args["project"] = project
        return await self._call_raw_text("get_code_snippet", args)

    async def search_code(self, pattern: str, limit: int = 50, project: Optional[str] = None) -> str:
        args: dict = {"pattern": pattern, "limit": limit}
        if project:
            args["project"] = project
        return await self._call_raw_text("search_code", args)

    async def get_architecture(self, aspects: Optional[list[str]] = None, project: Optional[str] = None) -> str:
        args: dict = {}
        if aspects:
            args["aspects"] = aspects
        if project:
            args["project"] = project
        return await self._call_raw_text("get_architecture", args)

    async def query_graph(self, query: str) -> Any:
        return await self._call("query_graph", {"query": query})

    async def close(self):
        if self._proc and self._proc.stdin:
            try:
                self._proc.stdin.close()
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except Exception:
                self._proc.kill()
