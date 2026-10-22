from __future__ import annotations
import asyncio
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Optional
from .config import Config

_STREAM_LIMIT = 64 * 1024 * 1024
_CALL_TIMEOUT = 60
_INDEX_TIMEOUT = 900
_PROJECT_PAGE = 200
_PROJECT_MAX = 5000
_TABLE_COLS = re.compile(r"\(cols:\s*([^)]*)\)")


def _parse_project_table(text: str) -> list[dict]:
    cols: list[str] = []
    rows: list[dict] = []
    for line in text.splitlines():
        if not cols:
            m = _TABLE_COLS.search(line)
            if m:
                cols = m.group(1).split()
            continue
        if not line.startswith(" "):
            break
        tokens = line.split()
        if not tokens:
            continue
        if len(tokens) < len(cols):
            values = tokens + [""] * (len(cols) - len(tokens))
        elif len(cols) <= 1:
            values = [" ".join(tokens)]
        else:
            trailing = len(cols) - 2
            tail = tokens[len(tokens) - trailing:] if trailing else []
            values = [tokens[0], " ".join(tokens[1:len(tokens) - trailing])] + tail
        row = dict(zip(cols, values))
        if row.get("name"):
            rows.append(row)
    return rows


def _present(extra: dict) -> dict:
    return {k: v for k, v in extra.items() if v is not None and v != "" and v != []}


def _project_page(result: Any) -> tuple[list[dict], bool]:
    if isinstance(result, list):
        return [p for p in result if isinstance(p, dict)], False
    if isinstance(result, dict):
        items = result.get("projects", [])
        return [p for p in items if isinstance(p, dict)] if isinstance(items, list) else [], bool(result.get("has_more"))
    if isinstance(result, str):
        return _parse_project_table(result), bool(re.search(r"has_more:\s*true", result))
    return [], False


class CodebaseMemoryClient:

    def __init__(self, cfg: Config):
        self._server = cfg.mcp_server
        self._args = cfg.mcp_args
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._lock = asyncio.Lock()
        self._req_id = 0
        self._available: Optional[bool] = None

    async def _ensure_started(self):
        if self._proc is not None or self._available is False:
            return
        try:
            self._proc = await asyncio.create_subprocess_exec(
                self._server,
                *(self._args or []),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                limit=_STREAM_LIMIT,
            )
        except (FileNotFoundError, OSError, TypeError):
            self._proc = None
            self._available = False
            return
        try:
            resp = await self._send_raw({"jsonrpc": "2.0", "method": "initialize", "id": 0,
                                         "params": {"protocolVersion": "2024-11-05",
                                                    "capabilities": {},
                                                    "clientInfo": {"name": "pentest", "version": "0.1"}}},
                                        timeout=_CALL_TIMEOUT)
            if resp is None or "error" in resp:
                raise OSError("initialize failed")
            await self._send_raw({"jsonrpc": "2.0", "method": "notifications/initialized",
                                   "params": {}})
            self._available = True
        except (asyncio.TimeoutError, OSError, ValueError, ConnectionError):
            self._available = False
            await self._terminate()

    async def _terminate(self):
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            proc.kill()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except (ProcessLookupError, asyncio.TimeoutError, OSError):
            pass

    async def _read_response(self, req_id: int) -> Optional[dict]:
        while True:
            resp_line = await self._proc.stdout.readline()
            if not resp_line:
                raise ConnectionError("codebase-memory-mcp closed its output")
            try:
                msg = json.loads(resp_line.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if isinstance(msg, dict) and msg.get("id") == req_id and (
                    "result" in msg or "error" in msg):
                return msg

    async def _send_raw(self, payload: dict, timeout: float = _CALL_TIMEOUT) -> Optional[dict]:
        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            return None
        line = json.dumps(payload) + "\n"
        self._proc.stdin.write(line.encode())
        await self._proc.stdin.drain()
        if "id" in payload:
            return await asyncio.wait_for(self._read_response(payload["id"]), timeout=timeout)
        return None

    async def _call(self, tool: str, args: dict, timeout: float = _CALL_TIMEOUT) -> Any:
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
                resp = await self._send_raw(req, timeout=timeout)
                if resp and "result" in resp:
                    content = resp["result"].get("content", [])
                    texts = [c["text"] for c in content if c.get("type") == "text"]
                    raw = "\n".join(texts)
                    try:
                        return json.loads(raw)
                    except json.JSONDecodeError:
                        return raw
            except (ConnectionError, BrokenPipeError, OSError):
                self._available = None
                await self._terminate()
                return None
            except (asyncio.TimeoutError, Exception):
                return None

    async def list_projects(self) -> list[dict]:
        projects: list[dict] = []
        seen: set[str] = set()
        offset = 0
        while True:
            page = await self._call("list_projects", {"format": "json", "limit": _PROJECT_PAGE,
                                                      "offset": offset})
            if page is None and offset == 0:
                page = await self._call("list_projects", {})
            items, more = _project_page(page)
            fresh = [p for p in items if p.get("name") and p.get("name") not in seen]
            seen.update(p["name"] for p in fresh)
            projects.extend(fresh)
            if not more or not fresh or len(projects) >= _PROJECT_MAX:
                return projects
            offset += len(items)

    async def find_project_for_repo(self, repo_path: str) -> Optional[str]:
        repo = Path(repo_path).resolve()
        best: Optional[str] = None
        best_depth = -1
        for p in await self.list_projects():
            name = p.get("name")
            root_raw = p.get("root_path") or ""
            if not name or not root_raw:
                continue
            try:
                root = Path(root_raw).resolve()
            except (OSError, RuntimeError):
                continue
            if root == repo:
                return name
            if root in repo.parents and len(root.parts) > best_depth:
                best, best_depth = name, len(root.parts)
        return best

    async def index_repository(self, repo_path: str) -> Optional[dict]:
        return await self._call("index_repository", {"repo_path": repo_path}, timeout=_INDEX_TIMEOUT)

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
        **extra: Any,
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
        args.update(_present(extra))
        return await self._call_raw_text("search_graph", args)

    async def trace_path(
        self,
        function_name: str,
        mode: str = "calls",
        depth: int = 5,
        project: Optional[str] = None,
        direction: Optional[str] = None,
        **extra: Any,
    ) -> str:
        args: dict = {"function_name": function_name, "mode": mode, "depth": depth}
        if direction:
            args["direction"] = direction
        if project:
            args["project"] = project
        args.update(_present(extra))
        return await self._call_raw_text("trace_path", args)

    async def get_code_snippet(self, qualified_name: str, project: Optional[str] = None,
                               **extra: Any) -> str:
        args: dict = {"qualified_name": qualified_name}
        if project:
            args["project"] = project
        args.update(_present(extra))
        return await self._call_raw_text("get_code_snippet", args)

    async def search_code(self, pattern: str, limit: int = 50, project: Optional[str] = None,
                          regex: bool = False) -> str:
        args: dict = {"pattern": pattern, "limit": limit}
        if regex:
            args["regex"] = True
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

    async def query_graph(self, query: str, project: Optional[str] = None,
                          max_rows: Optional[int] = None, fmt: Optional[str] = None) -> Any:
        args: dict = {"query": query}
        if project:
            args["project"] = project
        if max_rows is not None:
            args["max_rows"] = max_rows
        if fmt:
            args["format"] = fmt
        return await self._call("query_graph", args)

    async def query_graph_text(self, query: str, project: Optional[str] = None,
                               max_rows: Optional[int] = None) -> str:
        result = await self.query_graph(query, project=project, max_rows=max_rows)
        if result is None:
            return ""
        return result if isinstance(result, str) else json.dumps(result, indent=2)

    async def close(self):
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
            await asyncio.wait_for(proc.wait(), timeout=5)
            self._proc = None
        except Exception:
            await self._terminate()
