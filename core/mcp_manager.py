from __future__ import annotations
import json
import logging
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

_READONLY_TOOL_PREFIXES = (
    "read_", "list_", "get_", "search_", "grep_", "query_",
    "describe_", "show_", "fetch_", "find_", "check_",
)


def _is_readonly_tool(name: str, annotations: Any = None) -> bool:
    """Return True only if the tool is safe to expose to an LLM.

    Priority:
    1. If the server provided an MCP annotations object, trust readOnlyHint.
       readOnlyHint=True → allow; readOnlyHint=False → deny; absent → fall through.
    2. Fall back to prefix matching for servers that don't annotate.
    3. Unannotated tools whose names don't match a read-only prefix are denied.
    """
    if annotations is not None:
        hint = getattr(annotations, "readOnlyHint", None)
        if hint is True:
            return True
        if hint is False:
            return False
    n = name.lower()
    return any(n.startswith(p) for p in _READONLY_TOOL_PREFIXES)


class MCPManager:
    def __init__(self, configs: dict):
        self._configs = configs
        self._sessions: dict[str, Any] = {}
        self._stacks: dict[str, AsyncExitStack] = {}
        self._tools_cache: dict[str, list] = {}

    @classmethod
    def from_claude_config(cls, config_path: str = "~/.claude.json") -> "MCPManager":
        path = Path(config_path).expanduser()
        if not path.exists():
            return cls({})
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            return cls({})
        return cls(data.get("mcpServers", {}))

    async def _connect(self, name: str) -> None:
        if name in self._sessions:
            return
        cfg = self._configs.get(name)
        if not cfg:
            return

        transport = cfg.get("type", "stdio")

        if transport == "stdio":
            try:
                from mcp import ClientSession, StdioServerParameters
                from mcp.client.stdio import stdio_client
            except ImportError:
                return

            command = cfg.get("command", "")
            if not command:
                return
            args = cfg.get("args") or []
            env = cfg.get("env") or None

            stack = AsyncExitStack()
            try:
                params = StdioServerParameters(command=command, args=args, env=env)
                read, write = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                self._sessions[name] = session
                self._stacks[name] = stack
            except Exception as exc:
                _log.warning("MCP server %r failed to connect: %s", name, exc)
                await stack.aclose()

        elif transport in ("sse", "http"):
            try:
                from mcp.client.sse import sse_client
                from mcp import ClientSession
            except ImportError:
                return

            url = cfg.get("url", "")
            if not url:
                return

            stack = AsyncExitStack()
            try:
                read, write = await stack.enter_async_context(sse_client(url))
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                self._sessions[name] = session
                self._stacks[name] = stack
            except Exception as exc:
                _log.warning("MCP server %r failed to connect: %s", name, exc)
                await stack.aclose()

    async def list_all_tools(self) -> list[dict]:
        all_tools = []
        for name in self._configs:
            try:
                await self._connect(name)
                if name not in self._sessions:
                    continue
                if name not in self._tools_cache:
                    result = await self._sessions[name].list_tools()
                    self._tools_cache[name] = getattr(result, "tools", []) or []
                allow_list: set[str] = set(cfg.get("mcp_allow") or [])
                for tool in self._tools_cache[name]:
                    annotations = getattr(tool, "annotations", None)
                    if tool.name not in allow_list and not _is_readonly_tool(tool.name, annotations):
                        continue
                    schema = getattr(tool, "inputSchema", None) or {"type": "object"}
                    all_tools.append({
                        "type": "function",
                        "function": {
                            "name": f"mcp__{name}__{tool.name}",
                            "description": getattr(tool, "description", "") or "",
                            "parameters": schema,
                        },
                    })
            except Exception as exc:
                _log.warning("MCP server %r: error listing tools: %s", name, exc)
        return all_tools

    async def call_tool(self, mcp_name: str, tool_name: str, args: dict) -> str:
        try:
            await self._connect(mcp_name)
            session = self._sessions.get(mcp_name)
            if not session:
                return f"MCP server {mcp_name!r} not available"
            result = await session.call_tool(tool_name, args)
            content = getattr(result, "content", None)
            if content:
                parts = []
                for c in content:
                    if hasattr(c, "text"):
                        parts.append(c.text)
                    else:
                        parts.append(str(c))
                return "\n".join(parts) or "OK"
            return str(result)
        except Exception as ex:
            return f"MCP error ({mcp_name}/{tool_name}): {ex}"

    async def close(self) -> None:
        for stack in list(self._stacks.values()):
            try:
                await stack.aclose()
            except Exception:
                pass
        self._sessions.clear()
        self._stacks.clear()
        self._tools_cache.clear()
