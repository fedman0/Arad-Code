from __future__ import annotations
import asyncio
import json
import logging
import os
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)
_CONNECT_TIMEOUT = 30
_CALL_TIMEOUT = 120

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
    def __init__(self, configs: dict, mcp_allow: dict | None = None):
        self._configs = configs
        self._mcp_allow: dict[str, list[str]] = mcp_allow or {}
        self._sessions: dict[str, Any] = {}
        self._hosts: dict[str, _SessionHost] = {}
        self._failed: set[str] = set()
        self._tools_cache: dict[str, list] = {}

    @classmethod
    def from_claude_config(
        cls,
        config_path: str = "~/.claude.json",
        mcp_allow: dict | None = None,
    ) -> "MCPManager":
        path = Path(config_path).expanduser()
        if not path.exists():
            return cls({}, mcp_allow=mcp_allow)
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            return cls({}, mcp_allow=mcp_allow)
        servers = data.get("mcpServers", {}) if isinstance(data, dict) else {}
        return cls(servers if isinstance(servers, dict) else {}, mcp_allow=mcp_allow)

    async def _connect(self, name: str) -> None:
        if name in self._sessions or name in self._failed:
            return
        cfg = self._configs.get(name)
        if not isinstance(cfg, dict) or not cfg:
            return
        opener = _make_opener(name, cfg)
        if opener is None:
            return
        host = _SessionHost(name, opener)
        try:
            await host.start(_CONNECT_TIMEOUT)
        except Exception as exc:
            _log.warning("MCP server %r failed to connect: %s", name, exc)
            await host.close()
            self._failed.add(name)
            return
        self._hosts[name] = host
        self._sessions[name] = host.session

    async def _allowed_tools(self, name: str) -> list:
        await self._connect(name)
        if name not in self._sessions:
            return []
        if name not in self._tools_cache:
            result = await asyncio.wait_for(self._sessions[name].list_tools(),
                                            timeout=_CONNECT_TIMEOUT)
            self._tools_cache[name] = getattr(result, "tools", []) or []
        cfg = self._configs.get(name) or {}
        allow_list: set[str] = set(
            self._mcp_allow.get(name) or (cfg.get("mcp_allow") if isinstance(cfg, dict) else None) or []
        )
        return [tool for tool in self._tools_cache[name]
                if tool.name in allow_list
                or _is_readonly_tool(tool.name, getattr(tool, "annotations", None))]

    async def list_all_tools(self) -> list[dict]:
        all_tools = []
        for name in self._configs:
            try:
                for tool in await self._allowed_tools(name):
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
            allowed = {tool.name for tool in await self._allowed_tools(mcp_name)}
            session = self._sessions.get(mcp_name)
            if not session:
                return f"MCP server {mcp_name!r} not available"
            if tool_name not in allowed:
                return f"MCP tool {mcp_name}/{tool_name} is not allowed (not read-only or not in mcp_allow)"
            result = await asyncio.wait_for(session.call_tool(tool_name, args),
                                            timeout=_CALL_TIMEOUT)
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
        except asyncio.TimeoutError:
            return f"MCP error ({mcp_name}/{tool_name}): timed out"
        except Exception as ex:
            return f"MCP error ({mcp_name}/{tool_name}): {ex}"

    async def close(self) -> None:
        for host in list(self._hosts.values()):
            await host.close()
        self._sessions.clear()
        self._hosts.clear()
        self._failed.clear()
        self._tools_cache.clear()


def _make_opener(name: str, cfg: dict):
    transport = cfg.get("type") or ("http" if cfg.get("url") else "stdio")
    try:
        from mcp import ClientSession
    except ImportError:
        return None

    if transport == "stdio":
        command = cfg.get("command", "")
        if not command:
            return None

        async def open_stdio(stack: AsyncExitStack):
            from mcp import StdioServerParameters
            from mcp.client.stdio import stdio_client
            params = StdioServerParameters(command=command, args=cfg.get("args") or [],
                                           env=cfg.get("env") or None)
            errlog = stack.enter_context(open(os.devnull, "w"))
            streams = await stack.enter_async_context(stdio_client(params, errlog=errlog))
            return await stack.enter_async_context(ClientSession(streams[0], streams[1]))
        return open_stdio

    url = cfg.get("url", "")
    if not url:
        return None
    headers = cfg.get("headers") or None

    if transport == "sse":
        async def open_sse(stack: AsyncExitStack):
            from mcp.client.sse import sse_client
            streams = await stack.enter_async_context(sse_client(url, headers=headers))
            return await stack.enter_async_context(ClientSession(streams[0], streams[1]))
        return open_sse

    if transport in ("http", "streamable-http", "streamable_http"):
        async def open_http(stack: AsyncExitStack):
            import mcp.client.streamable_http as streamable
            if hasattr(streamable, "streamable_http_client"):
                kwargs = {}
                if headers:
                    kwargs["http_client"] = await stack.enter_async_context(
                        streamable.create_mcp_http_client(headers=headers))
                streams = await stack.enter_async_context(
                    streamable.streamable_http_client(url, **kwargs))
            else:
                streams = await stack.enter_async_context(
                    streamable.streamablehttp_client(url, headers=headers))
            return await stack.enter_async_context(ClientSession(streams[0], streams[1]))
        return open_http

    _log.warning("MCP server %r uses unsupported transport %r", name, transport)
    return None


class _SessionHost:
    def __init__(self, name: str, opener):
        self.name = name
        self.session: Any = None
        self.error: BaseException | None = None
        self._opener = opener
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None

    async def start(self, timeout: float) -> None:
        self._task = asyncio.create_task(self._run(), name=f"mcp-session-{self.name}")
        try:
            await asyncio.wait_for(self._ready.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"no response within {timeout:.0f}s") from None
        if self.session is None:
            raise ConnectionError(str(self.error or "connection closed"))

    async def _run(self) -> None:
        try:
            async with AsyncExitStack() as stack:
                session = await self._opener(stack)
                await session.initialize()
                self.session = session
                self._ready.set()
                await self._stop.wait()
        except BaseException as exc:
            self.error = exc
        finally:
            self.session = None
            self._ready.set()

    async def close(self) -> None:
        self._stop.set()
        task = self._task
        if task is None or task.done():
            return
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=10)
        except BaseException:
            task.cancel()
            try:
                await task
            except BaseException:
                pass
