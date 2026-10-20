from __future__ import annotations


def _size(message: dict) -> int:
    n = len(str(message.get("content") or ""))
    for call in message.get("tool_calls") or ():
        if isinstance(call, dict):
            n += len(str((call.get("function") or {}).get("arguments") or ""))
    return n


class ContextWindow:
    def __init__(self, limit_chars: int, keep_recent: int = 6, head_chars: int = 1500):
        self.limit = max(0, int(limit_chars or 0))
        self.keep_recent = max(1, keep_recent)
        self.head = max(200, head_chars)
        self._boundary = 0

    def _trim(self, message: dict) -> dict:
        content = str(message.get("content") or "")
        if len(content) <= self.head + 200:
            return message
        cut = len(content) - self.head
        return {**message, "content": content[:self.head]
                + f"\n[{cut} more characters of this older tool result were trimmed to keep the "
                  f"context small. Call the tool again if you need them.]"}

    def _render(self, messages: list[dict]) -> list[dict]:
        if not self._boundary:
            return messages
        return [self._trim(m) if i < self._boundary and m.get("role") == "tool" else m
                for i, m in enumerate(messages)]

    def view(self, messages: list[dict]) -> list[dict]:
        if not self.limit:
            return messages
        out = self._render(messages)
        if sum(_size(m) for m in out) <= self.limit:
            return out
        tools = [i for i, m in enumerate(messages) if m.get("role") == "tool"]
        if len(tools) <= self.keep_recent:
            return out
        boundary = tools[-self.keep_recent]
        if boundary <= self._boundary:
            return out
        self._boundary = boundary
        return self._render(messages)

    @property
    def trimmed_before(self) -> int:
        return self._boundary
