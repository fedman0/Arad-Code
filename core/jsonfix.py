from __future__ import annotations
import json
import re
from typing import Optional

_HEX4 = re.compile(r"[0-9a-fA-F]{4}")
_CONTROL = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}
_MAX_EDITS = 12
_TAIL = 20


def _repair(text: str) -> tuple[Optional[str], int]:
    out: list[str] = []
    stack: list[str] = []
    i, n, in_str, edits = 0, len(text), False, 0
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\":
                nxt = text[i + 1] if i + 1 < n else ""
                if nxt and nxt in '"\\/bfnrt':
                    out.append(ch + nxt)
                    i += 2
                    continue
                if nxt == "u" and _HEX4.match(text, i + 2):
                    out.append(text[i:i + 6])
                    i += 6
                    continue
                edits += 1
                if nxt == "'":
                    out.append("'")
                    i += 2
                    continue
                out.append("\\\\")
                i += 1
                continue
            if ch == '"':
                j = i + 1
                while j < n and text[j] in " \t\r\n":
                    j += 1
                if j >= n or text[j] in ",:}]":
                    in_str = False
                    out.append(ch)
                else:
                    edits += 1
                    out.append('\\"')
                i += 1
                continue
            if ch in _CONTROL:
                out.append(_CONTROL[ch])
            elif ord(ch) < 32:
                out.append(f"\\u{ord(ch):04x}")
            else:
                out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
        elif ch in "{[":
            stack.append("}" if ch == "{" else "]")
            out.append(ch)
        elif ch in "}]":
            if stack and stack[-1] == ch:
                stack.pop()
                out.append(ch)
                if not stack:
                    if len(text[i + 1:].strip()) > _TAIL:
                        return None, edits
                    return "".join(out), edits
            else:
                edits += 1
        else:
            out.append(ch)
        i += 1
    if in_str or not out:
        return None, edits
    edits += len(stack)
    out.extend(reversed(stack))
    return "".join(out), edits


def loads_object(text: str) -> Optional[dict]:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        value = None
        fixed, edits = _repair(text or "")
        if fixed is not None and edits <= _MAX_EDITS:
            try:
                value = json.loads(fixed)
            except json.JSONDecodeError:
                value = None
    return value if isinstance(value, dict) else None
