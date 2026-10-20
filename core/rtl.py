from __future__ import annotations
import re
import textwrap
from typing import Optional

_RTL_RANGES = (
    (0x0590, 0x05FF),   # Hebrew
    (0x0600, 0x06FF),   # Arabic (includes Persian/Farsi)
    (0x0750, 0x077F),   # Arabic Supplement
    (0x08A0, 0x08FF),   # Arabic Extended-A
    (0xFB50, 0xFDFF),   # Arabic Presentation Forms-A
    (0xFE70, 0xFEFF),   # Arabic Presentation Forms-B
)

# Matches Rich markup tags like [green], [/green], [bold cyan], [dim]
_RICH_TAG = re.compile(r'(\\*)(\[[a-z#/@][^\[]*?\])')


def has_rtl(text: str) -> bool:
    for ch in text:
        cp = ord(ch)
        for lo, hi in _RTL_RANGES:
            if lo <= cp <= hi:
                return True
    return False


def _wrap(line: str, width: Optional[int]) -> list[str]:
    if not width or width < 1 or len(line) <= width:
        return [line]
    rows = textwrap.wrap(line, width=width, break_long_words=True,
                         break_on_hyphens=False, replace_whitespace=False)
    return rows or [line]


def _visual(line: str, width: Optional[int], reshape, get_display) -> str:
    return "\n".join(get_display(reshape(row), base_dir='R') for row in _wrap(line, width))


def render(text: str, width: Optional[int] = None) -> str:
    """RTL-render a plain text string (no Rich markup).

    Uses base_dir='R' so the paragraph is treated as RTL:
    - Pure Persian text displays correctly.
    - Mixed "English: فارسی text" also displays as RTL paragraph,
      matching the user's explicit preference.
    """
    if not text or not has_rtl(text):
        return text
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
    except ImportError:
        return text
    return "\n".join(
        _visual(line, width, arabic_reshaper.reshape, get_display) if has_rtl(line) else line
        for line in text.split("\n")
    )


def _tokenize(markup: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []

    def add_text(s: str) -> None:
        if not s:
            return
        if tokens and tokens[-1][0] == "text":
            tokens[-1] = ("text", tokens[-1][1] + s)
        else:
            tokens.append(("text", s))

    pos = 0
    for m in _RICH_TAG.finditer(markup):
        start, end = m.span()
        if start > pos:
            add_text(markup[pos:start].replace("\\[", "["))
        backslashes, escaped = divmod(len(m.group(1)), 2)
        if backslashes:
            add_text("\\" * backslashes)
        if escaped:
            add_text(m.group(2))
        else:
            tokens.append(("tag", m.group(2)))
        pos = end
    if pos < len(markup):
        add_text(markup[pos:].replace("\\[", "["))
    return tokens


def _split_lines(tokens: list[tuple[str, str]]) -> list[list[tuple[str, str]]]:
    lines: list[list[tuple[str, str]]] = [[]]
    for kind, value in tokens:
        if kind == "tag":
            lines[-1].append((kind, value))
            continue
        for i, piece in enumerate(value.split("\n")):
            if i:
                lines.append([])
            if piece:
                lines[-1].append(("text", piece))
    return lines


def _escape_text(text: str, before_tag: bool) -> str:
    out = []
    pos = 0
    for m in _RICH_TAG.finditer(text):
        out.append(text[pos:m.start()].replace("\\[", "\\\\["))
        out.append(m.group(1) * 2 + "\\" + m.group(2))
        pos = m.end()
    out.append(text[pos:].replace("\\[", "\\\\["))
    result = "".join(out)
    if before_tag:
        result += "\\" * (len(result) - len(result.rstrip("\\")))
    return result


def _emit(tokens: list[tuple[str, str]]) -> str:
    out = []
    for i, (kind, value) in enumerate(tokens):
        if kind == "tag":
            out.append(value)
        else:
            out.append(_escape_text(value, i + 1 < len(tokens)))
    return "".join(out)


def _render_line(tokens: list[tuple[str, str]], width: Optional[int], reshape, get_display) -> str:
    plain = "".join(value for kind, value in tokens if kind == "text")
    if not has_rtl(plain):
        return _emit(tokens)
    text_idx = [i for i, (kind, value) in enumerate(tokens) if kind == "text" and value.strip()]
    first, last = text_idx[0], text_idx[-1]
    prefix = [value for kind, value in tokens[:first] if kind == "tag"]
    middle = [value for kind, value in tokens[first:last + 1] if kind == "tag"]
    suffix = [value for kind, value in tokens[last + 1:] if kind == "tag"]
    visual = _visual(plain, width, reshape, get_display)
    if middle:
        return _escape_text(visual, True) + "".join(prefix + middle + suffix)
    return "".join(prefix) + _escape_text(visual, bool(suffix)) + "".join(suffix)


def rtl_markup(text: str, width: Optional[int] = None) -> str:
    """RTL-render a Rich markup string.

    Splits the string on Rich markup tags (e.g. [green], [/bold]),
    applies render() only to the text segments between tags, then
    re-joins. This prevents get_display from reordering the markup
    tags themselves.

    Falls back to plain render() if no RTL chars are present.
    """
    if not has_rtl(text):
        return text
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
    except ImportError:
        return text
    return "\n".join(
        _render_line(line, width, arabic_reshaper.reshape, get_display)
        for line in _split_lines(_tokenize(text))
    )
