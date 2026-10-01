from __future__ import annotations
import re

_RTL_RANGES = (
    (0x0590, 0x05FF),   # Hebrew
    (0x0600, 0x06FF),   # Arabic (includes Persian/Farsi)
    (0x0750, 0x077F),   # Arabic Supplement
    (0x08A0, 0x08FF),   # Arabic Extended-A
    (0xFB50, 0xFDFF),   # Arabic Presentation Forms-A
    (0xFE70, 0xFEFF),   # Arabic Presentation Forms-B
)

# Matches Rich markup tags like [green], [/green], [bold cyan], [dim]
_RICH_TAG = re.compile(r'(\[[^\[\]\n]*?\])')


def has_rtl(text: str) -> bool:
    for ch in text:
        cp = ord(ch)
        for lo, hi in _RTL_RANGES:
            if lo <= cp <= hi:
                return True
    return False


def render(text: str) -> str:
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
        reshaped = arabic_reshaper.reshape(text)
        return get_display(reshaped, base_dir='R')
    except ImportError:
        return text


def rtl_markup(text: str) -> str:
    """RTL-render a Rich markup string.

    Splits the string on Rich markup tags (e.g. [green], [/bold]),
    applies render() only to the text segments between tags, then
    re-joins. This prevents get_display from reordering the markup
    tags themselves.

    Falls back to plain render() if no RTL chars are present.
    """
    if not has_rtl(text):
        return text

    parts = _RICH_TAG.split(text)
    out = []
    for part in parts:
        if _RICH_TAG.fullmatch(part):
            out.append(part)
        else:
            out.append(render(part))
    return ''.join(out)
