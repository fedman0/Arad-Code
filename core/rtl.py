from __future__ import annotations

_RTL_RANGES = (
    (0x0590, 0x05FF),
    (0x0600, 0x06FF),
    (0x0750, 0x077F),
    (0x08A0, 0x08FF),
    (0xFB50, 0xFDFF),
    (0xFE70, 0xFEFF),
)


def has_rtl(text: str) -> bool:
    for ch in text:
        cp = ord(ch)
        for lo, hi in _RTL_RANGES:
            if lo <= cp <= hi:
                return True
    return False


def render(text: str) -> str:
    if not text or not has_rtl(text):
        return text
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
        reshaped = arabic_reshaper.reshape(text)
        return get_display(reshaped, base_dir='R')
    except ImportError:
        return text
