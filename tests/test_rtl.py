import random
import textwrap

import arabic_reshaper
from bidi.algorithm import get_display
from rich.markup import escape
from rich.text import Text

from core.rtl import _escape_text, _tokenize, has_rtl, render, rtl_markup

ALPHABET = ["a", "b", "[", "]", "\\", "/", "#", "@", " ", "س", "x", "\n"]
TAGS = ["[bold]", "[/bold]", "[red]", "[/red]", "[/]", "\\[bold]", "\\\\[red]", "[Phase: x]"]
LONG = "این یک جمله بسیار طولانی فارسی است که باید قبل از دوطرفه سازی شکسته شود تا ترتیب درست بماند"


def vis(s):
    return get_display(arabic_reshaper.reshape(s), base_dir="R")


def full_span(text, style):
    return any(sp.start == 0 and sp.end == len(text.plain) and sp.style == style for sp in text.spans)


def test_trailing_backslash_before_closing_tag():
    s = "[bold]سلام\\\\[/bold]"
    t = Text.from_markup(rtl_markup(s))
    assert t.plain == vis(Text.from_markup(s).plain)
    assert full_span(t, "bold"), t.spans


def test_escaped_trailing_backslash_before_closing_tag():
    s = "[red]" + escape("مسیر C:\\dir\\") + "[/red]"
    t = Text.from_markup(rtl_markup(s))
    assert t.plain == vis("مسیر C:\\dir\\")
    assert full_span(t, "red"), t.spans


def test_whole_line_order():
    out = rtl_markup("[bold]سلام[/bold] دنیا")
    assert Text.from_markup(out).plain == vis("سلام دنیا")


def test_uniform_line_keeps_style():
    out = rtl_markup("[cyan]پاسخ مدل به سوال شما[/cyan]")
    t = Text.from_markup(out)
    assert t.plain == vis("پاسخ مدل به سوال شما") and t.spans and t.spans[0].style == "cyan"


def test_multi_line_tag_balance():
    s = "[dim]line one\nسلام [bold]x[/bold] دنیا\nline three[/dim]"
    t = Text.from_markup(rtl_markup(s))
    expected = [vis(line) if has_rtl(line) else line for line in Text.from_markup(s).plain.split("\n")]
    assert t.plain.split("\n") == expected
    assert expected == ["line one", vis("سلام x دنیا"), "line three"]
    assert full_span(t, "dim"), t.spans


def test_width_wrapping():
    out = rtl_markup("[cyan]" + LONG + "[/cyan]", width=30)
    rows = Text.from_markup(out).plain.split("\n")
    assert all(len(r) <= 30 for r in rows)
    logical_rows = textwrap.wrap(LONG, 30)
    assert rows == [vis(r) for r in logical_rows], (rows,)
    assert rows[0] == vis(logical_rows[0])
    assert render(LONG, 30).split("\n") == [vis(r) for r in logical_rows]


def test_bracketed_text_not_a_tag():
    out = rtl_markup("[bold magenta][Phase: فاز اول][/bold magenta]")
    assert Text.from_markup(out).plain == vis("[Phase: فاز اول]")


def test_non_rtl_passthrough_identity():
    for s in ["[bold]hi[/bold]", "foo \\[bar]", "x [ y", "plain"]:
        assert rtl_markup(s) == s


def test_escape_roundtrip_fuzz():
    rng = random.Random(1)
    for _ in range(20000):
        p = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 12)))
        e = _escape_text(p, False)
        assert Text.from_markup(e).plain == p, (p, e, Text.from_markup(e).plain)
        e2 = _escape_text(p, True) + "[bold]z[/bold]"
        t = Text.from_markup(e2)
        assert t.plain == p + "z", (p, e2, t.plain)


def test_tokenizer_and_rtl_markup_fuzz():
    rng = random.Random(2)
    n = 0
    for _ in range(20000):
        parts = [rng.choice(ALPHABET + TAGS) for _ in range(rng.randint(0, 10))]
        m = "".join(parts)
        try:
            ref = Text.from_markup(m).plain
        except Exception:
            continue
        toks = _tokenize(m)
        plain = "".join(v for k, v in toks if k == "text")
        assert plain == ref, (m, plain, ref)
        out = rtl_markup(m, width=rng.choice([None, 5, 20]))
        try:
            Text.from_markup(out)
        except Exception as exc:
            raise AssertionError((m, out, exc))
        n += 1
    assert n > 0
