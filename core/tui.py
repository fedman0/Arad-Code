from __future__ import annotations
import asyncio
import os
import shlex
import sys
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

from rich.markup import escape as _escape
from rich.text import Text
from textual import on
from textual.actions import SkipAction
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import Footer, Header, Input, RichLog, Static, Tree

from .rtl import has_rtl as _has_rtl, render as _rtl_render, rtl_markup as _rtlm

from .version import VERSION
from .usage import BudgetExceeded, Usage, format_cost, format_tokens

def _model_short(model: str, limit: int = 18) -> str:
    name = (model or "").rsplit("/", 1)[-1]
    return name if len(name) <= limit else name[:limit - 1] + "…"


def _usage_text(usage) -> str:
    if not usage or not usage.get("calls"):
        return ""
    u = Usage.from_dict(usage)
    return f"{format_tokens(u.total_tokens)} tok · {format_cost(u)}"


_SEV_ICON = {
    "critical": "[bright_red]■[/bright_red]",
    "high": "[red]■[/red]",
    "medium": "[yellow]■[/yellow]",
    "low": "[green]■[/green]",
}
_SEV_COLOR = {"critical": "bright_red", "high": "red", "medium": "yellow", "low": "green"}

_STATUS_STYLE = {
    "initial": "dim",
    "evidence_supported": "green",
    "reproduced": "bold green",
    "human_confirmed": "bold green",
    "needs_recheck": "yellow",
    "blocked": "yellow",
    "refuted": "dim red",
    "rejected": "dim red",
}

_IMMEDIATE_VERBS = {"help", "clear", "cls", "exit", "quit", "headless"}
_CLI_VERBS = {"report", "peers", "triage", "coverage", "calibrate", "query", "doctor",
              "sarif", "init", "reconcile", "verify", "list-skills", "config-init", "usage"}


def _sev_label(sev) -> str:
    if isinstance(sev, int):
        if sev >= 9:
            return "critical"
        if sev >= 7:
            return "high"
        if sev >= 4:
            return "medium"
        return "low"
    return str(sev).lower() if sev else "low"


def _clip(value, limit: int = 0) -> str:
    s = " ".join(str("" if value is None else value).split())
    if limit and len(s) > limit:
        s = s[: max(1, limit - 1)].rstrip() + "…"
    return s


def _short(value, limit: int = 0) -> str:
    return _escape(_clip(value, limit))


def _pad(value, width: int) -> str:
    return _escape(_clip(value, width).ljust(width))


def _fmt_elapsed(seconds: float) -> str:
    if seconds < 10:
        return f"{seconds:.1f}s"
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m{secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def _status_tag(status, width: int = 0) -> str:
    st = str(status or "?")
    style = _STATUS_STYLE.get(st, "dim")
    return f"[{style}]{_escape(f'[{st}]'.ljust(width))}[/{style}]"


def _sev_badge(sev, width: int = 8) -> str:
    sl = _sev_label(sev)
    color = _SEV_COLOR.get(sl, "white")
    return f"[{color}]{_escape(sl.upper().ljust(width))}[/{color}]"


def _hyp_title(hyp) -> str:
    return getattr(hyp, "violated_invariant", None) or str(hyp)


def _split_cmd(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


_BANNER = (
    f"[bold cyan]Arad Code[/bold cyan] [dim]v{VERSION}  ·  security research terminal[/dim]\n"
    "[dim]Type a command, or[/dim] [bold cyan]>[/bold cyan] [dim]to ask about the current run.  "
    "Tab focuses the workflow tree.[/dim]"
)

_SHORTCUTS = (
    "[cyan]run[/cyan] [dim]<repo>[/dim] · [cyan]skill[/cyan] [dim]<name> <repo>[/dim] · "
    "[cyan]workflow[/cyan] [dim]<script.py>[/dim] · [cyan]deep-research[/cyan] [dim]<q>[/dim] · "
    "[cyan]headless[/cyan] · [cyan]help[/cyan]"
)

_HELP = """
[bold]Commands[/bold]
  [cyan]run[/cyan] <repo> [--phase N] [--resume] [--restart] [--all-skills]
  [cyan]skill[/cyan] <name> <repo> \\[context…]
  [cyan]workflow[/cyan] <script.py> [--repo <path>]
  [cyan]deep-research[/cyan] <question> [--repo <path>]
  [cyan]report[/cyan] <repo>  ·  peers  ·  coverage  ·  sarif  ·  doctor  ·  calibrate
  reconcile  ·  verify  ·  init  ·  list-skills  ·  usage <repo>  ·  query <repo> "<expression>"
      [dim]passed to pentest.py, run in the current directory[/dim]
  triage  ·  config-init  ·  query <repo>
      [dim]interactive — run these in headless mode[/dim]
  [cyan]headless[/cyan]       exit TUI and relaunch in headless CLI mode
  [cyan]help[/cyan]  ·  [cyan]clear[/cyan]  ·  [cyan]exit[/cyan]
  [dim]While a task runs, other commands queue; help/clear/exit/> run at once.[/dim]

[bold]Inline query (any time, even mid-run)[/bold]
  > <anything>        Ask about the current or last run
  > status            Summary: findings so far, phases done
  > findings          List all hypotheses with severity

[bold]Workflow panel  (Ctrl+W toggle · Tab focus)[/bold]
  ↑↓     Navigate phases / agents / findings
  Enter  Show details · expand / collapse
  Space  Expand / collapse

[bold]Keys[/bold]
  ↑↓       Command history
  Tab      Focus workflow tree (Tab again → input)
  Ctrl+C   Stop running task
  Ctrl+L   Clear LLM query responses (scan output preserved)
  Ctrl+W   Toggle workflow panel
  Ctrl+Q   Quit
  Escape   Focus input
  End      Follow new output after scrolling up

[dim]Env: PENTEST_API_KEY · PENTEST_MODEL · PENTEST_API_BASE[/dim]
"""


# ── Workflow data model ───────────────────────────────────────────────────────

class _PhaseNode:
    def __init__(self, name: str, title: str):
        self.name = name
        self.title = title
        self.agents: list[_AgentNode] = []
        self.done = False
        self.state = "running"
        self.elapsed = 0.0
        self.started_at = time.monotonic()


class _AgentNode:
    def __init__(self, label: str, key=None):
        self.label = label
        self.key = label if key is None else key
        self.done = False
        self.state = "running"
        self.elapsed = 0.0
        self.error: Optional[str] = None
        self.started_at = time.monotonic()
        self.findings: list = []
        self.model = ""
        self.usage: dict = {}


class WorkflowModel:
    def __init__(self):
        self.phases: list[_PhaseNode] = []
        self._phase_idx: dict[str, _PhaseNode] = {}
        self._agent_idx: dict = {}
        self.current_tool: str = ""

    def reset(self):
        self.phases.clear()
        self._phase_idx.clear()
        self._agent_idx.clear()
        self.current_tool = ""

    def add_phase(self, name: str, title: str) -> _PhaseNode:
        node = self._phase_idx.get(name)
        if node is not None:
            if node.done:
                node.done = False
                node.state = "running"
                node.title = title
                node.started_at = time.monotonic()
            return node
        node = _PhaseNode(name=name, title=title)
        self.phases.append(node)
        self._phase_idx[name] = node
        return node

    def finish_phase(self, name: str, state: str = "done"):
        node = self._phase_idx.get(name)
        if node:
            node.done = True
            node.state = state
            node.elapsed = time.monotonic() - node.started_at

    def get_agent(self, key) -> Optional[_AgentNode]:
        return self._agent_idx.get(key)

    def add_agent(self, label: str, phase_name: Optional[str], key=None) -> _AgentNode:
        k = label if key is None else key
        if k in self._agent_idx:
            return self._agent_idx[k]
        node = _AgentNode(label=label, key=k)
        self._agent_idx[k] = node
        phase = self._phase_idx.get(phase_name or "") if phase_name else None
        if phase is None and self.phases:
            phase = self.phases[-1]
        if phase:
            phase.agents.append(node)
        return node

    def restart_agent(self, key) -> int:
        node = self._agent_idx.get(key)
        if node is None:
            return 0
        dropped = len(node.findings)
        node.done = False
        node.state = "running"
        node.error = None
        node.elapsed = 0.0
        node.started_at = time.monotonic()
        node.findings = []
        return dropped

    def finish_agent(self, key, error: Optional[str] = None, state: Optional[str] = None):
        node = self._agent_idx.get(key)
        if node:
            node.done = True
            node.elapsed = time.monotonic() - node.started_at
            node.error = error
            node.state = state or ("failed" if error else "done")

    def add_findings(self, agent_key, hypotheses: list) -> None:
        node = self._agent_idx.get(agent_key)
        if node:
            node.findings.extend(hypotheses)

    def stop_running(self, state: str, error: Optional[str] = None) -> None:
        for node in self._agent_idx.values():
            if not node.done:
                self.finish_agent(node.key, error=error if state == "failed" else None, state=state)
        for phase in self.phases:
            if not phase.done:
                self.finish_phase(phase.name, state=state)


# ── WorkflowPanel ─────────────────────────────────────────────────────────────

def _node_key(node):
    if node is None or not isinstance(node.data, dict):
        return None
    return node.data.get("key")


class WorkflowPanel(Static):
    def __init__(self, model: WorkflowModel, **kwargs):
        super().__init__(**kwargs)
        self._model = model
        self._tree: Optional[Tree] = None

    def compose(self) -> ComposeResult:
        tree: Tree = Tree("Workflow", id="wf-tree")
        tree.guide_depth = 2
        tree.root.expand()
        self._tree = tree
        yield tree

    def on_mount(self) -> None:
        self._tree = self.query_one("#wf-tree", Tree)

    def _root_label(self) -> Text:
        tool = self._model.current_tool
        return Text.from_markup(
            "[bold]Workflow[/bold]"
            + (f"  [yellow]⟳ {_short(tool, max(8, self._room(0, True) - 13))}[/yellow]" if tool else "")
        )

    def set_tool(self) -> None:
        if self._tree is not None:
            self._tree.root.set_label(self._root_label())

    def _room(self, depth: int, expandable: bool) -> int:
        width = self._tree.scrollable_content_region.width if self._tree is not None else 0
        if width < 20:
            width = 44
        guide = self._tree.guide_depth if self._tree is not None else 2
        return width - depth * guide - (2 if expandable else 0) - 1

    def _phase_label(self, phase: _PhaseNode) -> Text:
        total = len(phase.agents)
        finished = sum(1 for a in phase.agents if a.done)
        if phase.state == "failed":
            icon = "[red]✗[/red]"
        elif phase.state == "stopped":
            icon = "[yellow]■[/yellow]"
        elif phase.done:
            icon = "[green]✓[/green]"
        elif finished < total:
            icon = "[yellow]●[/yellow]"
        else:
            icon = "[dim]○[/dim]"
        meta = (f"  {finished}/{total}" if total else "") + (f"  {_fmt_elapsed(phase.elapsed)}" if phase.done else "")
        room = max(8, self._room(1, True) - 2 - len(meta))
        return Text.from_markup(f"{icon} [bold]{_short(phase.title, room)}[/bold][dim]{meta}[/dim]")

    def _agent_label(self, agent: _AgentNode) -> Text:
        found = ""
        found_len = 0
        if agent.findings:
            top = max(agent.findings, key=lambda h: getattr(h, "severity", 0) if isinstance(getattr(h, "severity", 0), int) else 0)
            color = _SEV_COLOR.get(_sev_label(getattr(top, "severity", 0)), "cyan")
            found = f"  [{color}]■ {len(agent.findings)}[/{color}]"
            found_len = 4 + len(str(len(agent.findings)))
        room = self._room(2, bool(agent.findings)) - 2 - found_len
        if agent.state == "failed":
            name = _clip(agent.label, max(8, room - 12))
            err = _short(agent.error or "failed", max(6, room - len(name) - 2))
            text = f"[red]✗[/red] {_escape(name)}  [red]{err}[/red]"
        elif agent.state == "stopped":
            text = f"[yellow]■[/yellow] {_short(agent.label, max(8, room - 9))}  [yellow]stopped[/yellow]{found}"
        elif agent.state == "cached":
            text = f"[green]✓[/green] [dim]{_short(agent.label, max(8, room - 8))}  cached[/dim]{found}"
        elif agent.state == "skipped":
            text = f"[dim]– {_short(agent.label, max(8, room - 5))}  n/a[/dim]"
        elif agent.done:
            meta = _fmt_elapsed(agent.elapsed)
            model = _model_short(agent.model, 16)
            if model and room - len(meta) - len(model) - 5 >= min(len(agent.label), 16):
                meta = f"{meta} · {model}"
            text = (f"[green]✓[/green] {_short(agent.label, max(8, room - len(meta) - 2))}  "
                    f"[dim]{_escape(meta)}[/dim]{found}")
        else:
            model = _model_short(agent.model, 16)
            if model and room - len(model) - 2 >= min(len(agent.label), 16):
                text = (f"[yellow]→[/yellow] {_short(agent.label, max(8, room - len(model) - 2))}  "
                        f"[dim]{_escape(model)}[/dim]{found}")
            else:
                text = f"[yellow]→[/yellow] {_short(agent.label, max(8, room))}{found}"
        return Text.from_markup(text)

    def _finding_label(self, hyp) -> Text:
        icon = _SEV_ICON.get(_sev_label(getattr(hyp, "severity", "")), "[white]■[/white]")
        return Text.from_markup(f"{icon} {_short(_hyp_title(hyp), max(8, self._room(3, False) - 2))}")

    def on_resize(self) -> None:
        self.rebuild()

    def rebuild(self):
        if self._tree is None:
            return
        tree = self._tree
        root = tree.root
        expanded: dict = {}
        stack = list(root.children)
        while stack:
            node = stack.pop()
            key = _node_key(node)
            if key is not None and node.allow_expand:
                expanded[key] = node.is_expanded
            stack.extend(node.children)
        cursor_key = _node_key(tree.cursor_node) if tree.cursor_line >= 0 else None

        root.remove_children()
        root.set_label(self._root_label())
        keyed: dict = {}
        for phase in self._model.phases:
            p_key = ("phase", phase.name)
            p_node = root.add(self._phase_label(phase),
                              data={"type": "phase", "name": phase.name, "key": p_key})
            keyed[p_key] = p_node
            for agent in phase.agents:
                a_key = ("agent", agent.key)
                data = {"type": "agent", "agent_key": agent.key, "key": a_key}
                if agent.findings:
                    a_node = p_node.add(self._agent_label(agent), data=data)
                    for i, hyp in enumerate(agent.findings):
                        f_key = ("finding", agent.key, getattr(hyp, "id", None) or i)
                        keyed[f_key] = a_node.add_leaf(
                            self._finding_label(hyp),
                            data={"type": "finding", "hyp": hyp, "key": f_key},
                        )
                    if expanded.get(a_key, True):
                        a_node.expand()
                else:
                    a_node = p_node.add_leaf(self._agent_label(agent), data=data)
                keyed[a_key] = a_node
            if expanded.get(p_key, True):
                p_node.expand()

        target = keyed.get(cursor_key) if cursor_key is not None else None
        if target is not None:
            tree.get_node_at_line(0)
            if target.line >= 0:
                tree.cursor_line = target.line


# ── StatusBar / ScrollIndicator ───────────────────────────────────────────────

class StatusBar(Static):
    op: reactive[str] = reactive("")
    elapsed: reactive[float] = reactive(0.0)
    findings: reactive[int] = reactive(0)
    tool: reactive[str] = reactive("")
    spend: reactive[str] = reactive("")

    def render(self) -> Text:
        if self.op:
            parts = [f"[yellow]●[/yellow] [bold]{_short(self.op, 48)}[/bold]  "
                     f"[dim]{_fmt_elapsed(self.elapsed)}[/dim]"]
        else:
            parts = ["[dim]○ ready[/dim]"]
        if self.tool:
            parts.append(f"[dim]→ {_short(self.tool, 40)}[/dim]")
        if self.findings:
            parts.append(f"[cyan]{self.findings} finding{'' if self.findings == 1 else 's'}[/cyan]")
        if self.spend:
            parts.append(f"[dim]{_escape(self.spend)}[/dim]")
        return Text.from_markup("   ".join(parts))


class ScrollIndicator(Static):
    locked: reactive[bool] = reactive(False)

    def render(self) -> Text:
        if self.locked:
            return Text.from_markup("[yellow]↓ new output — End to follow[/yellow]")
        return Text("")

    def watch_locked(self, locked: bool) -> None:
        self.set_class(locked, "locked")


# ── Main App ─────────────────────────────────────────────────────────────────

class AradCodeApp(App):
    CSS = """
    Screen {
        background: #0d1117;
    }
    Header {
        background: #161b22;
        color: #e6edf3;
        height: 1;
    }
    #main-split {
        height: 1fr;
    }
    #output-container {
        height: 1fr;
        padding: 0 0 0 1;
    }
    #output {
        height: 1fr;
        min-height: 5;
        overflow-x: hidden;
        background: #0d1117;
        color: #c9d1d9;
        scrollbar-size-vertical: 1;
        scrollbar-background: #0d1117;
        scrollbar-background-hover: #0d1117;
        scrollbar-background-active: #0d1117;
        scrollbar-color: #30363d;
        scrollbar-color-hover: #484f58;
        scrollbar-color-active: #6e7681;
    }
    #output:focus {
        background-tint: #e6edf3 0%;
    }
    #wf-panel {
        width: 34%;
        min-width: 32;
        max-width: 50;
        border-left: solid #30363d;
        background: #0d1117;
        padding: 0 0 0 1;
        display: none;
    }
    #wf-panel.visible {
        display: block;
    }
    #wf-tree {
        background: #0d1117;
        overflow-x: hidden;
        color: #c9d1d9;
        scrollbar-size-vertical: 1;
        scrollbar-background: #0d1117;
        scrollbar-color: #30363d;
    }
    #wf-tree:focus {
        background-tint: #e6edf3 0%;
    }
    #wf-tree > .tree--guides {
        color: #30363d;
    }
    #wf-tree > .tree--guides-selected {
        color: #484f58;
    }
    #wf-tree > .tree--cursor {
        background: #1f2937;
        text-style: none;
    }
    #wf-tree:focus > .tree--cursor {
        background: #1f6feb 40%;
        text-style: none;
    }
    #wf-tree > .tree--highlight-line {
        background: #161b22;
    }
    #status {
        height: 1;
        padding: 0 1;
        background: #161b22;
        color: #8b949e;
    }
    #scroll-indicator {
        height: 1;
        padding: 0 1;
        background: #161b22;
        color: #d29922;
        display: none;
    }
    #scroll-indicator.locked {
        display: block;
    }
    #input-area {
        background: #0d1117;
        border-top: solid #30363d;
        padding: 0 1;
        height: auto;
    }
    #input-hint {
        height: 1;
        color: #3fb950;
        display: none;
    }
    #input-hint.active {
        display: block;
    }
    #input {
        background: #0d1117;
        border: none;
        color: #e6edf3;
        padding: 0;
        height: 1;
    }
    #input:focus {
        border: none;
        background-tint: #e6edf3 0%;
    }
    Footer {
        background: #161b22;
        color: #8b949e;
        height: 1;
    }
    """

    BINDINGS = [
        Binding("ctrl+c", "stop_task", "Stop", show=True, priority=True),
        Binding("ctrl+l", "clear_chat", "Clear Chat", show=True),
        Binding("ctrl+w", "toggle_workflow", "Workflow", show=True, priority=True),
        Binding("ctrl+q", "quit_app", "Quit", show=True),
        Binding("escape", "focus_input", "Input", show=False),
        Binding("tab", "focus_workflow", "Workflow Focus", show=False, priority=True),
        Binding("end", "scroll_to_bottom", "↓ Follow", show=False),
    ]

    TITLE = f"Arad Code v{VERSION}"
    SUB_TITLE = "Security Research Terminal"

    def __init__(self, initial_cmd: str = "", **kwargs):
        super().__init__(**kwargs)
        self._initial_cmd = initial_cmd.strip()
        self._wf_model = WorkflowModel()
        self._cmd_task: Optional[asyncio.Task] = None
        self._initial_task: Optional[asyncio.Task] = None
        self._history: list[str] = []
        self._history_idx: int = -1
        self._waiting_to_exit: bool = False
        self._op_start: float = 0.0
        self._clock_task: Optional[asyncio.Task] = None
        self._queue: deque[str] = deque()
        self._query_tasks: set[asyncio.Task] = set()
        self._active_queries: int = 0
        self._shutting_down: bool = False
        self._wf_visible: bool = False
        self._wf_open_key = None
        self._wf_last_click_time: float = 0.0
        self._finding_count: int = 0
        self._session_usage = Usage()
        self._current_model: str = ""
        self._last_repo: str = ""
        self._last_db = None
        self._scroll_locked: bool = False
        self._scan_lines: list[Text] = []

    # ── Layout ────────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-split"):
            with Container(id="output-container"):
                yield RichLog(id="output", highlight=True, markup=True, wrap=True, min_width=20)
            yield WorkflowPanel(self._wf_model, id="wf-panel")
        yield StatusBar(id="status")
        yield ScrollIndicator(id="scroll-indicator")
        with Container(id="input-area"):
            yield Static("", id="input-hint")
            yield Input(placeholder="command  or  > query…", id="input")
        yield Footer()

    def on_mount(self) -> None:
        self._write_scan(_BANNER)
        self._write_scan(_SHORTCUTS)
        self._write_scan("")
        self._start_clock()
        self.watch(self.query_one("#output", RichLog), "scroll_y", self._on_output_scroll, init=False)
        self.query_one("#input", Input).focus()
        if self._initial_cmd:
            self.call_after_refresh(self._dispatch, self._initial_cmd, True)

    def exit(self, result=None, return_code: int = 0, message=None) -> None:
        self._shutting_down = True
        super().exit(result, return_code, message)

    # ── Clock ─────────────────────────────────────────────────────────────────

    def _start_clock(self):
        async def _tick():
            while True:
                await asyncio.sleep(0.5)
                try:
                    bar = self.query_one("#status", StatusBar)
                    if bar.op:
                        bar.elapsed = time.monotonic() - self._op_start
                except NoMatches:
                    pass
        self._clock_task = asyncio.create_task(_tick())

    def _set_op(self, name: str):
        try:
            bar = self.query_one("#status", StatusBar)
            bar.op = name
            bar.elapsed = 0.0
            self._op_start = time.monotonic()
        except NoMatches:
            pass

    def _set_op_label(self, name: str):
        try:
            self.query_one("#status", StatusBar).op = name
        except NoMatches:
            pass

    def _clear_op(self):
        try:
            bar = self.query_one("#status", StatusBar)
            bar.op = ""
            bar.elapsed = 0.0
            bar.tool = ""
        except NoMatches:
            pass

    def _set_tool(self, name: str):
        self._wf_model.current_tool = name
        try:
            self.query_one("#status", StatusBar).tool = name
        except NoMatches:
            pass
        try:
            self.query_one("#wf-panel", WorkflowPanel).set_tool()
        except NoMatches:
            pass

    def _rebuild_panel(self):
        try:
            self.query_one("#wf-panel", WorkflowPanel).rebuild()
        except NoMatches:
            pass

    def _command_running(self) -> bool:
        return self._cmd_task is not None and not self._cmd_task.done()

    # ── Log helpers ──────────────────────────────────────────────────────────

    def _output_width(self) -> Optional[int]:
        try:
            log = self.query_one("#output", RichLog)
        except NoMatches:
            return None
        width = log.scrollable_content_region.width
        if not log.show_vertical_scrollbar:
            width -= log.styles.scrollbar_size_vertical
        return width if width >= 20 else None

    def _to_text(self, markup: str) -> Text:
        rendered = _rtlm(markup, self._output_width())
        try:
            return Text.from_markup(rendered, emoji=False)
        except Exception:
            return Text(markup)

    def _write_text(self, text: Text, scan: bool) -> None:
        try:
            log = self.query_one("#output", RichLog)
        except NoMatches:
            return
        try:
            log.write(text, scroll_end=not self._scroll_locked)
        except Exception:
            text = Text(text.plain)
            log.write(text, scroll_end=not self._scroll_locked)
        if scan:
            self._scan_lines.append(text)

    def _write_scan(self, text: str):
        self._write_text(self._to_text(text), scan=True)

    def _log(self, text: str):
        self._write_scan(text)

    def _log_chat(self, text: str):
        self._write_text(self._to_text(text), scan=False)

    def _add_finding(self, count: int = 1):
        self._finding_count = max(0, self._finding_count + count)
        try:
            self.query_one("#status", StatusBar).findings = self._finding_count
        except NoMatches:
            pass

    def _reset_findings(self):
        self._finding_count = 0
        self._add_finding(0)

    def _finding_line(self, hyp, limit: int = 70) -> str:
        sl = _sev_label(getattr(hyp, "severity", 0))
        icon = _SEV_ICON.get(sl, "[white]■[/white]")
        return (f"{icon} {_sev_badge(getattr(hyp, 'severity', 0))} "
                f"{_status_tag(getattr(hyp, 'status', '?'), 20)} {_short(_hyp_title(hyp), limit)}")

    # ── Scroll ────────────────────────────────────────────────────────────────

    def _set_scroll_locked(self, locked: bool):
        self._scroll_locked = locked
        try:
            self.query_one("#scroll-indicator", ScrollIndicator).locked = locked
        except NoMatches:
            pass

    def _on_output_scroll(self, old: float, new: float) -> None:
        try:
            log = self.query_one("#output", RichLog)
        except NoMatches:
            return
        if new >= log.max_scroll_y:
            if self._scroll_locked:
                self._set_scroll_locked(False)
        elif new < old:
            self._set_scroll_locked(True)

    def _unlock_scroll(self):
        self._set_scroll_locked(False)
        try:
            self.query_one("#output", RichLog).scroll_end(animate=True)
        except NoMatches:
            pass

    # ── Input events ─────────────────────────────────────────────────────────

    @on(Input.Submitted, "#input")
    def _on_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.clear()
        self._history_idx = -1
        if self._waiting_to_exit and not text:
            self.exit(0)
            return
        if not text:
            return
        self._history.append(text)
        self._waiting_to_exit = False
        if text.startswith(">"):
            self._start_query(text[1:].strip())
            return
        parts = _split_cmd(text)
        verb = parts[0].lower() if parts else ""
        if verb in _IMMEDIATE_VERBS or not self._command_running():
            self._dispatch(text)
        else:
            self._queue.append(text)
            self._log(f"[dim]⏳ queued ({len(self._queue)}): {_short(text, 70)}[/dim]")

    @on(Input.Changed, "#input")
    def _on_input_changed(self, event: Input.Changed) -> None:
        hint = self.query_one("#input-hint", Static)
        if event.value.startswith(">"):
            hint.add_class("active")
            hint.update(Text.from_markup(
                "[green]query mode[/green] [dim]— ask about the current or last run "
                "(try: status · findings)[/dim]"))
        else:
            hint.remove_class("active")

    def on_key(self, event) -> None:
        try:
            inp = self.query_one("#input", Input)
        except NoMatches:
            return

        if event.key == "end":
            self._unlock_scroll()
            event.prevent_default()
            return

        if not inp.has_focus:
            return

        if event.key == "up":
            if self._history:
                if self._history_idx < 0:
                    self._history_idx = len(self._history) - 1
                else:
                    self._history_idx = max(0, self._history_idx - 1)
                inp.value = self._history[self._history_idx]
                inp.cursor_position = len(inp.value)
            event.prevent_default()

        elif event.key == "down":
            if self._history_idx >= 0:
                self._history_idx += 1
                if self._history_idx >= len(self._history):
                    self._history_idx = -1
                    inp.value = ""
                else:
                    inp.value = self._history[self._history_idx]
                    inp.cursor_position = len(inp.value)
            event.prevent_default()

    # ── Inline query ─────────────────────────────────────────────────────────

    def _start_query(self, question: str):
        task = asyncio.create_task(self._handle_inline_query(question))
        self._query_tasks.add(task)
        task.add_done_callback(self._on_query_done)

    def _on_query_done(self, task: asyncio.Task) -> None:
        self._query_tasks.discard(task)
        if self._shutting_down or task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            self._log_chat(f"[red]Query error:[/red] {_escape(str(exc) or type(exc).__name__)}")

    async def _handle_inline_query(self, question: str):
        if not question:
            self._log_chat("[dim]> (empty) — type a question after >, e.g.[/dim] [cyan]> status[/cyan]")
            return

        self._log_chat(f"\n[bold green]>[/bold green] {_escape(question)}")

        if question.lower() in ("status", "summary"):
            self._log_chat(self._build_status_text())
            return
        if question.lower() == "findings":
            self._log_chat(self._build_findings_text())
            return

        try:
            cfg, db, mcp, runner = self._make_deps()
        except ValueError as exc:
            self._log_chat(f"[red]Config error:[/red] {_escape(str(exc))}")
            return

        context = self._build_run_context()
        prompt = (
            f"Security researcher ran a pentest scan.\n"
            f"Context:\n{context}\n\n"
            f"Question: {question}\n\n"
            f"Answer in 2-5 sentences, specific and actionable."
        )

        owns_status = not self._command_running()
        self._active_queries += 1
        if owns_status:
            self._set_op("query")
        self._log_chat("[dim cyan]⟳ thinking…[/dim cyan]")

        try:
            buf: list[str] = []
            async for token in runner._llm.complete_stream(
                messages=[{"role": "user", "content": prompt}],
                system="You are a concise security research assistant.",
            ):
                buf.append(token)
            response = "".join(buf)
            self._log_chat(f"[cyan]{_escape(response)}[/cyan]")
            answered_by = getattr(runner._llm, "model", "")
            if answered_by:
                self._log_chat(f"[dim]— {_escape(answered_by)}[/dim]")
            self._log_chat("")
        except Exception as exc:
            self._log_chat(f"[red]Query error:[/red] {_escape(str(exc) or type(exc).__name__)}")
        finally:
            self._active_queries -= 1
            if owns_status and self._active_queries == 0 and not self._command_running():
                self._clear_op()
            await runner.close()

    def _hyps(self) -> list:
        if not self._last_db:
            return []
        return self._last_db.list_hypotheses(self._last_repo)

    def _build_run_context(self) -> str:
        parts = []
        if self._last_repo:
            parts.append(f"Repo: {self._last_repo}")
        parts.append(f"Findings so far: {self._finding_count}")
        if self._last_db:
            try:
                hyps = self._hyps()
                if hyps:
                    parts.append(f"Hypotheses ({len(hyps)}):")
                    for h in hyps[:8]:
                        parts.append(f"  [{_sev_label(h.severity)}] [{h.status}] {h.violated_invariant[:70]}")
            except Exception:
                pass
        return "\n".join(parts) if parts else "No run data yet."

    def _build_status_text(self) -> str:
        lines = ["\n[bold]Status[/bold]"]
        if self._last_repo:
            lines.append(f"  [dim]repo[/dim]      {_escape(self._last_repo)}")
        state = "[yellow]running[/yellow]" if self._command_running() else "[dim]idle[/dim]"
        lines.append(f"  [dim]state[/dim]     {state}")
        for phase in self._wf_model.phases:
            total = len(phase.agents)
            finished = sum(1 for a in phase.agents if a.done)
            lines.append(f"  [dim]phase[/dim]     {_short(phase.title, 40)}  "
                         f"[dim]{finished}/{total} done · {phase.state}[/dim]")
        lines.append(f"  [dim]findings[/dim]  [cyan]{self._finding_count}[/cyan]")
        if self._last_db:
            try:
                hyps = self._hyps()
            except Exception as exc:
                lines.append(f"  [red]{_escape(str(exc))}[/red]")
                hyps = []
            for h in hyps[:15]:
                lines.append("    " + self._finding_line(h, 60))
            if len(hyps) > 15:
                lines.append(f"    [dim]… {len(hyps) - 15} more —[/dim] [cyan]> findings[/cyan]")
        return "\n".join(lines)

    def _build_findings_text(self) -> str:
        if not self._last_db:
            return "[dim]No run data yet.[/dim]"
        lines = ["\n[bold]Findings[/bold]"]
        try:
            hyps = self._hyps()
            if not hyps:
                lines.append("  [dim](none)[/dim]")
            width = len(str(len(hyps)))
            for i, h in enumerate(hyps, 1):
                lines.append(f"  [dim]{str(i).rjust(width)}.[/dim] {self._finding_line(h, 60)}")
        except Exception as exc:
            lines.append(f"  [red]{_escape(str(exc))}[/red]")
        return "\n".join(lines)

    # ── Workflow tree — node detail on Enter ──────────────────────────────────

    @on(Tree.NodeSelected, "#wf-tree")
    def _on_wf_node_selected(self, event: Tree.NodeSelected) -> None:
        data = event.node.data
        if not isinstance(data, dict):
            return
        key = data.get("key")
        now = time.monotonic()
        if key == self._wf_open_key:
            if now - self._wf_last_click_time < 0.4:
                return
            self._wf_open_key = None
            self._wf_last_click_time = now
            self._log_chat("[dim]──[/dim]")
            return
        self._wf_last_click_time = now
        self._wf_open_key = key
        if data.get("type") == "phase":
            phase = self._wf_model._phase_idx.get(data["name"])
            if phase:
                self._log_chat(self._phase_detail(phase))
        elif data.get("type") == "agent":
            agent = self._wf_model.get_agent(data.get("agent_key"))
            if agent:
                self._log_chat(self._agent_detail(agent))
        elif data.get("type") == "finding":
            hyp = data.get("hyp")
            if hyp is not None:
                self._log_chat(self._finding_detail(hyp))

    @staticmethod
    def _state_text(state: str, elapsed: float = 0.0, error: Optional[str] = None) -> str:
        if state == "failed":
            return "[red]✗ failed[/red]" + (f" [red]— {_escape(error)}[/red]" if error else "")
        if state == "stopped":
            return "[yellow]■ stopped[/yellow]"
        if state == "cached":
            return "[green]✓[/green] [dim]cached (resumed)[/dim]"
        if state == "skipped":
            return "[dim]– not applicable to this project[/dim]"
        if state == "done":
            return f"[green]✓ done[/green]  [dim]{_fmt_elapsed(elapsed)}[/dim]"
        return "[yellow]● running…[/yellow]"

    def _phase_detail(self, phase: _PhaseNode) -> str:
        lines = [f"\n[bold magenta]Phase[/bold magenta] [bold]{_short(phase.title)}[/bold]  "
                 f"{self._state_text(phase.state, phase.elapsed)}"]
        lines.append(f"  [dim]agents[/dim]  {len(phase.agents)}")
        for a in phase.agents:
            lbl = _pad(a.label, 34)
            if a.state == "failed":
                lines.append(f"    [red]✗[/red] {lbl} [red]{_short(a.error, 80)}[/red]")
            elif a.state == "stopped":
                lines.append(f"    [yellow]■[/yellow] {lbl} [yellow]stopped[/yellow]")
            elif a.state == "cached":
                lines.append(f"    [green]✓[/green] {lbl} [dim]cached[/dim]")
            elif a.state == "skipped":
                lines.append(f"    [dim]– {lbl} not applicable[/dim]")
            elif a.done:
                lines.append(f"    [green]✓[/green] {lbl} [dim]{_fmt_elapsed(a.elapsed)}[/dim]")
            else:
                lines.append(f"    [yellow]→[/yellow] {lbl} [dim]running[/dim]")
        return "\n".join(lines)

    def _agent_detail(self, agent: _AgentNode) -> str:
        kind = "Agent" if isinstance(agent.key, tuple) else "Skill"
        lines = [f"\n[bold magenta]{kind}[/bold magenta] [bold]{_short(agent.label)}[/bold]  "
                 f"{self._state_text(agent.state, agent.elapsed, agent.error)}"]
        if agent.model:
            lines.append(f"  [dim]model[/dim]     {_escape(agent.model)}")
        if agent.usage and agent.usage.get("calls"):
            u = Usage.from_dict(agent.usage)
            lines.append(f"  [dim]usage[/dim]     {u.calls} call(s) · {format_tokens(u.prompt_tokens)} in "
                         f"({format_tokens(u.cached_tokens)} cached) · "
                         f"{format_tokens(u.completion_tokens)} out · {format_cost(u)}")
        if agent.findings:
            lines.append(f"  [dim]findings[/dim]  {len(agent.findings)}")
            for i, h in enumerate(agent.findings, 1):
                lines.append(f"    [dim]{i}.[/dim] {self._finding_line(h, 60)}")
        else:
            lines.append("  [dim]no findings yet[/dim]")
        return "\n".join(lines)

    def _finding_detail(self, hyp) -> str:
        def g(attr, default=None):
            return getattr(hyp, attr, default)

        sev = g("severity", 0)
        sl = _sev_label(sev)
        color = _SEV_COLOR.get(sl, "white")
        sev_text = f"[bold {color}]{_escape(sl.upper())}[/bold {color}]"
        if isinstance(sev, int):
            sev_text += f" [dim]sev {sev}/10[/dim]"
        conf = g("confidence")
        conf_text = f"  [dim]confidence[/dim] {_escape(str(conf))}/10" if conf is not None else ""
        lines = [
            f"\n[bold magenta]Finding[/bold magenta] [bold]{_short(g('id', '?'))}[/bold]  "
            f"{sev_text}{conf_text}  {_status_tag(g('status', '?'))}",
            f"  [bold]{_short(_hyp_title(hyp), 400)}[/bold]",
        ]
        rows = (
            ("exposure", g("exposure")),
            ("reachability", g("reachability")),
            ("input control", g("input_control")),
            ("cwe", g("cwe")),
            ("actor", g("actor")),
            ("capability", g("capability")),
            ("entry point", g("entry_point")),
            ("impact", g("observable_impact")),
            ("skill", g("skill_source")),
            ("model", g("model")),
            ("verified with", g("verified_with")),
        )
        for label, value in rows:
            if value:
                lines.append(f"  [dim]{label.ljust(14)}[/dim]{_short(value, 300)}")
        steps = list(g("execution_path") or [])
        if steps:
            lines.append("  [dim]execution path[/dim]")
            for i, step in enumerate(steps[:4], 1):
                lines.append(f"    [dim]{i}.[/dim] {_short(step, 200)}")
            if len(steps) > 4:
                lines.append(f"    [dim]… {len(steps) - 4} more step(s)[/dim]")
        evidence = []
        if self._last_db is not None and g("id"):
            try:
                evidence = self._last_db.get_evidence_for_hypothesis(g("id"))
            except Exception:
                evidence = []
        if evidence:
            lines.append("  [dim]evidence[/dim]")
            for ev in evidence[:6]:
                loc = f"{ev.file_path}:{ev.line_start}-{ev.line_end}"
                lines.append(f"    [cyan]{_escape(loc)}[/cyan]  {_short(ev.description, 200)}")
            if len(evidence) > 6:
                lines.append(f"    [dim]… {len(evidence) - 6} more[/dim]")
        else:
            lines.append(f"  [dim]{'evidence'.ljust(14)}none recorded[/dim]")
        return "\n".join(lines)

    # ── Progress events (workflow scripts) ────────────────────────────────────

    @staticmethod
    def _rec_key(rec) -> tuple:
        return ("wf", getattr(rec, "uid", None) or id(rec))

    def _progress(self, event: str, data):
        from .workflow import PhaseInfo, AgentRecord

        if event == "phase_start":
            p: PhaseInfo = data
            self._log(f"\n[bold magenta]{_escape(f'[Phase: {p.title}]')}[/bold magenta]")
            self._set_op(p.title)
            self._wf_model.add_phase(p.name, p.title)
        elif event == "phase_end":
            p: PhaseInfo = data
            self._log(f"[dim]Phase {_short(p.title, 60)} done in {_fmt_elapsed(p.elapsed())}[/dim]")
            self._wf_model.finish_phase(p.name)
        elif event == "agent_start":
            rec: AgentRecord = data
            self._log(f"  [yellow]→[/yellow] {_short(rec.label, 80)}")
            node = self._wf_model.add_agent(rec.label, rec.phase, key=self._rec_key(rec))
            node.model = self._current_model
        elif event == "agent_end":
            rec: AgentRecord = data["record"]
            elapsed = (rec.ended_at or time.monotonic()) - rec.started_at
            self._log(f"  [green]✓[/green] {_short(rec.label, 80)} [dim]{_fmt_elapsed(elapsed)}[/dim]")
            self._wf_model.finish_agent(self._rec_key(rec))
        elif event == "agent_error":
            rec: AgentRecord = data["record"]
            error = str(data.get("error", ""))
            self._log(f"  [red]✗[/red] {_short(rec.label, 60)}: [red]{_short(error, 120)}[/red]")
            self._wf_model.finish_agent(self._rec_key(rec), error=error or "error")
        elif event == "votes_counted":
            self._log(
                f"  [cyan]votes[/cyan] {_short(data.get('finding', '?'), 40)}: "
                f"[green]{data.get('true', 0)} real[/green] / [red]{data.get('false', 0)} refuted[/red] "
                f"[dim](round {data.get('round', 0) + 1})[/dim]"
            )
        elif event == "inconclusive_vote":
            self._log(f"  [yellow]⟳[/yellow] {_short(data.get('finding', '?'), 40)} inconclusive — "
                      f"re-examining [dim](round {data.get('round', 0) + 2})[/dim]")
        elif event == "pipeline_error":
            self._log(f"  [red]✗ pipeline[/red] {_short(data.get('item', '?'), 50)}: "
                      f"[red]{_short(data.get('error', ''), 120)}[/red]")

        self._rebuild_panel()

    def _on_tool_event(self, event: str, data: dict):
        if event == "tool_call":
            name = data.get("name", "")
            short = name.replace("mcp__codebase-memory-mcp__", "").replace("mcp__sqz__", "sqz.")
            self._set_tool(short)

    # ── Command dispatch ──────────────────────────────────────────────────────

    def _dispatch(self, cmd: str, initial: bool = False):
        parts = _split_cmd(cmd)
        if not parts:
            return
        verb = parts[0].lower()

        if verb in ("exit", "quit"):
            self.exit(0)
            return
        if verb in ("clear", "cls"):
            self.action_clear_chat()
            return
        if verb == "help":
            self._log(_HELP)
            return
        if verb == "headless":
            self.action_switch_headless()
            return

        self._log(f"\n[bold cyan]❯[/bold cyan] [bold]{_short(cmd, 120)}[/bold]")
        task = asyncio.create_task(self._run_command(cmd, parts))
        self._cmd_task = task
        if initial:
            self._initial_task = task
        task.add_done_callback(self._on_command_done)

    def _on_command_done(self, task: asyncio.Task) -> None:
        if self._shutting_down:
            return
        if task.cancelled():
            outcome = "stopped"
        elif task.exception() is not None:
            outcome = "error"
            exc = task.exception()
            self._log(f"\n[red]Error:[/red] {_escape(str(exc) or type(exc).__name__)}")
        else:
            outcome = task.result() or "done"
        self._clear_op()
        if self._active_queries:
            self._set_op("query")
        self._set_tool("")
        self._rebuild_panel()
        if task is self._initial_task:
            self._initial_task = None
            message = {
                "done": "[bold green]✓ Run complete.[/bold green]",
                "stopped": "[bold yellow]■ Run stopped.[/bold yellow]",
                "error": "[bold red]✗ Run failed.[/bold red]",
            }.get(outcome, "[bold green]✓ Run complete.[/bold green]")
            if self._queue:
                self._log(f"\n{message}")
            else:
                self._waiting_to_exit = True
                self._log(f"\n{message}  [dim]Press Enter (or type a command) to close.[/dim]")
        if self._queue:
            queued = self._queue.popleft()
            self._log(f"\n[dim]Running queued: {_short(queued, 70)}[/dim]")
            self._dispatch(queued)

    async def _run_command(self, cmd: str, parts: list[str]) -> str:
        verb = parts[0].lower()
        self._set_op(verb)
        try:
            if verb == "run":
                ok = await self._cmd_run(parts[1:])
            elif verb == "skill":
                ok = await self._cmd_skill(parts[1:])
            elif verb == "workflow":
                ok = await self._cmd_workflow(parts[1:])
            elif verb == "deep-research":
                ok = await self._cmd_deep_research(parts[1:])
            elif verb in _CLI_VERBS:
                ok = await self._cmd_cli(parts)
            else:
                self._log(f"[red]Unknown command:[/red] {_short(verb, 40)}  (type [cyan]help[/cyan])")
                ok = False
        except asyncio.CancelledError:
            self._mark_interrupted("stopped")
            hint = "  [dim]resume with[/dim] [cyan]run <repo> --resume[/cyan]" if verb == "run" else ""
            self._log(f"\n[yellow]■ Stopped.[/yellow]{hint}")
            return "stopped"
        except Exception as exc:
            message = str(exc) or type(exc).__name__
            self._mark_interrupted("failed", message)
            self._log(f"\n[red]Error:[/red] {_escape(message)}")
            return "error"
        return "error" if ok is False else "done"

    def _mark_interrupted(self, state: str, error: Optional[str] = None) -> None:
        self._wf_model.stop_running(state, error)
        self._set_tool("")
        self._rebuild_panel()

    def _resolve_repo(self, repo_path: str) -> Optional[str]:
        path = Path(repo_path).expanduser()
        if not path.is_dir():
            reason = "is not a directory" if path.exists() else "not found"
            self._log(f"[red]Repository {reason}:[/red] {_escape(repo_path)}")
            return None
        return str(path.resolve())

    async def _show_workflow(self) -> None:
        if self._wf_visible:
            return
        self._toggle_workflow()
        refreshed = asyncio.get_running_loop().create_future()
        self.call_after_refresh(lambda: refreshed.done() or refreshed.set_result(None))
        try:
            await asyncio.wait_for(refreshed, 0.5)
        except asyncio.TimeoutError:
            pass

    def _name_width(self) -> int:
        return max(16, min(38, (self._output_width() or 80) - 26))

    # ── Deps ──────────────────────────────────────────────────────────────────

    def _make_deps(self, api_key: str = "", model: str = "", api_base: str = "", config: str = ""):
        import os
        from .config import load_config
        from .db import EvidenceStore
        from .memory_mcp import CodebaseMemoryClient
        from .runner import SkillRunner
        from .mcp_manager import MCPManager

        _api_key = api_key or os.environ.get("PENTEST_API_KEY", "")
        _model = model or os.environ.get("PENTEST_MODEL", "")
        _api_base = api_base or os.environ.get("PENTEST_API_BASE", "")

        cfg = load_config(api_base=_api_base or None, api_key=_api_key,
                         model=_model or None, config_file=config or None)
        db = EvidenceStore(cfg.resolved_db())
        mcp = CodebaseMemoryClient(cfg)
        mcp_manager = MCPManager.from_claude_config(mcp_allow=cfg.mcp_allow)
        runner = SkillRunner(cfg, db, mcp, mcp_manager=mcp_manager)
        runner.set_event_handler(self._on_tool_event)
        runner.meter.on_record(self._on_usage)
        self._current_model = cfg.model
        return cfg, db, mcp, runner

    def _on_usage(self, scope: str, model: str, usage: Usage) -> None:
        self._session_usage.add(usage)
        total = self._session_usage
        try:
            self.query_one("#status", StatusBar).spend = (
                f"{format_cost(total)} · {format_tokens(total.total_tokens)} tok")
        except NoMatches:
            pass

    # ── run ───────────────────────────────────────────────────────────────────

    async def _cmd_run(self, args: list[str]):
        usage = "[red]Usage:[/red] run <repo_path> [--phase N] [--resume] [--restart] [--all-skills]"
        positional: list[str] = []
        phase: Optional[str] = None
        resume = False
        restart = False
        all_skills = False
        i = 0
        while i < len(args):
            a = args[i]
            if a == "--phase":
                if i + 1 >= len(args):
                    self._log(usage)
                    return False
                phase = args[i + 1]
                i += 2
                continue
            if a.startswith("--phase="):
                phase = a.split("=", 1)[1]
            elif a == "--resume":
                resume = True
            elif a == "--restart":
                restart = True
            elif a == "--all-skills":
                all_skills = True
            elif a.startswith("-") and len(a) > 1:
                self._log(f"[red]Unknown option:[/red] {_escape(a)}")
                self._log(usage)
                return False
            else:
                positional.append(a)
            i += 1

        if len(positional) != 1:
            if len(positional) > 1:
                self._log(f"[red]Unexpected argument:[/red] {_escape(positional[1])}")
            self._log(usage)
            return False
        if phase is not None:
            phase = phase.strip()
            if not phase:
                self._log(usage)
                return False
            if phase.isdigit():
                phase = f"p{phase}"

        repo = self._resolve_repo(positional[0])
        if repo is None:
            return False
        await self._show_workflow()

        try:
            cfg, db, mcp, runner = self._make_deps()
        except ValueError as exc:
            self._log(f"[red]Config error:[/red] {_escape(str(exc))}")
            return False

        self._last_repo = repo
        self._last_db = db
        self._reset_findings()
        started = time.monotonic()

        self._log(f"[bold]Running scan on[/bold] {_escape(repo)}")
        if phase:
            self._log(f"  [dim]phase:[/dim] {_escape(phase)}")

        if restart:
            from .cache import clear_run_state
            clear_run_state(repo)
            self._log("[dim]Run state cleared.[/dim]")

        self._wf_model.reset()
        self._wf_model.add_phase("run", f"Skill Scan · {phase}" if phase else "Skill Scan")

        if resume:
            from .cache import completed_skills, started_skills
            commit = runner._get_commit(repo)
            done = {s for s in completed_skills(repo, commit) if "#" not in s}
            started_names = started_skills(repo, commit)
            if started_names:
                partly = len(started_names - done)
                more = f", {partly} partly done" if partly else ""
                self._log(f"[dim]Resuming — {len(done)} skill(s) already done{more}[/dim]")
                try:
                    existing = [h for h in db.list_hypotheses(repo) if h.skill_source in started_names]
                    if existing:
                        by_skill: dict[str, list] = defaultdict(list)
                        for h in existing:
                            by_skill[h.skill_source].append(h)
                        for skill_nm, hyps in by_skill.items():
                            self._wf_model.add_agent(skill_nm, "run")
                            self._wf_model.finish_agent(skill_nm, state="cached")
                            self._wf_model.add_findings(skill_nm, hyps)
                        self._add_finding(len(existing))
                        self._log(f"[dim]  {len(existing)} finding(s) from previous run loaded[/dim]")
                except Exception:
                    pass
        self._rebuild_panel()
        interrupted: list[str] = []
        name_w = self._name_width()

        def _on_progress(name, status, result):
            if status == "started":
                node = self._wf_model.get_agent(name)
                if node is not None and node.done:
                    dropped = self._wf_model.restart_agent(name)
                    if dropped:
                        self._add_finding(-dropped)
                else:
                    node = self._wf_model.add_agent(name, "run")
                model = result.get("model", "") if isinstance(result, dict) else ""
                if node is not None and model:
                    node.model = model
                self._set_op_label(f"run · {name}" + (f" · {_model_short(model)}" if model else ""))
            elif status == "done":
                hyps = list(getattr(result, "hypotheses", None) or []) if result else []
                h_count = len(hyps)
                self._wf_model.add_agent(name, "run")
                self._wf_model.finish_agent(name)
                if hyps:
                    self._wf_model.add_findings(name, hyps)
                node = self._wf_model.get_agent(name)
                if node is not None:
                    node.model = getattr(result, "model", "") or node.model
                    node.usage = getattr(result, "usage", None) or {}
                took = _fmt_elapsed(node.elapsed if node else 0.0)
                if h_count:
                    suffix = f"[cyan]{h_count} finding{'' if h_count == 1 else 's'}[/cyan]"
                else:
                    suffix = "[dim]no findings[/dim]"
                spent = ""
                if node is not None and node.model:
                    spent = " · ".join(x for x in (node.model, _usage_text(node.usage)) if x)
                    spent = f"  [dim]{_escape(spent)}[/dim]"
                self._log(f"  [green]✓[/green] {_pad(name, name_w)} {suffix}  [dim]{took}[/dim]{spent}")
                if h_count:
                    self._add_finding(h_count)
            elif status == "skipped":
                self._wf_model.add_agent(name, "run")
                self._wf_model.finish_agent(name, state="cached")
                self._log(f"  [dim]✓ {_pad(name, name_w)} cached[/dim]")
            elif status == "not_applicable":
                self._wf_model.add_agent(name, "run")
                self._wf_model.finish_agent(name, state="skipped")
                self._log(f"  [dim]– {_pad(name, name_w)} skipped: {_escape(str(result or ''))}[/dim]")
            elif status == "interrupted":
                self._wf_model.add_agent(name, "run")
                self._wf_model.finish_agent(name, state="stopped")
                interrupted.append(name)
            self._rebuild_panel()

        try:
            try:
                extra = {"skill_gating": False} if all_skills else {}
                if phase:
                    await runner.run_phase(phase, repo, verbose=False, resume=resume,
                                           on_progress=_on_progress, **extra)
                else:
                    await runner.run_all(repo, verbose=False, resume=resume,
                                         on_progress=_on_progress, **extra)
            except asyncio.CancelledError:
                for name in interrupted:
                    self._log(f"  [yellow]■[/yellow] {_pad(name, name_w)} [yellow]stopped[/yellow]")
                raise
            except Exception as exc:
                for name in interrupted:
                    self._wf_model.finish_agent(name, error=str(exc) or type(exc).__name__)
                    self._log(f"  [red]✗[/red] {_pad(name, name_w)} [red]failed[/red]")
                raise
            self._wf_model.finish_phase("run")
            self._rebuild_panel()
            spent = ""
            meter = getattr(runner, "meter", None)
            if meter is not None and meter.total.calls:
                spent = (f" · {format_tokens(meter.total.total_tokens)} tok · "
                         f"{format_cost(meter.total)}")
            self._log(f"\n[green]✓ Scan complete[/green]  [dim]{self._finding_count} finding(s) · "
                      f"{_fmt_elapsed(time.monotonic() - started)}{_escape(spent)}[/dim]")
        finally:
            await runner.close()
            self._set_tool("")

    # ── skill ─────────────────────────────────────────────────────────────────

    async def _cmd_skill(self, args: list[str]):
        if len(args) < 2:
            self._log("[red]Usage:[/red] skill <name> <repo_path> \\[context…]")
            return False
        skill_name, repo_path = args[0], args[1]
        extra = " ".join(args[2:])

        repo = self._resolve_repo(repo_path)
        if repo is None:
            return False
        await self._show_workflow()

        try:
            cfg, db, mcp, runner = self._make_deps()
        except ValueError as exc:
            self._log(f"[red]Config error:[/red] {_escape(str(exc))}")
            return False

        self._last_repo = repo
        self._last_db = db
        self._reset_findings()
        self._log(f"[bold]Running skill[/bold] [cyan]{_escape(skill_name)}[/cyan] on {_escape(repo)}")
        self._wf_model.reset()
        self._wf_model.add_phase("skill", skill_name)
        node = self._wf_model.add_agent(skill_name, "skill")
        node.model = getattr(getattr(runner, "_llm", None), "model", "") or ""
        self._rebuild_panel()

        try:
            try:
                result = await runner.run_skill(skill_name, repo, extra)
            except BudgetExceeded as exc:
                saved = getattr(exc, "saved_batches", 0)
                if saved:
                    partial = exc.partial
                    self._wf_model.finish_agent(skill_name, state="stopped")
                    if partial.hypotheses:
                        self._wf_model.add_findings(skill_name, partial.hypotheses)
                        self._add_finding(len(partial.hypotheses))
                    self._log(f"[yellow]{saved} finished batch(es) of this skill were saved "
                              f"({len(partial.hypotheses)} finding(s)); the rest did not run.[/yellow]")
                    try:
                        runner.reconcile(repo)
                    except Exception:
                        pass
                raise
            h_count = len(result.hypotheses)
            conf = sum(1 for h in result.hypotheses if h.status in ("evidence_supported", "reproduced"))
            node.model = getattr(result, "model", "") or node.model
            node.usage = getattr(result, "usage", None) or {}
            self._wf_model.finish_agent(skill_name)
            if result.hypotheses:
                self._wf_model.add_findings(skill_name, result.hypotheses)
            self._wf_model.finish_phase("skill")
            self._rebuild_panel()
            noun = "hypothesis" if h_count == 1 else "hypotheses"
            spent = " · ".join(x for x in (node.model, _usage_text(node.usage)) if x)
            self._log(f"\n[green]✓ Done.[/green] {h_count} {noun} [dim]({conf} confirmed)"
                      f"{'  ' + _escape(spent) if spent else ''}[/dim]")
            self._add_finding(h_count)
            for h in result.hypotheses[:15]:
                self._log("  " + self._finding_line(h, 70))
            if h_count > 15:
                self._log(f"  [dim]… {h_count - 15} more —[/dim] [cyan]> findings[/cyan]")
            if result.open_questions:
                self._log(f"\n[dim]{len(result.open_questions)} open question(s)[/dim]")
            try:
                runner.reconcile(repo)
            except Exception as exc:
                self._log(f"[yellow]Reconcile failed:[/yellow] {_escape(str(exc))}")
        finally:
            await runner.close()
            self._set_tool("")

    # ── workflow ──────────────────────────────────────────────────────────────

    async def _cmd_workflow(self, args: list[str]):
        usage = "[red]Usage:[/red] workflow <script.py> [--repo <path>]"
        script_path = ""
        repo_path = ""
        i = 0
        while i < len(args):
            if args[i] == "--repo":
                if i + 1 >= len(args):
                    self._log(usage)
                    return False
                repo_path = args[i + 1]
                i += 2
                continue
            if not script_path:
                script_path = args[i]
            i += 1
        if not script_path:
            self._log(usage)
            return False

        if not Path(script_path).expanduser().is_file():
            self._log(f"[red]Script not found:[/red] {_escape(script_path)}")
            return False
        script = str(Path(script_path).expanduser().resolve())

        repo = ""
        if repo_path:
            repo = self._resolve_repo(repo_path)
            if repo is None:
                return False
        await self._show_workflow()

        try:
            cfg, db, mcp, runner = self._make_deps()
        except ValueError as exc:
            self._log(f"[red]Config error:[/red] {_escape(str(exc))}")
            return False

        self._last_repo = repo
        self._last_db = db
        self._log(f"[bold]Running workflow[/bold] {_escape(script_path)}"
                  + (f" [dim]on[/dim] {_escape(repo)}" if repo else ""))
        self._wf_model.reset()
        self._rebuild_panel()

        try:
            from .workflow import run_workflow_script
            result = await run_workflow_script(
                script,
                runner=runner,
                repo_path=repo,
                on_event=self._progress,
            )
            findings = result.get("findings", []) if isinstance(result, dict) else []
            if isinstance(findings, list) and findings:
                confirmed = [f for f in findings if isinstance(f, dict) and f.get("confirmed")]
                self._log(
                    f"\n[green]✓ Workflow complete.[/green] "
                    f"{len(confirmed)} confirmed / {len(findings)} total findings"
                )
            else:
                self._log("\n[green]✓ Workflow complete.[/green]")
        finally:
            await runner.close()
            self._set_tool("")

    # ── deep-research ─────────────────────────────────────────────────────────

    async def _cmd_deep_research(self, args: list[str]):
        usage = "[red]Usage:[/red] deep-research <question> [--repo <path>]"
        repo_path = ""
        qparts = []
        i = 0
        while i < len(args):
            if args[i] == "--repo":
                if i + 1 >= len(args):
                    self._log(usage)
                    return False
                repo_path = args[i + 1]
                i += 2
            else:
                qparts.append(args[i])
                i += 1

        question = " ".join(qparts)
        if not question.strip():
            self._log(usage)
            return False

        repo = ""
        if repo_path:
            repo = self._resolve_repo(repo_path)
            if repo is None:
                return False

        try:
            cfg, db, mcp, runner = self._make_deps()
        except ValueError as exc:
            self._log(f"[red]Config error:[/red] {_escape(str(exc))}")
            return False

        self._log(f"[bold]Deep Research:[/bold] {_escape(question)}")

        try:
            from .deep_research import deep_research, format_research_output
            result = await deep_research(question, runner=runner, repo_path=repo)
            self._log(format_research_output(result))
        finally:
            await runner.close()

    # ── cli passthrough ───────────────────────────────────────────────────────

    @staticmethod
    def _cli_is_interactive(parts: list[str]) -> bool:
        verb = parts[0].lower()
        if "--help" in parts:
            return False
        if verb in ("triage", "config-init"):
            return True
        if verb == "query":
            positional = []
            rest = parts[1:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a.startswith("-"):
                    i += 2 if a in ("--api-key", "--config") else 1
                    continue
                positional.append(a)
                i += 1
            return len(positional) < 2
        return False

    async def _cmd_cli(self, parts: list[str]):
        if self._cli_is_interactive(parts):
            self._log(
                f"[yellow]{_escape(parts[0])} is interactive and can't run inside the TUI.[/yellow]\n"
                f"  Run it from headless mode:  [cyan]python pentest.py --headless "
                f"{_escape(shlex.join(parts))}[/cyan]\n"
                f"  [dim](type[/dim] [cyan]headless[/cyan] [dim]to leave the TUI)[/dim]"
            )
            return False
        script = Path(__file__).resolve().parent.parent / "pentest.py"
        cmd = [sys.executable, str(script), "--headless"] + parts
        env = dict(os.environ)
        env["FORCE_COLOR"] = "1"
        env["COLUMNS"] = str(self._output_width() or 100)
        env.pop("NO_COLOR", None)
        self._log(f"[dim]→ pentest {_escape(shlex.join(parts))}[/dim]")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=os.getcwd(),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
            limit=1 << 20,
        )
        try:
            async for line in proc.stdout:
                text = line.decode("utf-8", errors="replace").rstrip().split("\r")[-1]
                if text.strip():
                    rendered = Text.from_ansi(text)
                    if _has_rtl(rendered.plain):
                        rendered = Text(_rtl_render(rendered.plain, self._output_width()))
                    self._write_text(rendered, scan=True)
            await proc.wait()
        except BaseException:
            if proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                try:
                    await proc.wait()
                except Exception:
                    pass
            raise
        if proc.returncode != 0:
            self._log(f"[red]✗ pentest {_escape(parts[0])} exited with code {proc.returncode}[/red]")
            return False
        return True

    # ── Actions ───────────────────────────────────────────────────────────────

    def _on_main_screen(self) -> bool:
        return self.screen is self.default_screen

    def _has_selection(self) -> bool:
        if getattr(self.focused, "selected_text", ""):
            return True
        try:
            return bool(self.screen.get_selected_text())
        except Exception:
            return False

    def action_stop_task(self) -> None:
        if not self._on_main_screen() or (
            not self._command_running() and not self._query_tasks and self._has_selection()
        ):
            raise SkipAction()
        if self._command_running():
            self._cmd_task.cancel()
            self._log("[dim yellow]Stopping…[/dim yellow]")
        elif self._query_tasks:
            for task in list(self._query_tasks):
                task.cancel()
            self._log_chat("[yellow]Query cancelled.[/yellow]")
        else:
            self._log("[dim]No task running.[/dim]")

    def action_clear_chat(self) -> None:
        try:
            log = self.query_one("#output", RichLog)
        except NoMatches:
            return
        log.clear()
        for line in self._scan_lines:
            log.write(line, scroll_end=False)
        log.write(self._to_text("[dim yellow]── chat cleared ──[/dim yellow]"), scroll_end=False)
        self._set_scroll_locked(False)
        log.scroll_end(animate=False)

    def action_focus_input(self) -> None:
        try:
            self.query_one("#input", Input).focus()
        except NoMatches:
            pass

    def action_toggle_workflow(self) -> None:
        if not self._on_main_screen():
            raise SkipAction()
        self._toggle_workflow()

    def _toggle_workflow(self) -> None:
        try:
            panel = self.query_one("#wf-panel", WorkflowPanel)
            tree = self.query_one("#wf-tree", Tree)
        except NoMatches:
            return
        self._wf_visible = not self._wf_visible
        if self._wf_visible:
            panel.add_class("visible")
        else:
            panel.remove_class("visible")
            if tree.has_focus:
                self.action_focus_input()

    def action_focus_workflow(self) -> None:
        if not self._on_main_screen():
            raise SkipAction()
        try:
            tree = self.query_one("#wf-tree", Tree)
        except NoMatches:
            return
        if tree.has_focus:
            self.action_focus_input()
            return
        if not self._wf_visible:
            self._toggle_workflow()
        tree.focus()
        if tree.cursor_line < 0:
            tree.cursor_line = 0

    def action_scroll_to_bottom(self) -> None:
        self._unlock_scroll()

    def action_quit_app(self) -> None:
        self.exit(0)

    def action_switch_headless(self) -> None:
        self.exit(result=("headless", self._initial_cmd))

    async def on_unmount(self) -> None:
        import contextlib
        self._shutting_down = True
        if self._clock_task:
            self._clock_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._clock_task
        pending = [t for t in (self._cmd_task, *self._query_tasks) if t is not None and not t.done()]
        for task in pending:
            task.cancel()
        for task in pending:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


def launch_tui(initial_cmd: str = "") -> Optional[tuple]:
    app = AradCodeApp(initial_cmd=initial_cmd)
    result = app.run()
    return result
