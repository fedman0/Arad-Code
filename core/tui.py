from __future__ import annotations
import asyncio
import shlex
import time
from pathlib import Path
from typing import Optional

from rich.markup import escape as _escape
from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import Footer, Header, Input, RichLog, Static, Tree

from .rtl import rtl_markup as _rtlm

VERSION = "2.2.0"

_SEV_ICON = {
    "critical": "[bright_red]■[/bright_red]",
    "high": "[red]■[/red]",
    "medium": "[yellow]■[/yellow]",
    "low": "[green]■[/green]",
}
_SEV_COLOR = {"critical": "bright_red", "high": "red", "medium": "yellow", "low": "green"}


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

_BANNER = (
    f"[bold cyan]Arad Code[/bold cyan] [dim]v{VERSION}[/dim]\n"
    "[dim]command or [bold cyan]>[/bold cyan] query  ·  Ctrl+W workflow  ·  "
    "Ctrl+L clear chat  ·  Ctrl+Q quit[/dim]"
)

_SHORTCUTS = (
    "[dim]run <repo>[/dim] · [dim]workflow <script.py>[/dim] · "
    "[dim]deep-research <q>[/dim] · [dim]skill <name> <repo>[/dim] · "
    "[dim][bold]>[/bold] question[/dim] · [dim]headless[/dim] · [dim]help[/dim]"
)

_HELP = """
[bold]Commands[/bold]
  run <repo> [--phase N] [--resume] [--restart]
  skill <name> <repo>
  workflow <script.py> [--repo <path>]
  deep-research <question> [--repo <path>]
  report <repo>  ·  peers  ·  triage  ·  coverage  ·  sarif
  headless       exit TUI and relaunch in headless CLI mode
  help  ·  clear  ·  exit

[bold]Inline query (any time, even mid-run)[/bold]
  > <anything>        Ask about the current or last run
  > status            Summary: findings so far, phases done
  > findings          List all hypotheses with severity

[bold]Workflow panel  (Ctrl+W toggle · Tab focus)[/bold]
  ↑↓   Navigate phases / agents
  Enter  Expand / collapse

[bold]Keys[/bold]
  ↑↓       Command history
  Ctrl+C   Stop running task
  Ctrl+L   Clear LLM query responses (scan output preserved)
  Ctrl+W   Toggle workflow panel
  Ctrl+Q   Quit
  Escape   Focus input

[dim]Env: PENTEST_API_KEY · PENTEST_MODEL · PENTEST_API_BASE[/dim]
"""


# ── Workflow data model ───────────────────────────────────────────────────────

class _PhaseNode:
    def __init__(self, name: str, title: str):
        self.name = name
        self.title = title
        self.agents: list[_AgentNode] = []
        self.done = False
        self.elapsed = 0.0
        self.started_at = time.monotonic()


class _AgentNode:
    def __init__(self, label: str):
        self.label = label
        self.done = False
        self.elapsed = 0.0
        self.error: Optional[str] = None
        self.started_at = time.monotonic()
        self.findings: list = []


class WorkflowModel:
    def __init__(self):
        self.phases: list[_PhaseNode] = []
        self._phase_idx: dict[str, _PhaseNode] = {}
        self._agent_idx: dict[str, _AgentNode] = {}
        self.current_tool: str = ""

    def reset(self):
        self.phases.clear()
        self._phase_idx.clear()
        self._agent_idx.clear()
        self.current_tool = ""

    def add_phase(self, name: str, title: str) -> _PhaseNode:
        if name in self._phase_idx:
            return self._phase_idx[name]
        node = _PhaseNode(name=name, title=title)
        self.phases.append(node)
        self._phase_idx[name] = node
        return node

    def finish_phase(self, name: str):
        node = self._phase_idx.get(name)
        if node:
            node.done = True
            node.elapsed = time.monotonic() - node.started_at

    def add_agent(self, label: str, phase_name: Optional[str]) -> _AgentNode:
        if label in self._agent_idx:
            return self._agent_idx[label]
        node = _AgentNode(label=label)
        self._agent_idx[label] = node
        phase = self._phase_idx.get(phase_name or "") if phase_name else None
        if phase is None and self.phases:
            phase = self.phases[-1]
        if phase:
            phase.agents.append(node)
        return node

    def finish_agent(self, label: str, error: Optional[str] = None):
        node = self._agent_idx.get(label)
        if node:
            node.done = True
            node.elapsed = time.monotonic() - node.started_at
            node.error = error

    def add_findings(self, agent_label: str, hypotheses: list) -> None:
        node = self._agent_idx.get(agent_label)
        if node:
            node.findings.extend(hypotheses)


# ── WorkflowPanel ─────────────────────────────────────────────────────────────

class WorkflowPanel(Static):
    def __init__(self, model: WorkflowModel, **kwargs):
        super().__init__(**kwargs)
        self._model = model
        self._tree: Optional[Tree] = None

    def compose(self) -> ComposeResult:
        tree: Tree = Tree("Workflow", id="wf-tree")
        tree.root.expand()
        self._tree = tree
        yield tree

    def on_mount(self) -> None:
        self._tree = self.query_one("#wf-tree", Tree)

    def rebuild(self):
        if self._tree is None:
            return
        root = self._tree.root
        root.remove_children()
        root.label = Text.from_markup(
            "[dim]Workflow[/dim]"
            + (f"  [yellow]⟳ {self._model.current_tool}[/yellow]" if self._model.current_tool else "")
        )
        for phase in self._model.phases:
            elapsed_text = f"  [dim]{phase.elapsed:.1f}s[/dim]" if phase.done else ""
            running = sum(1 for a in phase.agents if not a.done)
            if phase.done:
                icon = "[green]✓[/green]"
            elif running:
                icon = "[yellow]●[/yellow]"
            else:
                icon = "[dim]○[/dim]"
            p_node = root.add(
                Text.from_markup(f"{icon} {phase.title}{elapsed_text}"),
                data={"type": "phase", "name": phase.name},
            )
            for agent in phase.agents:
                if agent.error:
                    a_text = f"[red]✗[/red] {agent.label}  [red dim]{agent.error[:45]}[/red dim]"
                elif agent.done:
                    f_count = f"  [cyan]{len(agent.findings)}f[/cyan]" if agent.findings else ""
                    a_text = f"[green]✓[/green] {agent.label}  [dim]{agent.elapsed:.1f}s[/dim]{f_count}"
                else:
                    a_text = f"[yellow]→[/yellow] {agent.label}"
                if agent.findings:
                    a_node = p_node.add(Text.from_markup(a_text), data={"type": "agent", "label": agent.label})
                    for hyp in agent.findings:
                        icon = _SEV_ICON.get(_sev_label(getattr(hyp, "severity", "")), "[white]■[/white]")
                        title = getattr(hyp, "violated_invariant", str(hyp))[:50]
                        a_node.add_leaf(
                            Text.from_markup(f"{icon} {title}"),
                            data={"type": "finding", "hyp": hyp},
                        )
                    a_node.expand()
                else:
                    p_node.add_leaf(Text.from_markup(a_text), data={"type": "agent", "label": agent.label})
            p_node.expand()


# ── StatusBar / ScrollIndicator ───────────────────────────────────────────────

class StatusBar(Static):
    op: reactive[str] = reactive("")
    elapsed: reactive[float] = reactive(0.0)
    findings: reactive[int] = reactive(0)
    tool: reactive[str] = reactive("")

    def render(self) -> str:
        parts = []
        if self.op:
            parts.append(f"[yellow]●[/yellow] {self.op}  [dim]{self.elapsed:.1f}s[/dim]")
        else:
            parts.append("[dim]ready[/dim]")
        if self.tool:
            parts.append(f"[dim]→ {self.tool}[/dim]")
        if self.findings:
            parts.append(f"[cyan]{self.findings} finding(s)[/cyan]")
        return "  ".join(parts)


class ScrollIndicator(Static):
    locked: reactive[bool] = reactive(False)

    def render(self) -> str:
        if self.locked:
            return "[dim yellow]↓ new output — End to follow[/dim yellow]"
        return ""


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
        padding: 0 1;
    }
    #output {
        height: 1fr;
        min-height: 5;
    }
    #wf-panel {
        width: 40;
        border-left: solid #30363d;
        background: #0d1117;
        padding: 0 1;
        display: none;
    }
    #wf-panel.visible {
        display: block;
    }
    #wf-tree {
        background: #0d1117;
        color: #8b949e;
        scrollbar-color: #30363d #0d1117;
    }
    #wf-tree > .tree--guides {
        color: #30363d;
    }
    #wf-tree .tree--highlight {
        background: #1c2128;
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
        background: #0d1117;
        color: #8b949e;
    }
    #input-area {
        background: #161b22;
        border-top: solid #30363d;
        padding: 0 1;
        height: 3;
    }
    #input-hint {
        height: 1;
        color: #3d8b44;
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
    }
    Footer {
        background: #161b22;
        color: #8b949e;
        height: 1;
    }
    """

    BINDINGS = [
        Binding("ctrl+c", "stop_task", "Stop", show=True),
        Binding("ctrl+l", "clear_chat", "Clear Chat", show=True),
        Binding("ctrl+w", "toggle_workflow", "Workflow", show=True),
        Binding("ctrl+q", "quit_app", "Quit", show=True),
        Binding("ctrl+h", "switch_headless", "Headless", show=False),
        Binding("escape", "focus_input", "Input", show=False),
        Binding("tab", "focus_workflow", "Workflow Focus", show=False),
        Binding("end", "scroll_to_bottom", "↓ Follow", show=False),
    ]

    TITLE = f"Arad Code v{VERSION}"
    SUB_TITLE = "Security Research Terminal"

    def __init__(self, initial_cmd: str = "", **kwargs):
        super().__init__(**kwargs)
        self._initial_cmd = initial_cmd.strip()
        self._wf_model = WorkflowModel()
        self._task: Optional[asyncio.Task] = None
        self._history: list[str] = []
        self._history_idx: int = -1
        self._waiting_to_exit: bool = False
        self._op_start: float = 0.0
        self._clock_task: Optional[asyncio.Task] = None
        self._queued_input: Optional[str] = None
        self._wf_visible: bool = False
        self._wf_open_node_id: Optional[int] = None
        self._finding_count: int = 0
        self._last_repo: str = ""
        self._last_db = None
        self._scroll_locked: bool = False
        self._scan_lines: list[str] = []

    # ── Layout ────────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-split"):
            with Container(id="output-container"):
                yield RichLog(id="output", highlight=True, markup=True, wrap=True)
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
        self.query_one("#input", Input).focus()
        if self._initial_cmd:
            self.call_after_refresh(self._dispatch, self._initial_cmd)

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

    def _clear_op(self):
        try:
            bar = self.query_one("#status", StatusBar)
            bar.op = ""
            bar.elapsed = 0.0
            bar.tool = ""
        except NoMatches:
            pass

    def _set_tool(self, name: str):
        try:
            bar = self.query_one("#status", StatusBar)
            bar.tool = name
            self._wf_model.current_tool = name
            self.query_one("#wf-panel", WorkflowPanel).rebuild()
        except NoMatches:
            pass

    # ── Log helpers ──────────────────────────────────────────────────────────

    def _write_scan(self, text: str):
        rendered = _rtlm(text)
        self._scan_lines.append(rendered)
        try:
            log = self.query_one("#output", RichLog)
            log.write(rendered)
            if not self._scroll_locked:
                log.scroll_end(animate=False)
        except NoMatches:
            pass

    def _log(self, text: str):
        self._write_scan(text)

    def _log_chat(self, text: str):
        try:
            log = self.query_one("#output", RichLog)
            log.write(_rtlm(text))
            if not self._scroll_locked:
                log.scroll_end(animate=False)
        except NoMatches:
            pass

    def _add_finding(self, count: int = 1):
        self._finding_count += count
        try:
            self.query_one("#status", StatusBar).findings = self._finding_count
        except NoMatches:
            pass

    # ── Scroll ────────────────────────────────────────────────────────────────

    def _unlock_scroll(self):
        self._scroll_locked = False
        try:
            self.query_one("#scroll-indicator", ScrollIndicator).locked = False
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
            asyncio.create_task(self._handle_inline_query(text[1:].strip()))
        elif self._task and not self._task.done():
            self._queued_input = text
            self._log(f"[dim]Queued: {text[:60]}[/dim]")
        else:
            self._dispatch(text)

    @on(Input.Changed, "#input")
    def _on_input_changed(self, event: Input.Changed) -> None:
        hint = self.query_one("#input-hint", Static)
        if event.value.startswith(">"):
            hint.add_class("active")
            hint.update("[dim green]query mode — streams LLM response[/dim green]")
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

    async def _handle_inline_query(self, question: str):
        if not question:
            self._log_chat("[dim]> (empty)[/dim]")
            return

        self._log_chat(f"\n[bold green]>[/bold green] {question}")

        if question.lower() in ("status", "summary"):
            self._log_chat(self._build_status_text())
            return
        if question.lower() == "findings":
            self._log_chat(self._build_findings_text())
            return

        try:
            cfg, db, mcp, runner = self._make_deps()
        except ValueError as exc:
            self._log_chat(f"[red]Config error:[/red] {exc}")
            return

        context = self._build_run_context()
        prompt = (
            f"Security researcher ran a pentest scan.\n"
            f"Context:\n{context}\n\n"
            f"Question: {question}\n\n"
            f"Answer in 2-5 sentences, specific and actionable."
        )

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
            self._log_chat("")
        except Exception as exc:
            self._log_chat(f"[red]Query error:[/red] {exc}")
        finally:
            self._clear_op()
            await runner.close()

    def _build_run_context(self) -> str:
        parts = []
        if self._last_repo:
            parts.append(f"Repo: {self._last_repo}")
        parts.append(f"Findings so far: {self._finding_count}")
        if self._last_db:
            try:
                hyps = self._last_db.get_hypotheses()
                if hyps:
                    parts.append(f"Hypotheses ({len(hyps)}):")
                    for h in hyps[:8]:
                        parts.append(f"  [{_sev_label(h.severity)}] {h.violated_invariant[:70]}")
            except Exception:
                pass
        return "\n".join(parts) if parts else "No run data yet."

    def _build_status_text(self) -> str:
        lines = ["\n[bold]Status[/bold]"]
        if self._last_repo:
            lines.append(f"  Repo: {self._last_repo}")
        lines.append(f"  Total findings: [cyan]{self._finding_count}[/cyan]")
        if self._last_db:
            try:
                hyps = self._last_db.get_hypotheses()
                for h in hyps[:15]:
                    c = _SEV_COLOR.get(_sev_label(h.severity), "white")
                    lines.append(f"  [{c}]■[/{c}] [{h.status}] {h.violated_invariant[:68]}")
            except Exception:
                pass
        return "\n".join(lines)

    def _build_findings_text(self) -> str:
        if not self._last_db:
            return "[dim]No run data yet.[/dim]"
        lines = ["\n[bold]Findings[/bold]"]
        try:
            hyps = self._last_db.get_hypotheses()
            if not hyps:
                lines.append("  [dim](none)[/dim]")
            for i, h in enumerate(hyps, 1):
                sl = _sev_label(h.severity)
                c = _SEV_COLOR.get(sl, "white")
                lines.append(
                    f"  {i}. [{c}]{sl.upper()}[/{c}]  "
                    f"[{h.status}]  {h.violated_invariant[:60]}"
                )
        except Exception as exc:
            lines.append(f"  [red]{exc}[/red]")
        return "\n".join(lines)

    # ── Workflow tree — node detail on Enter ──────────────────────────────────

    @on(Tree.NodeSelected, "#wf-tree")
    def _on_wf_node_selected(self, event: Tree.NodeSelected) -> None:
        node_id = id(event.node)
        if node_id == self._wf_open_node_id:
            self._wf_open_node_id = None
            self._log_chat("[dim]──[/dim]")
            return
        self._wf_open_node_id = node_id
        data = event.node.data
        if not data:
            return
        if data.get("type") == "phase":
            phase = self._wf_model._phase_idx.get(data["name"])
            if not phase:
                return
            status = "[green]done[/green]" if phase.done else "[yellow]running[/yellow]"
            lines = [f"\n[bold magenta]Phase: {phase.title}[/bold magenta]  {status}"]
            if phase.done:
                lines.append(f"  elapsed: {phase.elapsed:.1f}s")
            lines.append(f"  agents: {len(phase.agents)}")
            for a in phase.agents:
                if a.error:
                    lines.append(f"    [red]✗[/red] {a.label}  [red dim]{a.error}[/red dim]")
                elif a.done:
                    lines.append(f"    [green]✓[/green] {a.label}  [dim]{a.elapsed:.1f}s[/dim]")
                else:
                    lines.append(f"    [yellow]→[/yellow] {a.label}")
            self._log_chat("\n".join(lines))

        elif data.get("type") == "agent":
            agent = self._wf_model._agent_idx.get(data["label"])
            if not agent:
                return
            lines = [f"\n[bold]Skill: {agent.label}[/bold]"]
            if agent.error:
                lines.append(f"  status:  [red]error — {agent.error}[/red]")
            elif agent.done:
                lines.append(f"  status:  [green]done[/green]  {agent.elapsed:.1f}s")
            else:
                lines.append(f"  status:  [yellow]running…[/yellow]")
            if agent.findings:
                lines.append(f"  findings so far: {len(agent.findings)}")
                for i, h in enumerate(agent.findings, 1):
                    sl = _sev_label(getattr(h, "severity", 0))
                    c = _SEV_COLOR.get(sl, "white")
                    inv = getattr(h, "violated_invariant", str(h))[:70]
                    st = getattr(h, "status", "?")
                    lines.append(f"    {i}. [{c}]{sl.upper()}[/{c}]  ({st})  {inv}")
            else:
                lines.append(f"  [dim]no findings yet[/dim]")
            self._log_chat("\n".join(lines))

        elif data.get("type") == "finding":
            hyp = data.get("hyp")
            if not hyp:
                return
            sl = _sev_label(getattr(hyp, "severity", 0))
            c = _SEV_COLOR.get(sl, "white")
            st = getattr(hyp, "status", "?")
            lines = [
                f"\n[bold][{c}]{sl.upper()}[/{c}][/bold]  ({st})",
                f"[bold]Issue:[/bold]",
                f"  {getattr(hyp, 'violated_invariant', '?')}",
            ]
            evidence = getattr(hyp, "evidence", None)
            if evidence:
                lines.append(f"\n[bold]Evidence:[/bold]")
                lines.append(f"  {str(evidence)[:400]}")
            recommendation = getattr(hyp, "recommendation", None)
            if recommendation:
                lines.append(f"\n[bold]Recommendation:[/bold]")
                lines.append(f"  {str(recommendation)[:300]}")
            for attr in ("file_path", "location", "cwe", "cvss"):
                val = getattr(hyp, attr, None)
                if val:
                    lines.append(f"  [dim]{attr}:[/dim] {val}")
            self._log_chat("\n".join(lines))

    # ── Progress events (workflow scripts) ────────────────────────────────────

    def _progress(self, event: str, data):
        from .workflow import PhaseInfo, AgentRecord
        try:
            panel = self.query_one("#wf-panel", WorkflowPanel)
        except NoMatches:
            panel = None

        if event == "phase_start":
            p: PhaseInfo = data
            self._log(f"\n[bold magenta][Phase: {p.title}][/bold magenta]")
            self._set_op(p.title)
            self._wf_model.add_phase(p.name, p.title)
        elif event == "phase_end":
            p: PhaseInfo = data
            self._log(f"[dim]Phase {p.title} done in {p.elapsed():.1f}s[/dim]")
            self._wf_model.finish_phase(p.name)
        elif event == "agent_start":
            rec: AgentRecord = data
            self._log(f"  [yellow]→[/yellow] {rec.label}")
            self._wf_model.add_agent(rec.label, rec.phase)
        elif event == "agent_end":
            rec: AgentRecord = data["record"]
            elapsed = (rec.ended_at or time.monotonic()) - rec.started_at
            self._log(f"  [green]✓[/green] {rec.label} [dim]{elapsed:.1f}s[/dim]")
            self._wf_model.finish_agent(rec.label)
        elif event == "agent_error":
            rec: AgentRecord = data["record"]
            self._log(f"  [red]✗[/red] {rec.label}: {data['error'][:80]}")
            self._wf_model.finish_agent(rec.label, error=data["error"][:60])
        elif event == "votes_counted":
            self._log(
                f"  [cyan]votes[/cyan] {data['finding']}: "
                f"[green]{data['true']} real[/green] / [red]{data['false']} refuted[/red] "
                f"(round {data['round'] + 1})"
            )
        elif event == "inconclusive_vote":
            self._log(f"  [yellow]⟳[/yellow] inconclusive — re-examining")

        if panel:
            panel.rebuild()

    def _on_tool_event(self, event: str, data: dict):
        if event == "tool_call":
            name = data.get("name", "")
            short = name.replace("mcp__codebase-memory-mcp__", "").replace("mcp__sqz__", "sqz.")
            self._set_tool(short)

    # ── Command dispatch ──────────────────────────────────────────────────────

    def _dispatch(self, cmd: str):
        try:
            parts = shlex.split(cmd)
        except ValueError:
            parts = cmd.split()
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

        self._log(f"\n[bold cyan]>[/bold cyan] {cmd[:80]}")
        self._task = asyncio.create_task(self._run_command(cmd, parts))

        def _done_cb(task):
            self._clear_op()
            self._wf_model.current_tool = ""
            try:
                self.query_one("#wf-panel", WorkflowPanel).rebuild()
            except NoMatches:
                pass
            if self._queued_input:
                queued = self._queued_input
                self._queued_input = None
                self._log(f"\n[dim]Resuming queued: {queued[:60]}[/dim]")
                self._dispatch(queued)
            elif self._initial_cmd:
                self._waiting_to_exit = True
                self._log("\n[bold green]✓ Run complete.[/bold green]  [dim]Press Enter (or type a command) to close.[/dim]")

        self._task.add_done_callback(_done_cb)

    async def _run_command(self, cmd: str, parts: list[str]):
        verb = parts[0].lower()
        self._set_op(verb)
        try:
            if verb == "run":
                await self._cmd_run(parts[1:])
            elif verb == "skill":
                await self._cmd_skill(parts[1:])
            elif verb == "workflow":
                await self._cmd_workflow(parts[1:])
            elif verb == "deep-research":
                await self._cmd_deep_research(parts[1:])
            elif verb in ("report", "peers", "triage", "coverage", "calibrate",
                          "query", "doctor", "sarif", "init"):
                await self._cmd_cli(parts)
            else:
                self._log(f"[red]Unknown command:[/red] {verb}  (type [cyan]help[/cyan])")
        except asyncio.CancelledError:
            self._log("\n[yellow]Stopped.[/yellow] (resume with --resume)")
        except Exception as exc:
            self._log(f"\n[red]Error:[/red] {exc}")

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
        return cfg, db, mcp, runner

    # ── run ───────────────────────────────────────────────────────────────────

    async def _cmd_run(self, args: list[str]):
        if not args:
            self._log("[red]Usage:[/red] run <repo_path> [--phase N] [--resume] [--restart]")
            return

        repo_path = args[0]
        phase: Optional[str] = None
        resume = "--resume" in args
        restart = "--restart" in args

        for i, a in enumerate(args):
            if a == "--phase" and i + 1 < len(args):
                phase = args[i + 1]

        try:
            cfg, db, mcp, runner = self._make_deps()
        except ValueError as exc:
            self._log(f"[red]Config error:[/red] {exc}")
            return

        repo = str(Path(repo_path).resolve())
        self._last_repo = repo
        self._last_db = db
        self._finding_count = 0
        try:
            self.query_one("#status", StatusBar).findings = 0
        except NoMatches:
            pass

        self._log(f"[bold]Running scan on[/bold] {repo}")
        if phase:
            self._log(f"  phase: {phase}")

        if restart:
            from .cache import clear_run_state
            clear_run_state(repo)
            self._log("[dim]Run state cleared.[/dim]")

        if resume:
            from .cache import completed_skills
            commit = runner._get_commit(repo)
            done = completed_skills(repo, commit)
            if done:
                self._log(f"[dim]Resuming — {len(done)} skill(s) already done[/dim]")

        self._wf_model.reset()
        self._wf_model.add_phase("run", "Skill Scan")
        if not self._wf_visible:
            self.action_toggle_workflow()

        try:
            panel = self.query_one("#wf-panel", WorkflowPanel)
            panel.rebuild()
        except NoMatches:
            panel = None

        def _on_progress(name, status, result):
            if status == "started":
                self._wf_model.add_agent(name, "run")
                if panel:
                    panel.rebuild()
            elif status == "done":
                hyps = getattr(result, "hypotheses", []) if result else []
                h_count = len(hyps)
                self._wf_model.finish_agent(name)
                if hyps:
                    self._wf_model.add_findings(name, hyps)
                if panel:
                    panel.rebuild()
                suffix = f"  [cyan]{h_count} finding(s)[/cyan]" if h_count else "  [dim]0[/dim]"
                self._log(f"  [green]✓[/green] {name}{suffix}")
                if h_count:
                    self._add_finding(h_count)
            elif status == "skipped":
                self._wf_model.add_agent(name, "run")
                self._wf_model.finish_agent(name)
                if panel:
                    panel.rebuild()
                self._log(f"  [dim]✓ {name}: cached[/dim]")

        try:
            if phase:
                await runner.run_phase(phase, repo, verbose=False, resume=resume,
                                       on_progress=_on_progress)
            else:
                await runner.run_all(repo, verbose=False, resume=resume,
                                     on_progress=_on_progress)
            self._wf_model.finish_phase("run")
            if panel:
                panel.rebuild()
        finally:
            await runner.close()
            self._set_tool("")

    # ── skill ─────────────────────────────────────────────────────────────────

    async def _cmd_skill(self, args: list[str]):
        if len(args) < 2:
            self._log("[red]Usage:[/red] skill <name> <repo_path>")
            return
        skill_name, repo_path = args[0], args[1]
        extra = " ".join(args[2:])

        try:
            cfg, db, mcp, runner = self._make_deps()
        except ValueError as exc:
            self._log(f"[red]Config error:[/red] {exc}")
            return

        repo = str(Path(repo_path).resolve())
        self._last_repo = repo
        self._last_db = db
        self._log(f"[bold]Running skill[/bold] {skill_name} on {repo}")
        self._wf_model.reset()
        self._wf_model.add_phase("skill", skill_name)
        self._wf_model.add_agent(skill_name, "skill")
        if not self._wf_visible:
            self.action_toggle_workflow()
        try:
            panel = self.query_one("#wf-panel", WorkflowPanel)
            panel.rebuild()
        except NoMatches:
            panel = None

        try:
            result = await runner.run_skill(skill_name, repo, extra)
            h_count = len(result.hypotheses)
            conf = sum(1 for h in result.hypotheses if h.status in ("evidence_supported", "reproduced"))
            self._wf_model.finish_agent(skill_name)
            self._wf_model.finish_phase("skill")
            if panel:
                panel.rebuild()
            self._log(f"\n[green]Done.[/green] {h_count} hypothesis/hypotheses ({conf} confirmed)")
            self._add_finding(h_count)
            for h in result.hypotheses[:15]:
                c = _SEV_COLOR.get(_sev_label(h.severity), "white")
                self._log(f"  [{c}]■[/{c}] [{h.status}] {h.violated_invariant[:78]}")
            if result.open_questions:
                self._log(f"\n[dim]{len(result.open_questions)} open question(s)[/dim]")
        finally:
            await runner.close()
            self._set_tool("")

    # ── workflow ──────────────────────────────────────────────────────────────

    async def _cmd_workflow(self, args: list[str]):
        if not args:
            self._log("[red]Usage:[/red] workflow <script.py> [--repo <path>]")
            return

        script_path = args[0]
        repo_path = ""
        i = 1
        while i < len(args):
            if args[i] == "--repo" and i + 1 < len(args):
                repo_path = args[i + 1]
                i += 2
            else:
                i += 1

        if not Path(script_path).exists():
            self._log(f"[red]Script not found:[/red] {script_path}")
            return

        try:
            cfg, db, mcp, runner = self._make_deps()
        except ValueError as exc:
            self._log(f"[red]Config error:[/red] {exc}")
            return

        self._last_repo = repo_path
        self._last_db = db
        self._log(f"[bold]Running workflow[/bold] {script_path}")
        self._wf_model.reset()
        if not self._wf_visible:
            self.action_toggle_workflow()

        try:
            from .workflow import run_workflow_script
            result = await run_workflow_script(
                script_path,
                runner=runner,
                repo_path=repo_path,
                on_event=self._progress,
            )
            if isinstance(result, dict):
                confirmed = [f for f in result.get("findings", []) if f.get("confirmed")]
                self._log(
                    f"\n[green]Workflow complete.[/green] "
                    f"{len(confirmed)} confirmed / {len(result.get('findings', []))} total findings"
                )
            else:
                self._log("\n[green]Workflow complete.[/green]")
        finally:
            await runner.close()
            self._set_tool("")

    # ── deep-research ─────────────────────────────────────────────────────────

    async def _cmd_deep_research(self, args: list[str]):
        if not args:
            self._log("[red]Usage:[/red] deep-research <question> [--repo <path>]")
            return

        repo_path = ""
        qparts = []
        i = 0
        while i < len(args):
            if args[i] == "--repo" and i + 1 < len(args):
                repo_path = args[i + 1]
                i += 2
            else:
                qparts.append(args[i])
                i += 1

        question = " ".join(qparts)
        try:
            cfg, db, mcp, runner = self._make_deps()
        except ValueError as exc:
            self._log(f"[red]Config error:[/red] {exc}")
            return

        self._log(f"[bold]Deep Research:[/bold] {question}")

        try:
            from .deep_research import deep_research, format_research_output
            result = await deep_research(question, runner=runner, repo_path=repo_path)
            self._log(format_research_output(result))
        finally:
            await runner.close()

    # ── cli passthrough ───────────────────────────────────────────────────────

    async def _cmd_cli(self, parts: list[str]):
        import sys
        cmd = [sys.executable, "pentest.py", "--headless"] + parts
        self._log(f"[dim]→ pentest {' '.join(parts)}[/dim]")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(Path(__file__).parent.parent),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        async for line in proc.stdout:
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                self._log(text)
        await proc.wait()
        if proc.returncode != 0:
            self._log(f"[red]Exited {proc.returncode}[/red]")

    # ── Actions ───────────────────────────────────────────────────────────────

    def action_stop_task(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            self._log("\n[yellow]Stopped.[/yellow]")
        else:
            self._log("[dim]No task running.[/dim]")
        self._clear_op()

    def action_clear_chat(self) -> None:
        try:
            log = self.query_one("#output", RichLog)
            log.clear()
            for line in self._scan_lines:
                log.write(line)
            log.write("[dim yellow]── chat cleared ──[/dim yellow]")
            if not self._scroll_locked:
                log.scroll_end(animate=False)
        except NoMatches:
            pass

    def action_focus_input(self) -> None:
        try:
            self.query_one("#input", Input).focus()
        except NoMatches:
            pass

    def action_toggle_workflow(self) -> None:
        try:
            panel = self.query_one("#wf-panel", WorkflowPanel)
            self._wf_visible = not self._wf_visible
            if self._wf_visible:
                panel.add_class("visible")
            else:
                panel.remove_class("visible")
        except NoMatches:
            pass

    def action_focus_workflow(self) -> None:
        if not self._wf_visible:
            self.action_toggle_workflow()
        try:
            self.query_one("#wf-tree", Tree).focus()
        except NoMatches:
            pass

    def action_scroll_to_bottom(self) -> None:
        self._unlock_scroll()

    def action_quit_app(self) -> None:
        self.exit(0)

    def action_switch_headless(self) -> None:
        self.exit(result=("headless", self._initial_cmd))

    async def on_unmount(self) -> None:
        if self._clock_task:
            self._clock_task.cancel()
        if self._task and not self._task.done():
            self._task.cancel()


def launch_tui(initial_cmd: str = "") -> Optional[tuple]:
    app = AradCodeApp(initial_cmd=initial_cmd)
    result = app.run()
    return result
