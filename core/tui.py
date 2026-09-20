from __future__ import annotations
import asyncio
import shlex
import time
from pathlib import Path
from typing import Optional

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import Footer, Header, Input, RichLog, Static

from .rtl import render as _rtl

VERSION = "2.0.1"

_BANNER = f"""[bold cyan]Arad Code[/bold cyan] [dim]v{VERSION}[/dim]
[dim]Type a command or message. ↑↓ history. Ctrl+C stop. Ctrl+L clear.[/dim]"""

_SHORTCUTS = "[dim]run <repo>[/dim] · [dim]workflow <script.py>[/dim] · [dim]deep-research <question>[/dim] · [dim]skill <name> <repo>[/dim] · [dim]help[/dim]"

_HELP = """
[bold]Commands[/bold]
  run <repo> [--phase N] [--resume] [--restart]
  skill <name> <repo>
  workflow <script.py> [--repo <path>]
  deep-research <question> [--repo <path>]
  report <repo>
  peers / triage / coverage / calibrate / query / doctor / sarif
  help · clear · exit

[dim]Env: PENTEST_API_KEY · PENTEST_MODEL · PENTEST_API_BASE[/dim]
"""


class StatusBar(Static):
    current_op: reactive[str] = reactive("")
    elapsed: reactive[float] = reactive(0.0)

    def render(self) -> str:
        if not self.current_op:
            return "[dim]ready[/dim]"
        return f"[yellow]●[/yellow] {self.current_op}  [dim]{self.elapsed:.1f}s[/dim]"


class AradCodeApp(App):
    CSS = """
    Screen {
        background: #0d1117;
        layers: base overlay;
    }
    Header {
        background: #161b22;
        color: #e6edf3;
        height: 1;
    }
    #output-container {
        height: 1fr;
        overflow-y: auto;
        padding: 0 1;
    }
    #output {
        height: auto;
        min-height: 100%;
        padding: 0;
    }
    #status {
        height: 1;
        padding: 0 1;
        background: #161b22;
        color: #8b949e;
    }
    #input-container {
        height: 3;
        background: #161b22;
        border-top: solid #30363d;
        padding: 0 1;
    }
    #input {
        background: #0d1117;
        border: none;
        height: 1;
        color: #e6edf3;
        padding: 0 1;
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
        Binding("ctrl+c", "stop_skill", "Stop", show=True),
        Binding("ctrl+l", "clear_output", "Clear", show=True),
        Binding("escape", "focus_input", "Focus Input", show=False),
    ]

    TITLE = f"Arad Code v{VERSION}"
    SUB_TITLE = "Security Research Terminal"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._skill_task: Optional[asyncio.Task] = None
        self._history: list[str] = []
        self._history_idx: int = -1
        self._op_start: float = 0.0
        self._clock_task: Optional[asyncio.Task] = None
        self._queued_input: Optional[str] = None
        self._current_cmd: Optional[str] = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="output-container"):
            yield RichLog(id="output", highlight=True, markup=True, wrap=True)
        yield StatusBar(id="status")
        with Container(id="input-container"):
            yield Input(placeholder="Enter command…", id="input")
        yield Footer()

    def on_mount(self) -> None:
        log = self.query_one("#output", RichLog)
        log.write(_BANNER)
        log.write(_SHORTCUTS)
        log.write("")
        self._start_clock()
        self.query_one("#input", Input).focus()

    def _start_clock(self):
        async def _tick():
            while True:
                await asyncio.sleep(0.5)
                try:
                    bar = self.query_one("#status", StatusBar)
                    if bar.current_op:
                        bar.elapsed = time.monotonic() - self._op_start
                except NoMatches:
                    pass
        self._clock_task = asyncio.create_task(_tick())

    def _set_op(self, name: str):
        bar = self.query_one("#status", StatusBar)
        bar.current_op = name
        bar.elapsed = 0.0
        self._op_start = time.monotonic()

    def _clear_op(self):
        bar = self.query_one("#status", StatusBar)
        bar.current_op = ""
        bar.elapsed = 0.0

    def _log(self, text: str):
        self.query_one("#output", RichLog).write(text)

    @on(Input.Submitted, "#input")
    def handle_input(self, event: Input.Submitted) -> None:
        cmd = event.value.strip()
        event.input.value = ""
        if not cmd:
            return

        self._history.append(cmd)
        self._history_idx = -1

        if self._skill_task and not self._skill_task.done():
            self._queued_input = cmd
            self._log(f"[dim]Queued: {_rtl(cmd)}[/dim]")
            return

        self._dispatch(cmd)

    def on_key(self, event) -> None:
        inp = self.query_one("#input", Input)
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
        elif event.key == "down":
            if self._history_idx >= 0:
                self._history_idx += 1
                if self._history_idx >= len(self._history):
                    self._history_idx = -1
                    inp.value = ""
                else:
                    inp.value = self._history[self._history_idx]
                inp.cursor_position = len(inp.value)

    def _dispatch(self, cmd: str):
        parts = shlex.split(cmd)
        if not parts:
            return
        verb = parts[0].lower()

        if verb in ("exit", "quit"):
            self.exit(0)
            return
        if verb in ("clear", "cls"):
            self.action_clear_output()
            return
        if verb == "help":
            self._log(_HELP)
            return

        self._log(f"\n[bold cyan]>[/bold cyan] {_rtl(cmd)}")
        self._current_cmd = cmd
        self._skill_task = asyncio.create_task(self._run_command(cmd, parts))

        def _done_cb(task):
            self._clear_op()
            self._current_cmd = None
            if self._queued_input:
                queued = self._queued_input
                self._queued_input = None
                self._log(f"\n[dim]Resuming queued: {_rtl(queued)}[/dim]")
                self._dispatch(queued)

        self._skill_task.add_done_callback(_done_cb)

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
            self._log("\n[yellow]Stopped.[/yellow]")
        except Exception as exc:
            self._log(f"\n[red]Error:[/red] {exc}")

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
        return cfg, db, mcp, runner

    def _progress(self, event: str, data):
        from .workflow import PhaseInfo, AgentRecord
        if event == "phase_start":
            p: PhaseInfo = data
            self._log(f"\n[bold magenta][Phase: {p.title}][/bold magenta]")
            self._set_op(p.title)
        elif event == "phase_end":
            p: PhaseInfo = data
            self._log(f"[dim]Phase {p.title} done in {p.elapsed():.1f}s[/dim]")
        elif event == "agent_start":
            rec: AgentRecord = data
            self._log(f"  [yellow]→[/yellow] {rec.label}")
        elif event == "agent_end":
            rec: AgentRecord = data["record"]
            elapsed = (rec.ended_at or time.monotonic()) - rec.started_at
            self._log(f"  [green]✓[/green] {rec.label} [dim]{elapsed:.1f}s[/dim]")
        elif event == "agent_error":
            rec: AgentRecord = data["record"]
            self._log(f"  [red]✗[/red] {rec.label}: {data['error'][:80]}")
        elif event == "votes_counted":
            self._log(
                f"  [cyan]votes[/cyan] {data['finding']}: "
                f"[green]{data['true']} real[/green] / [red]{data['false']} refuted[/red] "
                f"(round {data['round'] + 1})"
            )
        elif event == "inconclusive_vote":
            self._log(f"  [yellow]⟳[/yellow] inconclusive — re-examining from different angle")

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
        self._log(f"[bold]Running scan on[/bold] {repo}")
        if phase:
            self._log(f"  phase filter: {phase}")

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

        def _on_progress(name, status, result):
            if status == "done":
                h_count = len(result.hypotheses) if result else 0
                self._log(f"  [green]✓[/green] {name} — {h_count} hypothesis/hypotheses")
            elif status == "skipped":
                self._log(f"  [dim]→ {name}: skipped[/dim]")

        try:
            if phase:
                await runner.run_phase(phase, repo, verbose=False, resume=resume,
                                       on_progress=_on_progress)
            else:
                await runner.run_all(repo, verbose=False, resume=resume,
                                     on_progress=_on_progress)
        finally:
            await runner.close()

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
        self._log(f"[bold]Running skill[/bold] {skill_name} on {repo}")

        try:
            result = await runner.run_skill(skill_name, repo, extra)

            h_count = len(result.hypotheses)
            conf_count = sum(1 for h in result.hypotheses
                             if h.status in ("evidence_supported", "reproduced"))
            self._log(f"\n[green]Done.[/green] {h_count} hypothesis/hypotheses ({conf_count} confirmed)")

            _sev_color = {"critical": "bright_red", "high": "red",
                          "medium": "yellow", "low": "green"}
            for h in result.hypotheses[:15]:
                color = _sev_color.get(h.severity, "white")
                self._log(f"  [{color}]■[/{color}] [{h.status}] {h.violated_invariant[:80]}")

            if result.open_questions:
                self._log(f"\n[dim]{len(result.open_questions)} open question(s)[/dim]")
        finally:
            await runner.close()

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

        self._log(f"[bold]Running workflow[/bold] {script_path}")

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
                self._log(f"\n[green]Workflow complete.[/green] Result: {result}")
        finally:
            await runner.close()

    async def _cmd_deep_research(self, args: list[str]):
        if not args:
            self._log("[red]Usage:[/red] deep-research <question> [--repo <path>]")
            return

        repo_path = ""
        question_parts = []
        i = 0
        while i < len(args):
            if args[i] == "--repo" and i + 1 < len(args):
                repo_path = args[i + 1]
                i += 2
            else:
                question_parts.append(args[i])
                i += 1

        question = " ".join(question_parts)

        try:
            cfg, db, mcp, runner = self._make_deps()
        except ValueError as exc:
            self._log(f"[red]Config error:[/red] {exc}")
            return

        self._log(f"[bold]Deep Research:[/bold] {_rtl(question)}")

        try:
            from .deep_research import deep_research, format_research_output
            result = await deep_research(question, runner=runner, repo_path=repo_path)
            self._log(format_research_output(result))
        finally:
            await runner.close()

    async def _cmd_cli(self, parts: list[str]):
        import subprocess
        import sys

        cmd = [sys.executable, "pentest.py"] + parts
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
                self._log(_rtl(text))

        await proc.wait()
        if proc.returncode != 0:
            self._log(f"[red]Exited {proc.returncode}[/red]")

    def action_stop_skill(self) -> None:
        if self._skill_task and not self._skill_task.done():
            self._skill_task.cancel()
            self._log("\n[yellow]Stopping…[/yellow] (resume with --resume)")
        self._clear_op()

    def action_clear_output(self) -> None:
        self.query_one("#output", RichLog).clear()
        self.query_one("#output", RichLog).write(_BANNER)

    def action_focus_input(self) -> None:
        self.query_one("#input", Input).focus()

    async def on_unmount(self) -> None:
        if self._clock_task:
            self._clock_task.cancel()
        if self._skill_task and not self._skill_task.done():
            self._skill_task.cancel()


def launch_tui():
    app = AradCodeApp()
    app.run()
