import asyncio
import os
import sys
import traceback
from pathlib import Path

import pytest
from textual.widgets import Input, RichLog, Tree

from core import tui as tui_mod
from core.models import Evidence
from core.tui import AradCodeApp, ScrollIndicator, StatusBar
from fakes_tui import (
    FakeLLM, FakeRunner, install, log_text, make_db, make_hyp, status_text, tree_lines, type_cmd, wait_for,
    wait_idle, wait_started,
)

CASE_TIMEOUT = 60


class Case:
    def __init__(self, base, monkeypatch):
        self.tmp = base
        self.repo = base / "target repo"
        self.repo.mkdir()
        self.monkeypatch = monkeypatch
        self.results = []

    def check(self, name, cond, detail=""):
        self.results.append((name, bool(cond), detail))


def new_app(runner_kw=None, initial=""):
    db = make_db()
    runner = FakeRunner(db, **(runner_kw or {}))
    app = AradCodeApp(initial_cmd=initial)
    install(app, runner, db)
    return app, runner, db


async def t_markup_crashes(c):
    app, runner, db = new_app()
    async with app.run_test(size=(140, 40)) as pilot:
        await type_cmd(pilot, "foo [/bar]")
        await wait_idle(pilot)
        txt = log_text(app)
        c.check("A1 unknown command with [/bar] no crash", "Unknown command: foo" in txt, txt[-300:])
        runner.block_on = "p0-recon"
        await type_cmd(pilot, f"run '{c.repo}'")
        await pilot.pause(0.1)
        await type_cmd(pilot, "run /x/[/y]")
        txt = log_text(app)
        c.check("A1 queued run /x/[/y] logged literally", "queued (1): run /x/[/y]" in txt, txt[-300:])
        await pilot.press("ctrl+c")
        await wait_idle(pilot)
        txt = log_text(app)
        c.check("A1 queued command ran -> repo not found red error",
              "Repository not found: /x/[/y]" in txt, txt[-400:])
        await pilot.press("ctrl+l")
        await pilot.pause()
        c.check("A3 ctrl+l replay no crash", "chat cleared" in log_text(app))
        bar = app.query_one("#status", StatusBar)
        bar.op = "phase [/x] [bold]"
        bar.tool = "tool[/y]"
        await pilot.pause()
        c.check("A2 status bar renders op/tool literally", "phase [/x] [bold]" in status_text(app) and "tool[/y]" in status_text(app), status_text(app))
        app._log("[bold]unclosed [/nope]")
        app._log_chat("[/x]")
        await pilot.press("ctrl+l")
        await pilot.pause()
        c.check("A1/A3 broken markup falls back to plain and replays", "[bold]unclosed [/nope]" in log_text(app), log_text(app)[-200:])
    c.check("A app exited cleanly", app._exception is None, repr(app._exception))


async def t_status_findings(c):
    hyps = [make_hyp(), make_hyp(severity=10, status="initial", violated_invariant="RCE via [/eval] pickle"),
            make_hyp(severity=3, status="refuted", violated_invariant="low thing")]
    app, runner, db = new_app({"findings": {"p4-sqli": hyps}})
    ev = Evidence(hypothesis_id=hyps[0].id, kind="code", description="string concat into execute()",
                  file_path="app/db.py", line_start=41, line_end=44, snippet="cur.execute('...' + u)")
    db.save_evidence(str(c.repo.resolve()), ev)
    async with app.run_test(size=(160, 50)) as pilot:
        await type_cmd(pilot, f"run '{c.repo}'")
        await wait_idle(pilot)
        txt = log_text(app)
        c.check("B run complete summary", "Scan complete" in txt and "3 finding(s)" in txt, txt[-500:])
        c.check("B status bar findings after run", "3 findings" in status_text(app), status_text(app))
        await type_cmd(pilot, "> findings")
        await pilot.pause(0.2)
        txt = log_text(app)
        c.check("A4/B5 > findings shows status labels", "[evidence_supported]" in txt and "[initial]" in txt and "[refuted]" in txt, txt[-800:])
        c.check("B5 > findings lists escaped invariant", "RCE via [/eval] pickle" in txt, txt[-800:])
        c.check("B5 no AttributeError", "get_hypotheses" not in txt and "AttributeError" not in txt)
        await type_cmd(pilot, "> status")
        await pilot.pause(0.2)
        txt = log_text(app)
        c.check("B5 > status includes findings list", txt.count("SQL query built from user input") >= 2 and "Status" in txt, txt[-800:])
        ctx = app._build_run_context()
        c.check("B5 LLM context has hypotheses", "Hypotheses (3)" in ctx, ctx)
        tree = app.query_one("#wf-tree", Tree)
        target = None
        stack = [tree.root]
        while stack:
            n = stack.pop()
            if isinstance(n.data, dict) and n.data.get("type") == "finding" and n.data["hyp"].id == hyps[0].id:
                target = n
            stack.extend(n.children)
        tree.focus()
        await pilot.pause()
        tree.select_node(target)
        await pilot.pause(0.2)
        txt = log_text(app)
        c.check("B13 finding detail fields",
              all(s in txt for s in ("Finding", hyps[0].id, "HIGH", "sev 8/10", "confidence 7/10", "exposure", "internet",
                                     "reachability", "proven", "input control", "full", "CWE-89", "actor", "capability",
                                     "entry point", "POST /api/login", "impact", "execution path", "routes.py:login()",
                                     "1 more step", "app/db.py:41-44", "string concat into execute()")), txt[-1500:])
        agent_node = target.parent
        tree.select_node(agent_node)
        await pilot.pause(0.5)
        tree.select_node(agent_node.parent)
        await pilot.pause(0.2)
        txt = log_text(app)
        c.check("B13 agent/phase detail render", "Skill p4-sqli" in txt and "Phase Skill Scan" in txt, txt[-800:])
    c.check("B5 app exited cleanly", app._exception is None, repr(app._exception))


async def t_bindings(c):
    app, runner, db = new_app()
    async with app.run_test(size=(140, 40)) as pilot:
        inp = app.query_one("#input", Input)
        inp.value = "hello world"
        inp.cursor_position = len(inp.value)
        await pilot.press("ctrl+w")
        await pilot.pause()
        c.check("B6 ctrl+w toggles panel with input focused", app._wf_visible and inp.value == "hello world", (app._wf_visible, inp.value))
        await pilot.press("ctrl+w")
        await pilot.pause()
        c.check("B6 ctrl+w toggles back", not app._wf_visible)
        await pilot.press("tab")
        await pilot.pause()
        tree = app.query_one("#wf-tree", Tree)
        c.check("B6 tab focuses tree and shows panel", tree.has_focus and app._wf_visible, (app.focused, app._wf_visible))
        await pilot.press("escape")
        await pilot.pause()
        c.check("B6 escape returns to input", inp.has_focus, app.focused)
        await pilot.press("tab")
        await pilot.pause()
        await pilot.press("tab")
        await pilot.pause()
        c.check("B6 tab again returns to input", inp.has_focus, app.focused)
        keys = [b.key for b in AradCodeApp.BINDINGS]
        c.check("B6 ctrl+h binding removed", "ctrl+h" not in keys, keys)
        await type_cmd(pilot, "help")
        c.check("B help renders", "Commands" in log_text(app) and "[context…]" in log_text(app), log_text(app)[-300:])
    c.check("B6 app exited cleanly", app._exception is None, repr(app._exception))


async def t_query_status_and_tasks(c):
    app, runner, db = new_app({"delay": 0.05, "llm": FakeLLM(delay=0.05)})
    async with app.run_test(size=(140, 40)) as pilot:
        runner.block_on = "p1-surface"
        await type_cmd(pilot, f"run '{c.repo}'")
        await pilot.pause(0.4)
        before = status_text(app)
        bar = app.query_one("#status", StatusBar)
        op_before, tool_before = bar.op, bar.tool
        start_before = app._op_start
        await type_cmd(pilot, "> what is the risk?")
        await pilot.pause(0.1)
        mid = (bar.op, app._op_start)
        c.check("B7 query does not change running op", mid == (op_before, start_before), (mid, op_before))
        for _ in range(60):
            if not app._query_tasks:
                break
            await asyncio.sleep(0.05)
        await pilot.pause()
        c.check("B7 query finish does not clear running op", bar.op == op_before and bar.op != "", (bar.op, op_before))
        c.check("B18 query task tracked and released", not app._query_tasks)
        c.check("B21 query answered", "concatenates user input" in log_text(app))
        await pilot.press("ctrl+c")
        await wait_idle(pilot)
        lines = "\n".join(tree_lines(app))
        c.check("B8 interrupted agent shown stopped", "■ p1-surface" in lines and "stopped" in lines, lines)
        c.check("B8 phase marked stopped (not running)", "■ Skill Scan" in lines, lines)
        c.check("B8 status cleared after stop", "ready" in status_text(app), status_text(app))
        runner._llm = FakeLLM(fail=RuntimeError("bad [/key] token"))
        await type_cmd(pilot, "> again [/q]")
        await pilot.pause(0.3)
        txt = log_text(app)
        c.check("B21 echoed question escaped + error escaped", "> again [/q]" in txt and "Query error: bad [/key] token" in txt, txt[-400:])
        c.check("B7 idle query status cleared", "ready" in status_text(app), status_text(app))
        runner._llm = FakeLLM(delay=10)
        await type_cmd(pilot, "> slow one")
        await pilot.pause(0.2)
        pending = list(app._query_tasks)
        c.check("B18 slow query tracked", len(pending) == 1)
    c.check("B18 query cancelled on unmount", all(t.cancelled() or t.done() for t in pending), pending)
    c.check("B7 app exited cleanly", app._exception is None, repr(app._exception))


async def t_error_marks_failed(c):
    app, runner, db = new_app({"fail_on": "p1-surface"})
    async with app.run_test(size=(140, 40)) as pilot:
        await type_cmd(pilot, f"run '{c.repo}'")
        await wait_idle(pilot)
        lines = "\n".join(tree_lines(app))
        txt = log_text(app)
        c.check("B8 error marks agent failed", "✗ p1-surface" in lines, lines)
        c.check("B8 error marks phase failed", "✗ Skill Scan" in lines, lines)
        c.check("B8 error text escaped", "Error: LLM exploded [/boom] badly" in txt, txt[-300:])
    c.check("B8 app exited cleanly", app._exception is None, repr(app._exception))


async def t_cli(c):
    app, runner, db = new_app()
    seen = {}
    real_exec = asyncio.create_subprocess_exec
    script = c.tmp / "fake_cli.py"
    script.write_text("import os,sys\nprint('cwd', os.getcwd())\nprint('arr[i] and [bold]x[/bold]')\n"
                      "print('\\x1b[31mred text\\x1b[0m')\nprint('stdin', sys.stdin.read() == '')\n"
                      "print('cols', os.environ.get('COLUMNS'), os.environ.get('FORCE_COLOR'))\nprint('\u0633\u0644\u0627\u0645 \u062f\u0646\u06cc\u0627')\n")

    async def fake_exec(*cmd, **kw):
        seen["cmd"] = cmd
        seen["kw"] = kw
        return await real_exec(sys.executable, str(script), **kw)

    tui_mod.asyncio.create_subprocess_exec = fake_exec
    old_cwd = os.getcwd()
    os.chdir(c.repo)
    try:
        async with app.run_test(size=(140, 40)) as pilot:
            await type_cmd(pilot, "report .")
            await wait_idle(pilot)
            txt = log_text(app)
            c.check("B9 cli runs with cwd=os.getcwd()", seen["kw"]["cwd"] == str(c.repo) and f"cwd {c.repo}" in txt.replace("\n", ""), (seen["kw"]["cwd"], txt[-500:]))
            c.check("B9 cli uses absolute pentest.py", Path(seen["cmd"][1]).is_absolute() and seen["cmd"][1].endswith("pentest.py"), seen["cmd"])
            c.check("B9 stdin DEVNULL", seen["kw"]["stdin"] == asyncio.subprocess.DEVNULL and "stdin True" in txt, txt[-300:])
            c.check("B9 output plain, not markup", "arr[i] and [bold]x[/bold]" in txt, txt[-300:])
            c.check("B9 ansi colors kept, codes stripped", "red text" in txt and "\x1b" not in txt)
            from bidi.algorithm import get_display
            import arabic_reshaper
            c.check("D cli RTL line reordered", get_display(arabic_reshaper.reshape("سلام دنیا"), base_dir="R") in txt, txt[-200:])
            c.check("B9 COLUMNS/FORCE_COLOR env", "cols" in txt and " 1" in txt.split("cols", 1)[1].splitlines()[0], txt[-200:])
            log = app.query_one("#output", RichLog)
            red_line = [s for s in log.lines if "red text" in s.text][0]
            c.check("B9 ansi style applied", any(seg.style and seg.style.color for seg in red_line if "red" in seg.text), red_line)
            seen.clear()
            for cmd in ("triage .", "query .", "config-init"):
                await type_cmd(pilot, cmd)
                await wait_idle(pilot)
            txt = log_text(app)
            c.check("B9 interactive commands not launched", not seen and txt.count("is interactive") == 3, (seen, txt[-600:]))
            c.check("B9 headless hint", "python pentest.py --headless triage ." in txt, txt[-600:])
            script.write_text("import time\nprint('start', flush=True)\ntime.sleep(60)\n")
            await type_cmd(pilot, "report .")
            await pilot.pause(0.6)
            await pilot.press("ctrl+c")
            await wait_idle(pilot)
            c.check("B9 cancel kills child", "Stopped" in log_text(app), log_text(app)[-200:])
    finally:
        tui_mod.asyncio.create_subprocess_exec = real_exec
        os.chdir(old_cwd)
    c.check("B9 app exited cleanly", app._exception is None, repr(app._exception))


async def t_real_cli(c):
    app, runner, db = new_app()
    c.monkeypatch.setenv("PENTEST_API_KEY", "dummy")
    for name in ("PENTEST_API_BASE", "PENTEST_MODEL", "PENTEST_REASONING_EFFORT"):
        c.monkeypatch.delenv(name, raising=False)
    c.monkeypatch.chdir(c.tmp)
    async with app.run_test(size=(140, 40)) as pilot:
        await type_cmd(pilot, "list-skills")
        ok = await wait_idle(pilot, timeout=30)
        txt = log_text(app)
        c.check("B9 real pentest.py passthrough runs", ok and "→ pentest list-skills" in txt and len(txt.splitlines()) > 8, txt[-800:])
    c.check("B9 real app exited cleanly", app._exception is None, repr(app._exception))


async def t_workflow(c):
    wf = c.tmp / "wf_inject.py"
    wf.write_text(
        "async def run():\n"
        "    await phase('p1', title='Recon [/x] phase')\n"
        "    await agent('a', label='lbl [/y]')\n"
        "    await agent('explode please', label='bad agent')\n"
        "    await agent('dup', label='same')\n"
        "    await agent('dup', label='same')\n"
        "    v = await verify_finding({'id': 'F[/1]'})\n"
        "    await pipeline([1, 0], lambda x: 1 / x)\n"
        "    return {'findings': [v, 'not-a-dict']}\n")
    app, runner, db = new_app()
    old_cwd = os.getcwd()
    os.chdir(c.repo.parent)
    try:
        async with app.run_test(size=(160, 50)) as pilot:
            await type_cmd(pilot, f"workflow '{wf}' --repo '{c.repo.name}'")
            await wait_idle(pilot)
            txt = log_text(app)
            lines = "\n".join(tree_lines(app))
            c.check("B10 workflow repo resolved", any(call[0] == "run_prompt" and call[2] == str(c.repo.resolve()) for call in runner.calls), runner.calls)
            c.check("C/A2 workflow text escaped", "[Phase: Recon [/x] phase]" in txt and "lbl [/y]" in txt and "agent failed [/x] hard" in txt, txt[-1200:])
            c.check("C21w last phase ✓", "✓ Recon [/x] phase" in lines, lines)
            c.check("C22w duplicate labels both shown", "same #2" in lines and lines.count("✓ same") == 2, lines)
            c.check("C19w verify ran (3 verify agents)", lines.count("verify:F[/1]:r1") == 3, lines)
            c.check("C23w pipeline error logged", "pipeline" in txt and "division by zero" in txt, txt[-600:])
            c.check("C workflow complete summary", "1 confirmed / 2 total findings" in txt, txt[-300:])
            tree = app.query_one("#wf-tree", Tree)
            bad = None
            stack = [tree.root]
            while stack:
                n = stack.pop()
                if n.label.plain.startswith("✗ bad agent"):
                    bad = n
                stack.extend(n.children)
            tree.focus()
            tree.select_node(bad)
            await pilot.pause(0.2)
            c.check("A2 agent detail with [/x] error no crash", "Agent bad agent" in log_text(app) and "agent failed [/x] hard" in log_text(app).split("Agent bad agent")[-1])
            await type_cmd(pilot, "workflow nope.py")
            await type_cmd(pilot, f"workflow '{wf}' --repo /does/not/exist")
            await type_cmd(pilot, "deep-research what --repo /does/not/exist")
            await wait_idle(pilot)
            txt = log_text(app)
            c.check("B11 workflow/deep-research missing repo errors", "Script not found: nope.py" in txt and txt.count("Repository not found: /does/not/exist") == 2, txt[-500:])
    finally:
        os.chdir(old_cwd)
    c.check("C app exited cleanly", app._exception is None, repr(app._exception))


async def t_repo_checks_and_parse(c):
    app, runner, db = new_app()
    calls_before = []
    async with app.run_test(size=(140, 40)) as pilot:
        await type_cmd(pilot, "run /nope/missing")
        await type_cmd(pilot, "skill p4-sqli /nope/missing")
        await wait_idle(pilot)
        txt = log_text(app)
        c.check("B11 run/skill missing repo -> red error, no scan", txt.count("Repository not found: /nope/missing") == 2 and not runner.calls, (runner.calls, txt[-300:]))
        await type_cmd(pilot, f"run --phase 4 '{c.repo}'")
        await wait_idle(pilot)
        c.check("B19 --phase before repo parsed", runner.calls[-1][:3] == ("run_phase", "p4", str(c.repo.resolve())), runner.calls)
        await type_cmd(pilot, f"run '{c.repo}' --phase p2 --resume")
        await wait_idle(pilot)
        c.check("B19 --phase p2 after repo + resume", runner.calls[-1] == ("run_phase", "p2", str(c.repo.resolve()), True), runner.calls)
        await type_cmd(pilot, f"run --bogus '{c.repo}'")
        await wait_idle(pilot)
        c.check("B19 unknown option rejected", "Unknown option: --bogus" in log_text(app))
        runner.findings = {"p4-sqli": [make_hyp(), make_hyp()]}
        app._finding_count = 7
        await type_cmd(pilot, f"skill p4-sqli '{c.repo}' focus login")
        await wait_idle(pilot)
        c.check("B17 skill resets count", app._finding_count == 2, app._finding_count)
        c.check("B20 skill reconciles", runner.reconciled and runner.reconciled[-1] == str(c.repo.resolve()), runner.reconciled)
        c.check("A4 skill list shows status", "[evidence_supported]" in log_text(app))
    c.check("B11 app exited cleanly", app._exception is None, repr(app._exception))


async def t_resume_count(c):
    from core import cache
    repo = str(c.repo.resolve())
    db = make_db("resume")
    old = [make_hyp(skill_source="p0-recon", entry_point="GET /a"), make_hyp(skill_source="p0-recon", entry_point="GET /b"),
           make_hyp(skill_source="p9-old", entry_point="GET /c"), make_hyp(skill_source="p4-sqli", entry_point="GET /d")]
    for h in old:
        db.save_hypothesis(repo, h)
    cache.clear_run_state(repo)
    cache.mark_skill_done(repo, "abc123def456", "p0-recon")
    runner = FakeRunner(db, findings={"p4-sqli": [make_hyp()]})
    runner.done = {"p0-recon"}
    app = AradCodeApp()
    install(app, runner, db)
    async with app.run_test(size=(140, 40)) as pilot:
        await type_cmd(pilot, f"run '{c.repo}' --resume")
        await wait_idle(pilot)
        c.check("B17 resume counts only completed skills' findings + new", app._finding_count == 3, (app._finding_count, log_text(app)[-600:]))
        node = app._wf_model.get_agent("p0-recon")
        node2 = app._wf_model.add_agent("x", "run")
        c.check("B17 preloaded skill node cached with findings", node.state == "cached" and len(node.findings) == 2)
        dropped = app._wf_model.restart_agent("p0-recon")
        c.check("B17 restart resets node", dropped == 2 and not node.done and node.findings == [])
    cache.clear_run_state(repo)
    c.check("B17 app exited cleanly", app._exception is None, repr(app._exception))


async def t_restart_preloaded(c):
    from core import cache
    repo = str(c.repo.resolve())
    db = make_db("restart")
    db.save_hypothesis(repo, make_hyp(skill_source="p0-recon"))
    cache.clear_run_state(repo)
    cache.mark_skill_done(repo, "abc123def456", "p0-recon")
    runner = FakeRunner(db, findings={"p0-recon": [make_hyp(skill_source="p0-recon")]})
    runner.done = set()
    app = AradCodeApp()
    install(app, runner, db)
    async with app.run_test(size=(140, 40)) as pilot:
        await type_cmd(pilot, f"run '{c.repo}' --resume")
        await wait_idle(pilot)
        node = app._wf_model.get_agent("p0-recon")
        c.check("B17 preloaded skill that re-runs is reset (no double count)", app._finding_count == 1 and len(node.findings) == 1 and node.state == "done", (app._finding_count, node.state, len(node.findings)))
    cache.clear_run_state(repo)


async def t_queue_and_done(c):
    app, runner, db = new_app({"delay": 0.1}, initial=f"run '{c.repo}'")
    async with app.run_test(size=(140, 40)) as pilot:
        c.check("B15 initial running", await wait_started(pilot))
        await type_cmd(pilot, f"skill p0-recon '{c.repo}'")
        await type_cmd(pilot, "run /nope1")
        await type_cmd(pilot, "help")
        txt = log_text(app)
        c.check("B15 help immediate while running", "Commands" in txt and app._command_running(), txt[-300:])
        c.check("B15 FIFO keeps both queued", list(app._queue) == [f"skill p0-recon '{c.repo}'", "run /nope1"], list(app._queue))
        await wait_idle(pilot, timeout=10)
        txt = log_text(app)
        i1 = txt.find("Running skill")
        i2 = txt.find("Repository not found: /nope1")
        c.check("B15 queued ran in order", 0 < i1 < i2, (i1, i2))
        c.check("B16 run complete printed once", txt.count("Run complete") == 1, txt.count("Run complete"))
        c.check("B16 not waiting to exit while queue was pending", not app._waiting_to_exit)
    app2, runner2, db2 = new_app({"block_on": "p0-recon"}, initial=f"run '{c.repo}'")
    async with app2.run_test(size=(140, 40)) as pilot:
        await wait_started(pilot)
        await wait_for(pilot, lambda: ("run_all", str(c.repo.resolve()), False) in runner2.calls)
        await pilot.pause(0.2)
        await pilot.press("ctrl+c")
        await wait_idle(pilot)
        txt = log_text(app2)
        c.check("B16 stopped initial run worded as stopped", "Run stopped" in txt and "Run complete" not in txt and app2._waiting_to_exit, txt[-300:])
        await type_cmd(pilot, "run /nope")
        await wait_idle(pilot)
        c.check("B16 no extra completion message after later command", "Run complete" not in log_text(app2) and log_text(app2).count("Run stopped") == 1)
    app3, runner3, db3 = new_app({"fail_on": "p0-recon"}, initial=f"run '{c.repo}'")
    async with app3.run_test(size=(140, 40)) as pilot:
        await wait_for(pilot, lambda: "Run failed" in log_text(app3))
        await wait_idle(pilot)
        c.check("B16 failed initial run worded as failed", "Run failed" in log_text(app3), log_text(app3)[-300:])
        await pilot.press("enter")
        await pilot.pause()
    c.check("B16 enter closes after initial run", app3.return_code == 0 and app3._shutting_down)
    app4, runner4, db4 = new_app({"block_on": "p0-recon"})
    async with app4.run_test(size=(140, 40)) as pilot:
        await type_cmd(pilot, f"run '{c.repo}'")
        await type_cmd(pilot, f"run '{c.repo}'")
        await pilot.pause(0.1)
        await type_cmd(pilot, "exit")
        await pilot.pause()
    c.check("B16 exit while running doesn't dispatch queue", runner4.calls.count(("run_all", str(c.repo.resolve()), False)) == 1, runner4.calls)
    c.check("B16 apps exited cleanly", all(a._exception is None for a in (app, app2, app3, app4)))


async def t_headless(c):
    app, runner, db = new_app(initial="")
    async with app.run_test(size=(120, 30)) as pilot:
        await type_cmd(pilot, "headless")
        await pilot.pause()
    c.check("launch contract headless tuple", app.return_value == ("headless", ""), app.return_value)


async def t_scroll_lock(c):
    app, runner, db = new_app()
    async with app.run_test(size=(120, 30)) as pilot:
        for i in range(120):
            app._log(f"line {i}")
        await pilot.pause()
        log = app.query_one("#output", RichLog)
        c.check("B12 follows by default", log.scroll_y == log.max_scroll_y and not app._scroll_locked, (log.scroll_y, log.max_scroll_y))
        await pilot.hover("#output")
        from textual import events
        for _ in range(3):
            log.post_message(events.MouseScrollUp(log, 5, 5, 0, 0, 0, False, False, False, screen_x=5, screen_y=5))
        await pilot.pause()
        y = log.scroll_y
        ind = app.query_one("#scroll-indicator", ScrollIndicator)
        c.check("B12 scrolling up locks + indicator", app._scroll_locked and ind.locked and ind.display, (app._scroll_locked, ind.locked, ind.display))
        for i in range(30):
            app._log(f"more {i}")
        await pilot.pause()
        c.check("B12 new writes don't yank view", log.scroll_y == y and log.max_scroll_y > y, (log.scroll_y, y, log.max_scroll_y))
        await pilot.press("end")
        await pilot.pause(0.6)
        c.check("B12 End re-enables follow", not app._scroll_locked and log.scroll_y == log.max_scroll_y and not ind.display, (app._scroll_locked, log.scroll_y, log.max_scroll_y))
        for _ in range(2):
            log.post_message(events.MouseScrollUp(log, 5, 5, 0, 0, 0, False, False, False, screen_x=5, screen_y=5))
        await pilot.pause()
        c.check("B12 re-lock", app._scroll_locked)
        for _ in range(10):
            log.post_message(events.MouseScrollDown(log, 5, 5, 0, 0, 0, False, False, False, screen_x=5, screen_y=5))
        await pilot.pause()
        c.check("B12 scrolling back to bottom unlocks", not app._scroll_locked, (log.scroll_y, log.max_scroll_y))
        app._log("tail")
        await pilot.pause()
        c.check("B12 follows again", log.scroll_y == log.max_scroll_y)
    c.check("B12 app exited cleanly", app._exception is None, repr(app._exception))


async def t_tree_state(c):
    hyps = [make_hyp(), make_hyp(violated_invariant="second")]
    app, runner, db = new_app({"findings": {"p0-recon": hyps}, "block_on": "p1-surface"})
    async with app.run_test(size=(160, 50)) as pilot:
        await type_cmd(pilot, f"run '{c.repo}'")
        await pilot.pause(0.3)
        tree = app.query_one("#wf-tree", Tree)
        agent = None
        stack = [tree.root]
        while stack:
            n = stack.pop()
            if isinstance(n.data, dict) and n.data.get("key") == ("agent", "p0-recon"):
                agent = n
            stack.extend(n.children)
        tree.focus()
        await pilot.pause()
        tree.move_cursor(agent)
        await pilot.press("space")
        await pilot.pause()
        app._on_tool_event("tool_call", {"name": "grep"})
        app._wf_model.add_agent("extra-skill", "run")
        app._rebuild_panel()
        await pilot.pause()
        lines = tree_lines(app)
        c.check("B14 collapsed agent stays collapsed after rebuild", any("p0-recon" in l and "[collapsed]" in l for l in lines), lines)
        cur = tree.cursor_node
        c.check("B14 cursor preserved on same node", cur is not None and cur.data.get("key") == ("agent", "p0-recon"), cur and cur.label)
        root_before = tree.root.children[0]
        app._set_tool("read_file")
        await pilot.pause()
        c.check("B14 _set_tool only updates root label", tree.root.children and tree.root.children[0] is root_before and "read_file" in tree.root.label.plain, tree.root.label)
        await pilot.press("ctrl+c")
        await wait_idle(pilot)
    c.check("B14 app exited cleanly", app._exception is None, repr(app._exception))


async def t_rtl(c):
    app, runner, db = new_app()
    async with app.run_test(size=(80, 30)) as pilot:
        long = "این یک جمله بسیار طولانی فارسی است که باید قبل از دوطرفه سازی شکسته شود تا ترتیب درست بماند و خوانا باشد"
        app._log_chat(f"[cyan]{long}[/cyan]")
        app._log("[bold]سلام[/bold] دنیا")
        await pilot.pause()
        width = app._output_width()
        log = app.query_one("#output", RichLog)
        from bidi.algorithm import get_display
        import arabic_reshaper, textwrap
        rows = textwrap.wrap(long, width)
        expected_first = get_display(arabic_reshaper.reshape(rows[0]), base_dir="R")
        texts = [s.text.rstrip() for s in log.lines]
        c.check("D27 TUI passes width; first visual row = start of sentence", expected_first in texts, (width, texts[-6:]))
        c.check("D26 whole-line order", get_display(arabic_reshaper.reshape("سلام دنیا"), base_dir="R") in texts)
    c.check("D app exited cleanly", app._exception is None, repr(app._exception))


async def t_restart_and_ctrl_c(c):
    app, runner, db = new_app({"skills": ["resolve-open-questions", "p1-surface", "resolve-open-questions", "p4-sqli"],
                               "findings": {"resolve-open-questions": [make_hyp(skill_source="resolve-open-questions")]}})
    async with app.run_test(size=(140, 40)) as pilot:
        await type_cmd(pilot, f"run '{c.repo}'")
        await wait_idle(pilot)
        node = app._wf_model.get_agent("resolve-open-questions")
        lines = "\n".join(tree_lines(app))
        c.check("lead: re-started p0 node reset (not double counted)", app._finding_count == 1 and len(node.findings) == 1 and node.state == "done", (app._finding_count, node.state, lines))
        c.check("lead: p0 appears once in tree", lines.count("resolve-open-questions") == 1, lines)
        await pilot.press("ctrl+c")
        await pilot.pause()
        c.check("ctrl+c idle prints no task", "No task running." in log_text(app))
        inp = app.query_one("#input", Input)
        inp.value = "copy me"
        inp.focus()
        await pilot.pause()
        inp.select_all()
        await pilot.pause()
        before = log_text(app).count("No task running.")
        await pilot.press("ctrl+c")
        await pilot.pause()
        c.check("ctrl+c with selection falls through to copy", log_text(app).count("No task running.") == before and app.clipboard == "copy me", app.clipboard)
    c.check("restart app exited cleanly", app._exception is None, repr(app._exception))


async def t_models_usage_and_skips(c):
    hyp = make_hyp(model="gpt-5.5", verified_with="checker-model")
    app, runner, db = new_app({
        "models": {"p0-recon": "gpt-5.5", "p1-surface": "cheap-mini"},
        "usage": {"p1-surface": {"calls": 2, "prompt_tokens": 1200, "completion_tokens": 300,
                                 "cost": 0.0123, "unpriced_calls": 0}},
        "na": {"p4-sqli": "no web server or front-end code found"},
        "findings": {"p1-surface": [hyp]},
    })
    async with app.run_test(size=(160, 44)) as pilot:
        await type_cmd(pilot, f"run '{c.repo}' --all-skills")
        await wait_idle(pilot)
        txt = log_text(app)
        lines = "\n".join(tree_lines(app))
        c.check("model and spend logged for a finished skill",
                "cheap-mini" in txt and "1.5k tok" in txt and "$0.01" in txt, txt[-600:])
        c.check("skipped skill logged with its reason",
                "p4-sqli" in txt and "skipped: no web server or front-end code found" in txt, txt[-600:])
        c.check("skipped skill shown as n/a in the tree", "– p4-sqli" in lines and "n/a" in lines, lines)
        c.check("model shown next to a finished skill in the tree", "cheap-mini" in lines, lines)
        c.check("--all-skills turns gating off", runner.calls and runner.calls[-1][-1] == {"skill_gating": False},
                runner.calls)
        node = app._wf_model.get_agent("p1-surface")
        detail = app._agent_detail(node)
        c.check("skill detail lists model and calls", "cheap-mini" in detail and "2 call(s)" in detail, detail)
        finding = app._finding_detail(hyp)
        c.check("finding detail names reporting and verifying models",
                "gpt-5.5" in finding and "checker-model" in finding, finding)
        from core.usage import Usage
        app._on_usage("x@1", "m", Usage(calls=1, prompt_tokens=1000, cost=0.5))
        await pilot.pause()
        c.check("status bar shows the session spend", "$0.50" in status_text(app), status_text(app))
    c.check("models app exited cleanly", app._exception is None, repr(app._exception))


CASES = [t_markup_crashes, t_status_findings, t_bindings, t_query_status_and_tasks, t_error_marks_failed,
         t_cli, t_real_cli, t_workflow, t_repo_checks_and_parse, t_resume_count, t_restart_preloaded,
         t_queue_and_done, t_headless, t_scroll_lock, t_tree_state, t_rtl, t_restart_and_ctrl_c,
         t_models_usage_and_skips]


@pytest.mark.parametrize("case", CASES, ids=lambda f: f.__name__)
def test_tui(case, tmp_path, monkeypatch):
    monkeypatch.setenv("COLUMNS", "220")
    c = Case(tmp_path.resolve(), monkeypatch)
    try:
        asyncio.run(asyncio.wait_for(case(c), CASE_TIMEOUT))
    except Exception:
        c.results.append((case.__name__, False, traceback.format_exc()))
    failed = [(name, detail) for name, ok, detail in c.results if not ok]
    if failed:
        pytest.fail("\n".join(f"FAIL {name}  -- {detail}" for name, detail in failed), pytrace=False)
    assert c.results, f"{case.__name__} recorded no checks"
