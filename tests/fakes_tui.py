import asyncio
from pathlib import Path
from types import SimpleNamespace

from textual.widgets import Input, RichLog, Tree

from core.db import EvidenceStore
from core.models import Hypothesis
from core.tui import StatusBar


def make_hyp(**kw):
    base = dict(
        actor="unauthenticated user",
        capability="send crafted HTTP requests",
        entry_point="POST /api/login",
        security_boundary="auth",
        violated_invariant="SQL query built from user input",
        observable_impact="dump users table",
        execution_path=["routes.py:login()", "auth.py:check(user)", "db.py:raw(sql)", "sqlite execute", "rows returned"],
        severity=8,
        confidence=7,
        status="evidence_supported",
        reachability="proven",
        input_control="full",
        exposure="internet",
        cwe="CWE-89",
        skill_source="p4-sqli",
    )
    base.update(kw)
    return Hypothesis(**base)


class FakeLLM:
    def __init__(self, response="The login handler concatenates user input into SQL.", delay=0.0, fail=None):
        self.response = response
        self.delay = delay
        self.fail = fail

    async def complete_stream(self, messages, system=""):
        if self.fail:
            raise self.fail
        for word in self.response.split(" "):
            if self.delay:
                await asyncio.sleep(self.delay)
            yield word + " "


class FakeRunner:
    def __init__(self, db, skills=None, findings=None, delay=0.01, fail_on=None, block_on=None, llm=None,
                 models=None, usage=None, na=None):
        self.db = db
        self.skills = skills or ["p0-recon", "p1-surface", "p4-sqli"]
        self.findings = findings or {}
        self.delay = delay
        self.fail_on = fail_on
        self.block_on = block_on
        self._llm = llm or FakeLLM()
        self.handler = None
        self.calls = []
        self.closed = 0
        self.reconciled = []
        self.done = set()
        self.models = models or {}
        self.usage = usage or {}
        self.na = na or {}

    def set_event_handler(self, h):
        self.handler = h

    def _get_commit(self, repo):
        return "abc123def456"

    async def _run_list(self, skills, repo, resume, on_progress):
        for name in skills:
            if resume and name in self.done:
                on_progress(name, "skipped", None)
                continue
            if name in self.na:
                on_progress(name, "not_applicable", self.na[name])
                continue
            on_progress(name, "started", {"model": self.models[name]} if name in self.models else None)
            try:
                for tool in ("grep", "read_file", "mcp__codebase-memory-mcp__search_graph"):
                    if self.handler:
                        self.handler("tool_call", {"name": tool, "args": {}, "iteration": 0})
                    await asyncio.sleep(self.delay)
                if name == self.block_on:
                    await asyncio.sleep(3600)
                if name == self.fail_on:
                    raise RuntimeError("LLM exploded [/boom] badly")
            except BaseException:
                on_progress(name, "interrupted", None)
                raise
            hyps = self.findings.get(name, [])
            for h in hyps:
                self.db.save_hypothesis(repo, h)
            on_progress(name, "done", SimpleNamespace(hypotheses=hyps, model=self.models.get(name, ""),
                                                      usage=self.usage.get(name, {})))
        self.reconcile(repo)

    async def run_all(self, repo, verbose=False, resume=False, on_progress=None, **kw):
        self.calls.append(("run_all", repo, resume) + ((kw,) if kw else ()))
        await self._run_list(self.skills, repo, resume, on_progress)

    async def run_phase(self, phase, repo, verbose=False, resume=False, on_progress=None):
        self.calls.append(("run_phase", phase, repo, resume))
        await self._run_list(self.skills[:1], repo, resume, on_progress)

    async def run_skill(self, name, repo, extra=""):
        self.calls.append(("run_skill", name, repo, extra))
        await asyncio.sleep(self.delay)
        hyps = self.findings.get(name, [])
        for h in hyps:
            self.db.save_hypothesis(repo, h)
        return SimpleNamespace(hypotheses=hyps, open_questions=["q1"])

    async def run_prompt(self, prompt, repo_path="", extra_context="", schema=None):
        self.calls.append(("run_prompt", prompt[:30], repo_path))
        await asyncio.sleep(self.delay)
        if schema and "is_real" in str(schema):
            return {"is_real": True, "reasoning": "ok", "confidence": 8}
        if "explode" in prompt:
            raise RuntimeError("agent failed [/x] hard")
        return {"summary": "fine"}

    def reconcile(self, repo):
        self.reconciled.append(repo)
        return {}

    async def close(self):
        self.closed += 1


def make_db(name="t"):
    return EvidenceStore(Path(":memory:"))


def install(app, runner, db):
    def fake_make_deps(*a, **k):
        runner.set_event_handler(app._on_tool_event)
        return SimpleNamespace(), db, SimpleNamespace(), runner
    app._make_deps = fake_make_deps


def log_text(app):
    log = app.query_one("#output", RichLog)
    return "\n".join(s.text for s in log.lines)


def status_text(app):
    return app.query_one("#status", StatusBar).render().plain


def tree_lines(app):
    tree = app.query_one("#wf-tree", Tree)
    out = []

    def walk(node, depth):
        out.append(("  " * depth) + node.label.plain + ("" if node.is_expanded or not node.allow_expand or not node.children else " [collapsed]"))
        if node.is_expanded:
            for c in node.children:
                walk(c, depth + 1)
    walk(tree.root, 0)
    return out


async def type_cmd(pilot, text):
    inp = pilot.app.query_one("#input", Input)
    inp.focus()
    inp.value = text
    await pilot.press("enter")
    await pilot.pause()


async def wait_idle(pilot, timeout=5.0):
    app = pilot.app
    end = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < end:
        if not app._command_running() and not app._queue:
            await pilot.pause()
            return True
        await asyncio.sleep(0.02)
    return False


async def wait_started(pilot, timeout=10.0):
    app = pilot.app
    end = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < end:
        if app._command_running():
            return True
        await asyncio.sleep(0.02)
    return False


async def wait_for(pilot, predicate, timeout=10.0):
    end = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < end:
        if predicate():
            await pilot.pause()
            return True
        await asyncio.sleep(0.02)
    return False
