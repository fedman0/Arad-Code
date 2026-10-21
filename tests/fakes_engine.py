import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from core.config import Config
from core.db import EvidenceStore
from core.llm import Reply
from core.runner import SkillRunner

EMPTY = {"findings": {"hypotheses": [], "coverage": [], "open_questions": []}}


class FakeMCP:
    async def find_project_for_repo(self, repo):
        return "fake-project"

    async def search_graph(self, **kw):
        return "graph: nothing"

    async def trace_path(self, **kw):
        return json.dumps(kw)

    async def get_code_snippet(self, qn, project=None):
        return "def handler(): pass"

    async def search_code(self, pattern, limit=50, project=None, regex=False):
        return json.dumps({"pattern": pattern, "regex": regex})

    async def get_architecture(self, aspects=None, project=None):
        return "arch"

    async def close(self):
        pass


def tc(i, name, args):
    return SimpleNamespace(id=f"call_{i}", function=SimpleNamespace(name=name, arguments=json.dumps(args)))


class ScriptedLLM:
    def __init__(self, turns):
        self.turns = list(turns)
        self.calls = []

    async def complete_turn(self, messages, tools, system=None, tool_choice=None, **extra):
        self.calls.append({"messages": [dict(m) for m in messages], "tool_choice": tool_choice,
                           "tools": [t["function"]["name"] for t in tools], **extra})
        if not self.turns:
            return Reply(None, [tc(999, "finish", EMPTY)], "tool_calls")
        t = self.turns.pop(0)
        if isinstance(t, Reply):
            return t
        if isinstance(t, str):
            return Reply(t, None, "stop")
        return Reply(None, t, "tool_calls")


def make_repo(base):
    d = Path(base)
    d.mkdir(parents=True, exist_ok=True)
    (d / "app").mkdir()
    (d / "app" / "views.py").write_text(
        "import os\n"
        "def search(request):\n"
        "    name = request.GET['name']\n"
        "    cursor.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n"
        "    return name\n"
        "def other(request):\n"
        "    cursor.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n"
    )
    (d / ".github").mkdir()
    (d / ".github" / "ci.yml").write_text("on: pull_request_target\n")
    git = ["git", "-c", "user.email=a@b", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "init", "-q"], cwd=d, check=True)
    subprocess.run(git + ["add", "."], cwd=d, check=True)
    subprocess.run(git + ["commit", "-qm", "i"], cwd=d, check=True)
    return d


def make_runner(tmp):
    db = EvidenceStore(Path(tmp) / "e2e.db")
    cfg = Config(api_key="x", db_path=str(Path(tmp) / "e2e.db"))
    r = SkillRunner(cfg, db, FakeMCP())
    return r, db
