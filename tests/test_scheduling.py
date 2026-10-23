import asyncio
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cache import completed_skills
from core.config import Config
from core.context import ContextWindow
from core.db import EvidenceStore
from core.llm import LLMClient
from core.runner import SkillRunner
from core.skills import SkillCatalog
from core.stack import StackProfile, _compose_services, describe, detect_stack
from core.usage import usage_scope

SKILLS = Path(__file__).resolve().parent.parent / "skills"
EMPTY = {"findings": {"hypotheses": [], "coverage": [], "open_questions": []}}


def call(name, args, i=0):
    return SimpleNamespace(id=f"c{i}", function=SimpleNamespace(name=name, arguments=json.dumps(args)))


class CountingLLM:
    def __init__(self, model="main-model", delay=0.03, fail_for=None, script=None):
        self.model = model
        self.delay = delay
        self.fail_for = fail_for
        self.script = script
        self.active = 0
        self.peak = 0
        self.skills = []
        self.wires = []

    async def complete_with_tools(self, messages, tools, system=None, tool_choice=None):
        skill = usage_scope.get().rsplit("@", 1)[0]
        self.skills.append(skill)
        self.wires.append([dict(m) for m in messages])
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(self.delay)
            if skill == self.fail_for:
                raise RuntimeError("model exploded")
        finally:
            self.active -= 1
        if self.script:
            return None, self.script.pop(0)
        return None, [call("finish", EMPTY)]


class NoMCP:
    async def find_project_for_repo(self, repo):
        return None

    async def close(self):
        pass


def git_repo(path, files):
    path.mkdir(parents=True, exist_ok=True)
    for rel, text in files.items():
        f = path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "-c", "commit.gpgsign=false",
                    "commit", "-qm", "i"], cwd=path, check=True)
    return str(path)


def make_runner(tmp_path, llm=None, **cfg):
    cfg.setdefault("transcripts", False)
    db = EvidenceStore(tmp_path / "e.db")
    runner = SkillRunner(Config(api_key="x", db_path=str(tmp_path / "e.db"), **cfg), db, NoMCP())
    runner._llm = llm or CountingLLM()
    return runner, db


def p4_skills():
    return [s.name for s in SkillCatalog(SKILLS).phase_skills("p4")]


def test_p4_skills_run_in_parallel_up_to_the_limit(tmp_path):
    repo = git_repo(tmp_path / "repo", {"app.py": "print(1)\n"})
    runner, db = make_runner(tmp_path, concurrency=3)
    events = []
    results = asyncio.run(runner.run_phase("p4", repo, skill_gating=False,
                                           on_progress=lambda n, s, r: events.append((n, s, r))))
    assert runner._llm.peak == 3
    assert [r.skill_name for r in results] == p4_skills()
    started = [r for n, s, r in events if s == "started"]
    assert len(started) == len(p4_skills()) and all(r["parallel"] for r in started)
    assert {n for n, s, r in events if s == "done"} == set(p4_skills())


def test_concurrency_one_keeps_skills_sequential(tmp_path):
    repo = git_repo(tmp_path / "repo", {"app.py": "print(1)\n"})
    runner, db = make_runner(tmp_path, concurrency=1)
    asyncio.run(runner.run_phase("p4", repo, skill_gating=False))
    assert runner._llm.peak == 1
    assert runner._llm.skills == p4_skills()


def test_skills_that_do_not_apply_are_skipped_and_recorded(tmp_path):
    repo = git_repo(tmp_path / "repo", {"tool/cli.py": "import sys\nprint(sys.argv)\n",
                                        "pyproject.toml": "[project]\nname='t'\n"})
    runner, db = make_runner(tmp_path)
    events = []
    asyncio.run(runner.run_phase("p4", repo, on_progress=lambda n, s, r: events.append((n, s, r))))
    skipped = {n: r for n, s, r in events if s == "not_applicable"}
    assert {"hunt-iac-cicd-misconfig", "hunt-ai-llm-mcp-security", "hunt-xss",
            "hunt-open-redirect"} <= set(skipped)
    assert "hunt-injection-sqli-cmdi" not in skipped
    assert skipped["hunt-iac-cicd-misconfig"] == "no Docker, IaC or CI files found"
    assert not set(skipped) & set(runner._llm.skills)
    rows = {r["name"]: r for r in db.coverage_detail(repo) if r["kind"] == "skill"}
    assert rows["hunt-xss"]["status"] == "not_applicable"
    assert set(skipped) <= completed_skills(repo, runner._get_commit(repo))

    runner2, _ = make_runner(tmp_path)
    asyncio.run(runner2.run_phase("p4", repo, skill_gating=False))
    assert "hunt-xss" in runner2._llm.skills
    rows = {r["name"] for r in db.coverage_detail(repo) if r["kind"] == "skill"}
    assert "hunt-xss" not in rows


def test_gating_can_be_turned_off_in_config(tmp_path):
    repo = git_repo(tmp_path / "repo", {"tool/cli.py": "print(1)\n"})
    runner, db = make_runner(tmp_path, skill_gating=False)
    asyncio.run(runner.run_phase("p4", repo))
    assert set(runner._llm.skills) == set(p4_skills())


def test_optional_skills_are_skipped_unless_turned_on(tmp_path):
    assert Config().optional_skills is False
    repo = git_repo(tmp_path / "repo", {"app.py": "print(1)\n"})
    catalog = SkillCatalog(SKILLS).phase_skills("p4")
    optional = {s.name for s in catalog if s.optional}
    plain = {s.name for s in catalog if s.optional and not s.requires}
    assert len(optional) == 9 and plain
    runner, db = make_runner(tmp_path)
    events = []
    asyncio.run(runner.run_phase("p4", repo, on_progress=lambda n, s, r: events.append((n, s, r))))
    skipped = {n: r for n, s, r in events if s == "not_applicable"}
    assert optional <= set(skipped) and not optional & set(runner._llm.skills)
    assert all("optional_skills" in skipped[n] for n in plain)
    assert "hunt-injection-sqli-cmdi" in runner._llm.skills
    rows = {r["name"]: r for r in db.coverage_detail(repo) if r["kind"] == "skill"}
    assert all(rows[n]["status"] == "not_applicable" for n in plain)

    runner2, _ = make_runner(tmp_path, optional_skills=True)
    asyncio.run(runner2.run_phase("p4", repo))
    assert plain <= set(runner2._llm.skills)


def test_a_failing_parallel_skill_stops_the_batch(tmp_path):
    repo = git_repo(tmp_path / "repo", {"app.py": "print(1)\n"})
    runner, db = make_runner(tmp_path, llm=CountingLLM(fail_for="hunt-injection-sqli-cmdi"), concurrency=3)
    events = []
    with pytest.raises(RuntimeError, match="model exploded"):
        asyncio.run(runner.run_phase("p4", repo, skill_gating=False,
                                     on_progress=lambda n, s, r: events.append((n, s))))
    states = {}
    for n, s in events:
        states[n] = s
    assert states["hunt-injection-sqli-cmdi"] == "interrupted"
    assert all(s in ("done", "interrupted") for s in states.values())
    done = completed_skills(repo, runner._get_commit(repo))
    assert "hunt-injection-sqli-cmdi" not in done
    assert {n for n, s in states.items() if s == "done"} <= done


def test_fast_model_runs_the_mapping_skills(tmp_path):
    repo = git_repo(tmp_path / "repo", {"app.py": "print(1)\n"})
    runner, db = make_runner(tmp_path, fast_model="cheap-model")
    cheap = CountingLLM(model="cheap-model")
    runner._tier_clients["cheap-model"] = cheap
    events = []
    results = asyncio.run(runner.run_phase("p1", repo, on_progress=lambda n, s, r: events.append((n, s, r))))
    assert results and all(r.model == "cheap-model" for r in results)
    assert all(r["model"] == "cheap-model" for n, s, r in events if s == "started")
    assert runner._llm.skills == [] and len(cheap.skills) == len(results)
    asyncio.run(runner.run_phase("p5", repo))
    assert runner._llm.skills == ["compose-attack-chains"]


def test_one_model_by_default(tmp_path):
    runner, db = make_runner(tmp_path)
    assert runner._llm_for("fast") is runner._llm
    assert runner._llm_for("verify") is runner._llm
    assert runner._llm_for_skill("inventory-repository") is runner._llm


def test_extra_models_get_their_own_clients_sharing_the_meter(tmp_path):
    db = EvidenceStore(tmp_path / "e.db")
    cfg = Config(api_key="x", db_path=str(tmp_path / "e.db"), model="big", fast_model="small",
                 verify_model="checker", transcripts=False)
    runner = SkillRunner(cfg, db, NoMCP())
    fast = runner._llm_for("fast")
    verify = runner._llm_for("verify")
    assert isinstance(fast, LLMClient) and fast.model == "small" and fast.meter is runner.meter
    assert verify.model == "checker" and runner._llm_for("verify") is verify
    assert runner._llm_for("main").model == "big"
    asyncio.run(runner.close())


def test_tool_events_name_their_skill(tmp_path):
    repo = git_repo(tmp_path / "repo", {"app.py": "print(1)\n"})
    llm = CountingLLM(script=[[call("list_dir", {"path": "."})], [call("finish", EMPTY, 1)]])
    runner, db = make_runner(tmp_path, llm=llm)
    seen = []
    runner.set_event_handler(lambda e, d: seen.append((e, d.get("skill"))))
    asyncio.run(runner.run_skill("hunt-ssrf", repo))
    assert ("tool_call", "hunt-ssrf") in seen and ("tool_result", "hunt-ssrf") in seen


def test_old_tool_output_is_trimmed_but_the_run_keeps_full_history(tmp_path):
    big = "".join(f"line {i:04d} " + "x" * 60 + "\n" for i in range(700))
    repo = git_repo(tmp_path / "repo", {"big.py": big})
    script = [[call("read_file", {"file_path": "big.py"}, i)] for i in range(9)]
    script.append([call("finish", EMPTY, 99)])
    llm = CountingLLM(script=script, delay=0)
    runner, db = make_runner(tmp_path, llm=llm, context_char_limit=60000, transcripts=True)
    asyncio.run(runner.run_skill("hunt-ssrf", repo))
    last = llm.wires[-1]
    tools = [m for m in last if m.get("role") == "tool"]
    assert len(tools) == 9
    assert all("trimmed to keep the context small" in m["content"] for m in tools[:3])
    assert all("trimmed" not in m["content"] for m in tools[-6:])
    assert len(tools[0]["content"]) < 2000 and len(tools[-1]["content"]) > 10000
    transcript = next((tmp_path / "transcripts").rglob("*.jsonl")).read_text()
    assert "trimmed to keep the context small" not in transcript


def test_window_is_stable_and_can_be_disabled():
    msgs = [{"role": "user", "content": "go"}]
    for i in range(10):
        msgs.append({"role": "assistant", "tool_calls": [{"id": str(i), "function": {"arguments": "{}"}}]})
        msgs.append({"role": "tool", "tool_call_id": str(i), "content": "y" * 5000})
    w = ContextWindow(20000, keep_recent=3)
    first = w.view(msgs)
    assert sum(1 for m in first if "trimmed" in str(m.get("content"))) == 7
    assert msgs[2]["content"] == "y" * 5000
    again = w.view(msgs)
    assert [m.get("content") for m in again] == [m.get("content") for m in first]
    assert ContextWindow(0).view(msgs) is msgs
    small = ContextWindow(10 ** 9)
    assert small.view(msgs) is msgs


def test_stack_detection_examples(tmp_path):
    flask = detect_stack(git_repo(tmp_path / "flask", {
        "requirements.txt": "flask\njinja2\nopenai\n",
        "app/main.py": "from flask import Flask, render_template\n",
        "app/templates/i.html": "<p>{{ x }}</p>\n",
    }))
    assert {"web", "templates", "llm"} <= flask.signals and "iac" not in flask.signals
    cli = detect_stack(git_repo(tmp_path / "cli", {"tool/cli.py": "import click\n",
                                                  "pyproject.toml": "[project]\nname='t'\n"}))
    assert cli.signals == set() and cli.complete
    svc = detect_stack(git_repo(tmp_path / "svc", {
        "go.mod": "module x\nrequire github.com/segmentio/kafka-go v0.4.0\n",
        "docker-compose.yml": "services:\n  api:\n    image: a\n  worker:\n    image: b\n",
        "cmd/api/main.go": 'package main\nimport "net/http"\n',
        ".github/workflows/ci.yml": "on: push\n",
    }))
    assert {"iac", "messaging", "multiservice", "web"} <= svc.signals
    tenants = detect_stack(git_repo(tmp_path / "saas", {"models.py": "class Invoice:\n    tenant_id = 1\n"}))
    assert "multitenant" in tenants.signals
    ldap = detect_stack(git_repo(tmp_path / "ldap", {"auth.py": "conn = ldap.initialize('ldap://dc')\n"}))
    assert "ldap" in ldap.signals


def test_stack_detection_without_git_skips_vendor_dirs(tmp_path):
    root = tmp_path / "plain"
    (root / "node_modules" / "react").mkdir(parents=True)
    (root / "node_modules" / "react" / "index.jsx").write_text("x")
    (root / "src").mkdir()
    (root / "src" / "main.c").write_text("int main(){return 0;}\n")
    profile = detect_stack(str(root))
    assert profile.signals == set() and profile.files_seen == 1


def test_incomplete_scans_never_skip_anything():
    assert StackProfile(signals=set(), complete=False).has_any(["web"])
    assert StackProfile(signals=set(), complete=True).has_any([])
    assert not StackProfile(signals={"llm"}, complete=True).has_any(["web", "iac"])
    assert describe(["web", "templates"]) == "web server or front-end code or server-side templates"
    assert _compose_services("services:\n  a:\n    image: x\n  b:\n    image: y\nvolumes:\n  d:\n") == 2
